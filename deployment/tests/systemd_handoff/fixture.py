"""Isolated loopback/counter systemd fixtures; never used by production units."""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import sqlite3
import threading
import time
import uuid

stopped = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stopped.set())
signal.signal(signal.SIGINT, lambda *_: stopped.set())


def notify(message):
    address = os.environ.get('NOTIFY_SOCKET')
    if not address: return
    if address.startswith('@'): address = '\0' + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client: client.sendto(message.encode(), address)


def atomic(path, value):
    path = Path(path); temporary = path.with_name(path.name + '.' + str(os.getpid()))
    temporary.write_text(json.dumps(value)); temporary.replace(path)


def alive(pid):
    try: os.kill(pid, 0); return True
    except ProcessLookupError: return False


def core(root, worker):
    lock = threading.Lock(); total = 0; epoch = str(uuid.uuid4())
    def save(): atomic(root/('counter-'+worker+'.json'), {'pid':os.getpid(),'epoch':epoch,'total':total})
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            nonlocal total
            for data in iter(self.rfile.readline, b''):
                reply = b'ACK ' + data.strip() + b' ' + str(os.getpid()).encode() + b'\n'
                with lock:
                    total += len(data)+len(reply); save()
                self.wfile.write(reply); self.wfile.flush()
    class Server(socketserver.ThreadingTCPServer): daemon_threads=True;allow_reuse_address=True
    with Server(('127.0.0.1',0),Handler) as server:
        save(); atomic(root/('core-'+worker+'.json'), {'pid':os.getpid(),'port':server.server_address[1],'epoch':epoch})
        server.timeout=0.1; notify('READY=1')
        while not stopped.is_set(): server.handle_request()


def writer(root, actor, standby, fail_acquire):
    with (root/'writer.lock').open('a+b') as lease:
        while not stopped.is_set():
            try: fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                if not standby: return 71
                observed={}
                for worker in ('a','b','c'):
                    path=root/('counter-'+worker+'.json')
                    if path.exists(): observed[worker]=json.loads(path.read_text())
                atomic(root/(actor+'-warm.json'),{'pid':os.getpid(),'writer':False,'observed':observed})
                notify('STATUS=standby-ready; writer=false');stopped.wait(0.05)
        if stopped.is_set():return 0
        if fail_acquire:return 23
        database=sqlite3.connect(root/'ledger.sqlite3',timeout=1)
        database.execute('PRAGMA journal_mode=WAL')
        database.execute('CREATE TABLE IF NOT EXISTS counters(worker TEXT PRIMARY KEY,pid INTEGER,epoch TEXT,raw INTEGER,used INTEGER,sampled REAL)')
        database.execute('CREATE TABLE IF NOT EXISTS writers(seq INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT,pid INTEGER,at REAL)')
        database.execute('INSERT INTO writers(actor,pid,at) VALUES(?,?,?)',(actor,os.getpid(),time.monotonic()));database.commit()
        ready=False
        try:
            while not stopped.is_set():
                for worker in ('a','b','c'):
                    path=root/('counter-'+worker+'.json')
                    if not path.exists() or (root/('pause-'+worker)).exists():continue
                    value=json.loads(path.read_text())
                    if not alive(value['pid']):continue
                    old=database.execute('SELECT pid,epoch,raw,used FROM counters WHERE worker=?',(worker,)).fetchone()
                    if old and (old[0]!=value['pid'] or old[1]!=value['epoch'] or old[2]>value['total']):return 24
                    used=value['total'] if old is None else old[3]+value['total']-old[2]
                    database.execute('INSERT OR REPLACE INTO counters VALUES(?,?,?,?,?,?)',(worker,value['pid'],value['epoch'],value['total'],used,time.monotonic()))
                database.commit()
                if not ready:
                    notify('READY=1');ready=True
                notify('WATCHDOG=1');stopped.wait(0.05)
        finally:database.close()
    return 0


def guard(root, worker):
    ready=False
    while not stopped.is_set():
        valid=False
        try:
            with sqlite3.connect('file:'+str(root/'ledger.sqlite3')+'?mode=ro',uri=True,timeout=0.2) as database:
                value=database.execute('SELECT pid,epoch,sampled FROM counters WHERE worker=?',(worker,)).fetchone()
            current=json.loads((root/('counter-'+worker+'.json')).read_text())
            valid=bool(value and value[0]==current['pid'] and value[1]==current['epoch'] and alive(value[0]) and 0<=time.monotonic()-value[2]<=5)
        except (OSError,sqlite3.Error):pass
        if not valid:
            bootstrap=root/('bootstrap-'+worker+'.json')
            if bootstrap.exists():
                proof=json.loads(bootstrap.read_text())
                valid=proof.get('api_only') is True and 0<=time.monotonic()-proof['prepared']<=5
        if valid:
            if not ready:notify('READY=1');ready=True
            notify('WATCHDOG=1')
        elif ready:return 25
        stopped.wait(0.05)
    return 0


def tls_probe(view, source, result):
    # This tests namespace/permissions and directory updates, not real TLS crypto.
    try:Path(source).read_bytes();return 26
    except PermissionError:pass
    try:Path(view).write_bytes(b'forbidden');return 27
    except OSError:pass
    while not stopped.is_set():
        value=Path(view).read_bytes()
        atomic(Path(result),{'pid':os.getpid(),'uid':os.getuid(),'sha256':hashlib.sha256(value).hexdigest()})
        notify('READY=1');stopped.wait(0.05)
    return 0


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('role',choices=['core','writer','guard','tls'])
    parser.add_argument('--root',type=Path)
    parser.add_argument('--worker')
    parser.add_argument('--actor',default='old')
    parser.add_argument('--standby',action='store_true')
    parser.add_argument('--fail-acquire',action='store_true')
    parser.add_argument('--view');parser.add_argument('--source');parser.add_argument('--result')
    args=parser.parse_args()
    if args.role=='core':return core(args.root,args.worker)
    if args.role=='writer':return writer(args.root,args.actor,args.standby,args.fail_acquire)
    if args.role=='guard':return guard(args.root,args.worker)
    return tls_probe(args.view,args.source,args.result)


if __name__=='__main__':raise SystemExit(main())
