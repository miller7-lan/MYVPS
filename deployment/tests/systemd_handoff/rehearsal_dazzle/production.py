"""Rehearsal writer and warmed standby with the production unit's argv and notify protocol."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import time
import socket
import threading

from .common import MODE, age, api_sample, cgroup_pid, connect, notify, now, persist, read_policy, stop_event, workers


def fault_mode():
    value = MODE.read_text().strip() if MODE.exists() else ""
    if value.startswith("{"):
        from .release_marker import RELEASE
        fault = json.loads(value)
        return fault["mode"] if fault["release"] == RELEASE else ""
    return value


def portal_socket(state_dir, policy, active, stopped):
    """Stand-in for the private portal RPC; only the dedicated web uid can query it."""
    path = Path("/run/dazzle-vps-portal/agent.sock")
    if policy.get("version") != 2:
        return
    server = socket.socket(socket.AF_UNIX)
    path.unlink(missing_ok=True)
    server.bind(str(path))
    os.chown(path, os.geteuid(), __import__('pwd').getpwnam("dazzle-web").pw_gid)
    os.chmod(path, 0o660)
    server.listen(8)
    server.settimeout(0.2)
    def serve():
        import struct
        while not stopped.is_set():
            try:
                client, _ = server.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(1)
                _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                client.recv(4096)
                status = 403 if uid != policy['portal_uid'] else 404 if active.is_set() else 503
                if status == 404:
                    with open(Path(state_dir)/'fixture-portal-probes', 'a') as log:
                        log.write('authorized-unknown-token-query\n')
                client.sendall(json.dumps({'status':status}).encode()+b'\n')
        server.close()
    threading.Thread(target=serve, daemon=True).start()


def rpc(state_dir, policy):
    """Explicit fixture RPC, using real privilege drop and SQLite transactions."""
    request = json.loads(sys.stdin.buffer.readline())
    connection = connect(state_dir, read_only=False)
    action, params = request['action'], request.get('params', {})
    def meta(key, default=None):
        row = connection.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone()
        return json.loads(row[0]) if row else default
    def set_meta(key,value):
        connection.execute('INSERT OR REPLACE INTO meta VALUES(?,?)',(key,json.dumps(value)))
    revision = meta('revision',0)
    reply = {'ok':True,'revision':revision,'data':{},'error':None}
    if action == 'snapshot':
        users=[]
        for row in connection.execute('SELECT * FROM users'):
            user=dict(row)
            worker=connection.execute('SELECT public_port FROM production_workers WHERE user_id=?',(user['id'],)).fetchone()
            user.update(port=worker[0],disabled_reasons=json.loads(user.pop('reasons_json')),trial=None)
            users.append(user)
        used=sum(user['used_upload']+user['used_download'] for user in users)
        configured=meta('fixture-budget-configured',False)
        total=meta('fixture-budget-total',0)
        reserved=sum(max(0,(user['quota_bytes'] or 0)+user['topup_bytes']-user['used_upload']-user['used_download'])
                     for user in users if user['role']=='member' and user['quota_pool']!='administrator')
        reply['data']={'budget':{'configured':configured,'used_bytes':used,'admin_remaining_bytes':max(0,total-used-reserved)},
                       'users':users,'health':{'controller_mode':'normal'}}
    elif request.get('expected_revision') != revision:
        reply.update(ok=False,error={'code':'REVISION_CONFLICT'})
    elif action == 'budget.configure' and fault_mode() == 'budget-rejected':
        reply.update(ok=False,error={'code':'FIXTURE_BUDGET_REJECTED'})
    elif action == 'budget.configure':
        connection.execute('BEGIN IMMEDIATE')
        set_meta('fixture-budget-configured',True)
        set_meta('fixture-budget-total',params['total_bytes'])
        connection.execute("UPDATE users SET unlimited=0 WHERE role='admin'")
        set_meta('revision',revision+1)
        connection.execute('COMMIT')
        reply['revision']=revision+1
    elif action == 'user.update' and params.get('quota_pool')=='administrator':
        connection.execute('BEGIN IMMEDIATE')
        connection.execute("UPDATE users SET quota_pool='administrator' WHERE id=?",(params['user_id'],))
        set_meta('revision',revision+1)
        connection.execute('COMMIT')
        reply['revision']=revision+1
    else:
        reply.update(ok=False,error={'code':'UNKNOWN_FIXTURE_ACTION'})
    connection.close()
    print(json.dumps(reply))
    return 0 if reply['ok'] else 1


def sample_all(connection):
    result = []
    for worker in workers(connection):
        pid, sample = cgroup_pid(worker["role"], worker["worker_id"]), api_sample(worker["api_port"])
        if pid and sample:
            result.append((worker, sample, pid))
    return result


PHASE, DRAIN_LAG = 0.45, 0.35


def write_loop(connection, stopped, origin):
    """Production cadence: each worker's 1 s frame at its own phase, persisted only on a
    later drain tick and stamped with the frame time, so persisted ages never all reach zero."""
    schedule, pending = {}, []
    while not stopped.is_set():
        now = time.monotonic()
        for index, worker in enumerate(workers(connection)):
            due = schedule.setdefault(worker["worker_id"], origin + 1.0 + PHASE * index)
            if now >= due:
                schedule[worker["worker_id"]] = due + 1.0
                pid, sample = cgroup_pid(worker["role"], worker["worker_id"]), api_sample(worker["api_port"])
                if pid and sample:
                    pending.append((now + DRAIN_LAG, worker, sample, pid))
        ready = [(worker, sample, pid) for due, worker, sample, pid in pending if due <= now]
        if ready:
            persist(connection, ready)
            pending = [item for item in pending if item[0] > now]
        notify("WATCHDOG=1")
        stopped.wait(0.05)


def warm(state_dir):
    """Read-only proof: fresh trusted ledger, same Core PID and native epoch per worker."""
    try:
        reader = connect(state_dir, read_only=True)
    except Exception:
        return False
    try:
        rows = workers(reader)
        for worker in rows:
            user = reader.execute("SELECT * FROM users WHERE id=?", (worker["user_id"],)).fetchone()
            sample = api_sample(worker["api_port"])
            if (not user or not user["trusted_sample"] or age(user["last_sample_at"]) > 5.0 or not sample
                    or sample["epoch"] != user["meter_epoch"] or cgroup_pid(worker["role"], worker["worker_id"]) != worker["process_id"]):
                return False
        return bool(rows)
    finally:
        reader.close()


def standby(state_dir, stopped, active):
    lock = os.open(Path(state_dir) / "agent.lock", os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(lock)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        return 2
    ready, last_status = False, 0.0
    while not stopped.is_set():
        if warm(state_dir) and fault_mode() != 'standby-never-ready':
            if not ready or time.monotonic() - last_status >= 0.5:
                notify("STATUS=standby-ready; writer=false; pid=%d; lock_inode=%d; checked_ns=%d" % (os.getpid(), info.st_ino, time.monotonic_ns()))
                if not ready:
                    print(json.dumps({'phase':'standby-ready','pid':os.getpid()}),flush=True)
                ready, last_status = True, time.monotonic()
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                stopped.wait(0.1)
                continue
            mode = fault_mode()
            if mode == "fail-takeover":
                return 23
            if mode == "hang-takeover":
                stopped.wait(3600)
                return 0
            connection = connect(state_dir, read_only=False)
            acquired = now()
            while not stopped.is_set():
                samples = sample_all(connection)
                if samples and all(sample["at"] > acquired.isoformat() for _, sample, _ in samples):
                    break
                stopped.wait(0.02)
            persist(connection, samples)
            active.set()
            notify("READY=1\nSTATUS=writer-ready; trusted-samples=true")
            write_loop(connection, stopped, time.monotonic())
            connection.close()
            return 0
        if ready:
            notify("STATUS=standby-warming; writer=false")
            ready = False
        stopped.wait(0.1)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("command", choices=["agent", "rpc", "subscription"])
    parser.add_argument("--standby", action="store_true")
    parser.add_argument("--allow-no-core-recovery", action="store_true")
    args = parser.parse_args(argv)
    policy = read_policy(args.policy)
    if args.command == 'rpc':
        return rpc(args.state_dir, policy)
    if args.command == 'subscription':
        from .portal import serve
        return serve('0.0.0.0',9443,'/etc/dazzle-vps/tls/cert.pem','/etc/dazzle-vps/tls/key.pem',None)
    stopped = stop_event()
    active = threading.Event()
    portal_socket(args.state_dir, policy, active, stopped)
    if args.standby:
        return standby(args.state_dir, stopped, active)
    lock = os.open(Path(args.state_dir) / "agent.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return 1
    connection = connect(args.state_dir, read_only=False)
    persist(connection, sample_all(connection))
    notify("READY=1\nSTATUS=writer-ready; trusted-samples=true")
    write_loop(connection, stopped, time.monotonic())
    connection.close()
    os.close(lock)
    return 0


if __name__ == "__main__":
    sys.exit(main())
