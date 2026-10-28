"""Run only on an isolated GitHub Ubuntu24.04 runner or our marked container.

Uses uniquely prefixed fixture units, loopback TCP and cumulative counters.
Never references production dazzle-vps units, credentials, ports or state.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid

REPOSITORY=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPOSITORY))
from deployment.handoff import render_existing_member,guard_name,OLD_WRITER


def wait_for(check,timeout=8):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            value=check()
            if value:return value
        except (OSError,KeyError,json.JSONDecodeError,sqlite3.Error):pass
        time.sleep(0.03)
    raise AssertionError('fixture condition deadline exceeded')


class LongClient:
    def __init__(self,port):
        self.connection=socket.create_connection(('127.0.0.1',port),timeout=2)
        self.connection.settimeout(1);self.reader=self.connection.makefile('rb')
        self.stopped=threading.Event();self.error=None;self.count=0;self.pids=set()
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        try:
            while not self.stopped.is_set():
                value=str(self.count).encode();self.connection.sendall(value+b'\n')
                answer=self.reader.readline().split()
                assert answer[:2]==[b'ACK',value]
                self.pids.add(int(answer[2]));self.count+=1;self.stopped.wait(0.02)
        except BaseException as exc:self.error=type(exc).__name__
    def close(self):
        self.stopped.set();self.thread.join(timeout=2);self.reader.close();self.connection.close()


class Scenario:
    def __init__(self,label):
        self.prefix='dazzle-handoff-it-'+uuid.uuid4().hex[:12]+'-'+label
        self.root=Path('/run')/self.prefix;self.root.mkdir(mode=0o700)
        self.fixture=Path('/run')/(self.prefix+'-fixture.py')
        self.fixture.write_bytes(Path(__file__).with_name('fixture.py').read_bytes());self.fixture.chmod(0o755)
        self.units={};self.clients={};self.extra_paths=[]
        self.old=self.prefix+'-old.service';self.new=self.prefix+'-new.service'
        self.identities={worker:str(uuid.uuid4()) for worker in ('a','b','c')}
    def ctl(self,*arguments,check=True):
        # The only mutated units must have been explicitly registered by this case.
        names=[arg for arg in arguments if arg.endswith('.service')]
        if any(name not in self.units for name in names):raise AssertionError('unowned unit operation')
        result=subprocess.run(['/usr/bin/systemctl',*arguments],capture_output=True,text=True,timeout=15)
        if check and result.returncode:raise AssertionError('fixture systemctl failed: '+str(arguments)+' '+result.stderr[:600])
        return result
    def name(self,role,worker):return self.prefix+'-'+role+'@'+worker+'.service'
    def write_unit(self,name,body):
        if not name.startswith(self.prefix+'-'):raise AssertionError('unowned unit filename')
        path=Path('/etc/systemd/system')/name
        if name not in self.units and (path.exists() or path.is_symlink()):raise AssertionError('fixture collision')
        path.write_text(body);path.chmod(0o644);self.units[name]=body
    def service(self,command,*,kind='notify',watchdog=None):
        return ('[Service]\nType='+kind+'\nNotifyAccess=main\nExecStart='+sys.executable+' '+str(self.fixture)+' '+command+
                '\nRestart=no\nKillMode=control-group\nTimeoutStartSec=8\nTimeoutStopSec=2\n'+
                ('WatchdogSec='+str(watchdog)+'\n' if watchdog else ''))
    def core_text(self,worker,guarded):
        old=(REPOSITORY/'deployment/systemd/dazzle-proxy@.service').read_text()
        if guarded:
            old=render_existing_member(old,self.identities[worker])
            old=old.replace(guard_name(self.identities[worker]),self.name('guard',worker))
        header=old.split('[Service]',1)[0].replace(OLD_WRITER,self.old)
        return header+self.service('core --root '+str(self.root)+' --worker %i',kind='exec')
    def setup(self,*,fail=False):
        self.write_unit(self.old,'[Unit]\nDescription=fixture original exclusive writer\n'+self.service('writer --root '+str(self.root)+' --actor old',watchdog=10))
        self.write_unit(self.new,'[Unit]\nDescription=fixture read-only warmed candidate writer\n'+self.service('writer --root '+str(self.root)+' --actor new --standby'+(' --fail-acquire' if fail else ''),watchdog=10))
        self.write_unit(self.prefix+'-core@.service',self.core_text('%i',False))
        for worker in ('a','b','c'):
            name=self.name('core',worker)
            if (Path('/etc/systemd/system')/name).exists():raise AssertionError('fixture instance collision')
            self.units[name]=None  # Initially loaded from the template, not a full instance file.
            self.write_unit(self.name('guard',worker),'[Unit]\nDescription=fixture individual truthful counter guard\n'+self.service('guard --root '+str(self.root)+' --worker '+worker,watchdog=5)+'ProtectSystem=strict\nReadOnlyPaths='+str(self.root)+'\n')
        self.ctl('daemon-reload');self.ctl('start',self.old)
        for worker in ('a','b'):
            self.ctl('start',self.name('core',worker))
            info=wait_for(lambda:json.loads((self.root/('core-'+worker+'.json')).read_text()))
            self.clients[worker]=LongClient(info['port'])
        wait_for(lambda:all(self.counter(worker) for worker in ('a','b')))
    def counter(self,worker):
        with sqlite3.connect('file:'+str(self.root/'ledger.sqlite3')+'?mode=ro',uri=True,timeout=.2) as db:
            return db.execute('SELECT pid,epoch,raw,used,sampled FROM counters WHERE worker=?',(worker,)).fetchone()
    def state(self,name):
        result=self.ctl('show',name,'--property=ActiveState,MainPID,NRestarts,BindsTo')
        return dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    def prepare(self):
        for worker in ('a','b'):self.ctl('start',self.name('guard',worker))
        self.ctl('start','--no-block',self.new)
        wait_for(lambda:(self.root/'new-warm.json').exists())
        assert self.state(self.new)['ActiveState']=='activating'
        with sqlite3.connect(self.root/'ledger.sqlite3') as db:assert db.execute('SELECT COUNT(*) FROM writers').fetchone()[0]==1
        # An unready guard must leave existing bindings untouched.
        self.ctl('start','--no-block',self.name('guard','c'));time.sleep(.1)
        assert self.state(self.name('guard','c'))['ActiveState']=='activating'
        assert self.old in self.state(self.name('core','b'))['BindsTo'].split()
        self.ctl('stop',self.name('guard','c'))
    def adopt(self):
        before={worker:self.state(self.name('core',worker)) for worker in ('a','b')}
        for worker in ('a','b'):self.write_unit(self.name('core',worker),self.core_text(worker,True))
        self.ctl('daemon-reload')
        for worker in ('a','b'):
            after=self.state(self.name('core',worker))
            assert after['MainPID']==before[worker]['MainPID'] and after['NRestarts']==before[worker]['NRestarts']
            assert self.old not in after['BindsTo'].split() and self.name('guard',worker) in after['BindsTo'].split()
        return before
    def assert_streams(self,before):
        for worker in ('a','b'):
            state=self.state(self.name('core',worker));client=self.clients[worker]
            assert state['ActiveState']=='active' and state['MainPID']==before[worker]['MainPID'] and state['NRestarts']=='0'
            assert client.error is None and client.count>2 and client.pids=={int(before[worker]['MainPID'])}
            counter=self.counter(worker);assert counter[2]==counter[3] # sum of absolute deltas, never duplicated/reset
    def success(self):
        self.setup();self.prepare();before=self.adopt()
        began=time.monotonic();self.ctl('stop',self.old)
        wait_for(lambda:self.state(self.new)['ActiveState']=='active',timeout=4)
        elapsed=time.monotonic()-began;assert elapsed<5
        time.sleep(.15);self.assert_streams(before)
        with sqlite3.connect(self.root/'ledger.sqlite3') as db:
            assert [row[0] for row in db.execute('SELECT actor FROM writers ORDER BY seq')]==['old','new']
        # New API-only core can bootstrap a guard, then must show real fresh frames.
        (self.root/'bootstrap-c.json').write_text(json.dumps({'api_only':True,'prepared':time.monotonic()}))
        self.ctl('start',self.name('guard','c'));self.write_unit(self.name('core','c'),self.core_text('c',True));self.ctl('daemon-reload')
        self.ctl('start',self.name('core','c'));wait_for(lambda:self.counter('c'))
        (self.root/'bootstrap-c.json').unlink();time.sleep(.1)
        assert self.state(self.name('core','c'))['ActiveState']=='active'
        # A crashed guard stops only its own core.
        self.ctl('kill','--kill-whom=main','--signal=SIGKILL',self.name('guard','a'))
        wait_for(lambda:self.state(self.name('core','a'))['ActiveState']=='inactive')
        assert self.state(self.name('core','b'))['MainPID']==before['b']['MainPID'] and self.clients['b'].error is None
        # No fake freshness: withholding only b's counter observations expires b.
        (self.root/'pause-b').touch();wait_for(lambda:self.state(self.name('core','b'))['ActiveState']=='inactive',timeout=7)
        assert self.state(self.name('core','c'))['ActiveState']=='active'
        return {'handoff_seconds':round(elapsed,3),'core_pid_and_single_tcp_preserved':True,'single_writer_accounting':True,'guard_failure_isolated':True,'stale_sample_failed_closed':True,'new_core_bootstrap':True}
    def fallback(self):
        self.setup(fail=True);self.prepare();before=self.adopt()
        began=time.monotonic();self.ctl('stop',self.old)
        wait_for(lambda:self.state(self.new)['ActiveState']=='failed',timeout=3)
        self.ctl('stop',self.new);self.ctl('start',self.old)
        wait_for(lambda:all(time.monotonic()-self.counter(worker)[4]<.2 for worker in ('a','b')),timeout=2)
        assert time.monotonic()-began<5
        # Restore old dependencies only after old writer has real fresh samples.
        for worker in ('a','b'):self.write_unit(self.name('core',worker),self.core_text(worker,False))
        self.ctl('daemon-reload');self.assert_streams(before)
        for worker in ('a','b'):assert self.old in self.state(self.name('core',worker))['BindsTo'].split()
        return {'failed_takeover_returned_to_old_writer':True,'core_pid_and_single_tcp_preserved':True,'database_restored':False}
    def tls_namespace(self):
        private=self.root/'private';private.mkdir(mode=0o700)
        source=private/'web-tls';source.mkdir(mode=0o750);os.chown(source,0,65534)
        # Fixture leaf is intentionally group-writable: only the readonly bind
        # (not DAC alone) must prevent writing from the nobody namespace.
        cert=source/'cert.pem';cert.write_bytes(b'fixture-certificate-one');cert.chmod(0o660);os.chown(cert,0,65534)
        view=Path('/run')/(self.prefix+'-tls-view');view.mkdir(mode=0o755);self.extra_paths.append(view)
        runtime=self.prefix+'-tls-result';result=Path('/run')/runtime/'result.json';self.extra_paths.append(result.parent)
        direct=subprocess.run(['/usr/sbin/runuser','-u','nobody','--','test','-r',str(cert)]).returncode
        assert direct!=0
        name=self.prefix+'-tls.service'
        body='[Unit]\nDescription=fixture readonly TLS directory namespace\n'+self.service('tls --view '+str(view/'cert.pem')+' --source '+str(cert)+' --result '+str(result))
        body+='User=nobody\nGroup=nogroup\nRuntimeDirectory='+runtime+'\nRuntimeDirectoryMode=0700\nProtectSystem=strict\nBindReadOnlyPaths='+str(source)+':'+str(view)+'\n'
        self.write_unit(name,body);self.ctl('daemon-reload');self.ctl('start',name)
        first=wait_for(lambda:json.loads(result.read_text()));assert first['uid']==65534
        replacement=source/'next.pem';replacement.write_bytes(b'fixture-certificate-two');replacement.chmod(0o660);os.chown(replacement,0,65534);replacement.replace(cert)
        expected=hashlib.sha256(b'fixture-certificate-two').hexdigest()
        last=wait_for(lambda:(value if (value:=json.loads(result.read_text()))['sha256']==expected else None))
        assert last['pid']==first['pid']
        return {'private_parent_not_readable':True,'readonly_directory_bind_worked':True,'rotation_visible_without_restart':True}
    def close(self):
        for client in self.clients.values():client.close()
        if self.units:
            instances=[name for name in self.units if '@.service' not in name]
            self.ctl('stop',*instances,check=False)
            self.ctl('reset-failed',*instances,check=False)
        for name,body in self.units.items():
            path=Path('/etc/systemd/system')/name
            if body is not None and path.is_file() and not path.is_symlink() and path.read_text()==body:path.unlink()
        if self.units:self.ctl('daemon-reload',check=False)
        shutil.rmtree(self.root,ignore_errors=True);self.fixture.unlink(missing_ok=True)
        for path in self.extra_paths:
            if path.parent==Path('/run') and path.name.startswith(self.prefix):shutil.rmtree(path,ignore_errors=True)


def main():
    isolated=os.environ.get('GITHUB_ACTIONS')=='true' or (Path('/.dockerenv').exists() and Path('/etc/dazzle-handoff-isolated-container').exists())
    if not isolated or os.geteuid()!=0 or Path('/proc/1/comm').read_text().strip()!='systemd':
        raise SystemExit('Run only in an isolated GitHub Ubuntu24.04 systemd runner or the dedicated marked container, as root.')
    release=Path('/etc/os-release').read_text()
    if 'VERSION_ID="24.04"' not in release:raise SystemExit('Ubuntu24.04 is required')
    results={}
    for label,operation in (('success','success'),('fallback','fallback'),('tls','tls_namespace')):
        scenario=Scenario(label)
        try:results[label]=getattr(scenario,operation)()
        finally:scenario.close()
    print(json.dumps({'isolated_systemd_handoff':'passed','results':results,'production_units_touched':False},sort_keys=True))


if __name__=='__main__':main()
