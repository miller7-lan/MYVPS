"""Real flock and gRPC-Web observations, never a production host or fake heartbeat."""
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
import uuid

from dazzle.metering import NativeAPI
from dazzle.production import handle_request
from dazzle.production_state import CORE_SHA256, ProductionStore
from dazzle.standby import HandoffError, WarmCollectors, run_standby, recovery_evidence, prepare_recovery
from dazzle.store import timestamp, utcnow
from test_native_api import local_server, EPOCH, UPLOAD, DOWNLOAD


def running_fixture(directory):
    now=utcnow();member=str(uuid.uuid4());admin=str(uuid.uuid4())
    policy={"version":1,"server_id":str(uuid.uuid4()),"server_endpoint":"8.8.8.8","agent_uid":max(os.getuid(),1),"core_sha256":CORE_SHA256,
            "workers":{admin:{"role":"admin","public_port":24430,"api_port":34430},member:{"role":"member","public_port":24431,"api_port":34431}}}
    store=ProductionStore(directory,policy=policy,initialize=True)
    result=handle_request(store,{"api_version":1,"request_id":str(uuid.uuid4()),"action":"user.add","server_id":store.server_id,
        "expected_revision":store.revision,"params":{"name":"Handoff fixture","role":"member","quota_bytes":2**63-1}},now)
    assert result['ok'],result
    store.conn.execute("UPDATE users SET manual_disabled=0,trusted_sample=1,meter_state='trusted',meter_epoch=?,last_sample_at=?,last_uplink=?,last_downlink=?,used_upload=10,used_download=20,reasons_json='[]' WHERE id=?",(str(EPOCH),timestamp(now),UPLOAD-11,DOWNLOAD-13,member))
    store.conn.execute("UPDATE production_workers SET generation=3,root_ack_generation=3,observed_generation=3,observed_state='running',process_id=123,provisioned=1,origin_pending=0,credential_version=1 WHERE worker_id=?",(member,))
    store.conn.execute("DELETE FROM production_jobs")
    return store,policy,member


class StandbyTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.store,self.policy,self.member=running_fixture(self.folder.name);self.addCleanup(self.store.close)
        self.lock=os.open(Path(self.folder.name)/'agent.lock',os.O_CREAT|os.O_RDWR,0o600);os.fchmod(self.lock,0o600)
        self.addCleanup(os.close,self.lock);fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        self.stop=threading.Event();self.addCleanup(self.stop.set)

    def warm(self,port):
        def helper_forbidden(*args,**kwargs):raise AssertionError('Standby must not call helper')
        class NoHelper:
            call=helper_forbidden
        return WarmCollectors(NoHelper(),api_factory=lambda host,unused,secret,timeout:NativeAPI(host,port,secret,timeout=timeout),
            runtime_probe=lambda worker,pid,role:{"pid":pid,"identity":str(pid)+":1000"})

    def test_standby_stays_readonly_until_same_inode_lock_then_charges_exact_delta(self):
        secret=self.store.worker(self.member)['api_secret']
        with local_server(expected_secret=secret) as (port,_):
            warm=self.warm(port);self.addCleanup(warm.close)
            evidence=[];notices=[];ready=threading.Event();taken=threading.Event();failures=[]
            before=self.store.conn.execute('PRAGMA data_version').fetchone()[0]
            old_user=dict(self.store.get_user(self.member));inode=os.fstat(self.lock).st_ino
            def emit(event):
                evidence.append(event)
                if event['phase']=='standby-ready':ready.set()
            def writer(store,helper,**kwargs):
                self.assertTrue(kwargs['takeover'])
                self.assertEqual(store.get_user(self.member)['used_upload'],21)
                self.assertEqual(store.get_user(self.member)['used_download'],33)
                probe=os.open(Path(self.folder.name)/'agent.lock',os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(probe)
                taken.set();self.stop.set()
            def target():
                try:run_standby(self.folder.name,self.policy,stop=self.stop,warm=warm,notify=notices.append,emit=emit,run_writer=writer)
                except Exception as exc:failures.append(exc);taken.set()
            thread=threading.Thread(target=target);thread.start();self.addCleanup(lambda:thread.join(2))
            self.assertTrue(ready.wait(2))
            self.assertFalse(taken.is_set())
            self.assertEqual(self.store.conn.execute('PRAGMA data_version').fetchone()[0],before)
            self.assertEqual(dict(self.store.get_user(self.member)),old_user)
            self.assertFalse(any('READY=1' in item for item in notices))
            self.assertEqual(evidence[0]['writer'],False)
            self.assertEqual(evidence[0]['lock_inode'],inode)
            fcntl.flock(self.lock,fcntl.LOCK_UN)
            self.assertTrue(taken.wait(3));self.stop.set();thread.join(2)
            self.assertFalse(failures,failures)
            self.assertEqual([item['phase'] for item in evidence],['standby-ready','writer-ready'])
            self.assertEqual(self.store.worker(self.member)['process_id'],123)

    def test_invalid_native_epoch_never_readies_or_writes(self):
        secret=self.store.worker(self.member)['api_secret']
        self.store.conn.execute("UPDATE users SET meter_epoch='different-epoch' WHERE id=?",(self.member,))
        with local_server(expected_secret=secret) as (port,_):
            warm=self.warm(port);events=[]
            thread=threading.Thread(target=lambda:run_standby(self.folder.name,self.policy,stop=self.stop,warm=warm,notify=lambda _:None,emit=events.append,run_writer=lambda *_args,**_kwargs:self.fail('Must not take over')))
            before=self.store.conn.execute('PRAGMA data_version').fetchone()[0]
            thread.start();time.sleep(.2);self.stop.set();thread.join(2)
            self.assertEqual(events,[])
            self.assertEqual(self.store.conn.execute('PRAGMA data_version').fetchone()[0],before)

    def test_warm_stream_keeps_bounded_latest_state_not_a_writer_queue(self):
        secret=self.store.worker(self.member)['api_secret']
        with local_server(expected_secret=secret) as (port,_):
            warm=self.warm(port);self.addCleanup(warm.close)
            with ProductionStore(self.folder.name,policy=self.policy,read_only=True) as reader:warm.synchronize(reader)
            deadline=time.monotonic()+2
            while not warm.latest and time.monotonic()<deadline:time.sleep(.01)
            self.assertEqual(len(warm.latest),1)
            self.assertTrue(warm.collector.events.empty())
            self.assertFalse(warm.collector.overflow.is_set())

    def test_post_lock_stream_ignores_old_warm_frame_after_old_writer_advanced(self):
        from test_native_api import frame,trailer,epoch_response
        from dazzle.proto.traffic_pb2 import Status
        totals={"up":UPLOAD,"down":DOWNLOAD}
        def response(path):
            body=epoch_response() if path.endswith("GetStartedAt") else frame(Status(trafficAvailable=True,uplinkTotal=totals["up"],downlinkTotal=totals["down"]).SerializeToString())+trailer()
            return 200,"application/grpc-web+proto",body
        with local_server(expected_secret=self.store.worker(self.member)['api_secret'],response_for=response) as (port,_):
            warm=self.warm(port);ready=threading.Event();done=threading.Event();errors=[]
            def emit(event):
                if event['phase']=='standby-ready':ready.set()
            def writer(store,helper,**kwargs):
                self.assertEqual(store.get_user(self.member)['used_upload'],110)
                self.assertEqual(store.get_user(self.member)['used_download'],220)
                self.assertFalse(store.conn.execute("SELECT 1 FROM metering_incidents").fetchone())
                self.stop.set();done.set()
            def target():
                try:run_standby(self.folder.name,self.policy,stop=self.stop,warm=warm,emit=emit,notify=lambda _:None,run_writer=writer)
                except Exception as error:errors.append(error);done.set()
            thread=threading.Thread(target=target);thread.start()
            self.assertTrue(ready.wait(2))
            # The old writer commits newer totals after the candidate warmed.
            self.store.conn.execute("UPDATE users SET last_uplink=?,last_downlink=?,used_upload=100,used_download=200,last_sample_at=? WHERE id=?",(UPLOAD+100,DOWNLOAD+200,timestamp(utcnow()),self.member))
            totals.update(up=UPLOAD+110,down=DOWNLOAD+220)
            fcntl.flock(self.lock,fcntl.LOCK_UN)
            self.assertTrue(done.wait(3));self.stop.set();thread.join(2)
            self.assertFalse(errors,errors)

    def test_recovery_rejects_live_public_core_and_api_failure_is_not_absence(self):
        warm=WarmCollectors(runtime_probe=lambda worker,pid,role:{"pid":123,"identity":"123:1"})
        with ProductionStore(self.folder.name,policy=self.policy,read_only=True) as reader:
            with self.assertRaises(HandoffError):recovery_evidence(reader,warm,unit_probe=lambda worker:{"active":"active","pid":123},proof_reader=lambda *_:{"mode":"running","phase":"complete","process_id":123,"generation":3})
            # Even a root-proven API-only process must have a real live frame.
            with self.assertRaises(HandoffError):recovery_evidence(reader,warm,unit_probe=lambda worker:{"active":"active","pid":123},proof_reader=lambda *_:{"mode":"staged","phase":"complete","process_id":123,"generation":3})
        warm.close()

    def test_recovery_requires_registered_unit_and_cgroup_to_agree_on_absence(self):
        warm=WarmCollectors(runtime_probe=lambda worker,pid,role:{"pid":None,"identity":None})
        with ProductionStore(self.folder.name,policy=self.policy,read_only=True) as reader:
            with self.assertRaises(HandoffError):recovery_evidence(reader,warm,unit_probe=lambda worker:{"active":"active","pid":123})
            result=recovery_evidence(reader,warm,unit_probe=lambda worker:{"active":"inactive","pid":0})
        self.assertEqual(result[0]['phase'],'confirmed-inactive');warm.close()

    def test_live_api_only_recovery_uses_real_frame_without_claiming_ledger_trust(self):
        secret=self.store.worker(self.member)['api_secret']
        self.store.conn.execute("UPDATE users SET trusted_sample=0,last_sample_at=? WHERE id=?",(timestamp(utcnow()-dt.timedelta(seconds=30)),self.member))
        self.store.conn.execute("UPDATE production_workers SET observed_state='staged' WHERE worker_id=?",(self.member,))
        with local_server(expected_secret=secret) as (port,_):
            warm=self.warm(port);self.addCleanup(warm.close)
            with ProductionStore(self.folder.name,policy=self.policy,read_only=True) as reader:warm.synchronize(reader)
            deadline=time.monotonic()+2
            while not warm.latest and time.monotonic()<deadline:time.sleep(.01)
            with ProductionStore(self.folder.name,policy=self.policy,read_only=True) as reader:
                result=recovery_evidence(reader,warm,unit_probe=lambda worker:{"active":"active","pid":123},
                    proof_reader=lambda *_:{"mode":"staged","phase":"complete","process_id":123,"generation":3})
            self.assertEqual(result[0]['phase'],'root-proven-api-only')
            self.assertFalse(self.store.get_user(self.member)['trusted_sample'])

    def test_preparing_cold_recovery_never_changes_administrator_account(self):
        now=utcnow()
        reply=handle_request(self.store,{"api_version":1,"request_id":str(uuid.uuid4()),"action":"user.add","server_id":self.store.server_id,
            "expected_revision":self.store.revision,"params":{"name":"Admin fixture","role":"admin"}},now)
        self.assertTrue(reply['ok'],reply)
        identifier=reply['data']['user']['id'];before=dict(self.store.get_user(identifier))
        prepare_recovery(self.store)
        self.assertEqual(dict(self.store.get_user(identifier)),before)
        self.assertNotIn(identifier,self.store.get_meta('agent_recovery_holds'))

    def test_empty_lock_with_live_untrusted_public_core_does_not_downgrade_to_recovery(self):
        self.store.conn.execute("UPDATE users SET last_sample_at=? WHERE id=?",(timestamp(utcnow()-dt.timedelta(seconds=30)),self.member))
        secret=self.store.worker(self.member)['api_secret']
        with local_server(expected_secret=secret) as (port,_):
            warm=self.warm(port);events=[]
            fcntl.flock(self.lock,fcntl.LOCK_UN)
            thread=threading.Thread(target=lambda:run_standby(self.folder.name,self.policy,stop=self.stop,warm=warm,notify=lambda _:None,emit=events.append,
                run_writer=lambda *_args,**_kwargs:self.fail('Cannot recover over live member'),allow_no_core_recovery=True,
                unit_probe=lambda worker:{"active":"active","pid":123},proof_reader=lambda *_:{"mode":"running","phase":"complete","process_id":123,"generation":3}))
            thread.start();time.sleep(.2);self.stop.set();thread.join(2)
            self.assertEqual(events,[])
            self.assertFalse(self.store.get_meta('agent_recovery_only',False))
            self.assertEqual(self.store.worker(self.member)['process_id'],123)

    def test_no_core_cold_recovery_keeps_totals_and_stages_without_public_activation(self):
        from dazzle.production import refresh_worker_status,process_one_job,accept_sample
        from test_production import StrictHelper,PUBLIC_KEY
        from dazzle.metering import MeterSample
        self.store.conn.execute("UPDATE users SET last_sample_at=? WHERE id=?",(timestamp(utcnow()-dt.timedelta(seconds=30)),self.member))
        warm=WarmCollectors(api_factory=lambda *_args,**_kwargs:(_ for _ in ()).throw(OSError('no API')),runtime_probe=lambda worker,pid,role:{"pid":None,"identity":None})
        fcntl.flock(self.lock,fcntl.LOCK_UN)
        calls=[]
        def writer(store,helper,**kwargs):
            self.assertTrue(kwargs['recovery'])
            self.assertIn(self.member,store.get_meta('agent_recovery_holds'))
            self.assertEqual((store.get_user(self.member)['used_upload'],store.get_user(self.member)['used_download']),(10,20))
            self.assertFalse(store.get_user(self.member)['trusted_sample'])
            owned=StrictHelper(self.policy,store)
            owned.records[self.member]={"generation":3,"worker_state":"stopped","public_key":PUBLIC_KEY,"process_id":None,"tombstoned":False}
            refresh_worker_status(store,owned)
            self.assertTrue(process_one_job(store,owned)['applied'])
            self.assertEqual(store.worker(self.member)['observed_state'],'staged')
            now=utcnow();worker=store.worker(self.member)
            store.conn.execute('BEGIN IMMEDIATE')
            accept_sample(store,self.member,worker['observed_generation'],MeterSample('recovered-api-only-epoch',0,0,timestamp(now)),now)
            store.conn.commit()
            self.assertTrue(store.get_user(self.member)['trusted_sample'])
            self.assertEqual((store.get_user(self.member)['used_upload'],store.get_user(self.member)['used_download']),(10,20))
            self.assertFalse(store.conn.execute("SELECT 1 FROM production_jobs WHERE action='activate' AND status IN ('pending','executing')").fetchone())
            self.assertTrue(store.conn.execute("SELECT 1 FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL",(self.member,)).fetchone())
            calls.append(True);self.stop.set()
        run_standby(self.folder.name,self.policy,stop=self.stop,warm=warm,notify=lambda _:None,emit=lambda _:None,run_writer=writer,
            allow_no_core_recovery=True,unit_probe=lambda worker:{"active":"inactive","pid":0})
        self.assertEqual(calls,[True])

    def test_recovery_manual_reconcile_releases_only_one_member_without_writer_restart(self):
        policy=json.loads(json.dumps(self.policy));policy.update(version=2,portal_uid=max(os.getuid(),1)+1)
        other=str(uuid.uuid4());policy['workers'][other]={"role":"member","public_port":24432,"api_port":34432}
        with ProductionStore(self.folder.name,policy=policy) as store:
            now=utcnow()
            def rpc(action,params):
                result=handle_request(store,{"api_version":1,"request_id":str(uuid.uuid4()),"action":action,"params":params,
                    "server_id":store.server_id,"expected_revision":store.revision},now)
                self.assertTrue(result['ok'],result);return result
            rpc('user.add',{'name':'Other recovery member','role':'member','quota_bytes':100000})
            prepare_recovery(store)
            self.assertEqual(set(store.get_meta('agent_recovery_holds')),{self.member,other})
            store.conn.execute("DELETE FROM production_jobs")
            for user in (self.member,other):
                store.conn.execute("UPDATE users SET manual_disabled=0,trusted_sample=1,last_sample_at=?,meter_epoch='api-only-epoch' WHERE id=?",(timestamp(now),user))
                store.conn.execute("UPDATE production_workers SET observed_state='staged',origin_pending=0,observed_generation=4,root_ack_generation=4,generation=4,provisioned=1,credential_version=1 WHERE user_id=?",(user,))
            rpc('meter.reconcile',{'user_id':self.member,'evidence':'Reviewed this member only; API-only current sample and preserved old byte totals confirmed'})
            self.assertNotIn(self.member,store.get_meta('agent_recovery_holds'))
            self.assertIn(other,store.get_meta('agent_recovery_holds'))
            self.assertTrue(store.get_meta('agent_recovery_only'))
            self.assertTrue(store.conn.execute("SELECT 1 FROM production_jobs WHERE worker_id=? AND action='activate' AND status='pending'",(self.member,)).fetchone())
            self.assertFalse(store.conn.execute("SELECT 1 FROM production_jobs WHERE worker_id=? AND action='activate' AND status='pending'",(other,)).fetchone())
            self.assertTrue(store.conn.execute("SELECT 1 FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL",(other,)).fetchone())
            rpc('user.revoke',{'user_id':other})
            self.assertFalse(store.get_meta('agent_recovery_holds'))
            self.assertFalse(store.get_meta('agent_recovery_only'))
            self.assertIsNotNone(store.get_user(other)['revoked_at'])

    def test_lock_inode_replacement_is_rejected(self):
        from dazzle.standby import _open_existing_lock,_same_inode
        descriptor=_open_existing_lock(self.folder.name);self.addCleanup(os.close,descriptor)
        path=Path(self.folder.name)/'agent.lock';path.rename(path.with_suffix('.old'))
        path.write_text('');path.chmod(0o600)
        with self.assertRaises(HandoffError):_same_inode(self.folder.name,descriptor)

    def test_absent_lock_is_never_created_by_standby(self):
        from dazzle.standby import _open_existing_lock
        path=Path(self.folder.name)/'missing';path.mkdir()
        with self.assertRaises(FileNotFoundError):_open_existing_lock(path)
        self.assertFalse((path/'agent.lock').exists())


if __name__=='__main__':unittest.main()
