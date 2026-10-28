"""Only local, real protocol fixtures and isolated proc/cgroup evidence."""
import copy
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from dazzle.meter_guard import GuardError, NativeWitness, RuntimeProbe, evaluate, read_proof, run_guard
from dazzle.metering import MeterSample, NativeAPI
from dazzle.production_state import CORE_SHA256, ProductionStore
from dazzle.store import timestamp, utcnow
from test_native_api import local_server, SECRET, EPOCH, UPLOAD, DOWNLOAD


def view_fixture(now):
    worker_id = str(uuid.uuid4())
    user = {"id":worker_id,"role":"member","manual_disabled":0,"revoked_at":None,"deleted_at":None,
            "meter_epoch":str(EPOCH),"last_sample_at":timestamp(now),"trusted_sample":1,"reasons_json":"[]",
            "unlimited":0,"quota_bytes":2**63-1,"topup_bytes":0,"used_upload":0,"used_download":0,"credential_version":1}
    worker={"worker_id":worker_id,"role":"member","user_id":worker_id,"process_id":123,
            "observed_state":"running","tombstoned":0,"origin_pending":0,"observed_generation":3,
            "root_ack_generation":3,"credential_version":1,"api_port":34431,"api_secret":SECRET}
    return {"worker":worker,"user":user,"job":None}


def proof_fixture(view, *, mode="staged", phase="prepared", age=0):
    return {"mode":mode,"phase":phase,"generation":4 if phase=="prepared" else 3,
            "process_id":123 if phase=="complete" else None,"age":age}


class GuardDecisionTests(unittest.TestCase):
    def setUp(self):
        self.now=utcnow(); self.view=view_fixture(self.now)
        self.sample=MeterSample(str(EPOCH),UPLOAD,DOWNLOAD,timestamp(self.now))
        self.actual={"pid":123,"identity":"123:1000"}

    def test_running_requires_real_fresh_ledger_native_pid_epoch_and_auth(self):
        self.assertEqual(evaluate(self.view,self.actual,self.sample,self.now)["phase"],"running")
        for change,code in [({"manual_disabled":1},"UNTRUSTED_AUTHORIZATION_OR_METER"),
                            ({"trusted_sample":0},"UNTRUSTED_AUTHORIZATION_OR_METER"),
                            ({"revoked_at":timestamp(self.now)},"AUTHORIZATION_REVOKED"),
                            ({"last_sample_at":timestamp(self.now-dt.timedelta(seconds=5.01))},"UNTRUSTED_AUTHORIZATION_OR_METER")]:
            view=copy.deepcopy(self.view);view["user"].update(change)
            with self.assertRaises(GuardError) as error:evaluate(view,self.actual,self.sample,self.now)
            self.assertEqual(error.exception.code,code)
        with self.assertRaisesRegex(GuardError,"PID_MISMATCH"):evaluate(self.view,{"pid":124},self.sample,self.now)
        with self.assertRaisesRegex(GuardError,"EPOCH_MISMATCH"):evaluate(self.view,self.actual,MeterSample("other",0,0,timestamp(self.now)),self.now)
        with self.assertRaises(GuardError):evaluate(self.view,self.actual,MeterSample(str(EPOCH),0,0,timestamp(self.now-dt.timedelta(seconds=5.01))),self.now)

    def test_never_started_ready_has_no_proxy_or_meter_privilege(self):
        for pid in (None,0):
            view=copy.deepcopy(self.view);view["worker"].update(process_id=pid,observed_state="unprovisioned")
            view["user"].update(meter_epoch=None,last_sample_at=None,trusted_sample=0)
            self.assertEqual(evaluate(view,{"pid":None,"identity":None},None,self.now)["phase"],"bootstrap-inactive")
            with self.assertRaises(GuardError):evaluate(view,{"pid":999,"identity":"999:1"},None,self.now)

    def test_prepared_api_only_stage_breaks_dependency_cycle_without_clearing_incident(self):
        view=copy.deepcopy(self.view);view["user"].update(trusted_sample=0,manual_disabled=1,reasons_json='["metering_failure"]')
        view["job"]={"action":"stage","generation":4}
        proof=proof_fixture(view)
        self.assertEqual(evaluate(view,{"pid":None,"identity":None},None,self.now,proof)["phase"],"api-only-transition")
        self.assertEqual(view["user"]["reasons_json"],'["metering_failure"]')
        proof["age"]=5.001
        with self.assertRaises(GuardError):evaluate(view,{"pid":None,"identity":None},None,self.now,proof)

    def test_completed_root_proof_cannot_grace_another_pid(self):
        self.view['job']={"action":"stage","generation":4}
        proof=proof_fixture(self.view);proof.update(phase='complete',process_id=444)
        with self.assertRaisesRegex(GuardError,'ROOT_PROOF_PID_MISMATCH'):
            evaluate(self.view,self.actual,self.sample,self.now,proof)

    def test_root_proven_api_only_can_sample_during_historical_failure(self):
        self.view["worker"]["observed_state"]="staged"
        self.view["user"].update(trusted_sample=0,manual_disabled=1,reasons_json='["metering_failure"]')
        proof=proof_fixture(self.view,phase="complete",age=100)
        self.assertEqual(evaluate(self.view,self.actual,self.sample,self.now,proof)["phase"],"api-only")
        with self.assertRaises(GuardError):evaluate(self.view,self.actual,None,self.now,proof)

    def test_activation_transition_requires_existing_authorization_and_fixed_five_seconds(self):
        self.view["job"]={"action":"activate","generation":4}
        proof=proof_fixture(self.view,mode="running")
        self.assertEqual(evaluate(self.view,{"pid":None,"identity":None},None,self.now,proof)["phase"],"activation-transition")
        self.view["user"]["manual_disabled"]=1
        with self.assertRaises(GuardError):evaluate(self.view,{"pid":None,"identity":None},None,self.now,proof)
        self.view["user"]["manual_disabled"]=0;proof["age"]=5.001
        with self.assertRaises(GuardError):evaluate(self.view,{"pid":None,"identity":None},None,self.now,proof)

    def test_one_worker_failure_does_not_decide_other_members(self):
        other=copy.deepcopy(self.view);other["worker"]["worker_id"]=str(uuid.uuid4())
        broken=copy.deepcopy(self.view);broken["user"]["manual_disabled"]=1
        with self.assertRaises(GuardError):evaluate(broken,self.actual,self.sample,self.now)
        self.assertEqual(evaluate(other,self.actual,self.sample,self.now)["phase"],"running")

    def test_real_native_protocol_witness_uses_received_epoch_and_integer_counters(self):
        with local_server() as (port,requests):
            witness=NativeWitness(lambda host,unused,secret,timeout:NativeAPI(host,port,secret,timeout=timeout))
            self.addCleanup(witness.close)
            worker=self.view["worker"]
            deadline=time.monotonic()+2
            sample=witness.sample(worker)
            while sample is None and time.monotonic()<deadline:
                time.sleep(.01);sample=witness.sample(worker)
            self.assertEqual((sample.epoch,sample.uplink,sample.downlink),(str(EPOCH),UPLOAD,DOWNLOAD))
            self.assertTrue(all(request["authorized"] for request in requests))

    def test_root_proof_is_bound_to_boot_worker_owner_and_immutable_prepared_clock(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);root.chmod(0o750)
            worker=self.view["worker"]["worker_id"]; server=str(uuid.uuid4());boot=str(uuid.uuid4())
            proof={"version":1,"server_id":server,"worker_id":worker,"generation":4,"mode":"staged","phase":"prepared",
                   "config_sha256":"a"*64,"process_id":None,"boot_id":boot,"prepared_monotonic_ns":1_000_000_000,"observed_monotonic_ns":1_000_000_000}
            path=root/(worker+".json");path.write_text(json.dumps(proof));path.chmod(0o640)
            result=read_proof({"server_id":server},worker,directory=root,current_boot=boot,monotonic_ns=5_000_000_000,trusted_uid=os.getuid())
            self.assertEqual(result["age"],4)
            proof.update(phase="complete",process_id=123,observed_monotonic_ns=5_000_000_000)
            path.write_text(json.dumps(proof))
            self.assertEqual(read_proof({"server_id":server},worker,directory=root,current_boot=boot,monotonic_ns=7_000_000_000,trusted_uid=os.getuid())["age"],6)
            with self.assertRaises(GuardError):read_proof({"server_id":server},worker,directory=root,current_boot=str(uuid.uuid4()),monotonic_ns=7_000_000_000,trusted_uid=os.getuid())
            path.chmod(0o660)
            with self.assertRaises(GuardError):read_proof({"server_id":server},worker,directory=root,current_boot=boot,monotonic_ns=7_000_000_000,trusted_uid=os.getuid())

    @unittest.skipUnless(Path('/proc/self/stat').exists(),"Linux proc/cgroup identity test")
    def test_actual_child_pid_fingerprint_comes_from_proc(self):
        with tempfile.TemporaryDirectory() as folder:
            worker=self.view["worker"]["worker_id"]
            group=Path(folder)/"system.slice"/("dazzle-proxy@"+worker+".service");group.mkdir(parents=True)
            child=subprocess.Popen(["/bin/sleep","10"])
            self.addCleanup(lambda:child.poll() is None and child.kill());self.addCleanup(child.wait)
            (group/'cgroup.procs').write_text(str(child.pid))
            evidence=RuntimeProbe(cgroup_root=folder)(worker,child.pid)
            self.assertEqual(evidence["pid"],child.pid)
            self.assertTrue(evidence["identity"].startswith(str(child.pid)+":"))


class GuardLoopTests(unittest.TestCase):
    def test_ready_is_based_on_native_and_ledger_observation_without_database_writes(self):
        from test_standby import running_fixture
        with tempfile.TemporaryDirectory() as folder:
            store,policy,member=running_fixture(folder)
            self.addCleanup(store.close)
            before=store.conn.execute('PRAGMA data_version').fetchone()[0]
            previous=dict(store.get_user(member));stop=threading.Event();notifications=[]
            with local_server(expected_secret=store.worker(member)['api_secret']) as (port,_):
                witness=NativeWitness(lambda host,unused,secret,timeout:NativeAPI(host,port,secret,timeout=timeout))
                def receive(message):
                    notifications.append(message)
                    if message=='WATCHDOG=1':stop.set()
                run_guard(folder,policy,member,stop=stop,witness=witness,
                    runtime_probe=lambda worker,pid:{"pid":pid,"identity":"123:1000"},proof_reader=lambda:None,ready=receive)
            self.assertTrue(any(item.startswith('READY=1') for item in notifications))
            self.assertEqual(store.conn.execute('PRAGMA data_version').fetchone()[0],before)
            self.assertEqual(dict(store.get_user(member)),previous)
            self.assertFalse((Path(folder)/'agent.lock').exists())

    def test_now_is_captured_after_new_native_frame_not_before_it(self):
        from test_standby import running_fixture
        with tempfile.TemporaryDirectory() as folder:
            store,policy,member=running_fixture(folder);self.addCleanup(store.close)
            class FreshWitness:
                def sample(inner,worker):return MeterSample(str(EPOCH),UPLOAD,DOWNLOAD,timestamp(utcnow()))
                def close(inner):pass
            stop=threading.Event();notices=[]
            def proof():time.sleep(.005);return None
            def receive(message):
                notices.append(message)
                if message=='WATCHDOG=1':stop.set()
            run_guard(folder,policy,member,stop=stop,witness=FreshWitness(),runtime_probe=lambda worker,pid:{"pid":pid,"identity":"123:1"},proof_reader=proof,ready=receive)
            self.assertTrue(any(message.startswith('READY=1') for message in notices))

    def test_persistent_reader_keeps_the_wal_pair_when_the_last_writer_connection_closes(self):
        # On the target the guard's state path is read-only: if SQLite deleted -wal/-shm when
        # the old writer closed, the guard could not reopen and would stop its member at once.
        from test_standby import running_fixture
        with tempfile.TemporaryDirectory() as folder:
            store,policy,member=running_fixture(folder)
            class FreshWitness:
                def sample(inner,worker):return MeterSample(str(EPOCH),UPLOAD,DOWNLOAD,timestamp(utcnow()))
                def close(inner):pass
            stop=threading.Event();beats=[];errors=[]
            def receive(message):
                if message=='WATCHDOG=1':beats.append(time.monotonic())
            def target():
                try:run_guard(folder,policy,member,stop=stop,witness=FreshWitness(),runtime_probe=lambda worker,pid:{"pid":pid,"identity":"123:1"},proof_reader=lambda:None,ready=receive)
                except Exception as exc:errors.append(exc)
            thread=threading.Thread(target=target);thread.start()
            deadline=time.monotonic()+3
            while not beats and time.monotonic()<deadline:time.sleep(.01)
            shm=Path(folder)/'state.sqlite3-shm';before=shm.stat().st_ino
            store.close()  # The writer's last connection goes away, as during a handoff.
            count=len(beats);time.sleep(.8)
            after=shm.stat().st_ino
            stop.set();thread.join(2)
            self.assertFalse(errors,errors)
            self.assertGreater(len(beats),count)
            self.assertEqual(before,after)
            self.assertTrue((Path(folder)/'state.sqlite3-wal').exists())

    def test_one_failed_guard_cannot_mutate_another_registered_member(self):
        from test_standby import running_fixture
        with tempfile.TemporaryDirectory() as folder:
            store,policy,member=running_fixture(folder);self.addCleanup(store.close)
            second=str(uuid.uuid4());policy={**policy,"version":2,"portal_uid":max(os.getuid(),1)+1,"workers":{**policy['workers'],second:{"role":"member","public_port":24432,"api_port":34432}}}
            with ProductionStore(folder,policy=policy):pass
            store.conn.execute("UPDATE users SET manual_disabled=1 WHERE id=?",(member,))
            class FixedWitness:
                def sample(inner,worker):return MeterSample(str(EPOCH),UPLOAD,DOWNLOAD,timestamp(utcnow()))
                def close(inner):pass
            with self.assertRaises(GuardError):
                run_guard(folder,policy,member,witness=FixedWitness(),runtime_probe=lambda worker,pid:{"pid":pid,"identity":"123:1000"},proof_reader=lambda:None,ready=lambda _:None)
            stop=threading.Event();notifications=[]
            def receive(message):
                notifications.append(message)
                if message=='WATCHDOG=1':stop.set()
            run_guard(folder,policy,second,stop=stop,witness=FixedWitness(),runtime_probe=lambda worker,pid:{"pid":None,"identity":None},proof_reader=lambda:None,ready=receive)
            self.assertTrue(any(item.startswith('READY=1') for item in notifications))
            self.assertEqual(store.conn.execute("SELECT observed_state FROM production_workers WHERE worker_id=?",(second,)).fetchone()[0],'unprovisioned')


if __name__=='__main__':unittest.main()
