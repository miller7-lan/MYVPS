"""Real helper dispatch bridged to the production controller, with no real processes."""
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from deployment.helper import Helper, Layout, read_json
from deployment.tests.test_helper import FakeRunner
from dazzle.metering import MeterSample
from dazzle.production import (HelperClient, ProductionError, accept_sample, handle_request,
                               process_one_job, refresh_worker_status, snapshot)
from dazzle.production_state import CORE_SHA256, ProductionStore
from dazzle.store import parse_time, timestamp


class FixtureCoreHelper(Helper):
    def _core(self, policy):
        # Only the real binary digest check is bypassed. The root policy,
        # registry, typed config validation, generations and cgroup proof run.
        if policy["core_sha256"] != CORE_SHA256:
            raise AssertionError("Bridge policy changed the pinned digest")


class DispatchBridge(HelperClient):
    def __init__(self, helper, peer_uid, store):
        self.helper, self.peer_uid, self.store = helper, peer_uid, store
        self.requests, self.responses = [], []

    def call(self, request):
        if self.store.conn.in_transaction:
            raise AssertionError("Root helper was called while SQLite held a transaction")
        wire_request = json.loads(json.dumps(request))
        self.requests.append(wire_request)
        envelope = self.helper.dispatch(wire_request, peer_uid=self.peer_uid)
        envelope = json.loads(json.dumps(envelope))
        self.responses.append(envelope)
        if envelope["request_id"] != request["request_id"]:
            raise AssertionError("Root helper response identity changed")
        if not envelope["ok"]:
            raise ProductionError(envelope["error"]["code"], envelope["error"]["message"])
        return envelope["data"]


class HelperBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.now = parse_time("2026-11-01T08:19:00Z")
        self.worker_id, self.admin_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.policy = {
            "version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "8.8.8.8",
            "agent_uid": 1001, "core_sha256": CORE_SHA256,
            "workers": {self.worker_id: {"role": "member", "public_port": 24431, "api_port": 34431},
                        self.admin_id: {"role": "admin", "public_port": 24430, "api_port": 34430}},
        }
        etc = self.base / "etc"
        for directory in (etc, etc / "workers", etc / "tls", self.base / "cgroups"):
            directory.mkdir(mode=0o700)
        (etc / "policy.json").write_text(json.dumps(self.policy))
        (etc / "policy.json").chmod(0o600)
        for name in ("cert.pem", "key.pem"):
            (etc / "tls" / name).write_text("local certificate fixture; never used by an SSL connection")
            (etc / "tls" / name).chmod(0o600)
        core = self.base / "nonexecutable-core-fixture"
        core.write_text("No binary is executed by this test")
        core.chmod(0o600)
        self.runner = FakeRunner()
        self.layout = Layout(etc, core, self.base / "cgroups", os.getuid())
        self.root = FixtureCoreHelper(self.layout, self.runner)
        self.store = ProductionStore(self.base / "state", policy=self.policy, initialize=True, now=self.now)
        self.addCleanup(self.store.close)
        self.bridge = DispatchBridge(self.root, self.policy["agent_uid"], self.store)
        forbidden_process = patch("deployment.helper.subprocess.run", side_effect=AssertionError("Real subprocess forbidden"))
        forbidden_process.start()
        self.addCleanup(forbidden_process.stop)

    def rpc(self, action, params=None, seconds=0):
        request = {"api_version": 1, "request_id": str(uuid.uuid4()), "action": action,
                   "server_id": self.store.server_id, "expected_revision": self.store.revision,
                   "params": params or {}}
        response = handle_request(self.store, request, self.now + dt.timedelta(seconds=seconds))
        self.assertTrue(response["ok"], response)
        return response["data"]

    def process(self, seconds=0):
        return process_one_job(self.store, self.bridge, self.now + dt.timedelta(seconds=seconds))

    def sample(self, upload=0, download=0, seconds=0):
        worker = self.store.worker(self.worker_id)
        at = self.now + dt.timedelta(seconds=seconds)
        self.store.conn.execute("BEGIN IMMEDIATE")
        try:
            result = accept_sample(self.store, self.worker_id, worker["observed_generation"],
                                   MeterSample("native-epoch-" + str(worker["observed_generation"]),
                                               upload, download, timestamp(at)), at)
            self.store.conn.commit()
            return result
        except BaseException:
            self.store.conn.rollback()
            raise

    def registry_worker(self):
        return read_json(self.layout.registry, os.getuid())["workers"][self.worker_id]

    def stage(self):
        added = self.rpc("user.add", {"name": "Parallel bridge fixture", "role": "member", "quota_bytes": 1000})
        self.assertEqual(added["user"]["id"], self.worker_id)
        self.assertTrue(self.process()["applied"])
        self.assertTrue(self.process()["applied"])
        self.sample(seconds=1)

    def running(self):
        self.stage()
        self.rpc("user.enable", {"user_id": self.worker_id}, seconds=1)
        self.assertTrue(self.process(seconds=1)["applied"])
        self.sample(13, 21, seconds=2)

    def test_complete_controller_lifecycle_matches_actual_helper_protocol(self):
        self.running()
        worker = self.store.worker(self.worker_id)
        self.assertEqual(worker["public_key"], "b" * 43)
        self.assertEqual(worker["root_ack_generation"], 3)
        self.assertEqual((self.store.get_user(self.worker_id)["used_upload"],
                          self.store.get_user(self.worker_id)["used_download"]), (13, 21))
        self.assertEqual(self.runner.checked[0]["inbounds"], [])
        active = self.runner.checked[1]
        self.assertEqual({item["type"] for item in active["inbounds"]}, {"vless", "tuic"})
        self.assertTrue(all(item["listen_port"] == 24431 for item in active["inbounds"]))
        self.assertEqual(active["services"][0]["listen_port"], 34431)

        self.rpc("user.disable", {"user_id": self.worker_id}, seconds=2)
        self.assertTrue(self.process(seconds=2)["applied"])
        self.assertEqual(self.runner.checked[-1]["inbounds"], [])
        self.sample(seconds=3)
        self.rpc("user.rotate", {"user_id": self.worker_id}, seconds=3)
        self.assertTrue(self.process(seconds=3)["applied"])
        self.sample(seconds=4)
        credentials = self.store.get_credentials(self.worker_id)
        root_credentials = self.registry_worker()["credentials"]
        self.assertEqual(root_credentials["vless_uuid"], credentials["vless_uuid"])
        self.assertEqual(root_credentials["tuic_password"], credentials["tuic_password"])
        self.rpc("user.revoke", {"user_id": self.worker_id}, seconds=4)
        self.assertTrue(self.process(seconds=4)["applied"])
        self.assertTrue(self.registry_worker()["tombstoned"])
        self.assertEqual(self.registry_worker()["generation"], 6)
        proof = self.bridge.responses[-1]["data"]
        self.assertEqual(proof["worker_state"], "revoked")
        self.assertTrue(proof["inactive_confirmed"])
        self.assertIsNone(proof["process_id"])
        public = json.dumps(snapshot(self.store, self.now + dt.timedelta(seconds=4)))
        self.assertNotIn(root_credentials["api_secret"], public)
        self.assertNotIn(root_credentials["tuic_password"], public)
        for call in self.runner.calls:
            if call[0] == "/usr/bin/systemctl":
                self.assertEqual(call[2], "dazzle-proxy@" + self.worker_id + ".service")
                self.assertNotIn(call[2], ("sing-box.service", "qqg-sub.service"))

    def test_real_helper_rejects_future_generation_but_unexecuted_cancel_reuses_next(self):
        self.stage()
        self.rpc("user.enable", {"user_id": self.worker_id}, seconds=1)
        pending = json.loads(self.store.conn.execute(
            "SELECT payload_json FROM production_jobs WHERE status='pending'").fetchone()[0])
        future = {**pending, "request_id": str(uuid.uuid4()), "generation": pending["generation"] + 1}
        with self.assertRaises(ProductionError) as denied:
            self.bridge.call(future)
        self.assertEqual(denied.exception.code, "STALE_GENERATION")
        self.assertEqual(self.registry_worker()["generation"], 2)
        self.rpc("user.rotate", {"user_id": self.worker_id}, seconds=1)
        self.assertTrue(self.process(seconds=1)["cancelled"])
        self.assertTrue(self.process(seconds=1)["applied"])
        self.assertEqual(self.registry_worker()["generation"], pending["generation"])
        self.assertEqual(self.registry_worker()["mode"], "staged")
        self.sample(seconds=2)
        self.rpc("user.revoke", {"user_id": self.worker_id}, seconds=2)
        self.assertTrue(self.process(seconds=2)["cancelled"])
        self.assertTrue(self.process(seconds=2)["applied"])
        self.assertEqual(self.registry_worker()["generation"], 4)
        self.assertTrue(self.registry_worker()["tombstoned"])

    def test_revoke_tombstone_persists_before_stop_and_requires_empty_exact_cgroup(self):
        self.running()
        self.rpc("user.revoke", {"user_id": self.worker_id}, seconds=2)
        group = self.layout.cgroup_root / "system.slice" / ("dazzle-proxy@" + self.worker_id + ".service")
        group.mkdir(parents=True)
        processes = group / "cgroup.procs"
        processes.write_text("4321\n")
        with patch("deployment.helper.time.sleep", return_value=None):
            result = self.process(seconds=2)
        self.assertFalse(result["applied"])
        self.assertEqual(result["error_code"], "STOP_FAILED")
        self.assertTrue(self.registry_worker()["tombstoned"])
        public_user = snapshot(self.store, self.now + dt.timedelta(seconds=2))["users"][0]
        self.assertEqual(public_user["runtime_state"], "stop_failed")
        self.assertFalse(self.bridge.responses[-1]["data"]["inactive_confirmed"])
        processes.write_text("")
        refresh_worker_status(self.store, self.bridge, self.now + dt.timedelta(seconds=3))
        self.assertEqual(self.store.worker(self.worker_id)["observed_state"], "revoked")
        self.assertTrue(self.bridge.responses[-1]["data"]["inactive_confirmed"])
        self.assertTrue(self.registry_worker()["tombstoned"])


if __name__ == "__main__":
    unittest.main()
