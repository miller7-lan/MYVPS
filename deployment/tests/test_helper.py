"""Root helper tests: every process operation is an in-memory fake runner."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

from deployment.helper import Helper, Layout, read_json, serve_connection


class FakeRunner:
    def __init__(self):
        self.calls, self.states, self.checked = [], {}, []
        self.sequence = 1000
        self.fail_check = False
        self.fail_stop = False

    def run(self, args, *, input=None, timeout=15):
        self.calls.append(list(args))
        if args[1:3] == ["generate", "reality-keypair"]:
            return subprocess.CompletedProcess(args, 0, b"PrivateKey: " + b"a"*43 + b"\nPublicKey: " + b"b"*43 + b"\n", b"")
        if args[1] == "check":
            self.checked.append(json.loads(Path(args[-1]).read_text()))
            return subprocess.CompletedProcess(args, int(self.fail_check), b"", b"password=never-log")
        unit = args[2]
        if args[1] == "show":
            pid = self.states.get(unit, 0)
            state = "active" if pid else "inactive"
            return subprocess.CompletedProcess(args, 0, f"ActiveState={state}\nSubState=running\nMainPID={pid}\nControlGroup=/system.slice/{unit}\n".encode(), b"")
        if args[1] == "restart":
            self.sequence += 1
            self.states[unit] = self.sequence
        elif args[1] == "stop" and not self.fail_stop:
            self.states[unit] = 0
        return subprocess.CompletedProcess(args, 0, b"", b"")


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.etc = self.base / "etc"
        for directory in (self.etc, self.etc / "workers", self.etc / "tls", self.base / "cgroup"):
            directory.mkdir(mode=0o700)
        self.core = self.base / "pinned-core"
        self.core.write_bytes(b"not-an-executable-test-fixture")
        self.core.chmod(0o600)
        self.core_hash = hashlib.sha256(self.core.read_bytes()).hexdigest()
        self.hash_patch = patch("deployment.helper.CORE_SHA256", self.core_hash)
        self.hash_patch.start()
        self.worker_id = str(uuid.uuid4())
        self.admin_id = str(uuid.uuid4())
        self.policy = {"version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "192.0.2.10",
                       "agent_uid": 1001, "core_sha256": self.core_hash,
                       "workers": {self.worker_id: {"role": "member", "public_port": 24431, "api_port": 34431},
                                   self.admin_id: {"role": "admin", "public_port": 24430, "api_port": 34430}}}
        self.write(self.etc / "policy.json", self.policy)
        for name in ("cert.pem", "key.pem"):
            (self.etc / "tls" / name).write_text("test-only")
            (self.etc / "tls" / name).chmod(0o600)
        self.runner = FakeRunner()
        self.layout = Layout(self.etc, self.core, self.base / "cgroup", os.getuid())
        self.helper = Helper(self.layout, self.runner)
        self.credentials = {"vless_uuid": str(uuid.uuid4()), "tuic_uuid": str(uuid.uuid4()),
                            "tuic_password": "p"*43, "short_id": "1234567890abcdef", "api_secret": "s"*48}

    def tearDown(self):
        self.hash_patch.stop()
        self.temporary.cleanup()

    def write(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def request(self, action, generation, *, worker=None, params=None, identifier=None):
        return {"version": 1, "request_id": identifier or str(uuid.uuid4()), "action": action,
                "worker_id": worker or self.worker_id, "generation": generation,
                "params": (dict(self.credentials) if action in {"provision", "stage", "activate"} else {}) if params is None else params}

    def call(self, action, generation, **kwargs):
        result = self.helper.dispatch(self.request(action, generation, **kwargs), peer_uid=1001)
        self.assertTrue(result["ok"], result)
        return result["data"]

    def provision(self): self.call("provision", 1)
    def stage(self): self.provision(); return self.call("stage", 2)

    def test_import_and_status_make_no_mutation_or_core_call(self):
        result = self.call("status", 0)
        self.assertEqual(result["worker_state"], "unprovisioned")
        self.assertFalse((self.etc / "registry.json").exists())
        self.assertFalse(result["managed_origin_zero"])
        self.assertTrue(all(call[1] == "show" for call in self.runner.calls))

    def test_peer_uid_must_match_installed_agent_or_root(self):
        response = self.helper.dispatch(self.request("provision", 1), peer_uid=1002)
        self.assertEqual(response["error"]["code"], "FORBIDDEN")
        self.assertEqual(self.runner.calls, [])

    def test_unregistered_uuid_and_legacy_unit_or_paths_are_rejected(self):
        for update in ({"worker_id": str(uuid.uuid4())}, {"worker_id": "sing-box.service"}, {"params": {"unit": "sing-box.service"}}, {"unit": "qqg-sub.service"}):
            response = self.helper.dispatch(self.request("status", 0) | update, peer_uid=1001)
            self.assertFalse(response["ok"])
        self.assertFalse((self.etc / "registry.json").exists())

    def test_credential_shapes_and_unknown_fields_are_rejected(self):
        for params in (self.credentials | {"path": "/etc/s-box/sb.json"}, self.credentials | {"api_secret": "weak"}, self.credentials | {"short_id": "../../etc/passwd"}, self.credentials | {"tuic_password": "a\n"*40}):
            response = self.helper.dispatch(self.request("provision", 1, params=params), peer_uid=1001)
            self.assertEqual(response["error"]["code"], "VALIDATION")

    def test_persistent_keys_are_never_returned(self):
        result = self.call("provision", 1)
        self.assertEqual(result["public_key"], "b"*43)
        response_text = json.dumps(result)
        for secret in ("a"*43, self.credentials["api_secret"], self.credentials["tuic_password"]): self.assertNotIn(secret, response_text)
        registry = self.etc / "registry.json"
        self.assertEqual(registry.stat().st_mode & 0o777, 0o600)

    def test_stage_has_no_proxy_inbounds_and_fresh_origin_only_on_transition(self):
        stage = self.stage()
        config = self.runner.checked[-1]
        self.assertEqual(config["inbounds"], [])
        self.assertEqual(config["services"][0]["listen"], "127.0.0.1")
        self.assertEqual(config["services"][0]["listen_port"], 34431)
        self.assertTrue(stage["managed_origin_zero"])
        self.assertFalse(self.call("status", 0)["managed_origin_zero"])

    def test_activate_contains_exact_single_user_and_approved_ports(self):
        self.stage()
        result = self.call("activate", 3)
        self.assertEqual(result["worker_state"], "running")
        config = self.runner.checked[-1]
        self.assertEqual(len(config["inbounds"]), 2)
        self.assertTrue(all(item["listen_port"] == 24431 and len(item["users"]) == 1 for item in config["inbounds"]))
        self.assertEqual(config["inbounds"][1]["tls"]["certificate_path"], str(self.etc / "tls" / "cert.pem"))
        self.assertEqual(config["inbounds"][1]["tls"]["key_path"], str(self.etc / "tls" / "key.pem"))

    def test_activate_requires_provisioned_stage_first(self):
        self.provision()
        result = self.helper.dispatch(self.request("activate", 2), peer_uid=1001)
        self.assertFalse(result["ok"])
        self.assertFalse(any(call[1] == "restart" for call in self.runner.calls))

    def test_bad_config_is_not_replaced_or_started(self):
        self.stage()
        path = self.etc / "workers" / (self.worker_id + ".json")
        before = path.read_bytes()
        count = sum(call[1] == "restart" for call in self.runner.calls)
        self.runner.fail_check = True
        result = self.helper.dispatch(self.request("activate", 3), peer_uid=1001)
        self.assertFalse(result["ok"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(sum(call[1] == "restart" for call in self.runner.calls), count)
        self.assertNotIn("never-log", json.dumps(result))

    def test_complete_retry_is_idempotent_without_second_restart(self):
        self.provision()
        request = self.request("stage", 2)
        original = self.helper.dispatch(request, peer_uid=1001)
        count = sum(call[1] == "restart" for call in self.runner.calls)
        self.assertEqual(self.helper.dispatch(request, peer_uid=1001), original)
        self.assertEqual(sum(call[1] == "restart" for call in self.runner.calls), count)

    def test_same_generation_different_payload_and_skipped_generation_are_rejected(self):
        self.provision()
        for request in (self.request("stage", 1), self.request("stage", 3)):
            response = self.helper.dispatch(request, peer_uid=1001)
            self.assertEqual(response["error"]["code"], "STALE_GENERATION")

    def test_changed_process_invalidates_completed_origin_retry(self):
        self.provision()
        request = self.request("stage", 2)
        self.assertTrue(self.helper.dispatch(request, peer_uid=1001)["ok"])
        self.runner.states[self.helper._unit(self.worker_id, self.policy["workers"][self.worker_id])] += 1
        response = self.helper.dispatch(request, peer_uid=1001)
        self.assertEqual(response["error"]["code"], "RECOVERY_REQUIRED")

    def test_stop_and_revoke_confirm_owned_cgroup_inactive(self):
        self.stage()
        self.call("activate", 3)
        stopped = self.call("stop", 4)
        self.assertTrue(stopped["inactive_confirmed"])
        self.assertIsNone(stopped["process_id"])
        revoked = self.call("revoke", 5)
        self.assertEqual(revoked["worker_state"], "revoked")
        self.assertTrue(revoked["tombstoned"])

    def test_failed_revoke_persists_tombstone_and_cannot_resurrect(self):
        self.stage()
        self.call("activate", 3)
        self.runner.fail_stop = True
        with patch("deployment.helper.time.sleep"):
            failed = self.helper.dispatch(self.request("revoke", 4), peer_uid=1001)
        self.assertEqual(failed["error"]["code"], "STOP_FAILED")
        status = self.call("status", 0)
        self.assertTrue(status["tombstoned"])
        self.assertEqual(status["worker_state"], "stop_failed")
        fresh_helper = Helper(self.layout, self.runner)
        response = fresh_helper.dispatch(self.request("stage", 5), peer_uid=1001)
        self.assertEqual(response["error"]["code"], "REVOKED")

    def test_nonempty_cgroup_is_not_claimed_stopped(self):
        self.stage()
        unit = self.helper._unit(self.worker_id, self.policy["workers"][self.worker_id])
        cgroup = self.layout.cgroup_root / "system.slice" / unit
        cgroup.mkdir(parents=True)
        (cgroup / "cgroup.procs").write_text("777\n")
        with patch("deployment.helper.time.sleep"):
            response = self.helper.dispatch(self.request("stop", 3), peer_uid=1001)
        self.assertEqual(response["error"]["code"], "STOP_FAILED")

    def test_core_hash_change_blocks_new_start_but_does_not_prevent_owned_stop(self):
        self.stage()
        self.core.write_bytes(b"changed")
        failed = self.helper.dispatch(self.request("activate", 3), peer_uid=1001)
        self.assertEqual(failed["error"]["code"], "CORE_CHANGED")
        self.assertEqual(self.call("stop", 3)["worker_state"], "stopped")

    def test_symlink_registry_or_worker_config_is_denied(self):
        elsewhere = self.base / "other"
        elsewhere.write_text("private-test")
        (self.etc / "registry.json").symlink_to(elsewhere)
        response = self.helper.dispatch(self.request("provision", 1), peer_uid=1001)
        self.assertEqual(response["error"]["code"], "FILESYSTEM")
        (self.etc / "registry.json").unlink()
        self.provision()
        (self.etc / "workers" / (self.worker_id + ".json")).symlink_to(elsewhere)
        response = self.helper.dispatch(self.request("stage", 2), peer_uid=1001)
        self.assertEqual(response["error"]["code"], "FILESYSTEM")
        self.assertEqual(elsewhere.read_text(), "private-test")

    def test_admin_unit_is_derived_from_root_role_not_request(self):
        self.call("provision", 1, worker=self.admin_id)
        self.call("stage", 2, worker=self.admin_id)
        restarted = [call[2] for call in self.runner.calls if call[1] == "restart"]
        self.assertEqual(restarted, ["dazzle-admin@" + self.admin_id + ".service"])
        self.assertFalse(any("sing-box.service" == argument or "qqg-sub.service" == argument for call in self.runner.calls for argument in call))

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux-only peer credential integration")
    def test_one_socket_request_returns_one_json_with_peer_identity(self):
        left, right = socket.socketpair()
        class Stub:
            def dispatch(self, request, *, peer_uid):
                return {"ok": peer_uid == os.getuid(), "request_id": request["request_id"]}
        worker = threading.Thread(target=serve_connection, args=(left, Stub()))
        worker.start()
        request = self.request("status", 0)
        right.sendall(json.dumps(request).encode() + b"\n")
        self.assertTrue(json.loads(right.recv(10000))["ok"])
        worker.join(timeout=2); left.close(); right.close()


if __name__ == "__main__": unittest.main()
