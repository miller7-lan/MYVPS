"""Parallel production tests use temporary stores and a strict fake root helper."""
import copy
import datetime as dt
import json
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

from dazzle import domain
from dazzle.collector import Collectors, HelperExecutor, tick
from dazzle.metering import MeterSample
from dazzle.production import (ALLOWED_ACTIONS, ProductionError, accept_sample, handle_request,
                               plan_jobs, process_one_job, refresh_worker_status, render_export,
                               snapshot, subscription_response)
from dazzle.production_state import CORE_SHA256, ProductionStore, validate_policy
from dazzle.store import Store, parse_time, timestamp, utcnow

PUBLIC_KEY = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"


class StrictHelper:
    """Models root immutable tombstones, exact+1 generations and origin replay."""
    def __init__(self, policy, store=None):
        self.policy, self.store = policy, store
        self.records, self.cache, self.calls = {}, {}, []
        self.failure = None
        self.lose_response = False
        self.on_call = None

    def call(self, request):
        if self.store is not None:
            assert not self.store.conn.in_transaction, "Helper I/O held SQLite transaction"
        self.calls.append(copy.deepcopy(request))
        if self.on_call:
            self.on_call(request)
        if self.failure:
            raise ProductionError(self.failure, "Fixture helper failure")
        worker_id, action = request["worker_id"], request["action"]
        slot = self.policy["workers"][worker_id]
        record = self.records.setdefault(worker_id, {"generation": 0, "worker_state": "unprovisioned",
                                                     "public_key": None, "process_id": None, "tombstoned": False})
        def response(origin=False):
            return {"worker_id": worker_id, **slot, **record, "server_id": self.policy["server_id"],
                    "managed_origin_zero": origin, "inactive_confirmed": record["process_id"] is None,
                    "recovery_required": False}
        if action == "status":
            return response()
        fingerprint = json.dumps(request, sort_keys=True)
        if request["request_id"] in self.cache:
            old_fingerprint, old_response = self.cache[request["request_id"]]
            if fingerprint != old_fingerprint:
                raise ProductionError("GENERATION", "Fixture request mismatch")
            if old_response["managed_origin_zero"] and old_response["process_id"] != record["process_id"]:
                raise ProductionError("RECOVERY_REQUIRED", "Fixture process changed")
            return copy.deepcopy(old_response)
        if request["generation"] != record["generation"] + 1:
            raise ProductionError("GENERATION", "Fixture requires exact+1 generation")
        if record["tombstoned"] and action not in {"stop", "revoke"}:
            raise ProductionError("REVOKED", "Fixture permanent tombstone")
        record["generation"] = request["generation"]
        if action == "provision":
            record.update(worker_state="provisioned", public_key=PUBLIC_KEY)
        elif action in {"stage", "activate"}:
            record.update(worker_state="staged" if action == "stage" else "running",
                          process_id=1000 + request["generation"])
        elif action in {"stop", "revoke"}:
            record.update(worker_state="revoked" if action == "revoke" else "stopped", process_id=None)
            if action == "revoke":
                record["tombstoned"] = True
        result = response(action in {"stage", "activate"})
        self.cache[request["request_id"]] = fingerprint, copy.deepcopy(result)
        if self.lose_response:
            self.lose_response = False
            raise ProductionError("HELPER_UNAVAILABLE", "Fixture response lost after apply")
        return result


class ProductionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.now = parse_time("2026-11-01T08:19:00Z")
        self.admin_id, self.member_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.policy = {"version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "8.8.8.8",
                       "agent_uid": 995, "core_sha256": CORE_SHA256,
                       "workers": {self.admin_id: {"role": "admin", "public_port": 24430, "api_port": 34430},
                                   self.member_id: {"role": "member", "public_port": 24431, "api_port": 34431}}}
        self.store = ProductionStore(self.folder.name, policy=self.policy, initialize=True, now=self.now)
        self.addCleanup(lambda: self.store.close())
        self.helper = StrictHelper(self.policy, self.store)

    def call(self, action, params=None, *, now=None, ok=True, request_id=None, server_id=None):
        request = {"api_version": 1, "request_id": request_id or str(uuid.uuid4()), "action": action,
                   "expected_revision": self.store.revision, "server_id": server_id or self.store.server_id,
                   "params": params or {}}
        result = handle_request(self.store, request, now=now or self.now)
        if ok:
            self.assertTrue(result["ok"], result)
        return result

    def add(self, role="member", quota=1000):
        return self.call("user.add", {"name": "Parallel test " + role, "role": role, "quota_bytes": quota})["data"]["user"]["id"]

    def process(self, seconds=0):
        return process_one_job(self.store, self.helper, now=self.now + dt.timedelta(seconds=seconds))

    def sample(self, user_id, up=0, down=0, seconds=0, epoch=None, generation=None):
        worker = self.store.worker(user_id)
        sample = MeterSample(epoch or "epoch-" + str(worker["observed_generation"]), up, down,
                             timestamp(self.now + dt.timedelta(seconds=seconds)))
        self.store.conn.execute("BEGIN IMMEDIATE")
        try:
            result = accept_sample(self.store, user_id, generation or worker["observed_generation"], sample,
                                   self.now + dt.timedelta(seconds=seconds))
            self.store.conn.commit()
            return result
        except BaseException:
            self.store.conn.rollback()
            raise

    def staged(self, role="member", quota=1000):
        user = self.add(role, quota)
        self.assertTrue(self.process()["applied"])
        self.assertTrue(self.process()["applied"])
        self.assertEqual(self.store.worker(user)["observed_state"], "staged")
        self.sample(user)
        return user

    def running(self, role="member", quota=1000):
        user = self.staged(role, quota)
        self.call("user.enable", {"user_id": user})
        self.assertTrue(self.process()["applied"])
        self.assertEqual(self.store.worker(user)["observed_state"], "running")
        return user

    def test_initialization_explicit_separate_and_root_identity_bound(self):
        state = snapshot(self.store, self.now)
        self.assertEqual(state["users"], [])
        self.assertEqual(state["mode"], "production")
        self.assertEqual(state["server_id"], self.policy["server_id"])
        self.assertEqual(state["capabilities"]["controller"], "root_policy")
        self.assertFalse(state["legacy"]["managed"])
        self.assertFalse(state["legacy"]["retirement_supported"])
        self.assertEqual(state["mail"]["transport"], "not_enabled")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                ProductionStore(directory, policy=self.policy)
            with Store(directory):
                pass
            with self.assertRaises(ValueError):
                ProductionStore(directory, policy=self.policy, initialize=True)
        changed = copy.deepcopy(self.policy)
        changed["server_id"] = str(uuid.uuid4())
        with self.assertRaises(ValueError):
            ProductionStore(self.folder.name, policy=changed)

    def test_policy_rejects_legacy_or_unapproved_ports(self):
        for key, value in (("public_port", 443), ("public_port", 8443), ("api_port", 22), ("public_port", 24432)):
            policy = copy.deepcopy(self.policy)
            policy["workers"][self.member_id][key] = value
            with self.assertRaises(ValueError):
                validate_policy(policy)

    def test_registered_slots_not_simulation_ids_or_arbitrary_ports(self):
        user = self.add()
        self.assertEqual(user, self.member_id)
        self.assertEqual(self.store.get_user(user)["port"], 24431)
        self.assertTrue(self.store.get_user(user)["manual_disabled"])
        duplicate = self.call("user.add", {"name": "No approved slot", "role": "member"}, ok=False)
        self.assertEqual(duplicate["error"]["code"], "APPROVAL_REQUIRED")
        denied = self.call("user.add", {"name": "Injected", "port": 443}, ok=False)
        self.assertEqual(denied["error"]["code"], "VALIDATION")

    def test_production_allowlist_rejects_simulation_clock_and_mail_actions(self):
        forbidden = ("demo.initialize", "mail.simulated_inbox", "mail.process", "mail.configure", "meter.sample",
                     "meter.failure", "cycle.tick", "runtime.process", "rollback.apply")
        for action in forbidden:
            self.assertFalse(self.call(action, ok=False)["ok"])
            self.assertNotIn(action, ALLOWED_ACTIONS)
        self.assertFalse(self.call("snapshot", {"at": timestamp(self.now)}, ok=False)["ok"])

    def test_wrong_server_or_revision_denies_mutation_without_new_user(self):
        result = self.call("user.add", {"name": "Denied"}, server_id=str(uuid.uuid4()), ok=False)
        self.assertEqual(result["error"]["code"], "SERVER_ID_MISMATCH")
        request = {"api_version": 1, "request_id": str(uuid.uuid4()), "action": "user.add",
                   "server_id": self.store.server_id, "expected_revision": 999, "params": {"name": "Denied"}}
        self.assertEqual(handle_request(self.store, request, self.now)["error"]["code"], "REVISION_CONFLICT")
        self.assertEqual(snapshot(self.store, self.now)["users"], [])

    def test_manual_request_retry_is_durable_and_idempotent(self):
        identifier = str(uuid.uuid4())
        first = self.call("user.add", {"name": "Idempotent"}, request_id=identifier)
        again = self.call("user.add", {"name": "Idempotent"}, request_id=identifier)
        self.assertEqual(first, again)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_unprovisioned_worker_cannot_export_live_configuration(self):
        user = self.add()
        result = self.call("user.export", {"user_id": user, "format": "uris"}, ok=False)
        self.assertEqual(result["error"]["code"], "NOT_PROVISIONED")

    def test_stage_zero_then_managed_active_origin_counts_first_nonzero(self):
        user = self.running()
        before = self.store.revision
        result = self.sample(user, 21, 34, seconds=1)
        self.assertEqual((result["upload_delta"], result["download_delta"]), (21, 34))
        self.assertEqual((self.store.get_user(user)["used_upload"], self.store.get_user(user)["used_download"]), (21, 34))
        self.assertEqual(self.store.revision, before)
        self.assertTrue(domain.eligible(self.store.get_user(user), self.now + dt.timedelta(seconds=1)))
        self.assertFalse(any(request.get("params", {}).get("public_port") == 443 for request in self.helper.calls))

    def test_queue_generation_does_not_fence_still_running_origin(self):
        user = self.running()
        self.sample(user, 10, 20, seconds=1)
        old = self.store.worker(user)["observed_generation"]
        self.call("user.disable", {"user_id": user}, now=self.now + dt.timedelta(seconds=1))
        self.assertGreater(self.store.worker(user)["generation"], old)
        self.sample(user, 15, 25, seconds=2, generation=old)
        self.assertEqual(self.store.get_user(user)["used_upload"], 15)

    def test_revoke_request_keeps_counting_known_tail_until_root_stop_confirmation(self):
        user = self.running()
        self.sample(user, 10, 20, seconds=1)
        self.call("user.revoke", {"user_id": user}, now=self.now + dt.timedelta(seconds=1))
        self.sample(user, 15, 27, seconds=2)
        self.assertEqual((self.store.get_user(user)["used_upload"], self.store.get_user(user)["used_download"]), (15, 27))
        collectors = Collectors(self.helper)
        collectors._emit(((user, self.store.worker(user)["observed_generation"]), "unavailable", None))
        collectors.drain(self.store, self.now + dt.timedelta(seconds=2))
        self.assertTrue(self.process(seconds=2)["applied"])
        self.assertEqual(self.store.worker(user)["observed_state"], "revoked")

    def test_quota_stage_preserves_usage_and_keeps_private_meter_available(self):
        user = self.running(quota=100)
        self.sample(user, 60, 50, seconds=1)
        self.assertIn("quota_exceeded", domain.disabled_reasons(self.store.get_user(user)))
        self.assertTrue(self.process(seconds=1)["applied"])
        self.assertEqual(self.store.worker(user)["observed_state"], "staged")
        self.sample(user, seconds=2)
        self.assertEqual(self.store.get_user(user)["used_upload"], 60)
        self.assertTrue(self.store.get_user(user)["trusted_sample"])
        self.assertFalse(domain.eligible(self.store.get_user(user), self.now + dt.timedelta(seconds=2)))
        self.assertTrue(self.store.conn.execute("SELECT 1 FROM metering_incidents WHERE kind='managed_stop_tail'").fetchone())

    def test_unexpected_epoch_pauses_member_and_preserves_unresolved_incident(self):
        user = self.running()
        self.sample(user, 10, 20, seconds=1)
        self.sample(user, 0, 0, seconds=2, epoch="unexpected-restart")
        self.assertIn("metering_failure", domain.disabled_reasons(self.store.get_user(user)))
        self.process(seconds=2)
        self.sample(user, seconds=3)
        self.assertIn("metering_failure", domain.disabled_reasons(self.store.get_user(user)))
        self.call("meter.reconcile", {"user_id": user, "evidence": "Reviewed unexpected worker restart and gap"}, now=self.now + dt.timedelta(seconds=3))
        self.assertNotIn("metering_failure", domain.disabled_reasons(self.store.get_user(user)))

    def test_administrator_remains_authorized_when_native_meter_fails(self):
        user = self.running("admin")
        self.sample(user, 1, 2, seconds=1)
        self.sample(user, 0, 0, seconds=2, epoch="unexpected-admin-restart")
        self.assertTrue(domain.eligible(self.store.get_user(user), self.now + dt.timedelta(seconds=20)))
        self.assertEqual(self.store.worker(user)["observed_state"], "running")

    def test_stale_activate_is_cancelled_and_generation_reused_for_rotate(self):
        user = self.staged()
        self.call("user.enable", {"user_id": user})
        queued = self.store.worker(user)["generation"]
        self.call("user.rotate", {"user_id": user})
        self.assertTrue(self.process()["cancelled"])
        self.assertTrue(self.process()["applied"])
        self.assertEqual(self.store.worker(user)["root_ack_generation"], queued)
        self.assertEqual(self.helper.records[user]["generation"], queued)
        self.assertEqual(self.helper.records[user]["worker_state"], "staged")

    def test_unexecuted_provision_cancelled_for_revoke_does_not_skip_generation(self):
        user = self.add()
        self.call("user.revoke", {"user_id": user})
        self.assertTrue(self.process()["cancelled"])
        self.assertTrue(self.process()["applied"])
        self.assertEqual(self.helper.records[user]["generation"], 1)
        self.assertTrue(self.helper.records[user]["tombstoned"])

    def test_lost_activate_response_replays_same_request_and_trusted_origin(self):
        user = self.staged()
        self.call("user.enable", {"user_id": user})
        self.helper.lose_response = True
        self.assertFalse(self.process()["applied"])
        requests = [request for request in self.helper.calls if request["action"] == "activate"]
        refresh_worker_status(self.store, self.helper, self.now)
        self.assertTrue(self.process()["applied"])
        replayed = [request for request in self.helper.calls if request["action"] == "activate"]
        self.assertEqual(requests[0], replayed[-1])
        self.sample(user, 31, 47, seconds=1)
        self.assertEqual(self.store.get_user(user)["used_upload"], 31)

    def test_revoke_after_unknown_activate_response_uses_acknowledged_next_generation(self):
        user = self.staged()
        self.call("user.enable", {"user_id": user})
        self.helper.lose_response = True
        self.process()
        accepted = self.helper.records[user]["generation"]
        self.call("user.revoke", {"user_id": user})
        self.assertTrue(self.process()["cancelled"])
        self.assertTrue(self.process()["applied"])
        self.assertEqual(self.helper.records[user]["generation"], accepted + 1)
        self.assertTrue(self.helper.records[user]["tombstoned"])

    def test_agent_restart_probes_inactive_member_instead_of_trusting_database_running(self):
        user = self.running()
        self.sample(user, 10, 20, seconds=1)
        self.helper.records[user].update(worker_state="stopped", process_id=None)
        refresh_worker_status(self.store, self.helper, self.now + dt.timedelta(seconds=2))
        self.assertEqual(self.store.worker(user)["observed_state"], "stopped")
        self.assertIn("metering_failure", domain.disabled_reasons(self.store.get_user(user)))
        self.assertTrue(self.process(seconds=2)["applied"])
        self.assertEqual(self.store.worker(user)["observed_state"], "staged")

    def test_root_tombstone_overlays_restored_local_credentials(self):
        user = self.staged()
        self.helper.records[user].update(tombstoned=True, worker_state="revoked", process_id=None)
        refresh_worker_status(self.store, self.helper, self.now)
        self.assertIsNotNone(self.store.get_user(user)["revoked_at"])
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM credentials WHERE user_id=?", (user,)).fetchone()[0], 0)
        self.assertFalse(self.call("user.enable", {"user_id": user}, ok=False)["ok"])

    def test_real_exports_use_approved_endpoint_and_never_testnet_or_simulation(self):
        user = self.staged()
        for format_name in ("uris", "shadowrocket", "mihomo"):
            result = self.call("user.export", {"user_id": user, "format": format_name})["data"]
            self.assertEqual(result["environment"], "production")
            self.assertEqual(result["server_id"], self.store.server_id)
            self.assertTrue(result["deployed"])
            self.assertIn("8.8.8.8", result["content"])
            self.assertNotIn("192.0.2.10", result["content"])
            self.assertNotIn("SIMULATION", result["content"])
            self.assertIn(PUBLIC_KEY, result["content"])
            self.assertTrue(result["nodes_url"].startswith("https://8.8.8.8:9443/"))
        cached = "".join(row[0] for row in self.store.conn.execute("SELECT response_json FROM requests"))
        for key in ("vless_uuid", "tuic_password", "subscription_token"):
            self.assertNotIn(self.store.get_credentials(user)[key], cached)

    def test_subscriptions_gate_live_tokens_and_describe_personal_payload_only(self):
        user = self.running()
        self.sample(user, 21, 34, seconds=1)
        token = self.store.get_credentials(user)["subscription_token"]
        response = subscription_response(self.store, token, "nodes.txt", self.now + dt.timedelta(seconds=1))
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["headers"]["Subscription-Userinfo"], "upload=21; download=34; total=1000")
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")
        self.assertEqual(subscription_response(self.store, "unknown-token-" * 4, "nodes.txt", self.now)["status"], 404)
        self.assertEqual(subscription_response(self.store, token, "management", self.now)["status"], 404)
        self.call("user.disable", {"user_id": user}, now=self.now + dt.timedelta(seconds=1))
        self.assertEqual(subscription_response(self.store, token, "nodes.txt", self.now + dt.timedelta(seconds=1))["status"], 403)
        state = snapshot(self.store, self.now + dt.timedelta(seconds=1))["users"][0]
        self.assertEqual(state["requested_authorization"], "disabled")
        self.assertEqual(state["runtime_state"], "stop_pending")

    def test_helper_failure_does_not_claim_stopped_or_applied(self):
        user = self.running()
        self.sample(user, 1, 2, seconds=1)
        self.call("user.disable", {"user_id": user}, now=self.now + dt.timedelta(seconds=1))
        self.helper.failure = "STOP_UNCONFIRMED"
        self.assertFalse(self.process(seconds=1)["applied"])
        state = snapshot(self.store, self.now + dt.timedelta(seconds=1))["users"][0]
        self.assertEqual(state["runtime_state"], "stop_failed")
        self.assertEqual(self.store.worker(user)["observed_state"], "running")

    def test_tick_and_counter_updates_do_not_bump_control_revision(self):
        user = self.running()
        before = self.store.revision
        for seconds in (1, 2, 3):
            self.sample(user, seconds, seconds, seconds=seconds)
            tick(self.store, self.now + dt.timedelta(seconds=seconds))
        self.assertEqual(self.store.revision, before)
        tick(self.store, parse_time("2026-11-24T08:19:00Z"))
        self.assertEqual(self.store.revision, before + 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox").fetchone()[0], 0)

    def test_late_known_sample_from_retired_origin_is_counted_without_clobbering_new_baseline(self):
        user = self.running()
        self.sample(user, 10, 20, seconds=1)
        old_generation = self.store.worker(user)["observed_generation"]
        old_epoch = self.store.get_user(user)["meter_epoch"]
        self.call("user.disable", {"user_id": user}, now=self.now + dt.timedelta(seconds=1))
        self.process(seconds=3)
        self.sample(user, seconds=3)
        new_epoch = self.store.get_user(user)["meter_epoch"]
        result = self.sample(user, 15, 27, seconds=2, epoch=old_epoch, generation=old_generation)
        self.assertTrue(result["allocated"])
        self.assertEqual((self.store.get_user(user)["used_upload"], self.store.get_user(user)["used_download"]), (15, 27))
        self.assertEqual(self.store.get_user(user)["meter_epoch"], new_epoch)

    def test_readonly_subscription_store_performs_no_schema_or_state_writes(self):
        user = self.running()
        self.sample(user, 1, 2, seconds=1)
        with ProductionStore(self.folder.name, policy=self.policy, read_only=True, now=self.now) as reader:
            statements = []
            reader.conn.set_trace_callback(statements.append)
            token = reader.get_credentials(user)["subscription_token"]
            self.assertEqual(subscription_response(reader, token, "config.yaml", self.now + dt.timedelta(seconds=1))["status"], 200)
            self.assertFalse(any(statement.startswith(("CREATE", "INSERT", "UPDATE", "DELETE")) for statement in statements))

    def test_blocked_helper_thread_does_not_block_sample_writer_or_tick(self):
        user = self.running()
        self.sample(user, 10, 20, seconds=1)
        self.call("user.disable", {"user_id": user}, now=self.now + dt.timedelta(seconds=1))
        entered, release = threading.Event(), threading.Event()
        def block(request):
            if request["action"] == "stage":
                entered.set()
                release.wait(3)
        helper = StrictHelper(self.policy)
        helper.records = copy.deepcopy(self.helper.records)
        helper.cache = copy.deepcopy(self.helper.cache)
        helper.on_call = block
        executor = HelperExecutor(self.store, helper)
        executor.start()
        executor.wake.set()
        try:
            self.assertTrue(entered.wait(2))
            began = time.monotonic()
            self.sample(user, 15, 25, seconds=2)
            tick(self.store, self.now + dt.timedelta(seconds=2))
            self.assertLess(time.monotonic() - began, 1)
            self.assertEqual(self.store.get_user(user)["used_upload"], 15)
        finally:
            release.set()
            executor.close()

    def test_collectors_queue_overflow_is_explicit_not_silent_loss(self):
        collectors = Collectors(self.helper, max_events=1)
        collectors._emit(((self.member_id, 0), "unavailable", None))
        collectors._emit(((self.member_id, 0), "unavailable", None))
        with self.assertRaises(ProductionError):
            collectors.drain(self.store, self.now)

    def test_managed_transition_pid_window_does_not_invent_unexpected_restart(self):
        user = self.running()
        self.sample(user, 10, 20, seconds=1)
        self.call("user.disable", {"user_id": user}, now=self.now + dt.timedelta(seconds=1))
        self.store.conn.execute("UPDATE production_jobs SET status='executing' WHERE status='pending'")
        collectors = Collectors(self.helper)
        generation = self.store.worker(user)["observed_generation"]
        collectors._emit(((user, generation), "identity_changed", None))
        collectors.drain(self.store, self.now + dt.timedelta(seconds=2))
        self.assertFalse(self.store.conn.execute("SELECT 1 FROM metering_incidents WHERE kind='worker_identity_changed'").fetchone())
        self.assertNotIn("metering_failure", domain.disabled_reasons(self.store.get_user(user)))


if __name__ == "__main__":
    unittest.main()
