"""Recovery stays local to one registered user and never invents meter trust."""
import datetime as dt
import json
import tempfile
import unittest
import uuid
from unittest.mock import patch

from dazzle import domain, recovery
from dazzle.metering import MeterSample
from dazzle.production import accept_sample, handle_request, plan_jobs, process_one_job, snapshot
from dazzle.production_state import CORE_SHA256, ProductionStore
from dazzle.store import parse_time, timestamp
from test_production import StrictHelper
from test_authorization_fixtures import seed_legacy_user


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = parse_time("2026-11-01T08:19:00Z")
        self.admin, self.member = str(uuid.uuid4()), str(uuid.uuid4())
        self.policy = {"version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "8.8.8.8",
                       "agent_uid": 995, "core_sha256": CORE_SHA256,
                       "workers": {self.admin: {"role": "admin", "public_port": 24430, "api_port": 34430},
                                   self.member: {"role": "member", "public_port": 24431, "api_port": 34431}}}
        self.store = ProductionStore(self.directory.name, policy=self.policy, initialize=True, now=self.now)
        self.addCleanup(self.store.close)
        self.helper = StrictHelper(self.policy, self.store)
        self.bootstrap("admin", self.admin)
        self.bootstrap("member", self.member)

    def call(self, action, params=None, *, request_id=None, revision=None, now=None):
        return handle_request(self.store, {"api_version": 1, "request_id": request_id or str(uuid.uuid4()),
            "action": action, "params": params or {}, "server_id": self.store.server_id,
            "expected_revision": self.store.revision if revision is None else revision}, now or self.now)

    def bootstrap(self, role, identifier):
        seed_legacy_user(self.store, {"name": "Recovery fixture " + role, "role": role, "quota_bytes": 100_000_000_000}, self.now)
        self.process()
        self.process()
        self.sample(identifier)
        self.assertTrue(self.call("user.enable", {"user_id": identifier})["ok"])
        self.process()
        self.sample(identifier, up=100, down=200)

    def process(self):
        return process_one_job(self.store, self.helper, self.now)

    def sample(self, identifier, up=0, down=0):
        worker = self.store.worker(identifier)
        self.now += dt.timedelta(milliseconds=50)
        self.store.conn.execute("BEGIN IMMEDIATE")
        try:
            result = accept_sample(self.store, identifier, worker["observed_generation"],
                MeterSample("fixture-epoch-" + str(worker["observed_generation"]), up, down, timestamp(self.now)), self.now)
            self.store.conn.commit()
            return result
        except BaseException:
            self.store.conn.rollback()
            raise

    def unhealthy(self):
        user = self.store.get_user(self.member)
        domain._incident(self.store, user, "meter_unavailable", self.now)
        self.store.conn.execute("UPDATE users SET trusted_sample=0,meter_state='reconciliation_required',reasons_json='[\"metering_failure\"]' WHERE id=?", (self.member,))

    def preview(self):
        result = self.call("user.recovery.preview", {"user_id": self.member})
        self.assertTrue(result["ok"], result)
        return result["data"]["recovery"]

    def apply(self, preview, *, confirmed=True, request_id=None, now=None):
        return self.call("user.recovery.apply", {"user_id": self.member, "preview_token": preview["preview_token"],
            "confirm_unknown_gap": confirmed}, revision=preview["expected_revision"], request_id=request_id, now=now)

    def advance(self, *, plan=True):
        self.store.conn.execute("BEGIN IMMEDIATE")
        try:
            recovery.advance(self.store, self.now)
            if plan:
                plan_jobs(self.store, self.now)
            self.store.conn.commit()
        except BaseException:
            self.store.conn.rollback()
            raise

    def test_preview_is_readonly_and_healthy_user_never_restarts(self):
        before = "\n".join(self.store.conn.iterdump())
        calls = len(self.helper.calls)
        worker = self.store.worker(self.member)
        result = self.preview()
        self.assertEqual(result["state"], "healthy")
        self.assertFalse(result["can_apply"])
        self.assertIsNone(result["preview_token"])
        self.assertEqual("\n".join(self.store.conn.iterdump()), before)
        self.assertEqual(len(self.helper.calls), calls)
        self.assertEqual(self.store.worker(self.member), worker)

    def test_explicit_force_preview_offers_healthy_target_without_changing_it(self):
        before = "\n".join(self.store.conn.iterdump())
        result = self.call("user.recovery.preview", {"user_id": self.member, "force_restart": True})
        self.assertTrue(result["ok"], result)
        preview = result["data"]["recovery"]
        self.assertTrue(preview["can_apply"])
        self.assertTrue(preview["force_restart"])
        self.assertTrue(preview["requires_unknown_gap_confirmation"])
        self.assertEqual("\n".join(self.store.conn.iterdump()), before)

    def test_confirmed_force_rebuilds_only_target_and_preserves_credentials_usage(self):
        admin, admin_worker = self.store.get_user(self.admin), self.store.worker(self.admin)
        credentials = self.store.get_credentials(self.member)
        user = self.store.get_user(self.member)
        preview = self.call("user.recovery.preview", {"user_id": self.member, "force_restart": True})
        self.assertTrue(preview["ok"], preview)
        preview = preview["data"]["recovery"]
        response = self.call("user.recovery.apply", {"user_id": self.member, "force_restart": True,
                             "preview_token": preview["preview_token"], "confirm_unknown_gap": True})
        self.assertTrue(response["ok"], response)
        self.assertFalse(response["data"].get("already_healthy", False))
        self.helper.calls.clear()
        self.assertTrue(self.process()["applied"])
        self.assertEqual(self.store.worker(self.member)["observed_state"], "staged")
        self.sample(self.member)
        self.advance()
        self.assertTrue(self.process()["applied"])
        self.sample(self.member)
        self.advance()
        self.assertEqual(recovery.status(self.store, self.store.get_user(self.member), now=self.now)["state"], "succeeded")
        self.assertEqual(self.store.get_credentials(self.member), credentials)
        self.assertEqual(tuple(self.store.get_user(self.member)[k] for k in ("used_upload", "used_download")),
                         tuple(user[k] for k in ("used_upload", "used_download")))
        self.assertEqual(self.store.get_user(self.admin), admin)
        self.assertEqual(self.store.worker(self.admin), admin_worker)
        self.assertEqual({c["worker_id"] for c in self.helper.calls}, {self.member})

    def test_force_mode_must_match_signed_preview_and_cannot_bypass_restrictions(self):
        self.unhealthy()
        preview = self.preview()
        result = self.call("user.recovery.apply", {"user_id": self.member, "force_restart": True,
                           "preview_token": preview["preview_token"], "confirm_unknown_gap": True})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "VALIDATION")
        self.assertIsNone(recovery._latest(self.store, self.member))
        self.store.conn.execute("UPDATE users SET manual_disabled=1 WHERE id=?", (self.member,))
        result = self.call("user.recovery.preview", {"user_id": self.member, "force_restart": True})
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["data"]["recovery"]["can_apply"])
        self.assertIn("manual_disabled", result["data"]["recovery"]["blocked_reasons"])

    def test_force_mode_is_explicit_boolean_and_reading_does_not_rebuild(self):
        worker = self.store.worker(self.member)
        for value in ("true", 1, None, [], {}):
            result = self.call("user.recovery.preview", {"user_id": self.member, "force_restart": value})
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "VALIDATION")
        for _ in range(3):
            self.call("snapshot")
            self.advance()
        self.assertEqual(self.store.worker(self.member), worker)
        self.assertIsNone(recovery._latest(self.store, self.member))

    def test_unhealthy_preview_contains_no_proxy_secrets_and_does_not_write(self):
        self.unhealthy()
        before = "\n".join(self.store.conn.iterdump())
        result = self.preview()
        self.assertTrue(result["can_apply"])
        self.assertTrue(result["requires_unknown_gap_confirmation"])
        credentials = self.store.get_credentials(self.member)
        for key in ("vless_uuid", "tuic_uuid", "tuic_password", "subscription_token"):
            self.assertNotIn(credentials[key], json.dumps(result))
        self.assertEqual("\n".join(self.store.conn.iterdump()), before)

    def test_recovery_requires_explicit_unknown_gap_confirmation(self):
        self.unhealthy()
        result = self.apply(self.preview(), confirmed=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "RECOVERY_CONFIRMATION_REQUIRED")
        self.assertIsNone(recovery._latest(self.store, self.member))

    def test_preview_expires_and_tampered_preview_is_rejected(self):
        self.unhealthy()
        preview = self.preview()
        expired = self.apply(preview, now=self.now + dt.timedelta(seconds=60))
        self.assertEqual(expired["error"]["code"], "RECOVERY_PREVIEW_EXPIRED")
        preview["preview_token"] = preview["preview_token"][:-5] + "abcde"
        tampered = self.apply(preview)
        self.assertEqual(tampered["error"]["code"], "VALIDATION")
        self.assertIsNone(recovery._latest(self.store, self.member))

    def test_reviewed_user_or_revision_change_requires_new_preview(self):
        self.unhealthy()
        preview = self.preview()
        self.store.conn.execute("UPDATE users SET quota_bytes=quota_bytes+1 WHERE id=?", (self.member,))
        changed = self.apply(preview)
        self.assertEqual(changed["error"]["code"], "RECOVERY_PREVIEW_CHANGED")
        preview = self.preview()
        self.store.set_meta("revision", self.store.revision + 1)
        stale = self.apply(preview)
        self.assertEqual(stale["error"]["code"], "REVISION_CONFLICT")

    def test_manual_quota_pool_revoked_and_deleted_cannot_be_recovered(self):
        self.unhealthy()
        original = self.store.get_user(self.member)
        cases = [("manual_disabled=1", (), "manual_disabled"),
                 ("quota_bytes=1", (), "quota_exceeded"),
                 ("reasons_json='[\"pool_protection\"]'", (), "pool_protection"),
                 ("revoked_at=?", (timestamp(self.now),), "revoked"),
                 ("deleted_at=?", (timestamp(self.now),), "deleted")]
        for sql, values, expected in cases:
            with self.subTest(reason=expected):
                self.store.conn.execute("UPDATE users SET " + sql + " WHERE id=?", (*values, self.member))
                preview = self.preview()
                self.assertFalse(preview["can_apply"])
                self.assertIn(expected, preview["blocked_reasons"])
                for key in ("manual_disabled", "quota_bytes", "reasons_json", "revoked_at", "deleted_at"):
                    self.store.conn.execute("UPDATE users SET " + key + "=? WHERE id=?", (original[key], self.member))

    def test_expired_trial_cannot_be_recovered(self):
        self.unhealthy()
        with patch("dazzle.recovery._expired", return_value=True):
            preview = self.preview()
        self.assertIn("expired", preview["blocked_reasons"])
        self.assertFalse(preview["can_apply"])

    def test_runtime_integrity_failure_is_not_retryable(self):
        self.unhealthy()
        self.store.conn.execute("UPDATE production_workers SET last_error='ROOT_REGISTRY_ROLLBACK' WHERE user_id=?", (self.member,))
        preview = self.preview()
        self.assertIn("runtime_integrity", preview["blocked_reasons"])
        self.assertFalse(preview["can_apply"])

    def test_only_target_is_staged_then_fresh_origin_reconciled_and_started(self):
        self.unhealthy()
        admin = self.store.get_user(self.admin)
        admin_worker = self.store.worker(self.admin)
        usage = (self.store.get_user(self.member)["used_upload"], self.store.get_user(self.member)["used_download"])
        credentials = self.store.get_credentials(self.member)
        self.helper.calls.clear()
        response = self.apply(self.preview())
        self.assertTrue(response["ok"], response)
        operation = response["data"]["recovery"]["operation_id"]
        self.assertTrue(operation)
        self.assertTrue(self.process()["applied"])
        self.assertEqual(self.store.worker(self.member)["observed_state"], "staged")
        self.advance()
        self.assertNotEqual(recovery.status(self.store, self.store.get_user(self.member), now=self.now)["state"], "succeeded")
        self.sample(self.member)
        self.assertFalse(self.store.conn.execute("SELECT 1 FROM production_jobs WHERE action='activate' AND status='pending'").fetchone())
        self.advance()
        self.assertEqual(recovery.status(self.store, self.store.get_user(self.member), now=self.now)["state"], "starting")
        self.assertTrue(self.process()["applied"])
        self.assertNotEqual(recovery.status(self.store, self.store.get_user(self.member), now=self.now)["state"], "succeeded")
        self.sample(self.member)
        self.advance()
        result = recovery.status(self.store, self.store.get_user(self.member), now=self.now)
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(self.store.get_credentials(self.member), credentials)
        self.assertEqual((self.store.get_user(self.member)["used_upload"], self.store.get_user(self.member)["used_download"]), usage)
        self.assertEqual(self.store.get_user(self.admin), admin)
        self.assertEqual(self.store.worker(self.admin), admin_worker)
        self.assertEqual({call["worker_id"] for call in self.helper.calls}, {self.member})
        self.assertFalse(self.store.conn.execute("SELECT 1 FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL", (self.member,)).fetchone())

    def test_apply_request_and_preview_replays_do_not_duplicate_work(self):
        self.unhealthy()
        preview = self.preview()
        request_id = str(uuid.uuid4())
        first = self.apply(preview, request_id=request_id)
        second = self.apply(preview, request_id=request_id)
        self.assertEqual(first, second)
        revision = self.store.revision
        third = self.apply(preview)
        self.assertTrue(third["ok"], third)
        self.assertTrue(third["data"]["already_applied"])
        self.assertEqual(self.store.revision, revision)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM user_recoveries").fetchone()[0], 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM production_jobs WHERE status='pending'").fetchone()[0], 1)

    def test_stale_native_sample_and_timeout_never_release_protection(self):
        self.unhealthy()
        self.assertTrue(self.apply(self.preview())["ok"])
        self.process()
        self.sample(self.member)
        self.now += dt.timedelta(seconds=6)
        self.advance()
        self.assertNotEqual(recovery._latest(self.store, self.member)["state"], "starting")
        self.now += dt.timedelta(seconds=60)
        self.advance()
        self.assertEqual(recovery._latest(self.store, self.member)["error_code"], "RECOVERY_TIMEOUT")
        self.assertIn("metering_failure", domain.disabled_reasons(self.store.get_user(self.member), self.now))

    def test_new_manual_disable_during_recovery_is_never_undone(self):
        self.unhealthy()
        self.assertTrue(self.apply(self.preview())["ok"])
        self.store.conn.execute("UPDATE users SET manual_disabled=1 WHERE id=?", (self.member,))
        self.advance()
        self.assertEqual(recovery._latest(self.store, self.member)["state"], "blocked")
        self.assertTrue(self.store.get_user(self.member)["manual_disabled"])

    def test_helper_failure_is_reported_and_never_claims_success(self):
        self.unhealthy()
        self.assertTrue(self.apply(self.preview())["ok"])
        self.helper.failure = "START_FAILED"
        self.assertFalse(self.process()["applied"])
        self.advance()
        result = recovery.status(self.store, self.store.get_user(self.member), now=self.now)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["error_code"], "RECOVERY_RUNTIME_FAILED")

    def test_snapshot_exposes_public_recovery_state_without_token(self):
        self.unhealthy()
        self.assertTrue(self.apply(self.preview())["ok"])
        member = next(user for user in snapshot(self.store, self.now)["users"] if user["id"] == self.member)
        self.assertIn(member["recovery"]["state"], {"checking", "recovering"})
        self.assertNotIn("preview_token", member["recovery"])

    def test_gap_preview_shows_bounded_ranges_and_preserves_unknown_bytes(self):
        self.unhealthy()
        user = self.store.get_user(self.member)
        domain._incident(self.store, user, "sample_gap", self.now,
                         at=self.now, known_delta=(7, 8), context="known-tail")
        result = self.preview()["gap_summary"]
        self.assertEqual(result["unresolved_count"], 2)
        self.assertEqual(result["last_trusted_at"], user["last_sample_at"])
        self.assertTrue(result["preserves_recorded_usage"])
        unknown = next(row for row in result["incidents"] if row["kind"] == "meter_unavailable")
        self.assertEqual(unknown["from_at"], user["last_sample_at"])
        self.assertIsNone(unknown["to_at"])
        self.assertIsNone(unknown["known_upload_bytes"])
        self.assertTrue(unknown["delta_unknown"])
        known = next(row for row in result["incidents"] if row["kind"] == "sample_gap")
        self.assertEqual((known["known_upload_bytes"], known["known_download_bytes"]), (7, 8))
        self.assertFalse(known["delta_unknown"])
        for number in range(25):
            domain._incident(self.store, user, "sample_gap", self.now, context=str(number))
        limited = self.preview()["gap_summary"]
        self.assertEqual(len(limited["incidents"]), 20)
        self.assertEqual(limited["omitted_count"], 7)

    def test_newly_discovered_gap_invalidates_previously_reviewed_preview(self):
        self.unhealthy()
        preview = self.preview()
        domain._incident(self.store, self.store.get_user(self.member), "sample_gap", self.now,
                         known_delta=(3, 4), context="arrived-after-review")
        response = self.apply(preview)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "RECOVERY_PREVIEW_CHANGED")
        self.assertIsNone(recovery._latest(self.store, self.member))
