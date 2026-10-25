"""Domain and RPC tests use isolated local simulation state only."""
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid

from dazzle.domain import eligible
from dazzle.rpc import handle_request
from dazzle.store import Store, parse_time, timestamp


class DomainTests(unittest.TestCase):
    def setUp(self):
        self.now = parse_time("2026-10-25T08:19:00Z")
        self.store = Store(memory=True, now=self.now)
        self.addCleanup(self.store.close)

    def request(self, action, params=None, *, expected=None, identifier=None, ok=True):
        request = {"api_version": 1, "request_id": identifier or str(uuid.uuid4()), "action": action,
                   "expected_revision": self.store.revision if expected is None else expected,
                   "params": params or {}}
        result = handle_request(self.store, request)
        if ok:
            self.assertTrue(result["ok"], result)
        return result

    def add(self, name="Member", role="member", quota=1000):
        params = {"name": name, "role": role}
        if role == "member":
            params["quota_bytes"] = quota
        return self.request("user.add", params)["data"]["user"]["id"]

    def sample(self, user, up=0, down=0, epoch="fixture-epoch", seconds=0):
        self.store.now += dt.timedelta(seconds=seconds)
        return self.request("meter.sample", {"user_id": user, "epoch": epoch, "uplink": up,
                                             "downlink": down, "at": timestamp(self.store.now)})

    def public(self, user):
        return next(value for value in self.request("snapshot")["data"]["users"] if value["id"] == user)

    def test_empty_snapshot_never_seeds_live_users(self):
        result = self.request("snapshot")["data"]
        self.assertEqual(result["users"], [])
        self.assertEqual(result["settings"]["default_quota_bytes"], 100000000000)
        self.assertIsNone(result["provider"]["observed_at"])
        self.assertEqual(result["provider"]["source"], "historical_manual_snapshot")

    def test_explicit_demo_initialization_only(self):
        result = self.request("demo.initialize")
        self.assertEqual(len(result["data"]["snapshot"]["users"]), 2)
        again = self.request("demo.initialize", ok=False)
        self.assertEqual(again["error"]["code"], "VALIDATION")

    def test_new_member_disabled_with_independent_credentials(self):
        first, second = self.add("A"), self.add("B")
        self.assertIn("manual_disabled", self.public(first)["disabled_reasons"])
        a, b = self.store.get_credentials(first), self.store.get_credentials(second)
        for key in ("vless_uuid", "tuic_uuid", "tuic_password", "subscription_token"):
            self.assertNotEqual(a[key], b[key])
        self.assertNotEqual(a["vless_uuid"], a["tuic_uuid"])

    def test_more_than_fifteen_users_are_allowed(self):
        for i in range(17):
            self.add(str(i))
        users = self.request("snapshot")["data"]["users"]
        self.assertEqual(len(users), 17)
        self.assertEqual(len({user["port"] for user in users}), 17)

    def test_only_one_live_admin_and_unlimited(self):
        admin = self.add(role="admin")
        self.assertTrue(self.public(admin)["unlimited"])
        self.assertIsNone(self.public(admin)["quota_bytes"])
        self.assertEqual(self.request("user.add", {"name": "Other", "role": "admin"}, ok=False)["error"]["code"], "VALIDATION")
        self.request("user.revoke", {"user_id": admin})
        self.add("Replacement", role="admin")

    def test_admin_cannot_be_changed_to_limited(self):
        admin = self.add(role="admin")
        result = self.request("user.update", {"user_id": admin, "unlimited": False}, ok=False)
        self.assertEqual(result["error"]["code"], "VALIDATION")
        self.assertTrue(self.public(admin)["unlimited"])

    def test_enable_waits_for_first_trusted_zero_baseline(self):
        user = self.add()
        self.request("user.enable", {"user_id": user})
        self.assertIn("metering_failure", self.public(user)["disabled_reasons"])
        self.sample(user)
        self.assertEqual(self.public(user)["disabled_reasons"], [])

    def test_admin_retains_access_when_metering_fails(self):
        admin = self.add(role="admin")
        self.request("user.enable", {"user_id": admin})
        self.request("meter.failure", {"user_id": admin, "at": timestamp(self.now + dt.timedelta(seconds=10))})
        self.assertEqual(self.public(admin)["disabled_reasons"], [])
        self.assertTrue(eligible(self.store.get_user(admin), self.now + dt.timedelta(days=1)))

    def test_sample_accumulates_payload_without_double_count(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 100, 200, seconds=1)
        self.sample(user, 125, 250, seconds=1)
        result = self.public(user)
        self.assertEqual((result["used_upload"], result["used_download"]), (125, 250))
        self.assertEqual(self.store.conn.execute("SELECT SUM(upload),SUM(download) FROM ledger").fetchone()[0], 125)

    def test_duplicate_sample_is_not_recounted(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=1)
        self.sample(user, 10, 20)
        self.assertEqual(self.public(user)["used_download"], 20)

    def test_128_samples_in_two_minutes_keep_totals_with_two_buckets(self):
        from dazzle.domain import handle_action
        self.store.now = parse_time("2026-10-25T08:19:00Z")
        user = self.add(quota=1000000)
        self.sample(user)
        # 128 genuine cumulative samples at0.8s spacing span1m42.4s.
        for index in range(1, 129):
            at = self.now + dt.timedelta(seconds=index * 0.8)
            self.store.now = at
            self.store.conn.execute("BEGIN IMMEDIATE")
            handle_action(self.store, "meter.sample", {"user_id": user, "epoch": "fixture-epoch", "uplink": index,
                                                       "downlink": index * 2, "at": timestamp(at)}, at)
            self.store.conn.commit()
        result = self.public(user)
        self.assertEqual((result["used_upload"], result["used_download"]), (128, 256))
        buckets = self.store.conn.execute("SELECT COUNT(*),SUM(upload),SUM(download) FROM ledger").fetchone()
        self.assertEqual(tuple(buckets), (2, 128, 256))

    def test_history_preview_is_non_destructive(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=1)
        before = [tuple(row) for row in self.store.conn.execute("SELECT * FROM ledger")]
        self.store.now += dt.timedelta(days=120)
        result = self.request("history.preview")["data"]
        self.assertEqual(result["older_minute_rows"], 1)
        self.assertFalse(result["delete_available"])
        self.assertEqual([tuple(row) for row in self.store.conn.execute("SELECT * FROM ledger")], before)

    def test_invalid_int64_or_bool_samples_rejected(self):
        user = self.add()
        for value in (-1, True, 2**63, 1.5):
            result = self.request("meter.sample", {"user_id": user, "epoch": "e", "uplink": value,
                                                  "downlink": 0, "at": timestamp(self.now)}, ok=False)
            self.assertEqual(result["error"]["code"], "VALIDATION")

    def test_epoch_change_preserves_ledger_and_requires_reconcile(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 50, 60, seconds=1)
        self.sample(user, 0, 0, epoch="new-epoch", seconds=1)
        self.assertEqual(self.public(user)["used_upload"], 50)
        self.assertIn("metering_failure", self.public(user)["disabled_reasons"])
        self.assertFalse(self.request("meter.reconcile", {"user_id": user, "evidence": "Checked epoch"}, ok=False)["ok"])
        self.sample(user, 4, 5, epoch="new-epoch", seconds=1)
        self.request("meter.reconcile", {"user_id": user, "evidence": "New counters checked"})
        self.assertNotIn("metering_failure", self.public(user)["disabled_reasons"])
        self.assertEqual(self.public(user)["used_upload"], 54)

    def test_regression_never_subtracts_recorded_usage(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 80, 70, seconds=1)
        self.sample(user, 40, 20, seconds=1)
        self.assertEqual(self.public(user)["used_upload"], 80)
        self.assertIn("metering_failure", self.public(user)["disabled_reasons"])

    def test_gap_over_five_seconds_is_not_silently_allocated(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 50, 100, seconds=6)
        result = self.public(user)
        self.assertEqual(result["used_upload"], 0)
        self.assertIn("metering_failure", result["disabled_reasons"])

    def test_exactly_five_seconds_still_trusted(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=5)
        self.assertEqual(self.public(user)["used_download"], 20)

    def test_quota_topup_cannot_clear_other_reasons(self):
        user = self.add(quota=100)
        self.sample(user)
        self.request("user.enable", {"user_id": user})
        self.sample(user, 50, 50, seconds=1)
        self.sample(user, 0, 0, epoch="new", seconds=1)
        self.request("user.disable", {"user_id": user})
        self.request("user.topup", {"user_id": user, "bytes": 100})
        result = self.public(user)
        self.assertNotIn("quota_exceeded", result["disabled_reasons"])
        self.assertIn("metering_failure", result["disabled_reasons"])
        self.assertIn("manual_disabled", result["disabled_reasons"])

    def test_permanent_revoke_removes_secrets_and_is_terminal(self):
        user = self.add()
        self.request("user.revoke", {"user_id": user})
        self.assertEqual(self.public(user)["status"], "revoked")
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM credentials WHERE user_id=?", (user,)).fetchone()[0], 0)
        for action in ("user.enable", "user.update", "user.rotate", "user.export"):
            result = self.request(action, {"user_id": user, "name": "x"}, ok=False)
            self.assertEqual(result["error"]["code"], "REVOKED")

    def test_rotate_independent_credentials_preserves_reasons_and_usage(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 20, 30, seconds=1)
        before = self.store.get_credentials(user)
        self.request("user.rotate", {"user_id": user})
        after = self.store.get_credentials(user)
        self.assertEqual(after["version"], 2)
        for key in ("vless_uuid", "tuic_uuid", "subscription_token", "tuic_password"):
            self.assertNotEqual(before[key], after[key])
        self.assertEqual(self.public(user)["used_upload"], 20)
        self.assertIn("manual_disabled", self.public(user)["disabled_reasons"])

    def test_snapshot_and_mutation_cache_never_contain_credentials(self):
        user = self.add()
        values = self.store.get_credentials(user)
        serialized = json.dumps(self.request("snapshot"))
        cached = "\n".join(row[0] for row in self.store.conn.execute("SELECT response_json FROM requests"))
        for key in ("vless_uuid", "tuic_uuid", "tuic_password", "subscription_token"):
            self.assertNotIn(values[key], serialized)
            self.assertNotIn(values[key], cached)

    def test_export_requires_revision_and_is_sensitive_only_in_memory(self):
        user = self.add()
        revision = self.store.revision
        result = self.request("user.export", {"user_id": user, "format": "uris"})
        self.assertTrue(result["data"]["sensitive"])
        self.assertIn("192.0.2.10", result["data"]["content"])
        self.assertEqual(revision, self.store.revision)
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM requests WHERE request_id=?", (result["request_id"],)).fetchone()[0], 0)

    def test_idempotent_mutation_returns_original_response_exactly(self):
        identifier = "same-operation"
        result = self.request("user.add", {"name": "A", "role": "member"}, identifier=identifier)
        self.add("Another")
        repeated = self.request("user.add", {"name": "A", "role": "member"}, identifier=identifier)
        self.assertEqual(result, repeated)
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM users").fetchone()[0], 2)

    def test_request_id_cannot_be_reused_for_different_mutation(self):
        self.request("user.add", {"name": "A"}, identifier="reuse")
        result = self.request("user.add", {"name": "B"}, identifier="reuse", ok=False)
        self.assertEqual(result["error"]["code"], "VALIDATION")

    def test_stale_revision_and_missing_revision_are_rejected(self):
        before = self.store.revision
        self.add()
        result = self.request("user.add", {"name": "Other"}, expected=before, ok=False)
        self.assertEqual(result["error"]["code"], "REVISION_CONFLICT")
        result = handle_request(self.store, {"api_version": 1, "request_id": "missing-rev", "action": "user.add", "params": {"name": "Other"}})
        self.assertEqual(result["error"]["code"], "VALIDATION")

    def test_successful_mutation_increments_once_failed_mutation_never(self):
        before = self.store.revision
        self.add()
        self.assertEqual(self.store.revision, before + 1)
        self.request("user.add", {"name": "", "role": "member"}, ok=False)
        self.assertEqual(self.store.revision, before + 1)

    def test_provider_observation_cannot_reset_user_cycle_or_usage(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 20, 30, seconds=1)
        cycle = self.request("snapshot")["data"]["quota_cycle"]
        self.request("provider.observe", {"instance_id": "4920", "remaining_display": "499GB",
                                           "kind": "paid_reset", "source": "manual", "evidence": "Fixture manual evidence"})
        self.assertEqual(self.request("snapshot")["data"]["quota_cycle"], cycle)
        self.assertEqual(self.public(user)["used_upload"], 20)
        self.assertIsNone(self.request("snapshot")["data"]["provider"]["remaining_bytes"])

    def test_provider_wrong_instance_rejected(self):
        result = self.request("provider.observe", {"instance_id": "other", "evidence": "Fixture"}, ok=False)
        self.assertEqual(result["error"]["code"], "VALIDATION")

    def test_provider_confirmed_reset_requires_explicit_actual_evidence(self):
        result = self.request("provider.observe", {"instance_id": "4920", "kind": "reset_confirmed", "evidence": "Fixture"}, ok=False)
        self.assertEqual(result["error"]["code"], "VALIDATION")

    def test_schedule_update_does_not_immediately_reset(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 20, 30, seconds=1)
        cycle = self.request("snapshot")["data"]["quota_cycle"]
        self.request("settings.update", {"day": 1, "time": "00:00", "timezone": "UTC"})
        self.assertEqual(self.request("snapshot")["data"]["quota_cycle"], cycle)
        self.assertEqual(self.public(user)["used_download"], 30)

    def test_monthly_boundary_uses_shanghai_24th_1619(self):
        cycle = self.request("snapshot")["data"]["quota_cycle"]
        self.assertEqual(parse_time(cycle["start_at"]), parse_time("2026-10-24T08:19:00Z"))
        self.assertEqual(parse_time(cycle["end_at"]), parse_time("2026-11-24T08:19:00Z"))

    def test_cycle_archives_usage_clears_topups_preserves_manual_disable(self):
        user = self.add(quota=100)
        self.sample(user)
        self.sample(user, 10, 20, seconds=1)
        self.request("user.topup", {"user_id": user, "bytes": 25})
        result = self.request("cycle.tick", {"at": "2026-11-24T08:19:00Z"})["data"]["snapshot"]
        current = next(value for value in result["users"] if value["id"] == user)
        self.assertEqual((current["used_upload"], current["used_download"], current["topup_bytes"]), (0, 0, 0))
        self.assertIn("manual_disabled", current["disabled_reasons"])
        report = next(cycle for cycle in result["cycles"] if cycle["status"] == "closed")["report"]
        self.assertEqual(report["used_upload"], 10)

    def test_boundary_gap_requiring_reconcile_does_not_guess_allocation(self):
        user = self.add()
        self.sample(user)
        self.request("cycle.tick", {"at": "2026-11-24T08:19:00Z"})
        result = self.public(user)
        self.assertIn("metering_failure", result["disabled_reasons"])
        self.sample(user, 100, 100)
        self.assertEqual(self.public(user)["used_upload"], 0)

    def test_continuous_boundary_sample_then_tick_restores_quota_only(self):
        self.store.now = parse_time("2026-11-24T08:18:58Z")
        user = self.add(quota=100)
        self.sample(user)
        self.request("user.enable", {"user_id": user})
        self.sample(user, 50, 50, seconds=1)
        self.assertIn("quota_exceeded", self.public(user)["disabled_reasons"])
        # Final sample lands 1s after the scheduled boundary, is fresh and
        # still belongs to the old ledger until tick closes that ledger.
        self.sample(user, 55, 55, seconds=2)
        result = self.request("cycle.tick")["data"]["snapshot"]
        current = next(value for value in result["users"] if value["id"] == user)
        self.assertEqual(current["disabled_reasons"], [])
        archived = next(value for value in result["cycles"] if value["status"] == "closed")
        self.assertEqual(archived["report"]["used_upload"], 55)
        self.assertTrue(archived["report"]["complete"])
        self.assertEqual(archived["report"]["allocation_uncertainty_seconds"], 5)
        self.sample(user, 60, 65, seconds=1)
        self.assertEqual((self.public(user)["used_upload"], self.public(user)["used_download"]), (5, 10))

    def test_auto_restore_false_keeps_manual_gate_after_new_cycle(self):
        self.store.now = parse_time("2026-11-24T08:18:58Z")
        user = self.add(quota=100)
        self.request("user.update", {"user_id": user, "auto_restore": False})
        self.sample(user)
        self.request("user.enable", {"user_id": user})
        self.sample(user, 50, 50, seconds=1)
        self.sample(user, 50, 50, seconds=1)
        self.request("cycle.tick")
        self.assertEqual(self.public(user)["disabled_reasons"], ["manual_disabled"])

    def test_missed_many_cycles_closes_only_real_old_ledger(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 20, 30, seconds=1)
        result = self.request("cycle.tick", {"at": "2027-02-25T09:00:00Z"})["data"]
        self.assertEqual(len(result["transitioned"]), 1)
        self.assertEqual(len(result["snapshot"]["cycles"]), 2)
        self.assertEqual(parse_time(result["snapshot"]["quota_cycle"]["start_at"]), parse_time("2027-02-24T08:19:00Z"))
        self.assertEqual(self.public(user)["used_upload"], 0)

    def test_unknown_provider_units_do_not_trigger_false_overallocation(self):
        for index in range(7):
            self.add(str(index), quota=100000000000)
        self.assertFalse(self.request("snapshot")["data"]["totals"]["overallocated"])

    def test_provider_pool_protection_cannot_disable_admin(self):
        member, admin = self.add(), self.add("Admin", role="admin")
        self.request("settings.update", {"admin_reserve_bytes": 100, "safety_margin_bytes": 20})
        self.request("provider.observe", {"instance_id": "4920", "kind": "manual", "evidence": "Confirmed fixture units",
                                           "unit_verified": True, "remaining_bytes": 110, "total_bytes": 500})
        self.assertIn("pool_protection", self.public(member)["disabled_reasons"])
        self.assertNotIn("pool_protection", self.public(admin)["disabled_reasons"])

    def test_new_user_cannot_bypass_existing_pool_protection(self):
        self.request("settings.update", {"admin_reserve_bytes": 100, "safety_margin_bytes": 20})
        self.request("provider.observe", {"instance_id": "4920", "kind": "manual", "evidence": "Confirmed fixture units",
                                           "unit_verified": True, "remaining_bytes": 110, "total_bytes": 500})
        user = self.add()
        self.request("user.enable", {"user_id": user})
        self.sample(user)
        self.assertEqual(self.public(user)["disabled_reasons"], ["pool_protection"])

    def test_changed_reserve_rechecks_existing_authorizations(self):
        user = self.add()
        self.request("provider.observe", {"instance_id": "4920", "kind": "manual", "evidence": "Confirmed fixture units",
                                           "unit_verified": True, "remaining_bytes": 110, "total_bytes": 500})
        self.request("settings.update", {"admin_reserve_bytes": 120})
        self.assertIn("pool_protection", self.public(user)["disabled_reasons"])

    def test_simulated_mail_inbox_requires_expected_revision(self):
        response = handle_request(self.store, {"api_version": 1, "request_id": "inbox-no-rev",
                                               "action": "mail.simulated_inbox", "params": {}})
        self.assertEqual(response["error"]["code"], "VALIDATION")
        result = self.request("mail.simulated_inbox")
        self.assertTrue(result["data"]["sensitive"])
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM requests WHERE request_id=?", (result["request_id"],)).fetchone()[0], 0)

    def test_rollback_preserves_revocation_and_ledger(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=1)
        self.store.conn.execute("INSERT INTO runtime_snapshots VALUES ('last_good',?,?)",
                                (json.dumps([{"user_id": user, "status": "running"}]), timestamp(self.now)))
        self.request("user.revoke", {"user_id": user})
        self.request("rollback.apply", {"target": "last_good"})
        self.assertEqual(self.public(user)["status"], "revoked")
        self.assertEqual(self.public(user)["used_upload"], 10)
        self.assertEqual(self.store.conn.execute("SELECT status FROM runtime_state WHERE user_id=?", (user,)).fetchone()[0], "stopped")

    def test_production_mode_rejects_mutation(self):
        self.store.set_meta("mode", "production")
        result = self.request("user.add", {"name": "A"}, ok=False)
        self.assertEqual(result["error"]["code"], "READ_ONLY")

    def test_unchanged_email_and_other_user_edits_preserve_verification(self):
        user_id = self.add()
        self.request("user.update", {"user_id": user_id, "email": "member@example.test"})
        self.store.conn.execute("UPDATE users SET email_verified=1 WHERE id=?", (user_id,))
        self.request("user.update", {"user_id": user_id, "email": "member@example.test", "name": "Renamed"})
        self.assertTrue(self.public(user_id)["email_verified"])
        self.request("user.update", {"user_id": user_id, "email": None})
        self.assertFalse(self.public(user_id)["email_verified"])

    def test_email_changes_invalidate_verification(self):
        user = self.add()
        self.store.conn.execute("UPDATE users SET email='old@example.com',email_verified=1 WHERE id=?", (user,))
        self.request("user.update", {"user_id": user, "email": "new@example.com"})
        self.assertFalse(self.public(user)["email_verified"])


class PersistenceAndCLITests(unittest.TestCase):
    def test_wal_permissions_and_durable_request_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "state"
            request = {"api_version": 1, "request_id": "durable-add", "action": "user.add",
                       "expected_revision": 1, "params": {"name": "Fixture"}}
            with Store(directory) as store:
                result = handle_request(store, request)
                self.assertTrue(result["ok"], result)
                self.assertEqual(store.conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            with Store(directory) as store:
                repeated = handle_request(store, request)
                self.assertEqual(result, repeated)
                self.assertEqual(store.conn.execute("SELECT count(*) FROM users").fetchone()[0], 1)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual((directory / "state.sqlite3").stat().st_mode & 0o777, 0o600)

    def test_preview_does_not_create_target_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "absent"
            with Store.preview(target) as store:
                result = handle_request(store, {"api_version": 1, "request_id": "preview", "action": "deploy.preview", "params": {}})
                self.assertTrue(result["ok"])
            self.assertFalse(target.exists())

    def test_cli_one_json_request_and_no_stderr_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            request = {"api_version": 1, "request_id": "cli-snapshot", "action": "snapshot", "params": {}}
            result = subprocess.run([sys.executable, "-m", "dazzle", "--state-dir", temporary, "rpc"],
                                    input=json.dumps(request), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertTrue(json.loads(result.stdout)["ok"])
            malformed = subprocess.run([sys.executable, "-m", "dazzle", "--state-dir", temporary, "rpc"],
                                       input="{", capture_output=True, text=True)
            self.assertEqual(malformed.returncode, 1)
            self.assertEqual(json.loads(malformed.stdout)["error"]["code"], "VALIDATION")


if __name__ == "__main__":
    unittest.main()
