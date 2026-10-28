"""Alerts and durable incident evidence use isolated simulation state only."""
import datetime as dt
import json
import re
import tempfile
import unittest
import uuid
from unittest.mock import patch

from dazzle import mail
from dazzle.agent import run_once
from dazzle.domain import eligible, handle_action, snapshot
from dazzle.rpc import handle_request
from dazzle.store import Store, parse_time, timestamp


class AlertsTests(unittest.TestCase):
    def setUp(self):
        self.now = parse_time("2026-11-01T08:19:00Z")
        self.store = Store(memory=True, now=self.now)
        self.addCleanup(lambda: self.store.close())

    def call(self, action, params=None, *, at=None, ok=True):
        now = at or self.now
        self.store.now = now
        result = handle_request(self.store, {
            "api_version": 1, "request_id": str(uuid.uuid4()), "action": action,
            "expected_revision": self.store.revision, "params": params or {},
        }, now=now)
        if ok:
            self.assertTrue(result["ok"], result)
        return result

    def add(self, role="member", quota=1000):
        params = {"name": "Test " + role, "role": role}
        if role != "admin":
            params["quota_bytes"] = quota
        return self.call("user.add", params)["data"]["user"]["id"]

    def configure(self):
        self.call("mail.configure", {"host": "smtp.example.com", "port": 465, "security": "ssl",
                                     "username": "mailer", "sender": "sender@example.com",
                                     "admin_email": "admin@example.com"})

    def verify(self, user_id=None):
        params = {} if user_id is None else {"user_id": user_id}
        sent = self.call("mail.verify.send", params)["data"]
        message = next(row for row in mail.simulated_mailbox_for_tests(self.store)
                       if row["outbox_id"] == sent["id"])
        code = re.search(r"[0-9]{6}", message["body"]).group()
        self.assertTrue(self.call("mail.verify.confirm", {**params, "code": code})["data"]["verified"])

    def ready_admin(self):
        self.configure()
        self.verify()

    def messages(self, kind):
        return [dict(row) for row in self.store.conn.execute(
            "SELECT * FROM mail_outbox WHERE kind=? ORDER BY rowid", (kind,))]

    def incidents(self, user_id):
        return [dict(row) for row in self.store.conn.execute(
            "SELECT * FROM metering_incidents WHERE user_id=? ORDER BY rowid", (user_id,))]

    def sample(self, user_id, up=0, down=0, *, seconds=0, epoch="test-epoch"):
        at = self.now + dt.timedelta(seconds=seconds)
        return self.call("meter.sample", {"user_id": user_id, "epoch": epoch, "uplink": up,
                                          "downlink": down, "at": timestamp(at)}, at=at)

    def provider_expected(self, expected, **extra):
        provider = self.store.get_meta("provider")
        provider.update({"observed_at": timestamp(self.now), "source": "administrator_panel_confirmation",
                         "evidence": "Administrator verified reset timestamp in provider panel",
                         "sync_state": "manual_confirmed", "expected_reset_at": timestamp(expected), **extra})
        self.store.set_meta("provider", provider)

    def test_bootstrap_gate_does_not_consume_failure_alert(self):
        self.ready_admin()
        user = self.add()
        self.call("user.enable", {"user_id": user})
        self.assertEqual(self.messages("metering_failure"), [])
        self.sample(user)
        self.call("cycle.tick", at=self.now + dt.timedelta(seconds=6))
        self.assertEqual(len(self.messages("metering_failure")), 1)

    def test_meter_failure_notifies_verified_admin_once_per_episode(self):
        self.ready_admin()
        user = self.add()
        self.sample(user)
        self.call("user.enable", {"user_id": user})
        for seconds in (6, 7, 3607):
            self.call("cycle.tick", at=self.now + dt.timedelta(seconds=seconds))
        messages = self.messages("metering_failure")
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["recipient"], "admin@example.com")
        self.assertIn("本地模拟", messages[0]["body"])
        self.assertEqual(len(self.incidents(user)), 1)

    def test_new_failure_after_reconciliation_has_new_event_identity(self):
        self.ready_admin()
        self.call("mail.preferences", {"cooldown_seconds": 0})
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=6)
        self.sample(user, 11, 21, seconds=7)
        self.call("meter.reconcile", {"user_id": user, "evidence": "First gap reviewed"},
                  at=self.now + dt.timedelta(seconds=7))
        self.sample(user, 20, 30, seconds=13)
        self.assertEqual(len(self.messages("metering_failure")), 2)

    def test_admin_meter_failure_alert_preserves_admin_access(self):
        self.ready_admin()
        admin = self.add("admin")
        self.call("user.enable", {"user_id": admin})
        self.call("meter.failure", {"user_id": admin}, at=self.now + dt.timedelta(seconds=6))
        self.assertTrue(eligible(self.store.get_user(admin), self.now + dt.timedelta(seconds=6)))
        message = self.messages("metering_failure")[0]
        self.assertIn("管理员访问继续保留", message["body"])
        self.assertEqual(message["user_id"], None)

    def test_unverified_admin_skips_failure_alert(self):
        self.configure()
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=6)
        self.assertEqual(self.messages("metering_failure"), [])

    def test_user_verification_does_not_verify_admin_recipient(self):
        self.configure()
        user = self.add()
        self.call("user.update", {"user_id": user, "email": "member@example.com"})
        self.verify(user)
        self.sample(user)
        self.sample(user, 10, 20, seconds=6)
        self.assertEqual(self.messages("metering_failure"), [])

    def test_pool_protection_alert_is_aggregate_and_exempts_admin(self):
        self.ready_admin()
        admin = self.add("admin")
        member = self.add()
        self.call("user.enable", {"user_id": admin})
        self.call("settings.update", {"admin_reserve_bytes": 100, "safety_margin_bytes": 10})
        self.call("provider.observe", {"instance_id": self.store.get_meta("provider")["instance_id"],
                                       "evidence": "Panel byte units confirmed", "unit_verified": True,
                                       "total_bytes": 1000, "remaining_bytes": 100})
        self.add()
        self.call("cycle.tick")
        self.assertEqual(len(self.messages("pool_protection")), 1)
        self.assertIn("pool_protection", json.loads(self.store.get_user(member)["reasons_json"]))
        self.assertTrue(eligible(self.store.get_user(admin), self.now))

    def test_stale_provider_high_balance_cannot_clear_existing_pool_protection(self):
        admin = self.add("admin")
        user = self.add()
        self.call("user.enable", {"user_id": admin})
        self.call("settings.update", {"admin_reserve_bytes": 100, "safety_margin_bytes": 10})
        self.call("provider.observe", {"instance_id": self.store.get_meta("provider")["instance_id"],
                                       "evidence": "Verified low balance in provider panel", "unit_verified": True,
                                       "total_bytes": 1000, "remaining_bytes": 100})
        provider = self.store.get_meta("provider")
        provider["remaining_bytes"] = 900
        self.store.set_meta("provider", provider)
        later = self.now + dt.timedelta(seconds=3601)
        self.call("cycle.tick", at=later)
        state = snapshot(self.store, later)
        self.assertEqual(state["totals"]["protection_state"], "stale")
        self.assertEqual(state["provider_freshness"]["state"], "stale")
        self.assertIn("pool_protection", json.loads(self.store.get_user(user)["reasons_json"]))
        self.assertTrue(eligible(self.store.get_user(admin), later))
        self.assertTrue(any("observation is missing or older" in warning for warning in state["health"]["warnings"]))
        self.call("provider.observe", {"instance_id": provider["instance_id"],
                                       "evidence": "Fresh high balance confirmed in provider panel", "unit_verified": True,
                                       "total_bytes": 1000, "remaining_bytes": 900}, at=later)
        self.assertNotIn("pool_protection", json.loads(self.store.get_user(user)["reasons_json"]))

    def test_missing_provider_observation_is_not_reported_ready(self):
        provider = self.store.get_meta("provider")
        provider.update({"unit_verified": True, "total_bytes": 1000, "remaining_bytes": 900})
        self.store.set_meta("provider", provider)
        state = snapshot(self.store, self.now)
        self.assertEqual(state["totals"]["protection_state"], "stale")
        self.assertIsNone(state["provider_freshness"]["age_seconds"])

    def test_only_failed_stop_tasks_emit_pause_failed_alerts(self):
        self.ready_admin()
        user = self.add()
        for verb, status in (("stop", "failed"), ("start", "failed"), ("rotate", "failed"), ("stop", "applied")):
            self.store.conn.execute("INSERT INTO runtime_queue VALUES (?,?,?,?,?,?,?,?)",
                                    (str(uuid.uuid4()), user, verb, status, "fixture", timestamp(self.now),
                                     timestamp(self.now), "Fixture only"))
        self.call("cycle.tick")
        self.call("cycle.tick", at=self.now + dt.timedelta(hours=2))
        messages = self.messages("runtime_pause_failed")
        self.assertEqual(len(messages), 1)
        self.assertIn("尚未确认此账户的连接已经停止", messages[0]["body"])

    def test_failed_stop_alert_is_not_repeated_when_quota_cycle_changes(self):
        self.ready_admin()
        self.store.conn.execute("INSERT INTO runtime_queue VALUES (?,?,?,?,?,?,NULL,NULL)",
                                ("fixture-failed-stop", "missing-user", "stop", "failed", "fixture", timestamp(self.now)))
        self.call("cycle.tick")
        self.call("cycle.tick", at=parse_time("2026-12-01T08:19:00Z"))
        self.assertEqual(len(self.messages("runtime_pause_failed")), 1)

    def test_quota_warning_uses_requested_simulated_suspension_wording(self):
        self.configure()
        user = self.add(quota=100)
        self.call("user.update", {"user_id": user, "email": "member@example.com"})
        self.verify(user)
        self.sample(user)
        self.sample(user, 100, 0, seconds=1)
        body = self.messages("quota_exceeded")[0]["body"]
        self.assertIn("已请求暂停", body)
        self.assertIn("未执行线上停用操作", body)

    def test_quota_upcoming_within_24_hours_is_deduplicated(self):
        self.ready_admin()
        for at in ("2026-11-23T08:19:00Z", "2026-11-23T10:19:00Z", "2026-11-24T08:18:59Z"):
            self.call("cycle.tick", at=parse_time(at))
        messages = self.messages("quota_cycle_upcoming")
        self.assertEqual(len(messages), 1)
        self.assertIn("不代表服务商流量即将重置", messages[0]["body"])

    def test_quota_upcoming_is_absent_outside_24_hours(self):
        self.ready_admin()
        self.call("cycle.tick", at=parse_time("2026-11-23T08:18:59Z"))
        self.assertEqual(self.messages("quota_cycle_upcoming"), [])

    def test_provider_upcoming_is_distinct_from_quota_schedule(self):
        self.ready_admin()
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=1)
        before = snapshot(self.store, self.now)["quota_cycle"]["id"]
        self.provider_expected(self.now + dt.timedelta(hours=23))
        self.call("cycle.tick")
        self.call("cycle.tick", at=self.now + dt.timedelta(hours=1))
        self.assertEqual(len(self.messages("provider_cycle_upcoming")), 1)
        self.assertEqual(self.messages("quota_cycle_upcoming"), [])
        self.assertEqual(snapshot(self.store, self.now)["quota_cycle"]["id"], before)
        self.assertEqual(self.store.get_user(user)["used_upload"], 10)

    def test_expected_timestamp_needs_current_verified_evidence(self):
        self.ready_admin()
        expected = self.now + dt.timedelta(hours=2)
        for overrides in ({"source": "historical_manual_snapshot"}, {"observed_at": None},
                          {"sync_state": "unverified"}, {"evidence": None},
                          {"observed_at": timestamp(self.now + dt.timedelta(days=1))}):
            self.provider_expected(expected, **overrides)
            self.call("cycle.tick")
        self.assertEqual(self.messages("provider_cycle_upcoming"), [])

    def test_default_unavailable_provider_does_not_spam_daily_alerts(self):
        self.ready_admin()
        for days in (0, 1, 2):
            self.call("cycle.tick", at=self.now + dt.timedelta(days=days))
        self.assertFalse(self.store.get_meta("provider")["automatic_available"])
        for kind in ("provider_cycle_upcoming", "provider_reset_waiting", "provider_warning"):
            self.assertEqual(self.messages(kind), [])

    def test_overdue_provider_waits_without_resetting_usage_or_cycle(self):
        self.ready_admin()
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=1)
        self.call("user.topup", {"user_id": user, "bytes": 200})
        before = snapshot(self.store, self.now)["quota_cycle"]["id"]
        self.provider_expected(self.now - dt.timedelta(hours=1))
        for days in (0, 1, 2):
            self.call("cycle.tick", at=self.now + dt.timedelta(days=days))
        self.assertEqual(len(self.messages("provider_reset_waiting")), 1)
        self.assertEqual(self.messages("provider_cycle_upcoming"), [])
        self.assertEqual(snapshot(self.store, self.now)["quota_cycle"]["id"], before)
        user = self.store.get_user(user)
        self.assertEqual((user["used_upload"], user["used_download"], user["topup_bytes"]), (10, 20, 200))
        self.assertIsNone(self.store.get_meta("provider")["last_actual_reset_at"])

    def test_actual_provider_confirmation_suppresses_waiting(self):
        self.ready_admin()
        expected = self.now - dt.timedelta(hours=1)
        self.provider_expected(expected, last_actual_reset_at=timestamp(expected))
        self.call("cycle.tick")
        self.assertEqual(self.messages("provider_reset_waiting"), [])

    def test_provider_upcoming_then_overdue_are_separate_events(self):
        self.ready_admin()
        self.provider_expected(self.now + dt.timedelta(hours=1))
        self.call("cycle.tick")
        self.call("cycle.tick", at=self.now + dt.timedelta(hours=1))
        self.call("cycle.tick", at=self.now + dt.timedelta(hours=3))
        self.assertEqual(len(self.messages("provider_cycle_upcoming")), 1)
        self.assertEqual(len(self.messages("provider_reset_waiting")), 1)

    def test_notifications_disabled_prevents_health_alerts(self):
        self.ready_admin()
        self.call("mail.preferences", {"enabled": False})
        self.provider_expected(self.now - dt.timedelta(hours=1))
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=6)
        self.call("cycle.tick")
        self.assertEqual(self.messages("metering_failure"), [])
        self.assertEqual(self.messages("provider_reset_waiting"), [])

    def test_agent_tick_sends_simulated_alert_without_rpc_snapshot_cache_or_smtp(self):
        self.ready_admin()
        user = self.add()
        self.sample(user)
        self.call("user.enable", {"user_id": user})
        requests_before = self.store.conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        with patch.object(mail.smtplib, "SMTP") as smtp, patch.object(mail.smtplib, "SMTP_SSL") as smtp_ssl:
            run_once(self.store, self.now + dt.timedelta(seconds=6))
            smtp.assert_not_called()
            smtp_ssl.assert_not_called()
        self.assertEqual(len(self.messages("metering_failure")), 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0], requests_before)

    def test_gap_records_known_unallocated_delta_without_booking_it(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=1)
        self.sample(user, 40, 70, seconds=7)
        self.sample(user, 40, 70, seconds=7)
        incidents = self.incidents(user)
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident["kind"], "sample_gap")
        self.assertEqual((incident["previous_uplink"], incident["sample_uplink"]), (10, 40))
        self.assertEqual((incident["unallocated_upload"], incident["unallocated_download"]), (30, 50))
        self.assertEqual(incident["delta_unknown"], 0)
        self.assertEqual((self.store.get_user(user)["used_upload"], self.store.get_user(user)["used_download"]), (10, 20))
        self.assertIsNone(incident["resolved_at"])

    def test_epoch_change_keeps_unknown_delta_null_instead_of_zero(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 50, 60, seconds=1)
        self.sample(user, 0, 0, seconds=2, epoch="new-epoch")
        incident = self.incidents(user)[0]
        self.assertEqual(incident["kind"], "worker_epoch_changed")
        self.assertEqual((incident["previous_epoch"], incident["sample_epoch"]), ("test-epoch", "new-epoch"))
        self.assertEqual(incident["delta_unknown"], 1)
        self.assertIsNone(incident["unallocated_upload"])
        self.assertIsNone(incident["unallocated_download"])

    def test_regression_is_audited_without_negative_delta(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 50, 60, seconds=1)
        self.sample(user, 10, 20, seconds=2)
        incident = self.incidents(user)[0]
        self.assertEqual(incident["kind"], "counter_regression")
        self.assertEqual(incident["delta_unknown"], 1)
        self.assertIsNone(incident["unallocated_upload"])
        self.assertEqual(self.store.get_user(user)["used_upload"], 50)

    def test_reconcile_persists_evidence_actor_and_unallocated_gap(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=6)
        self.sample(user, 11, 22, seconds=7)
        self.call("meter.reconcile", {"user_id": user, "evidence": "Compared worker counters with preserved ledger"},
                  at=self.now + dt.timedelta(seconds=7))
        incident = self.incidents(user)[0]
        self.assertEqual(incident["resolved_at"], timestamp(self.now + dt.timedelta(seconds=7)))
        self.assertEqual(incident["operator"], "local_simulation_administrator")
        self.assertEqual(incident["evidence"], "Compared worker counters with preserved ledger")
        self.assertEqual(incident["resolution"], "acknowledged_unallocated_gap")
        self.assertEqual((incident["unallocated_upload"], incident["unallocated_download"]), (10, 20))
        self.assertEqual((self.store.get_user(user)["used_upload"], self.store.get_user(user)["used_download"]), (1, 2))

    def test_reconcile_failure_does_not_resolve_incident(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=6)
        result = self.call("meter.reconcile", {"user_id": user, "evidence": "Attempted without fresh trusted sample"},
                           at=self.now + dt.timedelta(seconds=6), ok=False)
        self.assertFalse(result["ok"])
        self.assertIsNone(self.incidents(user)[0]["resolved_at"])

    def test_incident_snapshot_redacts_credentials_in_reconciliation_note(self):
        user = self.add()
        self.sample(user)
        self.sample(user, 10, 20, seconds=6)
        self.sample(user, 11, 21, seconds=7)
        credentials = self.store.get_credentials(user)
        self.call("meter.reconcile", {"user_id": user,
                                      "evidence": "Reviewed vless://fake-sensitive-link token=fake-sensitive-token "
                                                  + credentials["vless_uuid"] + " " + credentials["subscription_token"]},
                  at=self.now + dt.timedelta(seconds=7))
        public = json.dumps(snapshot(self.store, self.now + dt.timedelta(seconds=7)))
        self.assertIn("metering_incidents", public)
        self.assertNotIn("fake-sensitive", public)
        for key in ("vless_uuid", "tuic_password", "subscription_token"):
            self.assertNotIn(self.store.get_credentials(user)[key], public)

    def test_incident_and_reconciliation_survive_sqlite_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            self.store.close()
            self.store = Store(directory, now=self.now)
            user = self.add()
            self.sample(user)
            self.sample(user, 50, 60, seconds=1)
            self.sample(user, 0, 0, seconds=2, epoch="new-epoch")
            identifier = self.incidents(user)[0]["id"]
            self.store.close()
            self.store = Store(directory, now=self.now + dt.timedelta(seconds=3))
            self.assertEqual(self.incidents(user)[0]["id"], identifier)
            self.sample(user, 2, 3, seconds=3, epoch="new-epoch")
            self.call("meter.reconcile", {"user_id": user, "evidence": "Restarted and reviewed original gap"},
                      at=self.now + dt.timedelta(seconds=3))
            self.store.close()
            self.store = Store(directory, now=self.now + dt.timedelta(seconds=4))
            incident = self.incidents(user)[0]
            self.assertEqual(incident["id"], identifier)
            self.assertEqual(incident["evidence"], "Restarted and reviewed original gap")
            self.assertEqual(incident["delta_unknown"], 1)
            self.assertIsNotNone(incident["resolved_at"])


if __name__ == "__main__":
    unittest.main()
