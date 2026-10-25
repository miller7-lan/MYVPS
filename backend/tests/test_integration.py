"""Cross-module checks against private temporary databases, never a VPS."""
from datetime import timedelta
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import uuid

from dazzle.rendering import subscription_response
from dazzle.rpc import handle_request
from dazzle.store import Store, parse_time, timestamp


class LocalIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "state"
        self.now = parse_time("2026-11-24T08:18:56Z")
        self.store = Store(self.directory, now=self.now)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def reopen(self):
        self.store.close()
        self.store = Store(self.directory, now=self.now)

    def request(self, action, params=None, *, now=None, ok=True, request_id=None):
        if now is not None:
            self.now = parse_time(now)
            self.store.now = self.now
        response = handle_request(self.store, {
            "api_version": 1, "request_id": request_id or str(uuid.uuid4()), "action": action,
            "expected_revision": self.store.revision, "params": params or {},
        }, now=self.now)
        if ok:
            self.assertTrue(response["ok"], response["error"])
        return response

    def snapshot(self):
        return self.request("snapshot")["data"]

    def user(self, user_id):
        return next(user for user in self.snapshot()["users"] if user["id"] == user_id)

    def add(self, name="Member", role="member", quota=1000):
        params = {"name": name, "role": role}
        if role == "member":
            params["quota_bytes"] = quota
        result = self.request("user.add", params)
        return next(user["id"] for user in result["data"]["snapshot"]["users"] if user["name"] == name)

    def sample(self, user_id, upload=0, download=0, *, seconds=0, epoch="worker-epoch"):
        self.now += timedelta(seconds=seconds)
        self.store.now = self.now
        return self.request("meter.sample", {"user_id": user_id, "epoch": epoch, "uplink": upload,
                            "downlink": download, "at": timestamp(self.now)})

    def activate(self, user_id):
        self.sample(user_id)
        self.request("user.enable", {"user_id": user_id})

    def observe(self, kind, **values):
        params = {"instance_id": "4920", "kind": kind,
                  "evidence": "Isolated fixture; explicit provider panel evidence"}
        params.update(values)
        return self.request("provider.observe", params)

    def run_agent(self, at):
        backend = str(Path(__file__).resolve().parents[1])
        env = dict(os.environ)
        env["PYTHONPATH"] = backend + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        return subprocess.run([sys.executable, "-m", "dazzle.agent", "--state-dir", str(self.directory),
                               "--once", "--at", at], capture_output=True, text=True, timeout=15, env=env)

    def test_provider_gift_renewal_upgrade_paid_reset_preserve_schedule_and_ledger_on_disk(self):
        user_id = self.add()
        self.sample(user_id)
        self.sample(user_id, 150, 200, seconds=1)
        self.request("user.topup", {"user_id": user_id, "bytes": 50})
        old_cycle = self.snapshot()["quota_cycle"]
        for kind in ("manual", "gift", "renewal", "upgrade", "paid_reset"):
            with self.subTest(kind=kind):
                self.observe(kind, remaining_display="500GB", expected_reset_date="2026-12-24")
                self.assertEqual(self.snapshot()["quota_cycle"], old_cycle)
                self.assertEqual(self.user(user_id)["used_upload"], 150)
                self.assertEqual(self.user(user_id)["topup_bytes"], 50)
        self.reopen()
        self.assertEqual(self.user(user_id)["used_download"], 200)
        self.assertEqual(self.snapshot()["quota_cycle"], old_cycle)
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM ledger").fetchone()[0], 1)

    def test_confirmed_provider_reset_deduplicates_after_restart_without_allocating_quota(self):
        user_id = self.add()
        self.sample(user_id)
        self.sample(user_id, 70, 90, seconds=1)
        old_cycle = self.snapshot()["quota_cycle"]
        values = {"external_cycle_id": "provider-fixture-001", "last_actual_reset_at": timestamp(self.now),
                  "unit_verified": True, "total_bytes": 500_000_000_000, "remaining_bytes": 500_000_000_000}
        self.observe("reset_confirmed", **values)
        self.reopen()
        self.assertTrue(self.observe("reset_confirmed", **values)["data"]["duplicate"])
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM provider_history").fetchone()[0], 1)
        self.assertEqual(self.snapshot()["quota_cycle"], old_cycle)
        self.assertEqual(self.user(user_id)["used_upload"], 70)

    def test_new_raw_only_observation_invalidates_old_normalized_provider_amount(self):
        user_id = self.add()
        self.sample(user_id)
        self.sample(user_id, 60, 40, seconds=1)
        self.observe("manual", unit_verified=True, total_bytes=10000, remaining_bytes=9000)
        self.observe("gift", remaining_display="12.5G")
        self.reopen()
        provider = self.snapshot()["provider"]
        self.assertIsNone(provider["remaining_bytes"])
        self.assertIsNone(provider["total_bytes"])
        self.assertFalse(provider["unit_verified"])
        self.assertEqual(self.user(user_id)["used_upload"], 60)

    def test_rejected_provider_observation_is_atomic(self):
        user_id = self.add()
        self.sample(user_id)
        before = self.snapshot()
        revision = self.store.revision
        response = self.request("provider.observe", {"instance_id": "not-4920", "kind": "renewal",
                                "evidence": "Invalid isolated identity", "remaining_display": "999G"}, ok=False)
        self.assertEqual(response["error"]["code"], "VALIDATION")
        self.assertEqual(self.store.revision, revision)
        self.assertEqual(self.snapshot()["provider"], before["provider"])
        self.assertEqual(self.snapshot()["quota_cycle"], before["quota_cycle"])

    def test_provider_pool_guard_never_restricts_administrator_or_clears_manual_disable(self):
        member, admin = self.add(), self.add("Admin", "admin")
        self.activate(member)
        self.request("user.enable", {"user_id": admin})
        self.request("settings.update", {"admin_reserve_bytes": 100, "safety_margin_bytes": 50})
        self.observe("manual", unit_verified=True, total_bytes=10000, remaining_bytes=100)
        self.assertIn("pool_protection", self.user(member)["disabled_reasons"])
        self.assertEqual(self.user(admin)["disabled_reasons"], [])
        self.request("user.disable", {"user_id": member})
        self.observe("gift", unit_verified=True, total_bytes=10000, remaining_bytes=5000)
        self.assertNotIn("pool_protection", self.user(member)["disabled_reasons"])
        self.assertIn("manual_disabled", self.user(member)["disabled_reasons"])

    def test_delayed_start_is_rechecked_after_revoke_and_restart(self):
        user_id = self.add()
        self.activate(user_id)
        self.assertGreater(self.store.conn.execute("SELECT count(*) FROM runtime_queue WHERE verb='start' AND status='pending'").fetchone()[0], 0)
        self.request("user.revoke", {"user_id": user_id})
        self.reopen()
        self.request("runtime.process")
        state = self.store.conn.execute("SELECT status FROM runtime_state WHERE user_id=?", (user_id,)).fetchone()[0]
        self.assertEqual(state, "stopped")
        self.assertEqual(self.user(user_id)["status"], "revoked")
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM credentials WHERE user_id=?", (user_id,)).fetchone()[0], 0)

    def test_delayed_start_and_rotation_do_not_bypass_manual_disable(self):
        user_id = self.add()
        self.activate(user_id)
        self.request("user.rotate", {"user_id": user_id})
        self.request("user.disable", {"user_id": user_id})
        self.reopen()
        self.request("runtime.process")
        state = self.store.conn.execute("SELECT status,runtime_version FROM runtime_state WHERE user_id=?", (user_id,)).fetchone()
        self.assertEqual(state["status"], "stopped")
        self.assertEqual(state["runtime_version"], 2)

    def test_delayed_start_fails_closed_when_sample_becomes_stale(self):
        user_id = self.add()
        self.activate(user_id)
        self.now += timedelta(seconds=6)
        self.request("runtime.process", now=self.now)
        self.assertEqual(self.store.conn.execute("SELECT status FROM runtime_state WHERE user_id=?", (user_id,)).fetchone()[0], "stopped")
        self.assertIn("metering_failure", self.user(user_id)["disabled_reasons"])

    def test_rotation_invalidates_old_subscription_token_across_restart(self):
        user_id = self.add()
        self.activate(user_id)
        old = self.store.get_credentials(user_id)["subscription_token"]
        self.assertEqual(subscription_response(self.store, old, "uris")["status"], 200)
        self.request("user.rotate", {"user_id": user_id})
        fresh = self.store.get_credentials(user_id)["subscription_token"]
        self.reopen()
        self.assertEqual(subscription_response(self.store, old, "uris")["status"], 404)
        response = subscription_response(self.store, fresh, "uris")
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")

    def test_disabled_subscription_is_denied_but_explicit_export_allows_preparation(self):
        user_id = self.add()
        token = self.store.get_credentials(user_id)["subscription_token"]
        self.assertEqual(subscription_response(self.store, token, "uris")["status"], 403)
        exported = self.request("user.export", {"user_id": user_id, "format": "uris"})
        self.assertTrue(exported["data"]["sensitive"])
        self.assertIsNone(exported["data"]["subscription_url"])
        self.assertIn("192.0.2.10", exported["data"]["content"])

    def test_subscription_headers_describe_personal_quota_not_provider_remaining(self):
        first, second = self.add("First", quota=1000), self.add("Second", quota=2000)
        self.activate(first)
        self.activate(second)
        self.sample(first, 30, 40, seconds=1)
        self.observe("manual", remaining_display="493.36GB")
        first_token = self.store.get_credentials(first)["subscription_token"]
        second_token = self.store.get_credentials(second)["subscription_token"]
        one = subscription_response(self.store, first_token, "mihomo")
        two = subscription_response(self.store, second_token, "mihomo")
        self.assertEqual(one["headers"]["Subscription-Userinfo"], "upload=30; download=40; total=1000")
        self.assertEqual(two["headers"]["Subscription-Userinfo"], "upload=0; download=0; total=2000")
        self.assertNotIn(self.store.get_credentials(second)["vless_uuid"], one["body"])

    def test_revocation_invalidates_subscription_and_export_after_restart(self):
        user_id = self.add()
        self.activate(user_id)
        token = self.store.get_credentials(user_id)["subscription_token"]
        self.request("user.revoke", {"user_id": user_id})
        self.reopen()
        self.assertEqual(subscription_response(self.store, token, "uris")["status"], 404)
        rejected = self.request("user.export", {"user_id": user_id, "format": "uris"}, ok=False)
        self.assertEqual(rejected["error"]["code"], "REVOKED")

    def test_agent_once_crosses_cycle_without_app_or_provider_mutation(self):
        user_id = self.add()
        self.sample(user_id)
        self.sample(user_id, 120, 230, seconds=1)
        self.request("user.topup", {"user_id": user_id, "bytes": 50})
        provider = self.snapshot()["provider"]
        self.store.close()
        child = self.run_agent("2026-11-24T08:19:00Z")
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stderr, "")
        summary = json.loads(child.stdout)
        self.assertFalse(summary["production_changed"])
        self.assertEqual(set(summary["tasks"]), {"cycle.tick", "runtime.process", "mail.process"})
        self.now = parse_time("2026-11-24T08:19:00Z")
        self.store = Store(self.directory, now=self.now)
        self.assertEqual(self.snapshot()["provider"], provider)
        self.assertEqual((self.user(user_id)["used_upload"], self.user(user_id)["topup_bytes"]), (0, 0))
        closed = next(cycle for cycle in self.snapshot()["cycles"] if cycle["status"] == "closed")
        self.assertEqual(closed["report"]["used_upload"], 120)
        self.assertEqual(closed["report"]["used_download"], 230)
        self.assertIn("manual_disabled", self.user(user_id)["disabled_reasons"])

    def test_agent_restart_same_boundary_never_archives_or_grants_twice(self):
        self.add()
        self.store.close()
        first = self.run_agent("2026-11-24T08:19:00Z")
        second = self.run_agent("2026-11-24T08:19:00Z")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.now = parse_time("2026-11-24T08:19:00Z")
        self.store = Store(self.directory, now=self.now)
        cycles = self.snapshot()["cycles"]
        self.assertEqual(sum(cycle["status"] == "closed" for cycle in cycles), 1)
        self.assertEqual(sum(cycle["status"] == "active" for cycle in cycles), 1)
        self.assertEqual(self.snapshot()["quota_cycle"]["source"], "administrator_schedule")

    def test_agent_refuses_non_simulation_state(self):
        self.add()
        self.store.set_meta("mode", "production")
        self.store.close()
        child = self.run_agent("2026-11-24T08:19:00Z")
        self.assertNotEqual(child.returncode, 0)
        self.assertEqual(child.stdout, "")
        self.store = Store(self.directory, now=self.now)
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM cycles WHERE status='closed'").fetchone()[0], 0)

    def test_simulated_inbox_sensitive_response_is_never_durably_cached(self):
        self.request("mail.configure", {"host": "smtp.example.com", "port": 465, "security": "ssl",
                     "username": "fixture", "sender": "sender@example.com", "admin_email": "admin@example.com"})
        self.request("mail.verify.send")
        inbox = self.request("mail.simulated_inbox", request_id="sensitive-local-inbox")
        self.assertTrue(inbox["data"]["sensitive"])
        code = re.search(r"[0-9]{6}", inbox["data"]["messages"][0]["body"]).group()
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM requests WHERE request_id='sensitive-local-inbox'").fetchone()[0], 0)
        self.assertNotIn(code, json.dumps(self.snapshot()))
        self.reopen()
        verified = self.request("mail.verify.confirm", {"code": code})
        self.assertTrue(verified["data"]["verified"])


if __name__ == "__main__":
    unittest.main()
