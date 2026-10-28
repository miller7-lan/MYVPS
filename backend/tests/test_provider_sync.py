"""Automatic QQG sync: private key storage, observation intake, alerts and the budget cap."""
import datetime as dt
import json
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from dazzle import budget, provider_sync, qqg
from dazzle.production import handle_request
from dazzle.production_state import CORE_SHA256, ProductionStore
from dazzle.store import Store, parse_time, timestamp
from test_authorization_fixtures import confirm_test_budget, seed_legacy_user

GB = budget.GB
USER = "owner@example.com"
TOKEN = "T0kenValue1234567890abcdefABCDEF"


def card(used_gib, total_gib=500, reset="2026-11-24", host=4920):
    return qqg.parse_flow({"total": f"{total_gib}GB", "used": f"{used_gib:.2f}GB",
                           "leave": f"{total_gib - used_gib:.2f}GB", "reset_flow_date": reset}, host)


class FakeClient:
    def __init__(self, items):
        self.items = list(items)
        self.reads = 0

    def read_flow(self):
        self.reads += 1
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class ProviderSyncTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.now = parse_time("2026-11-01T08:19:00Z")
        admin, member, spare = (str(uuid.uuid4()) for _ in range(3))
        workers = {admin: {"role": "admin", "public_port": 24430, "api_port": 34430},
                   member: {"role": "member", "public_port": 24431, "api_port": 34431},
                   spare: {"role": "member", "public_port": 24432, "api_port": 34432}}
        self.policy = {"version": 2, "server_id": str(uuid.uuid4()), "server_endpoint": "8.8.8.8", "portal_uid": 994,
                       "agent_uid": 995, "core_sha256": CORE_SHA256, "workers": workers}
        self.store = ProductionStore(self.folder.name, policy=self.policy, initialize=True, now=self.now)
        self.addCleanup(self.store.close)
        self.admin = seed_legacy_user(self.store, {"role": "admin", "name": "Administrator"}, self.now)
        self.member = seed_legacy_user(self.store, {"role": "member", "quota_bytes": 100 * GB}, self.now)
        confirm_test_budget(self.store, self.now)
        self.notices = []
        notify = patch("dazzle.provider_sync._notify",
                       side_effect=lambda store, kind, key, now, detail: self.notices.append((kind, key)))
        notify.start()
        self.addCleanup(notify.stop)
        self.client = FakeClient([])
        self.cache = provider_sync.SyncCache(lambda creds: self.client)

    def call(self, action, params=None, *, ok=True):
        self.store.now = self.now
        result = handle_request(self.store, {"api_version": 1, "request_id": str(uuid.uuid4()), "action": action,
                                             "expected_revision": self.store.revision, "server_id": self.store.server_id,
                                             "params": params or {}}, self.now)
        if ok:
            self.assertTrue(result["ok"], result)
        return result

    def configure(self, **params):
        return self.call("provider.configure", {"enabled": True, "username": USER, "token": TOKEN, **params})

    def sync(self, *items, after=None):
        if items:
            self.client.items.extend(items)
        if after is not None:
            self.now += after
        self.store.now = self.now
        return provider_sync.sync_once(self.store, self.cache, now=self.now)

    def use(self, payload):
        self.store.conn.execute("UPDATE users SET used_download=used_download+? WHERE id=?", (payload, self.member["id"]))

    def test_the_key_is_stored_privately_and_never_echoed(self):
        before = self.store.conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        response = self.configure()
        sync = response["data"]["provider_sync"]
        self.assertEqual((sync["enabled"], sync["credential_configured"], sync["username_hint"], sync["state"],
                          sync["api_host"], sync["host_id"], sync["interval_seconds"]),
                         (True, True, "ow***@example.com", "waiting", "www.qqg.net", 4920, 600))
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0], before)
        self.assertEqual(self.store.conn.execute("SELECT username,token FROM provider_api_secret").fetchone()[:], (USER, TOKEN))
        for text in (json.dumps(response, ensure_ascii=False), json.dumps(self.call("snapshot")["data"], ensure_ascii=False),
                     json.dumps([dict(row) for row in self.store.conn.execute("SELECT * FROM operations")], ensure_ascii=False)):
            self.assertNotIn(TOKEN, text)
            self.assertNotIn(USER, text)

    def test_configuration_is_validated(self):
        cases = [({"enabled": True}, "VALIDATION"),
                 ({"enabled": False, "host_id": 1234}, "VALIDATION"),
                 ({"enabled": False, "interval_seconds": 60}, "VALIDATION"),
                 ({"enabled": False, "username": USER}, "VALIDATION"),
                 ({"enabled": False, "api_url": "https://evil.example"}, "VALIDATION"),
                 ({"enabled": True, "username": "not a login", "token": TOKEN}, "VALIDATION"),
                 ({"enabled": True, "username": USER, "token": "short"}, "VALIDATION"),
                 ({"enabled": True, "surprise": 1}, "VALIDATION")]
        for params, code in cases:
            with self.subTest(params=params):
                result = self.call("provider.configure", params, ok=False)
                self.assertEqual(result["error"]["code"], code)
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM provider_api_secret").fetchone())

    def test_a_new_site_or_instance_drops_the_stored_key(self):
        self.configure()
        result = self.call("provider.configure", {"enabled": False, "api_url": "https://my.qqg.net"})
        self.assertFalse(result["data"]["provider_sync"]["credential_configured"])
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM provider_api_secret").fetchone())
        self.configure(api_url="https://my.qqg.net")
        result = self.call("provider.configure", {"username": None, "token": None, "enabled": False})
        self.assertEqual(result["data"]["provider_sync"]["state"], "not_configured")

    def test_a_reading_becomes_the_verified_fresh_provider_record(self):
        self.configure()
        self.sync(card(6.64))
        provider = self.store.get_meta("provider")
        self.assertEqual((provider["source"], provider["sync_state"], provider["unit_verified"], provider["automatic_available"]),
                         ("qqg_api", "verified", True, True))
        self.assertEqual((provider["remaining_bytes"], provider["total_bytes"]), (card(6.64).remaining_bytes, 500 * qqg.GIB))
        self.assertEqual((provider["remaining_display"], provider["used_display"], provider["expected_reset_date"]),
                         ("493.36GB", "6.64GB", "2026-11-24"))
        snapshot = self.call("snapshot")["data"]
        self.assertEqual((snapshot["provider_freshness"]["state"], snapshot["provider_sync"]["state"],
                          snapshot["health"]["provider"]), ("fresh", "ok", "automatic_ok"))
        self.assertTrue(snapshot["budget"]["provider_remaining_verified"])
        self.assertNotIn("Provider allowance and reset time have not been verified.", snapshot["health"]["warnings"])
        self.assertEqual(parse_time(self.store.get_meta("provider_sync")["next_attempt_at"]) - self.now, dt.timedelta(seconds=600))
        self.sync(after=dt.timedelta(seconds=60))
        self.assertEqual(self.client.reads, 1)  # Not due: QQG is not asked again.

    def test_failures_change_only_the_sync_state(self):
        self.configure()
        self.sync(card(6.64))
        provider, users = self.store.get_meta("provider"), [dict(row) for row in self.store.conn.execute("SELECT * FROM users")]
        self.sync(qqg.QqgError("NETWORK", "无法连接 QQG"), after=dt.timedelta(seconds=601))
        state = self.store.get_meta("provider_sync")
        self.assertEqual((state["consecutive_failures"], state["last_error"]["code"]), (1, "NETWORK"))
        self.assertEqual(parse_time(state["next_attempt_at"]) - self.now, dt.timedelta(seconds=60))
        self.sync(qqg.QqgError("AUTH_FAILED", "QQG 拒绝了 API 登录：鉴权失败"), after=dt.timedelta(seconds=61))
        state = self.store.get_meta("provider_sync")
        self.assertEqual((state["consecutive_failures"], state["last_error"]["code"]), (2, "AUTH_FAILED"))
        self.assertEqual(parse_time(state["next_attempt_at"]) - self.now, dt.timedelta(seconds=3600))
        self.assertEqual(self.store.get_meta("provider"), provider)
        self.assertEqual([dict(row) for row in self.store.conn.execute("SELECT * FROM users")], users)
        self.assertEqual(self.call("snapshot")["data"]["provider_sync"]["state"], "error")

    def test_one_failure_notice_per_episode_and_only_after_an_hour(self):
        self.configure()
        start = self.now
        for minutes in (0, 30, 61, 75):
            self.now = start + dt.timedelta(minutes=minutes)
            self.sync(qqg.QqgError("NETWORK", "无法连接 QQG"))
            if minutes < 60:
                self.assertEqual(self.notices, [])
        keys = [key for kind, key in self.notices if kind == "provider_sync_failed"]
        self.assertEqual(set(keys), {"provider_sync_failed:" + timestamp(start)})

    def test_a_reset_is_detected_recorded_and_alerted_once(self):
        self.configure()
        self.sync(card(400))
        self.sync(card(1.5, reset="2026-12-24"), after=dt.timedelta(seconds=601))
        reset_at = timestamp(self.now)
        self.sync(card(2.0, reset="2026-12-24"), after=dt.timedelta(seconds=601))
        provider = self.store.get_meta("provider")
        self.assertEqual((provider["cycle_id"], provider["last_actual_reset_at"], provider["expected_reset_date"]),
                         ("qqg:2026-11-24", reset_at, "2026-12-24"))
        history = self.store.conn.execute("SELECT kind,event_key FROM provider_history").fetchall()
        self.assertEqual([tuple(row) for row in history], [("reset_detected", "provider_reset:4920:qqg:2026-11-24")])
        self.assertEqual([key for kind, key in self.notices if kind == "provider_auto_reset"],
                         ["provider_auto_reset:4920:qqg:2026-11-24"])

    def test_low_remaining_alerts_name_the_most_severe_level(self):
        self.configure()
        for used in (390, 410, 410.5, 460, 480):
            self.sync(card(used), after=dt.timedelta(seconds=601))
        keys = [key for kind, key in self.notices if kind == "provider_auto_low"]
        self.assertEqual(list(dict.fromkeys(keys)), ["provider_auto_low:4920:2026-11-24:20",
                                                     "provider_auto_low:4920:2026-11-24:10",
                                                     "provider_auto_low:4920:2026-11-24:5"])

    def test_the_estimate_subtracts_later_local_payload_and_expires(self):
        self.configure()
        self.sync(card(100))
        observed = self.store.get_meta("provider")["remaining_bytes"]
        self.use(5 * GB)
        estimate = provider_sync.remaining_estimate(self.store, self.now + dt.timedelta(minutes=5))
        self.assertEqual((estimate["local_payload_since_bytes"], estimate["estimated_remaining_bytes"]),
                         (5 * GB, observed - 5 * GB))
        self.assertIsNone(provider_sync.remaining_estimate(self.store, self.now + dt.timedelta(hours=6, seconds=1)))
        self.call("provider.configure", {"enabled": False})
        self.assertIsNone(provider_sync.remaining_estimate(self.store, self.now))

    def test_qqg_lowers_the_admin_share_and_refuses_growing_promises(self):
        self.configure()
        self.sync(card(300))
        remaining = card(300).remaining_bytes
        info = budget.snapshot(self.store, self.now)
        cap = remaining - 100 * GB  # The member's unused reservation stays protected.
        self.assertEqual((info["limited_by"], info["admin_remaining_bytes"], info["local_available_bytes"]),
                         ("provider", cap, 400 * GB))
        self.assertEqual(info["provider"]["admin_cap_bytes"], cap)
        budget.refresh_admin(self.store, self.now)
        admin = self.store.get_user(self.admin["id"])
        self.assertEqual(admin["quota_bytes"], admin["used_upload"] + admin["used_download"] + cap)
        result = self.call("user.add", {"name": "Late member", "role": "member", "quota_bytes": 150 * GB}, ok=False)
        self.assertEqual(result["error"]["code"], "PROVIDER_REMAINING_EXCEEDED")
        self.call("user.update", {"user_id": self.member["id"], "quota_bytes": 50 * GB})

    def test_a_card_for_another_instance_changes_nothing(self):
        self.configure()
        self.sync(card(10, host=1111))
        self.assertEqual(self.store.get_meta("provider_sync")["last_error"]["code"], "BAD_RESPONSE")
        self.assertEqual(self.store.get_meta("provider")["source"], "historical_manual_snapshot")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM provider_samples").fetchone()[0], 0)

    def test_calibration_compares_qqg_with_local_payload(self):
        self.configure()
        self.sync(card(10))
        self.use(int(0.4 * GB))
        self.sync(card(10.5), after=dt.timedelta(seconds=601))
        self.assertIsNone(provider_sync.calibration(self.store)["ratio"])
        self.use(int(9.6 * GB))
        self.sync(card(30.66), after=dt.timedelta(seconds=601))
        result = provider_sync.calibration(self.store)
        self.assertEqual(result["local_payload_delta_bytes"], 10 * GB)
        self.assertAlmostEqual(result["ratio"], (card(30.66).used_bytes - card(10).used_bytes) / (10 * GB), places=3)

    def test_payload_across_one_closed_cycle_uses_its_report(self):
        rows = [("cycle-a", "2026-10-24T08:19:00Z", "2026-11-24T08:19:00Z",
                 json.dumps({"used_upload": 3 * GB, "used_download": 7 * GB})),
                ("cycle-b", "2026-11-24T08:19:00Z", "2026-12-24T08:19:00Z", "{}"),
                ("cycle-z", "2027-01-24T08:19:00Z", "2027-02-24T08:19:00Z", "{}")]
        for identifier, start, end, report in rows:
            self.store.conn.execute("INSERT INTO cycles VALUES (?,?,?,?,?,?)", (identifier, start, end, "test", "closed", report))
        between = provider_sync._payload_between
        self.assertEqual(between(self.store, "cycle-a", 4 * GB, "cycle-b", 2 * GB), 8 * GB)
        self.assertEqual(between(self.store, "cycle-b", 1 * GB, "cycle-b", 3 * GB), 2 * GB)
        self.assertIsNone(between(self.store, "cycle-a", 4 * GB, "cycle-z", 2 * GB))

    def test_an_open_transaction_is_refused(self):
        self.store.conn.execute("BEGIN")
        try:
            with self.assertRaises(RuntimeError):
                provider_sync.sync_once(self.store, self.cache, now=self.now)
        finally:
            self.store.conn.rollback()

    def test_the_writer_thread_starts_and_stops_cleanly(self):
        executor = provider_sync.ProviderExecutor(self.store, client_factory=lambda creds: FakeClient([]))
        executor.start()
        time.sleep(0.3)
        executor.close()
        executor.thread.join(2)
        self.assertFalse(executor.thread.is_alive())
        self.assertFalse(executor.failed.is_set())


class UnmigratedStoreTests(unittest.TestCase):
    def test_an_older_database_reads_as_not_configured(self):
        store = Store(memory=True)
        self.addCleanup(store.close)
        for table in provider_sync.TABLES:
            store.conn.execute("DROP TABLE " + table)
        self.assertEqual(provider_sync.status(store)["state"], "not_configured")
        self.assertIsNone(provider_sync.remaining_estimate(store, store.now))
        self.assertEqual(budget.snapshot(store, store.now)["limited_by"], None)


if __name__ == "__main__":
    unittest.main()
