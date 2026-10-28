"""Real-mail queue behavior with mocked delivery and no external connections."""
import datetime as dt
import json
import re
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
import uuid

from dazzle import mail
from dazzle import domain
from dazzle.production import handle_request, process_one_job, snapshot
from dazzle.production_state import CORE_SHA256, ProductionStore
from dazzle.store import parse_time
from test_production import StrictHelper
from test_authorization_fixtures import seed_legacy_user


class LiveMailTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = parse_time("2026-11-01T08:19:00Z")
        self.admin, self.member = str(uuid.uuid4()), str(uuid.uuid4())
        self.policy = {"version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "8.8.8.8",
                       "core_sha256": CORE_SHA256, "agent_uid": 1001,
                       "workers": {self.admin: {"role": "admin", "public_port": 24430, "api_port": 34430},
                                   self.member: {"role": "member", "public_port": 24431, "api_port": 34431}}}
        self.store = ProductionStore(self.directory.name, policy=self.policy, initialize=True, now=self.now)
        self.addCleanup(lambda: self.store.close())
        self.config = {"host": "smtp.example.test", "port": 465, "security": "ssl", "username": "sender@example.test",
                       "sender": "sender@example.test", "admin_email": "admin@example.test"}
        self.secret = "test-only-authorization-code-unique"
        self.helper = StrictHelper(self.policy, self.store)
        for name in ("SMTP", "SMTP_SSL"):
            mocked = patch.object(mail.smtplib, name, side_effect=AssertionError("Real SMTP network forbidden"))
            mocked.start()
            self.addCleanup(mocked.stop)

    def rpc(self, action, params=None, seconds=0, ok=True):
        self.request_id = str(uuid.uuid4())
        result = handle_request(self.store, {"api_version": 1, "request_id": self.request_id, "action": action,
                               "server_id": self.store.server_id, "expected_revision": self.store.revision,
                               "params": params or {}}, self.now + dt.timedelta(seconds=seconds))
        if ok:
            self.assertTrue(result["ok"], result)
        return result

    def configure(self, secret=True, **changes):
        return self.rpc("mail.configure", {**self.config, **({"secret": self.secret} if secret else {}), **changes})

    def verify(self, user_id=None):
        params = {"user_id": user_id} if user_id else {}
        queued = self.rpc("mail.verify.send", params)["data"]
        payload = self.store.conn.execute("SELECT body FROM mail_private_payload WHERE outbox_id=?", (queued["id"],)).fetchone()[0]
        code = re.search(r"[0-9]{6}", payload).group()
        self.assertTrue(self.rpc("mail.verify.confirm", {**params, "code": code})["data"]["verified"])
        return code

    def ready(self):
        self.configure()
        self.verify()

    def test_missing_secret_is_not_reported_connected_or_queued(self):
        response = self.configure(secret=False)["data"]
        self.assertFalse(response["configured"])
        self.assertFalse(response["connected"])
        self.assertTrue(response["credential_required"])
        current = self.rpc("mail.status")["data"]
        self.assertTrue(current["settings_configured"])
        self.assertFalse(current["secret_configured"])
        self.assertEqual(self.rpc("mail.verify.send")["data"]["reason"], "smtp_secret_required")
        self.assertEqual(self.rpc("mail.test")["data"]["reason"], "smtp_secret_required")
        self.assertEqual(mail.process_live_outbox(self.store, self.now)["state"], "not_configured")

    def test_authorization_code_only_in_private_secret_table_not_rpc_cache_snapshot_or_config(self):
        response = self.configure()
        private_id = self.request_id
        self.assertTrue(response["data"]["configured"])
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM requests WHERE request_id=?", (private_id,)).fetchone())
        self.assertEqual(self.store.conn.execute("SELECT secret FROM mail_secrets").fetchone()[0], self.secret)
        self.assertNotIn(self.secret, json.dumps(response))
        self.assertNotIn(self.secret, json.dumps(snapshot(self.store, self.now)))
        self.assertNotIn(self.secret, self.store.conn.execute("SELECT settings_json FROM mail_config").fetchone()[0])
        self.assertNotIn(self.secret, "".join(row[0] for row in self.store.conn.execute("SELECT response_json FROM requests")))
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)

    def test_verification_code_private_and_confirm_request_not_durably_cached(self):
        self.configure()
        queued = self.rpc("mail.verify.send")["data"]
        payload = self.store.conn.execute("SELECT body FROM mail_private_payload WHERE outbox_id=?", (queued["id"],)).fetchone()[0]
        code = re.search(r"[0-9]{6}", payload).group()
        self.assertNotIn(code, json.dumps(self.rpc("mail.status")))
        self.assertNotIn(code, self.store.conn.execute("SELECT body FROM mail_outbox WHERE id=?", (queued["id"],)).fetchone()[0])
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_simulated_mailbox").fetchone()[0], 0)
        result = self.rpc("mail.verify.confirm", {"code": code})
        self.assertTrue(result["data"]["verified"])
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM requests WHERE request_id=?", (self.request_id,)).fetchone())

    def test_verification_sends_actual_private_payload_outside_transaction(self):
        self.configure()
        queued = self.rpc("mail.verify.send")["data"]
        delivered = []
        def deliver(config, message, secret):
            self.assertFalse(self.store.conn.in_transaction)
            self.assertEqual(secret, self.secret)
            self.assertIn("验证码", message["body"])
            self.assertRegex(message["body"], r"\b[0-9]{6}\b")
            with ProductionStore(self.directory.name, policy=self.policy) as other:
                other.set_meta("delivery_progress", True)
            delivered.append(message["id"])
        result = mail.process_live_outbox(self.store, self.now, delivery=deliver)
        self.assertEqual(result["state"], "sent")
        self.assertEqual(delivered, [queued["id"]])
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM mail_private_payload WHERE outbox_id=?", (queued["id"],)).fetchone())
        history = self.rpc("mail.status")["data"]["history"]
        self.assertEqual(history[0]["status"], "sent")
        self.assertIsNotNone(history[0]["submitted_at"])

    def test_ordinary_test_mail_requires_verified_recipient(self):
        self.configure()
        self.assertEqual(self.rpc("mail.test")["data"]["reason"], "email_unverified")
        self.verify()
        self.assertTrue(self.rpc("mail.test")["data"]["queued"])

    def test_host_or_username_change_invalidates_secret_but_admin_binding_change_invalidates_verification(self):
        self.ready()
        self.assertTrue(self.configure(secret=False)["data"]["configured"])
        result = self.configure(secret=False, admin_email="new-admin@example.test")["data"]
        self.assertTrue(result["configured"])
        self.assertFalse(result["mail"]["admin_email_verified"])
        result = self.configure(secret=False, host="new-smtp.example.test")["data"]
        self.assertFalse(result["configured"])
        self.assertFalse(result["secret_configured"])

    def test_wrong_verification_attempt_is_committed_but_never_echoed(self):
        self.configure()
        self.rpc("mail.verify.send")
        for _ in range(5):
            result = self.rpc("mail.verify.confirm", {"code": "invalid-attempt"})
            self.assertEqual(result["data"]["reason"], "invalid_code")
            self.assertNotIn("invalid-attempt", json.dumps(result))
        self.assertEqual(self.rpc("mail.verify.confirm", {"code": "000000"})["data"]["reason"], "attempt_limit")

    def test_expired_verification_is_cancelled_and_private_payload_removed(self):
        self.configure()
        queued = self.rpc("mail.verify.send")["data"]
        result = mail.process_live_outbox(self.store, self.now + dt.timedelta(minutes=11),
                                          delivery=lambda *_: self.fail("Expired code must not be sent"))
        self.assertEqual(result["state"], "cancelled")
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM mail_private_payload WHERE outbox_id=?", (queued["id"],)).fetchone())

    def test_auth_failure_is_safe_terminal_error_and_tls_network_error_retries(self):
        self.ready()
        # Already-verified OTP is cancelled before the test notification.
        mail.process_live_outbox(self.store, self.now, delivery=lambda *_: None)
        self.rpc("mail.test")
        def auth_failure(*_):
            raise mail.MailDeliveryError("AUTHENTICATION_FAILED", retryable=False)
        result = mail.process_live_outbox(self.store, self.now, delivery=auth_failure)
        self.assertEqual(result["state"], "dead")
        self.assertEqual(self.store.conn.execute("SELECT error_code FROM mail_outbox WHERE kind='test'").fetchone()[0], "AUTHENTICATION_FAILED")
        self.rpc("mail.preferences", {"cooldown_seconds": 0})
        self.rpc("mail.test", seconds=1)
        def temporary_failure(*_):
            raise RuntimeError(self.secret + " raw SMTP diagnostic")
        self.assertEqual(mail.process_live_outbox(self.store, self.now + dt.timedelta(seconds=1), delivery=temporary_failure)["state"], "retry")
        self.assertNotIn(self.secret, json.dumps(self.rpc("mail.status")))

    def test_live_queue_retry_lease_and_config_survive_restart(self):
        self.configure()
        self.rpc("mail.verify.send")
        self.store.close()
        self.store = ProductionStore(self.directory.name, policy=self.policy, now=self.now)
        self.assertTrue(self.rpc("mail.status")["data"]["secret_configured"])
        result = mail.process_live_outbox(self.store, self.now, delivery=lambda *_: None)
        self.assertEqual(result["state"], "sent")

    def test_live_smtp_uses_verified_tls_context_and_stable_message_id(self):
        factory = MagicMock()
        client = factory.return_value.__enter__.return_value
        client.send_message.return_value = {}
        message = {"id": "fixture-id", "recipient": "admin@example.test", "subject": "Fixture", "body": "Fixture"}
        mail._smtp_send(self.config, message, password=self.secret, allow_live=True, smtp_ssl_factory=factory)
        context = factory.call_args.kwargs["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(client.send_message.call_args.args[0]["Message-ID"], "<dazzle-fixture-id@example.test>")

    def test_mail_worker_network_wait_cannot_block_another_store_writer(self):
        entered, release = threading.Event(), threading.Event()
        def blocked_delivery(connection):
            self.assertFalse(connection.conn.in_transaction)
            entered.set()
            release.wait(3)
            return {"state": "idle"}
        with patch("dazzle.mail.process_live_outbox", side_effect=blocked_delivery):
            executor = mail.MailExecutor(self.store)
            executor.start()
            try:
                self.assertTrue(entered.wait(2))
                before = time.monotonic()
                self.store.conn.execute("BEGIN IMMEDIATE")
                self.store.set_meta("main_counter_progress", 1)
                self.store.conn.commit()
                self.assertLess(time.monotonic() - before, 1)
            finally:
                release.set()
                executor.close()

    def test_delete_archives_user_keeps_ledger_and_root_tombstone_and_never_reuses_slot(self):
        user = seed_legacy_user(self.store, {"name": "Delete fixture", "role": "member"}, self.now)["id"]
        self.store.conn.execute("UPDATE users SET used_upload=13,used_download=21 WHERE id=?", (user,))
        self.store.conn.execute("INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?)", ("fixture-ledger", user, "fixture-cycle", "fixture-epoch", 13, 21, "2026-11-01T08:19:00Z", "2026-11-01T08:19:00Z"))
        self.rpc("user.delete", {"user_id": user})
        self.assertEqual(snapshot(self.store, self.now)["users"], [])
        archived = snapshot(self.store, self.now)["deleted_users"][0]
        self.assertEqual(archived["id"], user)
        self.assertIsNotNone(archived["deleted_at"])
        self.assertEqual(snapshot(self.store, self.now)["totals"]["used_download"], 21)
        self.assertEqual(self.store.conn.execute("SELECT SUM(upload) FROM ledger").fetchone()[0], 13)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 0)
        process_one_job(self.store, self.helper, self.now)  # Cancel unexecuted provision.
        self.assertTrue(process_one_job(self.store, self.helper, self.now)["applied"])
        self.assertTrue(self.helper.records[user]["tombstoned"])
        self.assertEqual(len(self.rpc("user.list", {"include_deleted": True})["data"]["users"]), 1)
        self.assertEqual(self.rpc("user.add", {"name": "No reuse"}, ok=False)["error"]["code"], "APPROVAL_REQUIRED")
        self.assertEqual(self.rpc("user.enable", {"user_id": user}, ok=False)["error"]["code"], "REVOKED")

    def test_last_administrator_delete_is_rejected(self):
        admin = self.rpc("user.add", {"name": "Admin", "role": "admin"})["data"]["user"]["id"]
        response = self.rpc("user.delete", {"user_id": admin}, ok=False)
        self.assertEqual(response["error"]["code"], "LAST_ADMIN")
        self.assertIsNone(self.store.get_user(admin)["revoked_at"])
        self.assertIsNone(self.store.get_user(admin)["deleted_at"])

    def test_delete_cancels_pending_verification_and_keeps_stop_pending_visible_in_archive(self):
        self.configure()
        user = seed_legacy_user(self.store, {"name": "Pending archive", "role": "member"}, self.now)["id"]
        self.rpc("user.update", {"user_id": user, "email": "member@example.test"})
        queued = self.rpc("mail.verify.send", {"user_id": user})["data"]
        self.assertTrue(self.store.conn.execute("SELECT 1 FROM mail_private_payload WHERE outbox_id=?", (queued["id"],)).fetchone())
        result = self.rpc("user.delete", {"user_id": user})["data"]["snapshot"]
        self.assertEqual(result["users"], [])
        self.assertEqual(result["deleted_users"][0]["runtime_state"], "stop_pending")
        self.assertEqual(self.store.conn.execute("SELECT status FROM mail_outbox WHERE id=?", (queued["id"],)).fetchone()[0], "cancelled")
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM mail_private_payload WHERE outbox_id=?", (queued["id"],)).fetchone())
        self.store.close()
        self.store = ProductionStore(self.directory.name, policy=self.policy, now=self.now)
        self.assertEqual(snapshot(self.store, self.now)["deleted_users"][0]["id"], user)
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM credentials WHERE user_id=?", (user,)).fetchone())

    def test_deleted_failed_root_stop_is_visible_in_archive(self):
        user = seed_legacy_user(self.store, {"name": "Failed archive", "role": "member"}, self.now)["id"]
        self.rpc("user.delete", {"user_id": user})
        process_one_job(self.store, self.helper, self.now)
        self.helper.failure = "STOP_FAILED"
        self.assertFalse(process_one_job(self.store, self.helper, self.now)["applied"])
        archived = snapshot(self.store, self.now)["deleted_users"][0]
        self.assertEqual(archived["runtime_state"], "stop_failed")
        self.assertEqual(archived["last_error"], "STOP_FAILED")

    def test_existing_user_ledger_and_metadata_survive_additive_schema_upgrade(self):
        user = seed_legacy_user(self.store, {"name": "Migration fixture", "role": "member"}, self.now)["id"]
        self.store.conn.execute("UPDATE users SET used_upload=123,used_download=456 WHERE id=?", (user,))
        self.store.conn.execute("DROP INDEX IF EXISTS one_live_user_per_port")
        self.store.conn.execute("ALTER TABLE users DROP COLUMN deleted_at")
        self.store.conn.execute("DROP TABLE mail_secrets")
        self.store.conn.execute("DROP TABLE mail_private_payload")
        old_columns = [row[1] for row in self.store.conn.execute("PRAGMA table_info(users)")]
        old_row = tuple(self.store.conn.execute("SELECT * FROM users WHERE id=?", (user,)).fetchone())
        revision = self.store.revision
        self.store.close()
        self.store = ProductionStore(self.directory.name, policy=self.policy, now=self.now)
        self.assertEqual(tuple(self.store.conn.execute("SELECT " + ",".join(old_columns) + " FROM users WHERE id=?", (user,)).fetchone()), old_row)
        self.assertIsNone(self.store.get_user(user)["deleted_at"])
        self.assertEqual(self.store.revision, revision)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_secrets").fetchone()[0], 0)

    def test_live_quota_notifications_require_verified_member_and_do_not_claim_simulation(self):
        self.ready()
        user = seed_legacy_user(self.store, {"name": "Quota email fixture", "role": "member", "quota_bytes": 100}, self.now)["id"]
        self.rpc("user.update", {"user_id": user, "email": "member@example.test"})
        self.verify(user)
        self.store.conn.execute("UPDATE users SET used_upload=100 WHERE id=?", (user,))
        for _ in range(2):
            domain._quota(self.store, user, self.now)
        rows = self.store.conn.execute("SELECT body,transport FROM mail_outbox WHERE kind='quota_exceeded'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["transport"], "smtp")
        self.assertNotIn("本地模拟", rows[0]["body"])
        self.assertIn("已请求暂停", rows[0]["body"])

    def test_production_reconcile_records_ssh_authenticated_administrator(self):
        user = seed_legacy_user(self.store, {"name": "Maintenance audit fixture", "role": "member"}, self.now)["id"]
        domain._incident(self.store, self.store.get_user(user), "fixture_api_only_maintenance_gap", self.now)
        self.store.conn.execute("UPDATE users SET trusted_sample=1,last_sample_at=?,meter_state='reconciliation_required',reasons_json='[\"metering_failure\"]' WHERE id=?",
                                (self.now.isoformat(), user))
        evidence = "Approved API-only maintenance interval verified; unknown gap remains retained"
        self.rpc("meter.reconcile", {"user_id": user, "evidence": evidence})
        incident = self.store.conn.execute("SELECT * FROM metering_incidents WHERE user_id=?", (user,)).fetchone()
        self.assertEqual(incident["operator"], "ssh_authenticated_administrator")
        self.assertEqual(incident["evidence"], evidence)
        self.assertIsNotNone(incident["resolved_at"])
        self.assertEqual(incident["delta_unknown"], 1)


if __name__ == "__main__":
    unittest.main()
