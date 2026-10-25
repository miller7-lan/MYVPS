import json
import re
import sqlite3
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from dazzle import mail


class MailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "mail.sqlite3")
        self.store = self.open_store()
        self.store.conn.execute("""CREATE TABLE users(
            id TEXT PRIMARY KEY,name TEXT,role TEXT,email TEXT,email_verified INTEGER DEFAULT 0,
            updated_at TEXT,revoked_at TEXT)""")
        self.store.conn.execute("INSERT INTO users(id,name,role,email) VALUES('member','Member','member','member@example.com')")
        mail.ensure_schema(self.store)
        self.now = datetime(2026, 10, 25, 0, 0, tzinfo=timezone.utc)
        self.config = {"host": "smtp.example.com", "port": 465, "security": "ssl", "username": "mailer",
                       "sender": "sender@example.com", "admin_email": "admin@example.com"}

    def open_store(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return SimpleNamespace(conn=conn, get_meta=lambda key: "simulation" if key == "mode" else None)

    def tearDown(self):
        self.store.conn.close()
        self.temp.cleanup()

    def call(self, action, params=None, at=None):
        return mail.handle_mail(self.store, action, params or {}, at or self.now)

    def configure(self):
        return self.call("mail.configure", self.config)

    def verify(self, user_id="member"):
        params = {} if user_id is None else {"user_id": user_id}
        sent = self.call("mail.verify.send", params)
        message = next(row for row in mail.simulated_mailbox_for_tests(self.store) if row["outbox_id"] == sent["id"])
        code = re.search(r"[0-9]{6}", message["body"]).group()
        result = self.call("mail.verify.confirm", {**params, "code": code})
        self.assertTrue(result["verified"])
        return code

    def enqueue(self, event_key="quota80", **extra):
        return mail.enqueue_notification(self.store, event_key=event_key, user_id="member", kind="quota",
                                         subject="Quota notification", body="Quota usage is 80%", now=self.now,
                                         cycle_id=extra.pop("cycle_id", "cycle1"), **extra)

    def ready(self):
        self.configure()
        self.verify()

    def test_default_snapshot_is_unconfigured_simulation(self):
        snapshot = mail.snapshot_mail(self.store)
        self.assertFalse(snapshot["configured"])
        self.assertEqual(snapshot["transport"], "simulated")
        self.assertEqual(snapshot["queue"], [])
        self.assertEqual(snapshot["history"], [])

    def test_configure_and_process_never_connect_to_smtp(self):
        with patch.object(mail.smtplib, "SMTP") as smtp, patch.object(mail.smtplib, "SMTP_SSL") as smtp_ssl:
            result = self.configure()
            self.assertFalse(result["connected"])
            self.assertEqual(result["state"], "simulated")
            self.call("mail.verify.send", {"user_id": "member"})
            processed = self.call("mail.process")
            self.assertEqual(processed["simulated"], 1)
            smtp.assert_not_called()
            smtp_ssl.assert_not_called()

    def test_rejects_public_password_insecure_or_live_config(self):
        for update in ({"password": "do-not-persist"}, {"security": "plain"}, {"transport": "smtp"}, {"port": True}, {"host": "smtp.example.com\r\nBcc: attacker@example.com"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.call("mail.configure", {**self.config, **update})
        self.assertNotIn("do-not-persist", json.dumps(mail.snapshot_mail(self.store)))

    def test_only_verified_user_receives_notifications(self):
        self.configure()
        self.assertEqual(self.enqueue()["reason"], "email_unverified")
        self.verify()
        self.assertTrue(self.enqueue()["queued"])

    def test_admin_requires_separate_verification(self):
        self.configure()
        self.assertEqual(self.call("mail.test")["reason"], "email_unverified")
        self.verify(None)
        self.assertTrue(mail.snapshot_mail(self.store)["admin_email_verified"])
        self.assertTrue(self.call("mail.test")["queued"])

    def test_verification_hash_only_and_no_otp_in_public_snapshot(self):
        self.configure()
        response = self.call("mail.verify.send", {"user_id": "member"})
        message = mail.simulated_mailbox_for_tests(self.store)[0]
        code = re.search(r"[0-9]{6}", message["body"]).group()
        verification = dict(self.store.conn.execute("SELECT * FROM mail_verifications").fetchone())
        public = json.dumps({"result": response, "snapshot": mail.snapshot_mail(self.store)})
        self.assertNotIn(code, verification["code_hash"])
        self.assertNotIn(code, public)
        self.assertNotIn("code_hash", public)
        self.assertNotIn("salt", public)
        self.assertNotIn(code, self.store.conn.execute("SELECT body FROM mail_outbox").fetchone()["body"])

    def test_sensitive_simulated_inbox_completes_verification_without_network(self):
        self.configure()
        queued = self.call("mail.verify.send", {"user_id": "member"})
        inbox = self.call("mail.simulated_inbox")
        self.assertTrue(inbox["sensitive"])
        message = next(item for item in inbox["messages"] if item["id"] == queued["id"])
        code = re.search(r"[0-9]{6}", message["body"]).group()
        self.assertTrue(self.call("mail.verify.confirm", {"user_id": "member", "code": code})["verified"])
        self.assertNotIn(code, json.dumps(mail.snapshot_mail(self.store)))

    def test_simulated_inbox_denies_non_simulation_modes(self):
        self.store.get_meta = lambda _: "production"
        with self.assertRaises(ValueError):
            self.call("mail.simulated_inbox")

    def test_real_store_rpc_quota_events_use_verified_deduplicated_mail(self):
        from dazzle.rpc import handle_request
        from dazzle.store import Store

        real_store = Store(memory=True, now=self.now)
        sequence = 0
        def rpc(action, params=None, seconds=0):
            nonlocal sequence
            sequence += 1
            response = handle_request(real_store, {"api_version": 1, "request_id": f"mail-integration-{sequence}",
                                      "action": action, "expected_revision": real_store.revision, "params": params or {}},
                                      now=self.now + timedelta(seconds=seconds))
            self.assertTrue(response["ok"], response["error"])
            return response
        try:
            rpc("user.add", {"name": "Mail integration", "role": "member", "quota_bytes": 1000})
            user_id = real_store.conn.execute("SELECT id FROM users").fetchone()[0]
            rpc("user.update", {"user_id": user_id, "email": "member@example.com"})
            rpc("mail.configure", self.config)
            rpc("mail.verify.send", {"user_id": user_id})
            code = re.search(r"[0-9]{6}", mail.simulated_mailbox_for_tests(real_store)[0]["body"]).group()
            self.assertTrue(rpc("mail.verify.confirm", {"user_id": user_id, "code": code})["data"]["verified"])
            for seconds, uplink in ((0, 0), (1, 800), (2, 810)):
                rpc("meter.sample", {"user_id": user_id, "epoch": "sim", "uplink": uplink, "downlink": 0,
                                     "at": (self.now + timedelta(seconds=seconds)).isoformat()}, seconds)
            count = real_store.conn.execute("SELECT count(*) FROM mail_outbox WHERE kind='quota_threshold'").fetchone()[0]
            self.assertEqual(count, 1)
            result = rpc("mail.process", seconds=3)
            self.assertEqual(result["data"]["simulated"], 1)
            self.assertNotIn(code, json.dumps(result))
            for row in real_store.conn.execute("SELECT response_json FROM requests"):
                self.assertNotIn(code, row["response_json"])
        finally:
            real_store.close()

    def test_wrong_codes_are_limited_and_persist_across_restart(self):
        self.configure()
        self.call("mail.verify.send", {"user_id": "member"})
        for _ in range(mail.VERIFY_MAX_ATTEMPTS):
            self.assertEqual(self.call("mail.verify.confirm", {"user_id": "member", "code": "not-a-code"})["reason"], "invalid_code")
        self.store.conn.commit()
        self.store.conn.close()
        self.store = self.open_store()
        result = self.call("mail.verify.confirm", {"user_id": "member", "code": "123456"})
        self.assertEqual(result["reason"], "attempt_limit")
        self.assertFalse(self.store.conn.execute("SELECT email_verified FROM users").fetchone()["email_verified"])

    def test_verification_expires_and_resend_has_cooldown(self):
        self.configure()
        self.call("mail.verify.send", {"user_id": "member"})
        response = self.call("mail.verify.send", {"user_id": "member"})
        self.assertEqual(response["reason"], "verification_cooldown")
        code = re.search(r"[0-9]{6}", mail.simulated_mailbox_for_tests(self.store)[0]["body"]).group()
        result = self.call("mail.verify.confirm", {"user_id": "member", "code": code}, self.now + timedelta(minutes=10))
        self.assertEqual(result["reason"], "expired")

    def test_email_change_invalidates_pending_verification_and_notification(self):
        self.ready()
        self.enqueue()
        self.store.conn.execute("UPDATE users SET email='new@example.com',email_verified=0 WHERE id='member'")
        result = self.call("mail.process")
        self.assertEqual(result["cancelled"], 2)
        self.assertFalse(mail.simulated_mailbox_for_tests(self.store, delivered_only=True))

    def test_admin_email_change_does_not_preserve_verification(self):
        self.configure()
        self.verify(None)
        self.call("mail.configure", {**self.config, "admin_email": "new-admin@example.com"})
        self.assertFalse(mail.snapshot_mail(self.store)["admin_email_verified"])

    def test_dedup_is_persistent_and_scoped_to_user_cycle(self):
        self.ready()
        queued = self.enqueue()
        duplicate = self.enqueue()
        self.assertFalse(duplicate["queued"])
        self.assertEqual(duplicate["id"], queued["id"])
        self.store.conn.commit()
        self.store.conn.close()
        self.store = self.open_store()
        self.assertEqual(self.enqueue()["reason"], "duplicate")
        self.assertTrue(self.enqueue(cycle_id="cycle2")["queued"])

    def test_cooldown_and_disabled_preferences(self):
        self.ready()
        self.enqueue()
        self.assertEqual(self.enqueue("quota81")["reason"], "cooldown")
        self.call("mail.preferences", {"enabled": False})
        self.assertEqual(self.enqueue("quota90")["reason"], "notifications_disabled")
        self.assertEqual(self.call("mail.process")["cancelled"], 2)

    def test_identical_event_for_different_verified_users_is_independent(self):
        self.ready()
        self.store.conn.execute("INSERT INTO users(id,name,role,email) VALUES('other','Other','member','other@example.com')")
        self.verify("other")
        self.assertTrue(self.enqueue()["queued"])
        other = mail.enqueue_notification(self.store, event_key="quota80", user_id="other", kind="quota",
                                           subject="Quota", body="80%", now=self.now, cycle_id="cycle1")
        self.assertTrue(other["queued"])

    def test_content_is_redacted_before_persistence(self):
        self.ready()
        secret_body = "password=hunter2 token=abc123 Authorization: Bearer xyz987\ntrojan://secretproxy@example.com:443?token=querysecret\nsubscription_url=https://example.com/private\n-----BEGIN PRIVATE KEY-----\nprivate material\n-----END PRIVATE KEY-----"
        result = mail.enqueue_notification(self.store, event_key="redact", user_id="member", kind="quota", subject="token=subjectsecret", body=secret_body, now=self.now, cycle_id="cycle1")
        row = dict(self.store.conn.execute("SELECT * FROM mail_outbox WHERE id=?", (result["id"],)).fetchone())
        for secret in ("hunter2", "abc123", "xyz987", "secretproxy", "querysecret", "private material", "subjectsecret", "example.com/private"):
            self.assertNotIn(secret, json.dumps(row))
            self.assertNotIn(secret, json.dumps(mail.simulated_mailbox_for_tests(self.store)))

    def test_process_success_is_explicitly_simulated_and_idempotent(self):
        self.ready()
        queued = self.enqueue()
        self.assertEqual(self.call("mail.process")["simulated"], 1)
        self.assertEqual(self.call("mail.process")["processed"], 0)
        row = self.store.conn.execute("SELECT status,transport FROM mail_outbox WHERE id=?", (queued["id"],)).fetchone()
        self.assertEqual(row["status"], "simulated")
        self.assertEqual(row["transport"], "simulated")
        self.assertEqual(len(mail.simulated_mailbox_for_tests(self.store, delivered_only=True)), 1)

    def test_exponential_retry_stops_after_max_attempts(self):
        self.ready()
        self.enqueue()
        self.call("mail.preferences", {"max_attempts": 3})
        def fail(_):
            raise mail.MailDeliveryError("TRANSIENT_DELIVERY_FAILURE")
        first = mail.process_outbox(self.store, self.now, delivery=fail)
        self.assertEqual(first["retry"], 1)
        row = self.store.conn.execute("SELECT * FROM mail_outbox WHERE kind='quota'").fetchone()
        self.assertEqual(row["next_attempt_at"], mail._iso(self.now + timedelta(seconds=60)))
        self.assertEqual(mail.process_outbox(self.store, self.now + timedelta(seconds=59), delivery=fail)["processed"], 0)
        mail.process_outbox(self.store, self.now + timedelta(seconds=60), delivery=fail)
        row = self.store.conn.execute("SELECT * FROM mail_outbox WHERE kind='quota'").fetchone()
        self.assertEqual(row["next_attempt_at"], mail._iso(self.now + timedelta(seconds=180)))
        self.assertEqual(mail.process_outbox(self.store, self.now + timedelta(seconds=180), delivery=fail)["dead"], 1)

    def test_exception_payloads_never_enter_history(self):
        self.ready()
        self.enqueue()
        def fail(_):
            raise RuntimeError("smtp password=do-not-leak token=secret-token")
        mail.process_outbox(self.store, self.now, delivery=fail)
        snapshot = json.dumps(mail.snapshot_mail(self.store))
        self.assertNotIn("do-not-leak", snapshot)
        self.assertNotIn("secret-token", snapshot)
        self.assertIn("DELIVERY_FAILED", snapshot)

    def test_worker_leases_recover_after_restart_and_reject_stale_worker(self):
        self.ready()
        queued = self.enqueue()
        claimed = mail.claim_messages(self.store, self.now, worker_id="worker1", lease_seconds=30)
        self.assertEqual(len(claimed), 2)
        self.assertEqual(mail.claim_messages(self.store, self.now, worker_id="worker2"), [])
        self.store.conn.commit()
        self.store.conn.close()
        self.store = self.open_store()
        later = self.now + timedelta(seconds=31)
        reclaimed = mail.claim_messages(self.store, later, worker_id="worker2")
        self.assertEqual(len(reclaimed), 2)
        self.assertFalse(mail.finish_message(self.store, queued["id"], "worker1", later))
        self.assertTrue(mail.finish_message(self.store, queued["id"], "worker2", later))
        self.assertEqual(self.store.conn.execute("SELECT attempts FROM mail_outbox WHERE id=?", (queued["id"],)).fetchone()["attempts"], 2)

    def test_repeated_worker_crashes_exhaust_retry_budget(self):
        self.ready()
        queued = self.enqueue()
        self.call("mail.preferences", {"max_attempts": 1})
        mail.claim_messages(self.store, self.now, worker_id="crashed", lease_seconds=1)
        later = self.now + timedelta(seconds=2)
        self.assertEqual(mail.claim_messages(self.store, later, worker_id="replacement"), [])
        row = self.store.conn.execute("SELECT status,error_code FROM mail_outbox WHERE id=?", (queued["id"],)).fetchone()
        self.assertEqual(row["status"], "dead")
        self.assertEqual(row["error_code"], "LEASE_EXPIRED")

    def test_ensure_schema_preserves_caller_transaction(self):
        self.store.conn.commit()
        self.store.conn.execute("BEGIN")
        self.configure()
        self.store.conn.rollback()
        self.assertFalse(mail.snapshot_mail(self.store)["configured"])

    def test_smtp_live_gate_prevents_network_even_with_configuration(self):
        factory = MagicMock()
        with self.assertRaises(mail.MailDeliveryError) as raised:
            mail._smtp_send(self.config, {"recipient": "a@example.com", "subject": "test", "body": "test"}, smtp_ssl_factory=factory)
        self.assertEqual(raised.exception.code, "LIVE_TRANSPORT_DISABLED")
        factory.assert_not_called()

    def test_starttls_mock_performs_tls_before_authentication(self):
        factory = MagicMock()
        client = factory.return_value.__enter__.return_value
        events = []
        client.starttls.side_effect = lambda **_: events.append("tls")
        client.login.side_effect = lambda *_: events.append("login")
        client.send_message.side_effect = lambda *_: events.append("send")
        mail._smtp_send({**self.config, "security": "starttls", "port": 587},
                        {"recipient": "a@example.com", "subject": "test", "body": "test"},
                        password="only-in-mock", allow_live=True, smtp_factory=factory)
        self.assertEqual(events, ["tls", "login", "send"])
        context = client.starttls.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_tls_failure_is_safe_and_never_falls_back_to_plain(self):
        factory = MagicMock()
        client = factory.return_value.__enter__.return_value
        client.starttls.side_effect = ssl.SSLError("password=must-not-leak")
        with self.assertRaises(mail.MailDeliveryError) as raised:
            mail._smtp_send({**self.config, "security": "starttls", "port": 587},
                            {"recipient": "a@example.com", "subject": "test", "body": "test"},
                            password="mock-only", allow_live=True, smtp_factory=factory)
        self.assertEqual(str(raised.exception), "TLS_ERROR")
        self.assertFalse(raised.exception.retryable)
        client.login.assert_not_called()
        client.send_message.assert_not_called()


if __name__ == "__main__":
    unittest.main()
