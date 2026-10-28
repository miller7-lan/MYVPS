"""Public admission tests use only isolated SQLite and mocked SMTP delivery."""
import base64
import concurrent.futures
import datetime as dt
import json
import os
import re
import socket
import tempfile
import unittest
from unittest.mock import patch
import uuid

from dazzle import domain, mail, registration
from dazzle.portal_rpc import dispatch, peer_uid
from dazzle.production import handle_request, snapshot, subscription_response, process_one_job, accept_sample
from dazzle.metering import MeterSample
from dazzle.store import timestamp
from dazzle.production_state import CORE_SHA256, ProductionStore
from dazzle.store import parse_time
from test_production import StrictHelper
from test_authorization_fixtures import confirm_test_budget, seed_legacy_user


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(); self.addCleanup(self.folder.cleanup)
        self.now = parse_time("2026-11-01T08:19:00Z")
        self.admin, self.member = str(uuid.uuid4()), str(uuid.uuid4())
        self.policy = {"version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "8.8.8.8", "agent_uid": 1001,
                       "core_sha256": CORE_SHA256,
                       "workers": {self.admin: {"role": "admin", "public_port": 24430, "api_port": 34430},
                                   self.member: {"role": "member", "public_port": 24431, "api_port": 34431}}}
        self.store = ProductionStore(self.folder.name, policy=self.policy, initialize=True, now=self.now)
        self.addCleanup(self.store.close)
        confirm_test_budget(self.store, self.now, total_gb=1000)
        registration.ensure_schema(self.store)
        self.store.set_setting("registration_enabled", True)
        self.rpc("mail.configure", {"host": "smtp.example.test", "port": 465, "security": "ssl", "username": "sender@example.test",
                                  "sender": "sender@example.test", "admin_email": "admin@example.test", "secret": "smtp-test-only-secret"})
        self.helper = StrictHelper(self.policy, self.store)
        for name in ("SMTP", "SMTP_SSL"):
            patched = patch.object(mail.smtplib, name, side_effect=AssertionError("Real SMTP forbidden")); patched.start(); self.addCleanup(patched.stop)

    def rpc(self, action, params=None, request_id=None, ok=True):
        result = handle_request(self.store, {"api_version": 1, "request_id": request_id or str(uuid.uuid4()),
                    "action": action, "params": params or {}, "server_id": self.store.server_id,
                    "expected_revision": self.store.revision}, self.now)
        if ok: self.assertTrue(result["ok"], result)
        return result

    def public(self, operation, params, *, store=None, ok=True, ip="192.0.2.8"):
        response = dispatch(store or self.store, {"version": 1, "request_id": str(uuid.uuid4()), "operation": operation,
                                               "params": params, "peer_ip": ip}, now=self.now)
        if ok: self.assertTrue(response["ok"], response)
        return response

    def request_code(self, email="friend@example.test", nickname="Friend"):
        result = self.public("auth.request_code", {"email": email, "nickname": nickname})
        challenge = result["data"]["challenge_id"]
        payload = self.store.conn.execute("SELECT p.body FROM portal_mail m JOIN mail_private_payload p ON m.outbox_id=p.outbox_id WHERE m.challenge_id=?", (challenge,)).fetchone()[0]
        return challenge, re.search(r"[0-9]{6}", payload).group()

    def register(self, email="friend@example.test"):
        challenge, code = self.request_code(email)
        result = self.public("auth.verify", {"challenge_id": challenge, "code": code})["data"]
        me = self.public("session.me", {"session_token": result["session_token"]})["data"]
        self.assertNotIn("subscriptions", me)
        self.assertNotIn("used_upload", me["account"])
        account = registration._account(self.store, me["account"]["id"])
        # Internal fixture helpers may inspect links without exposing them from
        # the personal web session endpoint.
        private_fixture = {"account": registration._public(self.store, account, self.now),
                           "subscriptions": registration._links(self.store, account)}
        return private_fixture, result["session_token"]

    def assert_silently_refused(self, email, **kwargs):
        """Closed, full or revoked: a real code's reply, but a decoy that sends nothing."""
        mails = lambda: self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE recipient=?", (email,)).fetchone()[0]
        before = mails()
        reply = self.public("auth.request_code", {"email": email}, **kwargs)
        self.assertEqual(set(reply["data"]), {"challenge_id"})
        challenge = reply["data"]["challenge_id"]
        row = self.store.conn.execute("SELECT account_id FROM portal_challenges WHERE id=?", (challenge,)).fetchone()
        self.assertEqual(row[0], registration.DECOY)
        self.assertEqual(mails(), before)
        refused = self.public("auth.verify", {"challenge_id": challenge, "code": "000000"}, ok=False, **kwargs)
        self.assertEqual(refused["error"]["code"], "INVALID_CODE")
        return challenge

    def extra_seats(self, count):
        """Unassigned approved member slots, so several applicants can wait at once."""
        for index in range(count):
            self.store.conn.execute("INSERT INTO production_workers(worker_id,role,public_port,api_port) VALUES(?,?,?,?)",
                                    (str(uuid.uuid4()), "member", 24432 + index, 34432 + index))

    def test_trials_and_manual_creation_cannot_take_verified_applicants_seats(self):
        self.extra_seats(2)
        applicants = [self.register("seat%d@example.test" % index)[0]["account"]["id"] for index in range(3)]
        before = registration.capacity(self.store)
        self.assertEqual(before, {"free_slots": 3, "waiting": 3, "full": True})
        users = self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        credentials = self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        for action, parameters in (("trial.create", {"name": "Cannot steal a held seat", "duration_days": 3, "quota_bytes": 5_000_000_000}),
                                   ("user.add", {"name": "Cannot steal a held seat", "quota_bytes": 100_000_000_000})):
            result = self.rpc(action, parameters, ok=False)
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "REGISTRATION_FULL")
            self.assertEqual(registration.capacity(self.store), before)
            self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], users)
            self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], credentials)
        # Each approval consumes its own held seat; a full waiting list cannot
        # prevent the users who already hold its reservations from activating.
        for account_id in applicants:
            self.rpc("registration.approve", {"account_id": account_id})
        self.assertEqual(registration.capacity(self.store), {"free_slots": 0, "waiting": 0, "full": True})

    def test_trial_can_use_only_the_unreserved_spare_capacity(self):
        self.extra_seats(1)
        me, _ = self.register("held@example.test")
        result = self.rpc("trial.create", {"name": "Spare seat", "duration_days": 3, "quota_bytes": 5_000_000_000})
        self.assertIsNotNone(result["data"]["user"]["id"])
        self.assertEqual(registration.capacity(self.store), {"free_slots": 1, "waiting": 1, "full": True})
        rejected = self.rpc("trial.create", {"name": "Second trial"}, ok=False)
        self.assertFalse(rejected["ok"])
        self.rpc("registration.approve", {"account_id": me["account"]["id"]})

    def sample_origin(self, user_id=None):
        user_id = user_id or self.member
        worker = self.store.worker(user_id)
        self.store.conn.execute("BEGIN IMMEDIATE")
        accept_sample(self.store,user_id,worker["observed_generation"],
                      MeterSample("fixture-epoch-"+str(worker["observed_generation"]),0,0,timestamp(self.now)),self.now)
        self.store.conn.commit()

    def running_registration(self):
        me, session = self.register()
        self.rpc("registration.approve",{"account_id":me["account"]["id"]})
        for _ in range(2):self.assertTrue(process_one_job(self.store,self.helper,now=self.now)["applied"])
        self.sample_origin()
        self.assertTrue(process_one_job(self.store,self.helper,now=self.now)["applied"])
        self.sample_origin()
        self.assertTrue(registration.activation_ready(self.store,registration._account(self.store,me["account"]["id"]),self.now))
        return me,session

    def activation_tick(self, store=None):
        from dazzle.collector import tick
        tick(store or self.store,self.now)

    def drain_mail(self, failure_kind=None):
        sent=[]
        def delivery(config,message,secret):
            if message["kind"]==failure_kind:
                raise mail.MailDeliveryError("TRANSIENT_DELIVERY_FAILURE")
            sent.append((message["kind"],message["body"]))
        for _ in range(20):
            if not mail.process_live_outbox(self.store,self.now,delivery=delivery).get("processed"):break
        return sent

    def test_activated_links_email_requires_current_sampled_running_worker(self):
        me,_=self.register()
        self.rpc("registration.approve",{"account_id":me["account"]["id"]})
        self.activation_tick()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],0)
        for _ in range(2):
            self.assertTrue(process_one_job(self.store,self.helper,now=self.now)["applied"])
            self.activation_tick()
        self.sample_origin()
        self.activation_tick()
        self.assertTrue(process_one_job(self.store,self.helper,now=self.now)["applied"])
        # Running alone still has no trusted observation of its new origin.
        self.activation_tick()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],0)
        self.sample_origin()
        self.activation_tick()
        row=self.store.conn.execute("SELECT id,body FROM mail_outbox WHERE kind='portal_activated'").fetchone()
        payload=self.store.conn.execute("SELECT body FROM mail_private_payload WHERE outbox_id=?",(row["id"],)).fetchone()[0]
        self.assertIn(me["subscriptions"]["clash"],payload)
        self.assertIn(me["subscriptions"]["shadowrocket"],payload)
        self.assertNotIn(me["subscriptions"]["clash"],row["body"])
        self.assertIsNone(self.store.conn.execute("SELECT activation_notified_at FROM portal_accounts").fetchone()[0])
        sent=self.drain_mail()
        self.assertEqual(sum(kind=='portal_activated' for kind,body in sent),1)
        self.assertIsNotNone(self.store.conn.execute("SELECT activation_notified_at FROM portal_accounts").fetchone()[0])

    def test_authorized_activation_reaches_fake_smtp_with_full_links_but_no_public_leak(self):
        me, _ = self.running_registration()
        self.activation_tick()
        messages = []
        class FakeSMTP:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def login(self, *_): pass
            def send_message(self, message):
                messages.append(message)
                return {}
        with patch.object(mail.smtplib, "SMTP_SSL", new=lambda *args, **kwargs: FakeSMTP()):
            for _ in range(12):
                if not mail.process_live_outbox(self.store, self.now).get("processed"):
                    break
        activated = [message.get_content() for message in messages if "个人订阅" in str(message["Subject"])]
        self.assertEqual(len(activated), 1)
        for link in me["subscriptions"].values():
            self.assertIn(link, activated[0])
            self.assertNotIn(link, json.dumps(mail.snapshot_mail(self.store)))
        self.assertNotIn("[redacted link]", activated[0])
        self.assertIsNotNone(self.store.conn.execute("SELECT activation_notified_at FROM portal_accounts").fetchone()[0])

    def test_systemd_inactive_pid_zero_bootstraps_with_ticks_between_steps(self):
        strict = self.helper
        class SystemdPIDShape:
            def call(inner, request):
                result = strict.call(request)
                if result.get("process_id") is None:
                    result["process_id"] = 0
                return result
        self.helper = SystemdPIDShape()
        me,_ = self.register()
        self.rpc("registration.approve",{"account_id":me["account"]["id"]})
        self.activation_tick()
        self.assertTrue(process_one_job(self.store,self.helper,now=self.now)["applied"])
        self.assertEqual(self.store.worker(self.member)["observed_state"],"provisioned")
        self.assertEqual(self.store.worker(self.member)["process_id"],0)
        self.activation_tick()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL",(self.member,)).fetchone()[0],0)
        self.assertTrue(process_one_job(self.store,self.helper,now=self.now)["applied"])
        self.activation_tick()
        self.sample_origin()
        self.activation_tick()
        self.assertTrue(process_one_job(self.store,self.helper,now=self.now)["applied"])
        self.activation_tick()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],0)
        self.sample_origin()
        self.activation_tick()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],1)
        self.assertGreater(self.store.worker(self.member)["process_id"],0)

    def test_fake_running_without_trusted_meter_never_sends_activation(self):
        me,_=self.running_registration()
        self.store.conn.execute("UPDATE users SET trusted_sample=0,meter_state='failure' WHERE id=?",(self.member,))
        self.activation_tick()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],0)
        self.assertIsNone(self.store.conn.execute("SELECT activation_notified_at FROM portal_accounts").fetchone()[0])

    def test_bootstrap_grace_does_not_cover_unexpected_process_or_erase_incidents(self):
        me,_=self.register();self.rpc("registration.approve",{"account_id":me["account"]["id"]})
        self.store.conn.execute("UPDATE production_workers SET process_id=999 WHERE worker_id=?",(self.member,))
        self.activation_tick()
        self.assertGreater(self.store.conn.execute("SELECT COUNT(*) FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL",(self.member,)).fetchone()[0],0)
        self.store.conn.execute("UPDATE production_workers SET process_id=NULL WHERE worker_id=?",(self.member,))
        self.activation_tick()
        self.assertGreater(self.store.conn.execute("SELECT COUNT(*) FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL",(self.member,)).fetchone()[0],0)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],0)

    def test_staged_timeout_and_previously_sampled_gap_still_trip_guard(self):
        me,_=self.register();self.rpc("registration.approve",{"account_id":me["account"]["id"]})
        for _ in range(2):self.assertTrue(process_one_job(self.store,self.helper,now=self.now)["applied"])
        self.now+=dt.timedelta(seconds=6)
        self.activation_tick()
        self.assertGreater(self.store.conn.execute("SELECT COUNT(*) FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL",(self.member,)).fetchone()[0],0)
        self.assertFalse(self.store.get_user(self.member)["trusted_sample"])
        self.store.conn.execute("UPDATE users SET meter_epoch='old-epoch',last_sample_at=?,trusted_sample=1 WHERE id=?",(timestamp(self.now-dt.timedelta(seconds=6)),self.member))
        self.store.conn.execute("UPDATE production_workers SET observed_state='provisioned',process_id=NULL,origin_pending=0 WHERE worker_id=?",(self.member,))
        self.activation_tick()
        self.assertFalse(self.store.get_user(self.member)["trusted_sample"])
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],0)

    def test_activation_email_deduplicates_ticks_restart_and_pause_restore(self):
        me,_=self.running_registration()
        for _ in range(3):self.activation_tick()
        with ProductionStore(self.folder.name,policy=self.policy) as another:self.activation_tick(another)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],1)
        self.drain_mail()
        self.rpc("user.disable",{"user_id":self.member})
        self.rpc("user.enable",{"user_id":self.member})
        self.activation_tick()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],1)

    def test_paused_or_revoked_queue_never_sends_link_payload(self):
        me,_=self.running_registration();self.activation_tick()
        self.rpc("user.disable",{"user_id":self.member})
        sent=self.drain_mail()
        self.assertFalse(any(kind=='portal_activated' for kind,body in sent))
        self.assertIsNone(self.store.conn.execute("SELECT activation_notified_at FROM portal_accounts").fetchone()[0])
        self.rpc("user.enable",{"user_id":self.member});self.activation_tick()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],2)
        self.rpc("user.revoke",{"user_id":self.member})
        self.assertFalse(any(kind=='portal_activated' for kind,body in self.drain_mail()))
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_private_payload p JOIN portal_mail m ON p.outbox_id=m.outbox_id WHERE m.kind='portal_activated'").fetchone()[0],0)

    def test_rotation_before_first_accepted_mail_requeues_current_links_after_running(self):
        me,_=self.running_registration();self.activation_tick()
        old=me["subscriptions"]["clash"].split("/")[-2]
        self.drain_mail(failure_kind='portal_activated')
        self.rpc("user.rotate",{"user_id":self.member})
        self.activation_tick()
        self.assertIsNone(self.store.conn.execute("SELECT activation_notified_at FROM portal_accounts").fetchone()[0])
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],1)
        self.assertTrue(process_one_job(self.store,self.helper,now=self.now)["applied"])
        self.sample_origin()
        self.assertTrue(process_one_job(self.store,self.helper,now=self.now)["applied"])
        self.sample_origin()
        self.activation_tick()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0],2)
        sent=self.drain_mail()
        activated=[body for kind,body in sent if kind=='portal_activated']
        self.assertEqual(len(activated),1)
        self.assertNotIn(old,activated[0])
        self.assertIn(self.store.get_credentials(self.member)["subscription_token"],activated[0])
        self.assertIsNotNone(self.store.conn.execute("SELECT activation_notified_at FROM portal_accounts").fetchone()[0])

    def test_verified_registration_issues_links_but_no_proxy_or_jobs(self):
        challenge, code = self.request_code()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 0)
        signed = self.public("auth.verify", {"challenge_id": challenge, "code": code})["data"]
        me = self.public("session.me", {"session_token": signed["session_token"]})["data"]
        self.assertEqual(me["account"]["status"], "pending")
        self.assertNotIn("subscriptions", me)
        token = registration._account(self.store, me["account"]["id"])["subscription_token"]
        self.assertEqual(subscription_response(self.store, token, "config.yaml", self.now)["status"], 403)
        self.assertEqual(subscription_response(self.store, token, "nodes.txt", self.now)["status"], 403)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM production_jobs").fetchone()[0], 0)

    def test_wrong_expired_superseded_and_used_codes_are_rejected(self):
        self.extra_seats(1)
        challenge, code = self.request_code()
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(5):
            self.assertFalse(self.public("auth.verify", {"challenge_id": challenge, "code": wrong}, ok=False)["ok"])
        self.assertEqual(self.store.conn.execute("SELECT attempts FROM portal_challenges WHERE id=?", (challenge,)).fetchone()[0], 5)
        self.assertFalse(self.public("auth.verify", {"challenge_id": challenge, "code": code}, ok=False)["ok"])
        self.now += dt.timedelta(seconds=61)
        second, code2 = self.request_code()
        self.assertFalse(self.public("auth.verify", {"challenge_id": challenge, "code": code}, ok=False)["ok"])
        self.public("auth.verify", {"challenge_id": second, "code": code2})
        self.assertFalse(self.public("auth.verify", {"challenge_id": second, "code": code2}, ok=False)["ok"])
        self.now += dt.timedelta(seconds=61)
        third, code3 = self.request_code("other@example.test")
        self.now += dt.timedelta(seconds=600)
        self.assertFalse(self.public("auth.verify", {"challenge_id": third, "code": code3}, ok=False)["ok"])

    def test_public_requests_cannot_choose_role_user_quota_or_management_action(self):
        for operation, params in [("user.enable", {"user_id": self.admin}),
                                  ("auth.request_code", {"email": "x@example.test", "role": "admin"}),
                                  ("auth.verify", {"challenge_id": "x", "code": "000000", "user_id": self.admin}),
                                  ("session.me", {"session_token": "x", "account_id": self.admin})]:
            self.assertEqual(self.public(operation, params, ok=False)["error"]["code"], "VALIDATION")

    def test_invalid_email_and_rate_limit_and_pause(self):
        self.assertFalse(self.public("auth.request_code", {"email": "bad\r\nX: mail"}, ok=False)["ok"])
        self.register()
        self.now += dt.timedelta(seconds=61)
        self.request_code()
        self.assertEqual(self.public("auth.request_code", {"email": "friend@example.test"}, ok=False)["error"]["code"], "RATE_LIMITED")
        self.rpc("settings.update", {"registration_enabled": False})
        self.assert_silently_refused("new@example.test")
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM portal_accounts WHERE email='new@example.test'").fetchone())
        self.now += dt.timedelta(seconds=61)
        self.request_code()  # A verified account may still sign in while new signup is paused.

    def test_closed_registration_also_closes_applications_started_while_open(self):
        self.extra_seats(1)
        in_flight, code = self.request_code("late@example.test")
        self.request_code("abandoned@example.test")
        self.rpc("settings.update", {"registration_enabled": False})
        # A code sent before closing is refused without spending an attempt ...
        refused = self.public("auth.verify", {"challenge_id": in_flight, "code": code}, ok=False)
        self.assertEqual(refused["error"]["code"], "REGISTRATION_CLOSED")
        self.assertEqual(tuple(self.store.conn.execute("SELECT attempts,used_at FROM portal_challenges WHERE id=?", (in_flight,)).fetchone()), (0, None))
        # ... and an application started while open cannot get a new code later.
        self.now += dt.timedelta(days=3)
        self.assert_silently_refused("abandoned@example.test")
        statuses = dict(self.store.conn.execute("SELECT email,status FROM portal_accounts").fetchall())
        self.assertEqual(statuses, {"late@example.test": "unverified", "abandoned@example.test": "unverified"})
        self.assertEqual(registration.capacity(self.store)["waiting"], 0)

    def test_code_sent_before_closing_still_verifies_if_registration_reopens_in_time(self):
        challenge, code = self.request_code("late@example.test")
        self.rpc("settings.update", {"registration_enabled": False})
        self.assertEqual(self.public("auth.verify", {"challenge_id": challenge, "code": code}, ok=False)["error"]["code"], "REGISTRATION_CLOSED")
        self.rpc("settings.update", {"registration_enabled": True})
        self.public("auth.verify", {"challenge_id": challenge, "code": code})
        self.assertEqual(self.store.conn.execute("SELECT status FROM portal_accounts WHERE email='late@example.test'").fetchone()[0], "pending")

    def test_code_requests_reveal_no_difference_between_users_and_strangers(self):
        existing = seed_legacy_user(self.store, {"name": "Existing", "quota_bytes": 100 * 10**9}, self.now)["id"]
        self.store.conn.execute("UPDATE users SET email='existing@example.test',email_verified=1 WHERE id=?", (existing,))
        self.rpc("settings.update", {"registration_enabled": False})
        known = self.public("auth.request_code", {"email": "existing@example.test"})
        stranger = self.public("auth.request_code", {"email": "stranger@example.test"})
        self.assertEqual((set(known), set(known["data"])), (set(stranger), set(stranger["data"])))
        wrong = [self.public("auth.verify", {"challenge_id": reply["data"]["challenge_id"], "code": "000000"}, ok=False)["error"]
                 for reply in (known, stranger)]
        self.assertEqual(wrong[0], wrong[1])
        attempts = [self.store.conn.execute("SELECT attempts FROM portal_challenges WHERE id=?", (reply["data"]["challenge_id"],)).fetchone()[0]
                    for reply in (known, stranger)]
        self.assertEqual(attempts, [1, 1])
        # The same sliding cooldown applies to both, whatever the minute boundary.
        self.now += dt.timedelta(seconds=30)
        for email in ("existing@example.test", "stranger@example.test"):
            self.assertEqual(self.public("auth.request_code", {"email": email}, ok=False)["error"]["code"], "RATE_LIMITED")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE recipient='stranger@example.test'").fetchone()[0], 0)

    def test_strangers_cannot_spend_the_daily_code_budget_of_existing_users(self):
        self.extra_seats(2)
        self.register("existing@example.test")
        accepted, refused = 0, None
        for index in range(300):
            reply = self.public("auth.request_code", {"email": "junk%d@example.test" % index},
                                ok=False, ip="198.51.%d.%d" % (index // 100, index % 100 + 1))
            if not reply["ok"]:
                refused = reply["error"]["code"]
                break
            accepted += 1
            # The SMTP worker drains the queue; only the daily budget remains in play.
            self.store.conn.execute("UPDATE mail_outbox SET status='sent' WHERE status='queued'")
        self.assertEqual((accepted, refused), (199, "RATE_LIMITED"))
        self.now += dt.timedelta(seconds=61)
        self.public("auth.request_code", {"email": "existing@example.test"}, ip="203.0.113.77")

    def test_binding_confirmation_has_no_links_once_and_history_is_redacted(self):
        me, session = self.register()
        token = me["subscriptions"]["clash"].split("/")[-2]
        welcome = self.store.conn.execute("SELECT id,body FROM mail_outbox WHERE kind='portal_welcome'").fetchone()
        payload = self.store.conn.execute("SELECT body FROM mail_private_payload WHERE outbox_id=?", (welcome["id"],)).fetchone()[0]
        self.assertNotIn("https://", payload)
        self.assertNotIn(token, payload)
        self.assertIn("等待管理员",payload)
        self.assertNotIn(token, welcome["body"])
        self.assertNotIn(token, json.dumps(snapshot(self.store, self.now)))
        self.assertNotIn(session, "".join(row[0] for row in self.store.conn.execute("SELECT response_json FROM requests")))
        self.now += dt.timedelta(seconds=61)
        challenge, code = self.request_code()
        self.public("auth.verify", {"challenge_id": challenge, "code": code})
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_welcome'").fetchone()[0], 1)

    def test_each_verified_application_notifies_verified_admin_once_without_applicant_details(self):
        queued = self.rpc("mail.verify.send")["data"]
        payload = self.store.conn.execute("SELECT body FROM mail_private_payload WHERE outbox_id=?", (queued["id"],)).fetchone()[0]
        code = re.search(r"[0-9]{6}", payload).group()
        self.assertTrue(self.rpc("mail.verify.confirm", {"code": code})["data"]["verified"])
        self.rpc("mail.preferences", {"enabled": True, "cooldown_seconds": 86400})
        self.extra_seats(1)

        def notices():
            return self.store.conn.execute("SELECT * FROM mail_outbox WHERE kind='portal_application_notice' ORDER BY id").fetchall()

        applicants = (("first@example.test", "申请甲"), ("second@example.test", "申请乙"))
        for index, (email, nickname) in enumerate(applicants):
            challenge, code = self.request_code(email, nickname)
            self.assertEqual(len(notices()), index)  # Requesting a code is not yet an application.
            response = self.public("auth.verify", {"challenge_id": challenge, "code": code})["data"]
            account = self.public("session.me", {"session_token": response["session_token"]})["data"]["account"]
            self.assertEqual(account["status"], "pending")
            self.assertEqual(len(notices()), index + 1)  # Every applicant bypasses the generic cooldown.

        self.now += dt.timedelta(seconds=61)
        challenge, code = self.request_code(applicants[0][0])
        self.public("auth.verify", {"challenge_id": challenge, "code": code})
        self.assertEqual(len(notices()), 2)  # A later login cannot create a second application notice.
        self.assertEqual(len({row["event_key"] for row in notices()}), 2)
        for row in notices():
            self.assertEqual(row["recipient"], "admin@example.test")
            self.assertIsNone(row["user_id"])
            self.assertIn("有一份新的注册申请", row["subject"])
            for email, nickname in applicants:
                self.assertNotIn(email, row["subject"] + row["body"])
                self.assertNotIn(nickname, row["subject"] + row["body"])

        messages = []
        class FakeSMTP:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def login(self, *_): pass
            def send_message(self, message):
                messages.append(message)
                return {}
        with patch.object(mail.smtplib, "SMTP_SSL", new=lambda *args, **kwargs: FakeSMTP()):
            for _ in range(20):
                if not mail.process_live_outbox(self.store, self.now).get("processed"):
                    break
        delivered = [message for message in messages if "有一份新的注册申请" in str(message["Subject"])]
        self.assertEqual(len(delivered), 2)
        for message in delivered:
            self.assertEqual(message["To"], "admin@example.test")
            for email, nickname in applicants:
                self.assertNotIn(email, message.get_content())
                self.assertNotIn(nickname, message.get_content())
        self.assertTrue(all(row["status"] == "sent" for row in notices()))

    def advance_fresh(self, seconds):
        """Let time pass while the member keeps a fresh, trusted stream."""
        for _ in range(int(seconds // 4) + 1):
            self.now += dt.timedelta(seconds=4)
            self.sample_origin()

    def test_page_named_challenge_survives_a_lost_reply(self):
        chosen = str(uuid.uuid4())
        reply = self.public("auth.request_code", {"email": "friend@example.test", "challenge_id": chosen})
        self.assertEqual(reply["data"], {"challenge_id": chosen})
        # The phone never saw this reply. The page still holds its own name for
        # the challenge, so the mailed code verifies in the same box.
        payload = self.store.conn.execute("SELECT p.body FROM portal_mail m JOIN mail_private_payload p ON m.outbox_id=p.outbox_id "
                                          "WHERE m.challenge_id=?", (chosen,)).fetchone()[0]
        signed = self.public("auth.verify", {"challenge_id": chosen, "code": re.search(r"[0-9]{6}", payload).group()})
        self.assertIn("session_token", signed["data"])
        self.now += dt.timedelta(seconds=61)
        for bad in (chosen, chosen.upper(), "not-a-uuid", "{" + str(uuid.uuid4()) + "}", 7):
            with self.subTest(bad=bad):
                refused = self.public("auth.request_code", {"email": "friend@example.test", "challenge_id": bad}, ok=False)
                self.assertEqual(refused["error"]["code"], "VALIDATION")
        # A refused address gets the same, page-named decoy.
        self.rpc("settings.update", {"registration_enabled": False})
        decoy = str(uuid.uuid4())
        self.assertEqual(self.public("auth.request_code", {"email": "stranger@example.test", "challenge_id": decoy})["data"],
                         {"challenge_id": decoy})
        self.assertEqual(self.store.conn.execute("SELECT account_id FROM portal_challenges WHERE id=?", (decoy,)).fetchone()[0],
                         registration.DECOY)

    def test_signed_in_resend_reaches_only_the_verified_mailbox_at_a_bounded_rate(self):
        self.extra_seats(1)
        pending, pending_session = self.register("waiting@example.test")
        self.assertEqual(self.public("session.resend_subscription", {"session_token": pending_session}, ok=False)["error"]["code"],
                         "NOT_ACTIVE")
        self.now += dt.timedelta(seconds=61)
        me, session = self.running_registration()
        resend = lambda ok=True: self.public("session.resend_subscription", {"session_token": session}, ok=ok)
        self.assertEqual(resend()["data"], {"queued": True, "email": "friend@example.test"})
        row = self.store.conn.execute("SELECT id,recipient,body FROM mail_outbox WHERE kind='subscription_resend'").fetchone()
        private = self.store.conn.execute("SELECT body FROM mail_private_payload WHERE outbox_id=?", (row["id"],)).fetchone()[0]
        self.assertEqual(row["recipient"], "friend@example.test")
        for link in me["subscriptions"].values():
            self.assertIn(link, private)
            self.assertNotIn(link, row["body"])
        self.assertIn("你在个人中心请求重新发送", private)
        sent = []
        while mail.process_live_outbox(self.store, self.now, delivery=lambda _, message, secret: sent.append(message)).get("processed"):
            pass
        resent = [message for message in sent if message["kind"] == "subscription_resend"]
        self.assertEqual([message["recipient"] for message in resent], ["friend@example.test"])
        self.assertIn(me["subscriptions"]["clash"], resent[0]["body"])
        self.assertEqual(resend(ok=False)["error"]["code"], "RESEND_COOLDOWN")
        for _ in range(4):
            self.advance_fresh(registration.RESEND_COOLDOWN_SECONDS)
            self.assertTrue(resend()["ok"])
        self.advance_fresh(registration.RESEND_COOLDOWN_SECONDS)
        self.assertEqual(resend(ok=False)["error"]["code"], "RESEND_COOLDOWN")  # Daily limit.
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='subscription_resend'").fetchone()[0],
                         registration.RESEND_DAILY_LIMIT)
        self.public("session.logout", {"session_token": session})
        self.assertEqual(resend(ok=False)["error"]["code"], "UNAUTHENTICATED")

    def test_one_unsendable_message_cannot_block_every_later_code(self):
        self.extra_seats(2)
        sent = []
        deliver = lambda _, message, secret: sent.append(message["recipient"])
        original = registration.authorize_mail
        def authorize(store, message, now):
            if message["recipient"] == "broken@example.test":
                raise RuntimeError("unexpected authorization failure")
            return original(store, message, now)
        for case in ("missing_private_body", "authorization_error"):
            with self.subTest(case=case):
                stuck, _ = self.request_code("lost@example.test" if case == "missing_private_body" else "broken@example.test")
                self.now += dt.timedelta(seconds=1)
                self.request_code("next-%s@example.test" % case)
                outbox = self.store.conn.execute("SELECT outbox_id FROM portal_mail WHERE challenge_id=?", (stuck,)).fetchone()[0]
                if case == "missing_private_body":
                    self.store.conn.execute("DELETE FROM mail_private_payload WHERE outbox_id=?", (outbox,))
                with patch.object(registration, "authorize_mail", side_effect=authorize):
                    # Each call used to raise and roll back its own claim, so the
                    # same oldest message was claimed again every five seconds.
                    self.assertEqual(mail.process_live_outbox(self.store, self.now, delivery=deliver)["state"], "dead")
                    self.assertEqual(mail.process_live_outbox(self.store, self.now, delivery=deliver)["state"], "sent")
                self.assertEqual(sent[-1], "next-%s@example.test" % case)
                self.assertEqual(tuple(self.store.conn.execute("SELECT status,error_code FROM mail_outbox WHERE id=?", (outbox,)).fetchone()),
                                 ("dead", "DELIVERY_FAILED"))
                self.assertIsNone(self.store.conn.execute("SELECT 1 FROM mail_private_payload WHERE outbox_id=?", (outbox,)).fetchone())
                self.now += dt.timedelta(seconds=61)

    def test_email_delivery_authorizes_private_recipient_and_cancels_stale_codes(self):
        challenge, code = self.request_code()
        self.now += dt.timedelta(seconds=61)
        newer, code2 = self.request_code()
        self.assertEqual(mail.process_live_outbox(self.store, self.now, delivery=lambda *_: None)["state"], "cancelled")
        sent = []
        mail.process_live_outbox(self.store, self.now, delivery=lambda _, message, secret: sent.append(message["body"]))
        self.assertIn(code2, sent[0]); self.assertNotIn(code, sent[0])
        self.public("auth.verify", {"challenge_id": newer, "code": code2})
        self.assertEqual(mail.process_live_outbox(self.store, self.now, delivery=lambda _, message, secret: sent.append(message["body"]))["state"], "sent")
        self.assertIn("邮箱已绑定", sent[-1])
        self.assertNotIn("https://", sent[-1])
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM mail_private_payload WHERE outbox_id=(SELECT id FROM mail_outbox WHERE kind='portal_welcome')").fetchone())

    def test_sessions_are_distinct_hashed_expire_and_isolate_accounts(self):
        self.extra_seats(1)
        first, one = self.register()
        second, two = self.register("second@example.test")
        self.assertNotEqual(first["account"]["id"], second["account"]["id"])
        self.assertEqual(self.public("session.me", {"session_token": one})["data"]["account"]["id"], first["account"]["id"])
        rows = list(self.store.conn.execute("SELECT token_hash FROM portal_sessions"))
        self.assertTrue(all(one not in r[0] and two not in r[0] for r in rows))
        self.public("session.logout", {"session_token": one})
        self.assertEqual(self.public("session.me", {"session_token": one}, ok=False)["error"]["code"], "UNAUTHENTICATED")
        self.now += dt.timedelta(days=7)
        self.assertEqual(self.public("session.me", {"session_token": two}, ok=False)["error"]["code"], "UNAUTHENTICATED")

    def test_approval_reuses_original_token_is_idempotent_and_waits_for_runtime(self):
        me, _ = self.register(); account = me["account"]["id"]; token = me["subscriptions"]["clash"].split("/")[-2]
        request = str(uuid.uuid4())
        result = self.rpc("registration.approve", {"account_id": account}, request_id=request)
        self.assertEqual(result["data"]["account"]["status"], "provisioning")
        self.assertEqual(self.store.get_credentials(self.member)["subscription_token"], token)
        self.assertEqual(subscription_response(self.store, token, "config.yaml", self.now)["status"], 403)
        self.rpc("registration.approve", {"account_id": account}, request_id=request)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM production_jobs").fetchone()[0], 1)

    def test_same_preissued_links_become_usable_only_after_trusted_activation(self):
        me, session = self.register()
        token = me["subscriptions"]["clash"].split("/")[-2]
        self.rpc("registration.approve", {"account_id": me["account"]["id"]})
        for _ in range(2):
            self.assertTrue(process_one_job(self.store, self.helper, now=self.now)["applied"])
        worker = self.store.worker(self.member)
        self.assertEqual(worker["observed_state"], "staged")
        self.assertEqual(subscription_response(self.store, token, "config.yaml", self.now)["status"], 403)
        self.store.conn.execute("BEGIN IMMEDIATE")
        accept_sample(self.store, self.member, worker["observed_generation"], MeterSample("stage-epoch", 0, 0, timestamp(self.now)), self.now)
        self.store.conn.commit()
        self.assertTrue(process_one_job(self.store, self.helper, now=self.now)["applied"])
        self.assertEqual(self.public("session.me", {"session_token": session})["data"]["account"]["status"], "provisioning")
        self.sample_origin()
        self.assertEqual(self.public("session.me", {"session_token": session})["data"]["account"]["status"], "active")
        for route in ("config.yaml", "nodes.txt"):
            artifact = subscription_response(self.store, token, route, self.now)
            self.assertEqual(artifact["status"], 200)
            self.assertTrue(artifact["body"])
        self.assertNotIn("subscriptions", self.public("session.me", {"session_token": session})["data"])
        self.rpc("user.disable", {"user_id": self.member})
        self.assertEqual(subscription_response(self.store, token, "config.yaml", self.now)["status"], 403)
        self.assertEqual(self.public("session.me", {"session_token": session})["data"]["account"]["status"], "disabled")
        self.rpc("user.enable", {"user_id": self.member})
        self.assertEqual(self.store.get_credentials(self.member)["subscription_token"], token)
        self.assertEqual(subscription_response(self.store, token, "config.yaml", self.now)["status"], 200)

    def test_concurrent_approval_claims_one_account_and_slot(self):
        me, _ = self.register(); identifier = me["account"]["id"]
        revision = self.store.revision
        def approve_once(_):
            with ProductionStore(self.folder.name, policy=self.policy) as store:
                return handle_request(store, {"api_version": 1,"request_id": str(uuid.uuid4()),"action":"registration.approve",
                    "server_id":store.server_id,"expected_revision":revision,"params":{"account_id":identifier}}, self.now)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(approve_once, range(2)))
        self.assertEqual(sum(reply["ok"] for reply in replies), 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM production_jobs").fetchone()[0], 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 1)

    def test_login_rate_is_durable_across_restarts_and_queue_is_bounded(self):
        self.request_code()
        with ProductionStore(self.folder.name, policy=self.policy) as another:
            self.assertEqual(self.public("auth.request_code", {"email":"friend@example.test"}, store=another,ok=False)["error"]["code"], "RATE_LIMITED")
        for i in range(200):
            mail._enqueue(self.store,event_key="queue-fixture-"+str(i),user_id=None,cycle_id=None,recipient="fixture@example.test",kind="test",subject="fixture",body="fixture",now=self.now)
        self.assertEqual(self.public("auth.request_code", {"email":"another@example.test"},ok=False)["error"]["code"], "RATE_LIMITED")

    def test_quota_cycle_cannot_approve_or_restore_pending_or_revoked_accounts(self):
        me, session = self.register()
        before = me["subscriptions"]
        self.now += dt.timedelta(days=32)
        self.rpc("status")
        self.assertEqual(registration.snapshot(self.store,self.now)["accounts"][0]["status"],"pending")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0],0)
        self.assertEqual(subscription_response(self.store,before["clash"].split("/")[-2],"config.yaml",self.now)["status"],403)

    def test_full_seats_refuse_new_applications_with_the_full_message(self):
        first, _ = self.register()
        # The public status carries the full message; the code reply itself
        # does not reveal whether a particular address could have applied.
        status = self.public("registration.status", {})["data"]
        self.assertEqual((status["enabled"], status["full"], status["accepting"], status["message"]),
                         (True, True, False, registration.FULL_MESSAGE))
        self.assert_silently_refused("next@example.test")
        self.assertIsNone(self.store.conn.execute("SELECT 1 FROM portal_accounts WHERE email='next@example.test'").fetchone())
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE recipient='next@example.test'").fetchone()[0], 0)
        self.rpc("registration.reject", {"account_id": first["account"]["id"]})
        self.assertTrue(self.public("registration.status", {})["data"]["accepting"])
        self.now += dt.timedelta(seconds=61)  # The refused request still counted toward its cooldown.
        self.register("next@example.test")

    def test_seat_taken_elsewhere_still_leaves_a_pending_application_waiting(self):
        first, _ = self.register()
        seed_legacy_user(self.store, {"name": "Taken by administrator", "quota_bytes": 100 * 10**9}, self.now)
        result = self.rpc("registration.approve", {"account_id": first["account"]["id"]})
        self.assertTrue(result["data"]["waiting_resources"])
        self.assertEqual(result["data"]["account"]["status"], "waiting_resources")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 1)

    def test_freed_historical_slot_is_not_a_registration_seat_for_approval(self):
        policy = json.loads(json.dumps(self.policy)); policy.update(version=2, portal_uid=1002)
        for port in range(24432, 24435):
            policy["workers"][str(uuid.uuid4())] = {"role": "member", "public_port": port, "api_port": port + 10000}
        original_store = self.store
        with ProductionStore(self.folder.name, policy=policy) as expanded:
            self.store = expanded
            try:
                me, _ = self.register("waiting@example.test")
                # Every registration seat became unusable after verification; only
                # the historical 24431 slot is unassigned, and it is not a seat.
                expanded.conn.execute("UPDATE production_workers SET tombstoned=1 WHERE public_port BETWEEN 24432 AND 24434")
                reply = self.rpc("registration.approve", {"account_id": me["account"]["id"]})["data"]
                self.assertTrue(reply["waiting_resources"])
                self.assertEqual(reply["account"]["status"], "waiting_resources")
                self.assertEqual(expanded.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
            finally:
                self.store = original_store

    def test_code_sent_before_the_last_seat_filled_is_refused_but_stays_usable(self):
        challenge, code = self.request_code("late@example.test")
        early, _ = self.register("early@example.test")
        refused = self.public("auth.verify", {"challenge_id": challenge, "code": code}, ok=False)
        self.assertEqual(refused["error"]["code"], "REGISTRATION_FULL")
        late = self.store.conn.execute("SELECT * FROM portal_accounts WHERE email='late@example.test'").fetchone()
        self.assertIsNone(late["email_verified_at"])
        row = self.store.conn.execute("SELECT attempts,used_at FROM portal_challenges WHERE id=?", (challenge,)).fetchone()
        self.assertEqual((row["attempts"], row["used_at"]), (0, None))
        self.rpc("registration.reject", {"account_id": early["account"]["id"]})
        self.public("auth.verify", {"challenge_id": challenge, "code": code})

    def test_existing_verified_user_can_still_sign_in_when_seats_are_full(self):
        existing = seed_legacy_user(self.store, {"name": "Existing", "quota_bytes": 100 * 10**9}, self.now)["id"]
        self.store.conn.execute("UPDATE users SET email='existing@example.test',email_verified=1 WHERE id=?", (existing,))
        self.assertTrue(self.public("registration.status", {})["data"]["full"])
        self.assert_silently_refused("stranger@example.test")
        me, _ = self.register("existing@example.test")
        self.assertEqual(me["account"]["proxy_user_id"], existing)

    def test_closed_registration_status_is_public_but_reveals_no_counts(self):
        self.store.set_setting("registration_enabled", False)
        status = self.public("registration.status", {})["data"]
        self.assertEqual(set(status), {"enabled", "full", "accepting", "message"})
        self.assertEqual((status["enabled"], status["full"], status["accepting"]), (False, False, False))
        self.assertFalse(self.public("registration.status", {"extra": "x"}, ok=False)["ok"])

    def test_three_new_seats_accept_three_applicants_and_refuse_the_fourth(self):
        original_user = seed_legacy_user(self.store, {"name":"Existing member", "role":"member", "quota_bytes":100000}, self.now)["id"]
        original_token = self.store.get_credentials(original_user)["subscription_token"]
        policy = json.loads(json.dumps(self.policy)); policy.update(version=2, portal_uid=1002)
        for port in range(24432,24435):
            policy["workers"][str(uuid.uuid4())] = {"role":"member", "public_port":port, "api_port":port+10000}
        original_store = self.store
        with ProductionStore(self.folder.name, policy=policy) as expanded:
            self.store = expanded
            try:
                for index in range(3):
                    me, _ = self.register(f"seat{index}@example.test")
                    reply = self.rpc("registration.approve", {"account_id":me["account"]["id"]})["data"]
                    self.assertEqual(reply["account"]["status"], "provisioning")
                self.assert_silently_refused("seat3@example.test")
                self.assertEqual(registration.snapshot(expanded,self.now)["pool"], {"available":0,"total":3})
                self.assertEqual(expanded.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0],4)
                self.assertEqual(expanded.get_credentials(original_user)["subscription_token"],original_token)
            finally:
                self.store = original_store

    def test_rejected_retention_boundary_runs_without_any_app_connected(self):
        from dazzle.collector import tick
        me, session = self.register(); account = me["account"]["id"]
        self.rpc("registration.reject", {"account_id": account})
        deadline = self.now + dt.timedelta(hours=72)
        row = registration.snapshot(self.store, self.now)["accounts"][0]
        self.assertEqual(row["rejected_delete_at"], timestamp(deadline))
        tick(self.store, deadline - dt.timedelta(microseconds=1))
        self.assertEqual(registration._account(self.store, account)["status"], "rejected")
        revision = self.store.revision
        rate_count = self.store.conn.execute("SELECT COUNT(*) FROM portal_rate").fetchone()[0]
        tick(self.store, deadline)
        self.assertEqual(self.store.revision, revision + 1)
        self.assertFalse(registration.snapshot(self.store, deadline)["accounts"])
        for table in ("portal_sessions", "portal_challenges", "portal_mail"):
            self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM " + table + " WHERE account_id=?", (account,)).fetchone()[0], 0)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_private_payload").fetchone()[0], 0)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM portal_rate").fetchone()[0], rate_count)
        self.assertEqual(registration.prune_rejected(self.store, deadline), 0)
        self.now = deadline
        self.assertEqual(self.public("session.me", {"session_token": session}, ok=False)["error"]["code"], "UNAUTHENTICATED")
        self.assertEqual(self.rpc("registration.approve", {"account_id": account}, ok=False)["error"]["code"], "NOT_FOUND")
        replacement, _ = self.register()
        self.assertNotEqual(replacement["account"]["id"], account)

    def test_retention_starts_at_rejection_and_repeated_rejection_does_not_extend_it(self):
        me, _ = self.register(); account = me["account"]["id"]
        created = self.now
        self.now += dt.timedelta(days=10)
        self.rpc("registration.reject", {"account_id": account})
        rejected = self.now
        self.now += dt.timedelta(hours=71)
        self.rpc("registration.reject", {"account_id": account})
        self.assertEqual(registration._account(self.store, account)["updated_at"], timestamp(rejected))
        self.assertEqual(registration.prune_rejected(self.store, rejected - dt.timedelta(seconds=30)), 0)
        self.assertEqual(registration.prune_rejected(self.store, self.now), 0)
        self.assertEqual(registration.prune_rejected(self.store, rejected + dt.timedelta(hours=72)), 1)
        self.assertLess(created, rejected)

    def test_expired_rejection_does_not_touch_linked_users_or_other_application_states(self):
        me, _ = self.register(); linked = me["account"]["id"]
        self.rpc("registration.approve", {"account_id": linked})
        users = [tuple(row) for row in self.store.conn.execute("SELECT * FROM users")]
        credentials = [tuple(row) for row in self.store.conn.execute("SELECT * FROM credentials")]
        workers = [tuple(row) for row in self.store.conn.execute("SELECT * FROM production_workers")]
        # Even a damaged linked row is excluded from automatic application cleanup.
        self.store.conn.execute("UPDATE portal_accounts SET status='rejected' WHERE id=?", (linked,))
        for status in ("pending", "unverified", "waiting_resources", "approved", "revoked", "rejected"):
            self.store.conn.execute("INSERT INTO portal_accounts(id,email,nickname,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                                    (status, status + "@example.test", status, status, timestamp(self.now), timestamp(self.now)))
        self.assertEqual(registration.prune_rejected(self.store, self.now + dt.timedelta(hours=72)), 1)
        self.assertIsNotNone(self.store.conn.execute("SELECT 1 FROM portal_accounts WHERE id=?", (linked,)).fetchone())
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM portal_accounts").fetchone()[0], 6)
        for table, previous in [("users", users), ("credentials", credentials), ("production_workers", workers)]:
            self.assertEqual([tuple(row) for row in self.store.conn.execute("SELECT * FROM " + table)], previous)

    def test_rejected_cleanup_waits_for_inflight_mail_and_preserves_notification_history(self):
        me, _ = self.register(); account = me["account"]["id"]
        self.rpc("registration.reject", {"account_id": account})
        message = self.store.conn.execute("SELECT outbox_id FROM portal_mail WHERE account_id=? LIMIT 1", (account,)).fetchone()[0]
        self.store.conn.execute("UPDATE mail_outbox SET status='sending' WHERE id=?", (message,))
        deadline = self.now + dt.timedelta(hours=72)
        self.assertEqual(registration.prune_rejected(self.store, deadline), 0)
        self.store.conn.execute("UPDATE mail_outbox SET status='sent' WHERE id=?", (message,))
        pending = self.store.conn.execute("SELECT COUNT(*) FROM portal_mail m JOIN mail_outbox o ON m.outbox_id=o.id WHERE m.account_id=? AND o.status IN ('queued','retry')", (account,)).fetchone()[0]
        self.assertEqual(registration.prune_rejected(self.store, deadline), 1)
        self.assertEqual(self.store.conn.execute("SELECT status FROM mail_outbox WHERE id=?", (message,)).fetchone()[0], "sent")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE status='cancelled' AND error_code='REGISTRATION_RETENTION_EXPIRED'").fetchone()[0], pending)

    def test_rejected_cleanup_is_transactional_and_handles_legacy_timestamps(self):
        from dazzle.collector import tick
        me, _ = self.register(); account = me["account"]["id"]
        self.rpc("registration.reject", {"account_id": account})
        deadline = self.now + dt.timedelta(hours=72)
        self.store.conn.execute("UPDATE portal_accounts SET updated_at=? WHERE id=?", (self.now.astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat(), account))
        with patch("dazzle.registration.queue_activation_notices", side_effect=RuntimeError("fixture maintenance failure")):
            with self.assertRaises(RuntimeError): tick(self.store, deadline)
        self.assertEqual(registration._account(self.store, account)["status"], "rejected")
        self.assertGreater(self.store.conn.execute("SELECT COUNT(*) FROM portal_sessions WHERE account_id=?", (account,)).fetchone()[0], 0)
        tick(self.store, deadline)
        self.assertFalse(registration.snapshot(self.store, deadline)["accounts"])

    def test_rejection_has_no_runtime_or_quota_side_effects(self):
        me, _ = self.register(); account = me["account"]["id"]
        self.rpc("registration.reject", {"account_id": account, "reason": "not now"})
        self.assertEqual(registration.snapshot(self.store, self.now)["accounts"][0]["status"], "rejected")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
        self.rpc("registration.approve", {"account_id": account})  # A later explicit admin action may reconsider.
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_personal_allowance_includes_topups_and_unlimited_is_not_zero(self):
        # A historical byte-scale allowance is still readable after adoption.
        seed_legacy_user(self.store, {"name":"Legacy allowance", "quota_bytes":123}, self.now)
        self.store.conn.execute("UPDATE users SET topup_bytes=456,email='friend@example.test',email_verified=1 WHERE id=?", (self.member,))
        me, session = self.register()
        account = registration._public(self.store, registration._account(self.store, me["account"]["id"]), self.now)
        self.assertEqual(account["allowance_bytes"],579)
        self.assertEqual(account["topup_bytes"],456)
        self.assertFalse(account["unlimited"])
        self.store.conn.execute("UPDATE users SET unlimited=1 WHERE id=?", (self.member,))
        account = registration._public(self.store, registration._account(self.store, me["account"]["id"]), self.now)
        self.assertTrue(account["unlimited"])
        self.assertIsNone(account["allowance_bytes"])
        public = self.public("session.me", {"session_token":session})["data"]["account"]
        self.assertTrue({"allowance_bytes", "unlimited", "topup_bytes", "used_upload", "used_download", "quota_bytes", "node_names"}.isdisjoint(public))

    def test_subscription_resend_uses_verified_email_and_same_private_links(self):
        user_id = self.existing_user(active=True)
        credentials = dict(self.store.get_credentials(user_id))
        before = dict(self.store.get_user(user_id))
        result = self.rpc("user.subscription_email", {"user_id": user_id})
        self.assertTrue(result["data"]["mail"]["queued"])
        row = self.store.conn.execute("SELECT * FROM mail_outbox WHERE kind='subscription_resend'").fetchone()
        payload = self.store.conn.execute("SELECT body FROM mail_private_payload WHERE outbox_id=?", (row["id"],)).fetchone()[0]
        self.assertEqual(row["recipient"], "friend@example.test")
        self.assertIn(credentials["subscription_token"] + "/config.yaml", payload)
        self.assertIn(credentials["subscription_token"] + "/nodes.txt", payload)
        self.assertNotIn(credentials["subscription_token"], row["body"])
        self.assertNotIn(credentials["subscription_token"], json.dumps(result))
        self.assertEqual(dict(self.store.get_credentials(user_id)), credentials)
        self.assertEqual(dict(self.store.get_user(user_id)), before)
        sent = self.drain_mail()
        self.assertEqual(sum(kind == "subscription_resend" for kind, _ in sent), 1)

    def test_subscription_resend_is_request_idempotent_and_cools_down(self):
        user_id = self.existing_user(active=True)
        identifier = str(uuid.uuid4())
        first = self.rpc("user.subscription_email", {"user_id": user_id}, request_id=identifier)
        second = self.rpc("user.subscription_email", {"user_id": user_id}, request_id=identifier)
        self.assertEqual(first, second)
        cooldown = self.rpc("user.subscription_email", {"user_id": user_id})
        self.assertFalse(cooldown["data"]["mail"]["queued"])
        self.assertEqual(cooldown["data"]["mail"]["reason"], "cooldown")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='subscription_resend'").fetchone()[0], 1)

    def test_subscription_resend_rejects_unavailable_or_unverified_users(self):
        user_id = self.existing_user(active=True)
        self.store.conn.execute("UPDATE users SET email_verified=0 WHERE id=?", (user_id,))
        self.assertEqual(self.rpc("user.subscription_email", {"user_id": user_id}, ok=False)["error"]["code"], "EMAIL_NOT_VERIFIED")
        self.store.conn.execute("UPDATE users SET email_verified=1,manual_disabled=1 WHERE id=?", (user_id,))
        self.assertEqual(self.rpc("user.subscription_email", {"user_id": user_id}, ok=False)["error"]["code"], "NOT_ACTIVE")
        self.store.conn.execute("UPDATE users SET manual_disabled=0 WHERE id=?", (user_id,))
        self.store.conn.execute("DELETE FROM mail_secrets")
        self.assertEqual(self.rpc("user.subscription_email", {"user_id": user_id}, ok=False)["error"]["code"], "MAIL_NOT_CONFIGURED")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='subscription_resend'").fetchone()[0], 0)

    def test_queued_subscription_resend_rechecks_rotation_and_current_authorization(self):
        user_id = self.existing_user(active=True)
        self.rpc("user.subscription_email", {"user_id": user_id})
        self.store.conn.execute("UPDATE credentials SET subscription_token=? WHERE user_id=?", ("rotated-token-" + "a" * 40, user_id))
        delivered = []
        result = mail.process_live_outbox(self.store, self.now, delivery=lambda *args: delivered.append(args))
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(delivered, [])
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_private_payload").fetchone()[0], 0)

    def test_rotation_and_revocation_invalidate_previously_emailed_url(self):
        me, session = self.register(); account = me["account"]["id"]; old = me["subscriptions"]["clash"].split("/")[-2]
        self.rpc("registration.approve", {"account_id": account})
        self.rpc("user.rotate", {"user_id": self.member})
        self.assertEqual(subscription_response(self.store, old, "config.yaml", self.now)["status"], 404)
        fresh = registration._links(self.store, registration._account(self.store, account))["clash"]
        self.assertNotIn(old, fresh)
        self.rpc("user.revoke", {"user_id": self.member})
        self.assertIsNone(self.store.conn.execute("SELECT subscription_token FROM portal_accounts WHERE id=?", (account,)).fetchone()[0])
        self.assertEqual(subscription_response(self.store, fresh.split("/")[-2], "config.yaml", self.now)["status"], 404)
        self.assertEqual(self.public("session.me", {"session_token": session}, ok=False)["error"]["code"], "UNAUTHENTICATED")

    def test_subscription_fetch_does_not_activate_and_does_not_expose_other_data(self):
        me, _ = self.register(); token = me["subscriptions"]["clash"].split("/")[-2]
        result = self.public("subscription.fetch", {"token": token, "route": "config.yaml"})["data"]
        self.assertEqual(result, {"status": 403, "headers": {"Cache-Control": "no-store"}, "body_b64": ""})
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 0)

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED") or hasattr(socket.socket, "getpeereid"), "Unix peer credentials unavailable")
    def test_peer_identity_uses_kernel_not_request_fields(self):
        first, second = socket.socketpair(); self.addCleanup(first.close); self.addCleanup(second.close)
        self.assertEqual(peer_uid(first), os.geteuid())

    def test_smtp_failure_retries_same_welcome_without_recreating_user(self):
        me, _ = self.register()
        # Spent challenge is cancelled, then the welcome is retried with identical private payload.
        for _ in range(2):
            mail.process_live_outbox(self.store, self.now, delivery=lambda *_: (_ for _ in ()).throw(mail.MailDeliveryError("TRANSIENT_DELIVERY_FAILURE")))
        self.assertEqual(self.store.conn.execute("SELECT status FROM mail_outbox WHERE kind='portal_welcome'").fetchone()[0], "retry")
        self.now += dt.timedelta(seconds=60)
        for _ in range(2):
            mail.process_live_outbox(self.store, self.now, delivery=lambda *_: None)
        self.assertEqual(self.store.conn.execute("SELECT status FROM mail_outbox WHERE kind='portal_welcome'").fetchone()[0], "sent")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM portal_accounts").fetchone()[0], 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def existing_user(self, *, email="friend@example.test", verified=True, active=False):
        user_id = self.rpc("user.add", {"name": "Existing", "role": "member", "quota_bytes": 100_000_000_000})["data"]["user"]["id"]
        self.store.conn.execute("UPDATE users SET email=?,email_verified=?,used_upload=123,used_download=456 WHERE id=?", (email, int(verified), user_id))
        if active:
            self.store.conn.execute("UPDATE users SET manual_disabled=0,trusted_sample=1,meter_state='trusted',meter_epoch='existing-origin',last_sample_at=?,reasons_json='[]' WHERE id=?", (timestamp(self.now), user_id))
            self.store.conn.execute("UPDATE production_workers SET provisioned=1,public_key=?,credential_version=1,observed_state='running',process_id=123,origin_pending=0 WHERE user_id=?", ("a"*43, user_id))
        return user_id

    def test_existing_verified_email_links_original_identity_without_user_or_mail_recreation(self):
        user_id = self.existing_user(email="Friend@Example.Test", active=True)
        old_user, old_credentials = self.store.get_user(user_id), self.store.get_credentials(user_id)
        old_jobs = self.store.conn.execute("SELECT COUNT(*) FROM production_jobs").fetchone()[0]
        self.store.set_setting("registration_enabled", False)
        me, _ = self.register("friend@example.test")
        self.assertEqual(me["account"]["proxy_user_id"], user_id)
        self.assertEqual(me["account"]["status"], "active")
        self.assertIn(old_credentials["subscription_token"], me["subscriptions"]["clash"])
        self.assertEqual(self.store.get_credentials(user_id), old_credentials)
        self.assertEqual(self.store.get_user(user_id), old_user)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM production_jobs").fetchone()[0], old_jobs)
        self.assertIsNotNone(self.store.conn.execute("SELECT activation_notified_at FROM portal_accounts").fetchone()[0])
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind IN ('portal_welcome','portal_activated','portal_application_notice')").fetchone()[0], 0)
        self.activation_tick()
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind='portal_activated'").fetchone()[0], 0)

    def test_unverified_matching_email_cannot_claim_or_create_a_duplicate_proxy(self):
        user_id = self.existing_user(verified=False)
        credentials = self.store.get_credentials(user_id)
        me, _ = self.register()
        self.assertIsNone(me["account"]["proxy_user_id"])
        self.assertEqual(me["account"]["status"], "needs_confirmation")
        self.assertEqual(me["account"]["binding_issue"], "email_not_verified")
        self.assertEqual(me["subscriptions"], {"clash": None, "shadowrocket": None})
        self.assertFalse(self.rpc("registration.approve", {"account_id": me["account"]["id"]}, ok=False)["ok"])
        self.assertEqual(self.store.get_credentials(user_id), credentials)

    def test_changing_verified_email_removes_old_session_access_to_secrets(self):
        user_id = self.existing_user(active=True)
        _, session = self.register()
        self.assertEqual(self.public("session.subscription", {"session_token": session, "format": "clash"}, ok=False)["error"]["code"], "EMAIL_DELIVERY_ONLY")
        self.store.conn.execute("UPDATE users SET email='new@example.test',email_verified=0 WHERE id=?", (user_id,))
        for operation, extra in (("session.me", {}), ("session.subscription", {"format": "clash"})):
            result = self.public(operation, {"session_token": session, **extra}, ok=False)
            self.assertEqual(result["error"]["code"], "UNAUTHENTICATED")

    def test_email_change_cancels_queued_subscription_mail_to_previous_address(self):
        _, _session = self.running_registration()
        self.activation_tick()
        self.store.conn.execute("UPDATE users SET email='changed@example.test',email_verified=0 WHERE id=?", (self.member,))
        self.assertFalse(any(kind == "portal_activated" for kind, _body in self.drain_mail()))
        self.assertIsNone(self.store.conn.execute("SELECT activation_notified_at FROM portal_accounts").fetchone()[0])

    def test_duplicate_verified_email_and_revoked_identity_never_auto_link(self):
        user_id = self.existing_user()
        admin_id = self.rpc("user.add", {"name": "Admin", "role": "admin"})["data"]["user"]["id"]
        self.store.conn.execute("UPDATE users SET email='FRIEND@example.test',email_verified=1 WHERE id=?", (admin_id,))
        me, _ = self.register()
        self.assertIsNone(me["account"]["proxy_user_id"])
        self.assertEqual(me["account"]["binding_issue"], "email_conflict")
        self.store.conn.execute("UPDATE users SET email='other@example.test' WHERE id=?", (admin_id,))
        self.rpc("user.revoke", {"user_id": user_id})
        self.now += dt.timedelta(seconds=61)
        me, _ = self.register()
        self.assertIsNone(me["account"]["proxy_user_id"])
        self.assertEqual(me["account"]["binding_issue"], "previous_authorization_revoked")

    def test_self_configuration_needs_active_session_and_cannot_select_another_user(self):
        _, session = self.running_registration()
        own = self.public("session.subscription", {"session_token": session, "format": "clash"}, ok=False)
        self.assertEqual(own["error"]["code"], "EMAIL_DELIVERY_ONLY")
        with ProductionStore(self.folder.name, policy=self.policy, read_only=True) as reader:
            before = reader.conn.total_changes
            self.assertEqual(self.public("session.subscription", {"session_token": session, "format": "shadowrocket"}, store=reader, ok=False)["error"]["code"], "EMAIL_DELIVERY_ONLY")
            self.assertEqual(reader.conn.total_changes, before)
        self.assertFalse(self.public("session.subscription", {"session_token": session, "format": "clash", "user_id": self.admin}, ok=False)["ok"])
        self.rpc("user.disable", {"user_id": self.member})
        denied = self.public("session.subscription", {"session_token": session, "format": "clash"}, ok=False)
        self.assertEqual(denied["error"]["code"], "NOT_ACTIVE")

    def test_pending_and_deleted_users_cannot_view_saved_configuration(self):
        me, session = self.register()
        denied = self.public("session.subscription", {"session_token": session, "format": "clash"}, ok=False)
        self.assertEqual(denied["error"]["code"], "NOT_ACTIVE")
        token = me["subscriptions"]["clash"].split("/")[-2]
        self.rpc("registration.approve", {"account_id": me["account"]["id"]})
        self.rpc("user.delete", {"user_id": self.member})
        self.assertEqual(subscription_response(self.store, token, "config.yaml", self.now)["status"], 404)
        self.assertEqual(self.public("session.subscription", {"session_token": session, "format": "clash"}, ok=False)["error"]["code"], "UNAUTHENTICATED")


    def test_administrator_can_review_and_confirm_corrected_existing_binding(self):
        user_id = self.existing_user(verified=False)
        before_user = self.store.get_user(user_id)
        before_credentials = self.store.get_credentials(user_id)
        me, session = self.register()
        account_id = me["account"]["id"]
        welcome_count = self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind IN ('portal_welcome','portal_activated')").fetchone()[0]
        self.assertNotIn("binding_candidates", me["account"])
        review = next(a for a in registration.snapshot(self.store, self.now)["accounts"] if a["id"] == account_id)
        self.assertEqual(review["binding_candidates"][0]["user_id"], user_id)
        self.assertFalse(review["binding_candidates"][0]["can_bind"])
        self.assertEqual(review["binding_candidates"][0]["reason"], "email_not_verified")
        self.assertFalse(self.rpc("registration.bind", {"account_id": account_id, "user_id": user_id}, ok=False)["ok"])
        self.store.conn.execute("UPDATE users SET email_verified=1 WHERE id=?", (user_id,))
        corrected = next(a for a in registration.snapshot(self.store, self.now)["accounts"] if a["id"] == account_id)
        self.assertTrue(corrected["binding_candidates"][0]["can_bind"])
        wrong = self.rpc("registration.bind", {"account_id": account_id, "user_id": self.admin}, ok=False)
        self.assertFalse(wrong["ok"])
        self.assertIsNone(registration._account(self.store, account_id)["proxy_user_id"])
        bound = self.rpc("registration.bind", {"account_id": account_id, "user_id": user_id})
        self.assertEqual(bound["data"]["account"]["proxy_user_id"], user_id)
        self.assertEqual(self.store.get_credentials(user_id), before_credentials)
        self.assertEqual(self.store.get_user(user_id)["used_upload"], before_user["used_upload"])
        self.assertEqual(self.store.get_user(user_id)["used_download"], before_user["used_download"])
        self.assertNotIn("binding_candidates", self.public("session.me", {"session_token": session})["data"]["account"])
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE kind IN ('portal_welcome','portal_activated')").fetchone()[0], welcome_count)

    def test_personal_configuration_waits_for_current_generation_native_origin(self):
        user_id = self.existing_user(active=True)
        _, session = self.register()
        self.store.conn.execute("UPDATE production_workers SET origin_pending=1 WHERE user_id=?", (user_id,))
        me = self.public("session.me", {"session_token": session})["data"]
        self.assertEqual(me["account"]["status"], "provisioning")
        self.assertNotIn("configuration_available", me["account"])
        self.assertEqual(self.public("session.subscription", {"session_token": session, "format": "clash"}, ok=False)["error"]["code"], "NOT_ACTIVE")
        self.store.conn.execute("UPDATE production_workers SET origin_pending=0 WHERE user_id=?", (user_id,))
        self.assertEqual(self.public("session.me", {"session_token": session})["data"]["account"]["status"], "active")


if __name__ == '__main__':
    unittest.main()
