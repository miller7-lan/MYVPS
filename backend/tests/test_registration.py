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
        return me, result["session_token"]

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
        self.assertTrue(me["subscriptions"]["clash"].endswith("/config.yaml"))
        self.assertTrue(me["subscriptions"]["shadowrocket"].endswith("/nodes.txt"))
        token = me["subscriptions"]["clash"].split("/")[-2]
        self.assertEqual(subscription_response(self.store, token, "config.yaml", self.now)["status"], 403)
        self.assertEqual(subscription_response(self.store, token, "nodes.txt", self.now)["status"], 403)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM production_jobs").fetchone()[0], 0)

    def test_wrong_expired_superseded_and_used_codes_are_rejected(self):
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
        self.request_code()
        self.assertEqual(self.public("auth.request_code", {"email": "friend@example.test"}, ok=False)["error"]["code"], "RATE_LIMITED")
        self.rpc("settings.update", {"registration_enabled": False})
        self.assertEqual(self.public("auth.request_code", {"email": "new@example.test"}, ok=False)["error"]["code"], "REGISTRATION_CLOSED")
        self.now += dt.timedelta(seconds=61)
        self.request_code()  # Existing account may still sign in while new signup is paused.

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
        self.assertEqual(self.public("session.me", {"session_token": session})["data"]["account"]["status"], "active")
        for route in ("config.yaml", "nodes.txt"):
            artifact = subscription_response(self.store, token, route, self.now)
            self.assertEqual(artifact["status"], 200)
            self.assertTrue(artifact["body"])
        self.assertEqual(self.public("session.me", {"session_token": session})["data"]["subscriptions"], me["subscriptions"])
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

    def test_pool_full_waits_without_creating_credentials(self):
        first, _ = self.register(); self.rpc("registration.approve", {"account_id": first["account"]["id"]})
        second, _ = self.register("next@example.test")
        result = self.rpc("registration.approve", {"account_id": second["account"]["id"]})
        self.assertTrue(result["data"]["waiting_resources"])
        self.assertEqual(result["data"]["account"]["status"], "waiting_resources")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 1)

    def test_five_new_pool_slots_accept_five_and_leave_sixth_waiting(self):
        original_user = self.rpc("user.add", {"name":"Existing member", "role":"member", "quota_bytes":100000})["data"]["user"]["id"]
        original_token = self.store.get_credentials(original_user)["subscription_token"]
        policy = json.loads(json.dumps(self.policy)); policy.update(version=2, portal_uid=1002)
        for port in range(24432,24437):
            policy["workers"][str(uuid.uuid4())] = {"role":"member", "public_port":port, "api_port":port+10000}
        original_store = self.store
        with ProductionStore(self.folder.name, policy=policy) as expanded:
            self.store = expanded
            try:
                for index in range(6):
                    me, _ = self.register(f"pool{index}@example.test")
                    reply = self.rpc("registration.approve", {"account_id":me["account"]["id"]})["data"]
                    self.assertEqual(reply["account"]["status"], "provisioning" if index < 5 else "waiting_resources")
                self.assertEqual(registration.snapshot(expanded,self.now)["pool"], {"available":0,"total":6})
                self.assertEqual(expanded.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0],6)
                self.assertEqual(expanded.get_credentials(original_user)["subscription_token"],original_token)
            finally:
                self.store = original_store

    def test_rejection_has_no_runtime_or_quota_side_effects(self):
        me, _ = self.register(); account = me["account"]["id"]
        self.rpc("registration.reject", {"account_id": account, "reason": "not now"})
        self.assertEqual(registration.snapshot(self.store, self.now)["accounts"][0]["status"], "rejected")
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
        self.rpc("registration.approve", {"account_id": account})  # A later explicit admin action may reconsider.
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_personal_allowance_includes_topups_and_unlimited_is_not_zero(self):
        me, session = self.register()
        self.rpc("registration.approve", {"account_id": me["account"]["id"], "quota_bytes":123})
        self.rpc("user.topup", {"user_id":self.member,"bytes":456})
        account = self.public("session.me", {"session_token":session})["data"]["account"]
        self.assertEqual(account["allowance_bytes"],579)
        self.assertEqual(account["topup_bytes"],456)
        self.assertFalse(account["unlimited"])
        self.rpc("user.update", {"user_id":self.member,"unlimited":True})
        account = self.public("session.me", {"session_token":session})["data"]["account"]
        self.assertTrue(account["unlimited"])
        self.assertIsNone(account["allowance_bytes"])

    def test_rotation_and_revocation_invalidate_previously_emailed_url(self):
        me, session = self.register(); account = me["account"]["id"]; old = me["subscriptions"]["clash"].split("/")[-2]
        self.rpc("registration.approve", {"account_id": account})
        self.rpc("user.rotate", {"user_id": self.member})
        self.assertEqual(subscription_response(self.store, old, "config.yaml", self.now)["status"], 404)
        fresh = self.public("session.me", {"session_token": session})["data"]["subscriptions"]["clash"]
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


if __name__ == '__main__':
    unittest.main()
