"""Budget/trial invariants with temporary SQLite and an in-process root fixture."""
import copy
import datetime as dt
import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from dazzle import budget, domain, trials
from dazzle.metering import MeterSample
from dazzle.production import (ProductionError, accept_sample, handle_request,
                               plan_jobs, process_one_job, snapshot, subscription_response)
from dazzle.production_state import CORE_SHA256, ProductionStore
from dazzle.store import SCHEMA, Store, parse_time, timestamp
from test_production import StrictHelper
from test_authorization_fixtures import seed_legacy_user

GB = budget.GB


class LeaseHelper(StrictHelper):
    """Preserve generation and retired identities when reclaiming a physical slot."""
    def __init__(self, policy, store):
        super().__init__(policy, store)
        self.retired = set()

    def call(self, request):
        identifier, action = request["worker_id"], request["action"]
        if action != "release":
            lease = request["params"].get("lease_id", identifier)
            if action in {"provision", "stage", "activate"} and (identifier, lease) in self.retired:
                raise ProductionError("REVOKED", "Retired fixture authorisation")
            result = super().call(request)
            if action == "provision":
                self.records[identifier]["lease_id"] = lease
            return result
        self.assert_no_transaction()
        self.calls.append(copy.deepcopy(request))
        record = self.records[identifier]
        fingerprint = json.dumps(request, sort_keys=True)
        if request["request_id"] in self.cache:
            previous, response = self.cache[request["request_id"]]
            if previous != fingerprint:
                raise ProductionError("GENERATION", "Fixture release request mismatch")
            return copy.deepcopy(response)
        lease = request["params"]["lease_id"]
        if (request["generation"] != record["generation"] + 1 or not record["tombstoned"] or
                record["worker_state"] != "revoked" or record["process_id"] is not None or
                record.get("lease_id", identifier) != lease):
            raise ProductionError("RELEASE_UNCONFIRMED", "Fixture refuses unconfirmed release")
        self.retired.add((identifier, lease))
        record.update(generation=request["generation"], worker_state="unprovisioned", process_id=None,
                      tombstoned=False, public_key=None, lease_id=None)
        result = {"worker_id": identifier, **self.policy["workers"][identifier], **record,
                  "server_id": self.policy["server_id"], "managed_origin_zero": False,
                  "inactive_confirmed": True, "recovery_required": False}
        self.cache[request["request_id"]] = fingerprint, copy.deepcopy(result)
        return result

    def assert_no_transaction(self):
        if self.store.conn.in_transaction:
            raise AssertionError("Fixture release I/O held a SQLite transaction")


class BudgetTrialTests(unittest.TestCase):
    def setUp(self):
        guard = patch('dazzle.budget.admin_guard_ready', return_value=True)
        guard.start()
        self.addCleanup(guard.stop)
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.now = parse_time("2026-11-01T08:19:00Z")
        self.admin = str(uuid.uuid4())
        self.members = [str(uuid.uuid4()) for _ in range(4)]
        workers = {self.admin: {"role": "admin", "public_port": 24430, "api_port": 34430}}
        workers.update({identifier: {"role": "member", "public_port": 24431 + index, "api_port": 34431 + index}
                        for index, identifier in enumerate(self.members)})
        self.policy = {"version": 2, "server_id": str(uuid.uuid4()), "server_endpoint": "8.8.8.8", "portal_uid": 994,
                       "agent_uid": 995, "core_sha256": CORE_SHA256, "workers": workers}
        self.store = ProductionStore(self.folder.name, policy=self.policy, initialize=True, now=self.now)
        self.addCleanup(self.store.close)
        self.helper = LeaseHelper(self.policy, self.store)

    def call(self, action, params=None, *, ok=True):
        result = handle_request(self.store, {"api_version": 1, "request_id": str(uuid.uuid4()), "action": action,
            "expected_revision": self.store.revision, "server_id": self.store.server_id, "params": params or {}}, self.now)
        if ok:
            self.assertTrue(result["ok"], result)
        return result

    def configure(self, total=500, margin=10):
        return self.call("budget.configure", {"total_bytes": total * GB, "safety_margin_bytes": margin * GB,
                        "confirmed": True, "evidence": "Isolated administrator budget fixture; no provider API"})

    def member(self, quota=100):
        result = self.call("user.add", {"name": "Budget fixture", "role": "member", "quota_bytes": quota * GB})
        return result["data"]["user"]["id"]

    def trial(self, days=3, quota=5):
        result = self.call("trial.create", {"name": "Trial fixture", "quota_bytes": quota * GB, "duration_days": days})
        return result["data"]["user"]["id"]

    def process(self):
        return process_one_job(self.store, self.helper, self.now)

    def sample(self, user_id, up=0, down=0):
        worker = self.store.worker(user_id)
        self.now += dt.timedelta(milliseconds=50)
        self.store.now = self.now
        self.store.conn.execute("BEGIN IMMEDIATE")
        try:
            result = accept_sample(self.store, worker["worker_id"], worker["observed_generation"],
                MeterSample("trial-epoch-" + str(worker["observed_generation"]), up, down, timestamp(self.now)), self.now)
            self.store.conn.commit()
            return result
        except BaseException:
            self.store.conn.rollback()
            raise

    def advance(self):
        self.store.now = self.now
        self.store.conn.execute("BEGIN IMMEDIATE")
        try:
            trials.advance(self.store, self.now)
            budget.refresh_admin(self.store, self.now)
            plan_jobs(self.store, self.now)
            self.store.conn.commit()
        except BaseException:
            self.store.conn.rollback()
            raise

    def running(self, user_id, *, trial=False):
        for _ in range(12):
            worker = self.store.worker(user_id)
            if worker["observed_state"] == "running" and not worker["origin_pending"]:
                return
            result = self.process()
            if not result.get("processed") and not trial:
                self.call("user.enable", {"user_id": user_id})
            worker = self.store.worker(user_id)
            if worker["origin_pending"]:
                self.sample(user_id)
            self.advance()
        self.fail("Fixture did not reach a trusted running state")

    def test_unconfigured_budget_preserves_existing_but_rejects_trial_creation(self):
        user = seed_legacy_user(self.store, {"name":"Existing member", "quota_bytes":100 * GB}, self.now)["id"]
        before = self.store.get_user(user)
        result = self.call("trial.create", {"name": "Trial", "quota_bytes": 5 * GB, "duration_days": 3}, ok=False)
        self.assertEqual(result["error"]["code"], "BUDGET_NOT_CONFIGURED")
        self.assertEqual(self.store.get_user(user), before)

    def test_adoption_requires_administrator_guard_without_changing_existing_account(self):
        admin=self.call('user.add',{'name':'Administrator','role':'admin'})['data']['user']['id']
        before=self.store.get_user(admin)
        with patch('dazzle.budget.admin_guard_ready',return_value=False):
            response=self.call('budget.configure',{'total_bytes':500*GB,'safety_margin_bytes':10*GB,'confirmed':True,'evidence':'Local fixture'},ok=False)
        self.assertEqual(response['error']['code'],'ADMIN_GUARD_REQUIRED')
        self.assertFalse(budget.configured(self.store))
        self.assertEqual(self.store.get_user(admin),before)

    def test_concurrent_issuance_cannot_overbook_the_same_budget(self):
        self.configure(total=500,margin=0)
        revision=self.store.revision
        def issue(index):
            with ProductionStore(self.folder.name,policy=self.policy,now=self.now) as other:
                return handle_request(other,{'api_version':1,'request_id':str(uuid.uuid4()),'action':'user.add',
                    'server_id':other.server_id,'expected_revision':revision,
                    'params':{'name':'Concurrent '+str(index),'quota_bytes':300*GB}},self.now)
        with ThreadPoolExecutor(max_workers=2) as executor:
            replies=list(executor.map(issue,(1,2)))
        self.assertEqual(sum(r['ok'] for r in replies),1)
        self.assertEqual(budget.snapshot(self.store)['members_reserved_bytes'],300*GB)

    def test_formal_minimum_integer_gb_and_total_pool_are_enforced_atomically(self):
        self.configure(total=200, margin=10)
        below = self.call("user.add", {"name": "Below", "quota_bytes": 49 * GB}, ok=False)
        self.assertFalse(below["ok"])
        fractional = self.call("user.add", {"name": "Fractional", "quota_bytes": 50 * GB + 1}, ok=False)
        self.assertFalse(fractional["ok"])
        first = self.member(quota=100)
        second = self.member(quota=90)
        revision = self.store.revision
        rejected = self.call("user.topup", {"user_id": first, "bytes": GB}, ok=False)
        self.assertEqual(rejected["error"]["code"], "BUDGET_EXCEEDED")
        self.assertEqual(self.store.revision, revision)
        self.assertEqual(self.store.get_user(first)["topup_bytes"], 0)
        self.assertEqual(self.store.get_user(second)["quota_bytes"], 90 * GB)

    def test_lowering_quota_below_used_is_rejected_without_resetting_usage(self):
        self.configure()
        user = self.member()
        self.running(user)
        self.sample(user, up=60 * GB)
        before = self.store.get_user(user)
        result = self.call("user.update", {"user_id": user, "quota_bytes": 50 * GB}, ok=False)
        self.assertEqual(result["error"]["code"], "QUOTA_BELOW_USED")
        self.assertEqual(self.store.get_user(user)["quota_bytes"], before["quota_bytes"])
        self.assertEqual(self.store.get_user(user)["used_upload"], 60 * GB)

    def test_administrator_spends_only_unreserved_balance(self):
        self.call("user.add", {"name": "Admin fixture", "role": "admin"})
        self.configure(total=200, margin=10)
        member = self.member(quota=100)
        self.running(self.admin)
        self.assertFalse(self.store.get_user(self.admin)["unlimited"])
        self.assertEqual(budget.snapshot(self.store)["admin_remaining_bytes"], 90 * GB)
        self.sample(self.admin, up=90 * GB)
        self.advance()
        self.assertEqual(budget.snapshot(self.store)["admin_remaining_bytes"], 0)
        self.assertIn("quota_exceeded", domain.disabled_reasons(self.store.get_user(self.admin), self.now))
        self.assertEqual(self.store.get_user(member)["quota_bytes"], 100 * GB)
        self.assertNotIn("pool_protection", domain.disabled_reasons(self.store.get_user(member), self.now))
        result = self.call("user.update", {"user_id": self.admin, "unlimited": True}, ok=False)
        self.assertFalse(result["ok"])

    def test_budget_adoption_rejects_existing_unlimited_member(self):
        user = seed_legacy_user(self.store, {"name":"Existing unlimited member", "quota_bytes":100 * GB,"unlimited":True}, self.now)["id"]
        result = self.call("budget.configure", {"total_bytes": 500 * GB, "safety_margin_bytes": 10 * GB,
            "confirmed": True, "evidence": "Reject unsafe adoption fixture"}, ok=False)
        self.assertFalse(result["ok"])
        self.assertFalse(budget.configured(self.store))

    def test_trial_lifetime_begins_only_after_actual_running_and_trusted_origin(self):
        self.configure()
        user = self.trial(days=2, quota=3)
        self.assertIsNone(trials.get(self.store, user)["started_at"])
        self.process()
        self.process()
        self.advance()
        self.assertIsNone(trials.get(self.store, user)["started_at"])
        self.sample(user)
        self.process()
        self.advance()
        self.assertIsNone(trials.get(self.store, user)["started_at"])
        self.sample(user)
        self.advance()
        value = trials.get(self.store, user)
        self.assertEqual(value["started_at"], timestamp(self.now))
        self.assertEqual(parse_time(value["expires_at"]) - parse_time(value["started_at"]), dt.timedelta(days=2))

    def test_trial_expiration_is_checked_on_subscription_before_cleanup_tick(self):
        self.configure()
        user = self.trial(days=1)
        self.running(user, trial=True)
        token = self.store.get_credentials(user)["subscription_token"]
        self.assertEqual(subscription_response(self.store, token, "config.yaml", self.now)["status"], 200)
        expiry = parse_time(trials.get(self.store, user)["expires_at"])
        self.assertEqual(subscription_response(self.store, token, "config.yaml", expiry)["status"], 403)
        self.assertEqual(subscription_response(self.store, token, "nodes.txt", expiry)["status"], 403)

    def test_trial_does_not_receive_new_allowance_at_regular_cycle_boundary(self):
        self.configure()
        user = self.trial(days=60)
        self.running(user, trial=True)
        self.sample(user, up=GB)
        before = trials.get(self.store, user)
        cycle = domain.ensure_cycle(self.store, self.now)
        self.now = parse_time(cycle["end_at"]) + dt.timedelta(seconds=1)
        self.store.now = self.now
        self.store.conn.execute("BEGIN IMMEDIATE")
        domain._cycle_tick(self.store, self.now)
        self.store.conn.commit()
        self.assertEqual(self.store.get_user(user)["used_upload"], GB)
        self.assertEqual(trials.get(self.store, user)["expires_at"], before["expires_at"])

    def test_deletion_invalidates_links_immediately_but_keeps_unconfirmed_reservation(self):
        self.configure()
        user = self.trial(quota=5)
        self.running(user, trial=True)
        token = self.store.get_credentials(user)["subscription_token"]
        self.call("user.delete", {"user_id": user})
        self.assertEqual(subscription_response(self.store, token, "config.yaml", self.now)["status"], 404)
        self.assertEqual(budget.snapshot(self.store)["members_reserved_bytes"], 5 * GB)
        self.assertFalse(trials.releasable(self.store, self.store.worker(user)))

    def test_expired_trial_cannot_be_extended_or_reenabled(self):
        self.configure()
        user = self.trial(days=1)
        self.running(user, trial=True)
        self.now = parse_time(trials.get(self.store, user)["expires_at"])
        result = self.call("trial.update", {"user_id": user, "duration_days": 2}, ok=False)
        self.assertEqual(result["error"]["code"], "EXPIRED")
        self.advance()
        self.assertIsNotNone(self.store.get_user(user)["revoked_at"])
        result = self.call("user.enable", {"user_id": user}, ok=False)
        self.assertFalse(result["ok"])

    def test_released_slot_gets_new_identity_and_old_links_stay_invalid(self):
        self.configure()
        old = self.trial()
        self.running(old, trial=True)
        worker_id = self.store.worker(old)["worker_id"]
        old_worker = self.store.worker(old)
        old_user = self.store.get_user(old)
        old_token = self.store.get_credentials(old)["subscription_token"]
        self.now += dt.timedelta(seconds=1)
        self.call("user.delete", {"user_id": old})
        self.process()  # Confirm actual revoked/inactive before release.
        self.advance()
        self.assertEqual(budget.snapshot(self.store)['members_reserved_bytes'],5*GB)
        self.assertFalse(trials.releasable(self.store, self.store.worker(old)))
        self.assertFalse(self.store.conn.execute("SELECT 1 FROM production_jobs WHERE action='release' AND status='pending'").fetchone())
        rejected = self.call("user.cleanup.confirm", {"user_id": old, "confirm_unknown_gap": False}, ok=False)
        self.assertFalse(rejected["ok"])
        self.call("user.cleanup.confirm", {"user_id": old, "confirm_unknown_gap": True})
        self.advance()
        release = self.process()
        self.assertTrue(release.get("applied"), release)
        self.assertIsNone(self.store.conn.execute("SELECT user_id FROM production_workers WHERE worker_id=?", (worker_id,)).fetchone()[0])
        new = self.trial()
        self.assertNotEqual(old, new)
        self.assertEqual(self.store.worker(new)["worker_id"], worker_id)
        self.assertEqual(subscription_response(self.store, old_token, "config.yaml", self.now)["status"], 404)
        self.assertNotEqual(self.store.get_credentials(new)["subscription_token"], old_token)
        self.assertIsNotNone(self.store.get_user(old)["revoked_at"])
        state = snapshot(self.store, self.now)
        self.assertIn(old, {user["id"] for user in state["deleted_users"]})
        self.assertEqual(self.store.conn.execute("SELECT status FROM resource_leases WHERE user_id=?", (old,)).fetchone()[0], "released")
        # A delayed sample belongs to the retired authorisation, never to the
        # newly assigned user which happens to share the same physical worker.
        self.store.conn.execute("BEGIN IMMEDIATE")
        try:
            accepted = accept_sample(self.store, worker_id, old_worker["observed_generation"],
                MeterSample(old_user["meter_epoch"], old_user["last_uplink"] + 17, old_user["last_downlink"] + 19,
                            timestamp(parse_time(old_user["last_sample_at"]) + dt.timedelta(milliseconds=500))), self.now)
            self.store.conn.commit()
        except BaseException:
            self.store.conn.rollback()
            raise
        self.assertTrue(accepted.get("retired"), accepted)
        self.assertEqual(self.store.get_user(new)["used_upload"] + self.store.get_user(new)["used_download"], 0)
        self.assertEqual(self.store.get_user(old)["used_upload"] - old_user["used_upload"], 17)
        self.assertEqual(self.store.get_user(old)["used_download"] - old_user["used_download"], 19)

    def test_permanent_revoke_releases_formal_and_trial_slots_only_after_stop_and_reconciliation(self):
        self.configure()
        for temporary in (False, True):
            with self.subTest(trial=temporary):
                old = self.trial() if temporary else self.member()
                self.running(old, trial=temporary)
                self.sample(old, 17, 19)
                old_worker = self.store.worker(old)
                old_user = self.store.get_user(old)
                old_credentials = self.store.get_credentials(old)
                worker_id = old_worker["worker_id"]
                self.now += dt.timedelta(seconds=1)
                self.call("user.revoke", {"user_id": old})
                self.assertFalse(trials.releasable(self.store, self.store.worker(old)))
                denied = self.call("user.cleanup.confirm", {"user_id": old, "confirm_unknown_gap": True}, ok=False)
                self.assertEqual(denied["error"]["code"], "CLEANUP_NOT_READY")
                self.process()
                self.advance()
                stopped = self.store.worker(old)
                self.assertEqual(stopped["observed_state"], "revoked")
                self.assertTrue(stopped["tombstoned"])
                self.assertIsNone(stopped["process_id"])
                self.assertIsNone(self.store.get_user(old)["deleted_at"])
                self.assertFalse(trials.releasable(self.store, stopped))
                self.assertEqual(trials.cleanup_status(self.store, self.store.get_user(old), stopped)["state"], "waiting_reconciliation")
                self.assertFalse(self.store.conn.execute("SELECT 1 FROM production_jobs WHERE worker_id=? AND action='release' AND status='pending'", (worker_id,)).fetchone())
                self.call("user.cleanup.confirm", {"user_id": old, "confirm_unknown_gap": True})
                self.assertTrue(trials.releasable(self.store, self.store.worker(old)))
                self.advance()
                result = self.process()
                self.assertTrue(result.get("applied"), result)
                self.assertEqual(trials.cleanup_status(self.store, self.store.get_user(old), self.store.worker(old))["state"], "released")
                if temporary:
                    self.assertEqual(trials.get(self.store, old)["status"], "cleaned")
                    self.assertEqual(trials.get(self.store, old)["end_reason"], "revoked")

                new = self.trial() if temporary else self.member()
                self.assertNotEqual(old, new)
                self.assertEqual(self.store.worker(new)["worker_id"], worker_id)
                self.running(new, trial=temporary)
                new_credentials = self.store.get_credentials(new)
                for field in ("vless_uuid", "tuic_uuid", "tuic_password", "subscription_token"):
                    self.assertNotEqual(old_credentials[field], new_credentials[field])
                self.assertEqual(subscription_response(self.store, old_credentials["subscription_token"], "config.yaml", self.now)["status"], 404)
                for action in ("user.enable", "user.rotate"):
                    denied = self.call(action, {"user_id": old}, ok=False)
                    self.assertFalse(denied["ok"], denied)
                recovery = self.call("user.recovery.preview", {"user_id": old})["data"]["recovery"]
                self.assertFalse(recovery["can_apply"])
                self.assertIn("revoked", recovery["blocked_reasons"])
                self.store.conn.execute("BEGIN IMMEDIATE")
                try:
                    accepted = accept_sample(self.store, worker_id, old_worker["observed_generation"],
                        MeterSample(old_user["meter_epoch"], 28, 32,
                                    timestamp(parse_time(old_user["last_sample_at"]) + dt.timedelta(milliseconds=500))), self.now)
                    self.store.conn.commit()
                except BaseException:
                    self.store.conn.rollback()
                    raise
                self.assertTrue(accepted.get("retired"), accepted)
                self.assertEqual(self.store.get_user(old)["used_upload"], 28)
                self.assertEqual(self.store.get_user(old)["used_download"], 32)
                self.assertEqual(self.store.get_user(new)["used_upload"] + self.store.get_user(new)["used_download"], 0)
                self.assertEqual(self.store.get_credentials(new), new_credentials)
                self.assertEqual(self.store.worker(new)["observed_state"], "running")


class PortHistoryMigrationTests(unittest.TestCase):
    def test_old_unique_port_schema_preserves_rows_and_foreign_key_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            connection = sqlite3.connect(database)
            connection.executescript(SCHEMA.replace("port INTEGER NOT NULL,", "port INTEGER NOT NULL UNIQUE,"))
            identifier = str(uuid.uuid4())
            at = "2026-10-26T00:00:00Z"
            connection.execute("INSERT INTO meta VALUES('mode','\"production\"')")
            connection.execute("INSERT INTO users(id,name,role,port,quota_bytes,used_upload,created_at,updated_at,revoked_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (identifier, "Archived fixture", "member", 24431, 100 * GB, GB, at, at, at, at))
            connection.execute("INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?)", ("old-entry", identifier, "old-cycle", "old-epoch", GB, 0, at, at))
            connection.commit()
            connection.close()
            with Store(directory, mode="production", now=at) as store:
                self.assertEqual(store.get_user(identifier)["used_upload"], GB)
                self.assertIsNotNone(store.get_user(identifier)["revoked_at"])
                self.assertEqual(store.conn.execute("SELECT upload FROM ledger WHERE id='old-entry'").fetchone()[0], GB)
                self.assertFalse(store.conn.execute("PRAGMA foreign_key_check").fetchall())
                fresh = str(uuid.uuid4())
                store.conn.execute("INSERT INTO users(id,name,role,port,quota_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (fresh, "Fresh fixture", "member", 24431, 100 * GB, at, at))
                with self.assertRaises(sqlite3.IntegrityError):
                    store.conn.execute("INSERT INTO users(id,name,role,port,quota_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (str(uuid.uuid4()), "Duplicate fixture", "member", 24431, 100 * GB, at, at))
