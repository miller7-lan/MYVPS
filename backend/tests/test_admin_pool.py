"""A member drawing on the administrators' remaining budget instead of a fixed allowance."""
import datetime as dt
import tempfile
import unittest
import uuid
from unittest.mock import patch

from dazzle import budget, domain, trials
from dazzle.metering import MeterSample
from dazzle.production import accept_sample, handle_request, plan_jobs, process_one_job
from dazzle.production_state import CORE_SHA256, ProductionStore
from dazzle.store import parse_time, timestamp
from test_authorization_fixtures import seed_legacy_user
from test_budget_trials import LeaseHelper

GB = budget.GB
POOL = budget.ADMIN_POOL


class AdminPoolTests(unittest.TestCase):
    def setUp(self):
        guard = patch("dazzle.budget.admin_guard_ready", return_value=True)
        guard.start()
        self.addCleanup(guard.stop)
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.now = parse_time("2026-11-01T08:19:00Z")
        self.admin = str(uuid.uuid4())
        members = [str(uuid.uuid4()) for _ in range(4)]
        workers = {self.admin: {"role": "admin", "public_port": 24430, "api_port": 34430}}
        workers.update({identifier: {"role": "member", "public_port": 24431 + index, "api_port": 34431 + index}
                        for index, identifier in enumerate(members)})
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

    def configure(self, total=500, margin=0):
        return self.call("budget.configure", {"total_bytes": total * GB, "safety_margin_bytes": margin * GB,
                         "confirmed": True, "evidence": "Isolated administrator pool fixture; no provider API"})

    def member(self, quota=100):
        return self.call("user.add", {"name": "Pool fixture", "role": "member", "quota_bytes": quota * GB})["data"]["user"]["id"]

    def sample(self, user_id, up=0, down=0):
        worker = self.store.worker(user_id)
        self.now += dt.timedelta(milliseconds=50)
        self.store.now = self.now
        self.store.conn.execute("BEGIN IMMEDIATE")
        try:
            accept_sample(self.store, worker["worker_id"], worker["observed_generation"],
                          MeterSample("pool-epoch-" + str(worker["observed_generation"]), up, down, timestamp(self.now)), self.now)
            self.store.conn.commit()
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

    def running(self, user_id):
        for _ in range(12):
            worker = self.store.worker(user_id)
            if worker["observed_state"] == "running" and not worker["origin_pending"]:
                return
            if not process_one_job(self.store, self.helper, self.now).get("processed"):
                self.call("user.enable", {"user_id": user_id})
            if self.store.worker(user_id)["origin_pending"]:
                self.sample(user_id)
            self.advance()
        self.fail("Fixture did not reach a trusted running state")

    def pool_ready(self):
        """Administrator and the second person both running with recorded usage."""
        self.call("user.add", {"name": "Administrator", "role": "admin"})
        self.configure()
        second = seed_legacy_user(self.store, {"name": "Existing second person", "quota_bytes": 100 * GB}, self.now)["id"]
        self.running(self.admin)
        self.running(second)
        self.sample(self.admin, up=10 * GB)
        self.sample(second, up=2 * GB)
        self.advance()
        return second

    def test_joining_releases_fixed_reservation_and_shares_the_remainder(self):
        second = self.pool_ready()
        credentials, worker = self.store.get_credentials(second), self.store.worker(second)
        self.assertEqual(budget.snapshot(self.store)["admin_remaining_bytes"], (500 - 12 - 98) * GB)
        self.call("user.update", {"user_id": second, "quota_pool": POOL})
        info = budget.snapshot(self.store)
        self.assertEqual(info["members_reserved_bytes"], 0)
        self.assertEqual(info["admin_remaining_bytes"], 488 * GB)
        self.assertEqual(set(info["administrator_pool"]["user_ids"]), {self.admin, second})
        self.assertEqual(self.store.get_user(second)["quota_bytes"], 490 * GB)
        self.assertEqual(self.store.get_user(self.admin)["quota_bytes"], 498 * GB)
        # Only the allowance basis changed: same role, slot, process, credentials and usage.
        current = self.store.get_user(second)
        self.assertEqual((current["role"], current["port"], current["used_upload"]), ("member", 24431, 2 * GB))
        self.assertEqual(self.store.get_credentials(second), credentials)
        self.assertEqual({key: self.store.worker(second)[key] for key in ("process_id", "generation", "observed_state")},
                         {key: worker[key] for key in ("process_id", "generation", "observed_state")})
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM production_jobs WHERE worker_id=? AND status IN ('pending','executing')",
                                                 (second,)).fetchone()[0], 0)
        public = next(user for user in self.call("snapshot")["data"]["users"] if user["id"] == second)
        self.assertEqual(public["quota_pool"], POOL)

    def test_released_legacy_worker_cannot_become_a_fourth_new_seat(self):
        from dazzle import registration
        self.call("user.add", {"name": "Administrator", "role": "admin"})
        self.configure()
        created = [self.member() for _ in range(3)]
        self.assertEqual(sorted(self.store.get_user(user_id)["port"] for user_id in created), [24432, 24433, 24434])
        # The historical physical worker is intentionally available here,
        # exactly as after a completed historical-user cleanup.
        legacy = self.store.conn.execute("SELECT user_id FROM production_workers WHERE public_port=24431").fetchone()
        self.assertIsNone(legacy[0])
        self.assertEqual(registration.snapshot(self.store, self.now)["pool"], {"available": 0, "total": 3})
        self.assertTrue(registration.capacity(self.store)["full"])
        for action, params in (("user.add", {"name": "Fourth member", "quota_bytes": 100 * GB}),
                               ("trial.create", {"name": "Fourth trial", "quota_bytes": 5 * GB})):
            rejected = self.call(action, params, ok=False)
            self.assertFalse(rejected["ok"])
            self.assertEqual(rejected["error"]["code"], "APPROVAL_REQUIRED")
        self.assertIsNone(self.store.conn.execute("SELECT user_id FROM production_workers WHERE public_port=24431").fetchone()[0])

    def test_new_registered_reservation_reduces_every_pool_member_alike(self):
        second = self.pool_ready()
        self.call("user.update", {"user_id": second, "quota_pool": POOL})
        self.member(quota=100)
        self.advance()
        self.assertEqual(budget.snapshot(self.store)["admin_remaining_bytes"], 388 * GB)
        self.assertEqual(self.store.get_user(second)["quota_bytes"], 390 * GB)
        self.assertEqual(self.store.get_user(self.admin)["quota_bytes"], 398 * GB)
        self.sample(second, up=5 * GB)  # Cumulative counter: three more bytes-of-GB from the pool.
        self.advance()
        self.assertEqual(budget.snapshot(self.store)["admin_remaining_bytes"], 385 * GB)
        self.assertEqual(self.store.get_user(self.admin)["quota_bytes"], 395 * GB)
        self.assertEqual(self.store.get_user(second)["quota_bytes"], 390 * GB)

    def test_pool_member_has_no_separate_topup_or_fixed_quota_until_it_leaves(self):
        second = self.pool_ready()
        self.call("user.update", {"user_id": second, "quota_pool": POOL})
        self.assertEqual(self.call("user.topup", {"user_id": second, "bytes": GB}, ok=False)["error"]["code"], "VALIDATION")
        self.assertEqual(self.call("user.update", {"user_id": second, "quota_bytes": 100 * GB}, ok=False)["error"]["code"], "VALIDATION")
        self.assertEqual(self.call("user.update", {"user_id": second, "quota_pool": None}, ok=False)["error"]["code"], "VALIDATION")
        self.call("user.update", {"user_id": second, "quota_pool": None, "quota_bytes": 100 * GB})
        self.assertIsNone(self.store.get_user(second)["quota_pool"])
        self.assertEqual(self.store.get_user(second)["quota_bytes"], 100 * GB)
        self.assertEqual(budget.snapshot(self.store)["members_reserved_bytes"], 98 * GB)

    def test_exhausted_pool_pauses_pool_members_but_never_reserved_members(self):
        self.call("user.add", {"name": "Administrator", "role": "admin"})
        self.configure(total=160)
        second, reserved = self.member(quota=50), self.member(quota=100)
        for user in (self.admin, second, reserved):
            self.running(user)
        self.call("user.update", {"user_id": second, "quota_pool": POOL})
        self.assertEqual(budget.snapshot(self.store)["admin_remaining_bytes"], 60 * GB)
        self.sample(self.admin, up=40 * GB)
        self.sample(second, up=20 * GB)
        self.advance()
        self.assertEqual(budget.snapshot(self.store)["admin_remaining_bytes"], 0)
        for user in (self.admin, second):
            self.assertIn("quota_exceeded", domain.disabled_reasons(self.store.get_user(user), self.now))
        self.assertTrue(domain.eligible(self.store.get_user(reserved), self.now))
        self.assertEqual(self.store.get_user(reserved)["quota_bytes"], 100 * GB)

    def test_joining_requires_budget_headroom_and_a_finite_non_trial_member(self):
        seeded = seed_legacy_user(self.store, {"name": "Before budget", "quota_bytes": 100 * GB}, self.now)["id"]
        self.assertEqual(self.call("user.update", {"user_id": seeded, "quota_pool": POOL}, ok=False)["error"]["code"],
                         "BUDGET_NOT_CONFIGURED")
        self.call("user.add", {"name": "Administrator", "role": "admin"})
        self.configure(total=100)
        self.assertEqual(self.call("user.update", {"user_id": self.admin, "quota_pool": POOL}, ok=False)["error"]["code"], "VALIDATION")
        self.store.conn.execute("UPDATE users SET used_upload=? WHERE id=?", (100 * GB, seeded))
        self.store.conn.execute("INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?)", (str(uuid.uuid4()), seeded, domain.ensure_cycle(self.store, self.now)["id"],
                                "pool-fixture", 100 * GB, 0, timestamp(self.now), timestamp(self.now)))
        self.assertEqual(self.call("user.update", {"user_id": seeded, "quota_pool": POOL}, ok=False)["error"]["code"], "BUDGET_EXCEEDED")
        self.assertIsNone(self.store.get_user(seeded)["quota_pool"])
        trial = self.call("trial.create", {"name": "Trial", "quota_bytes": GB, "duration_days": 1}, ok=False)
        self.assertFalse(trial["ok"])  # No budget headroom for any new promise either.

    def test_trial_user_cannot_join_the_pool(self):
        self.call("user.add", {"name": "Administrator", "role": "admin"})
        self.configure()
        trial = self.call("trial.create", {"name": "Trial", "quota_bytes": 5 * GB, "duration_days": 3})["data"]["user"]["id"]
        self.assertEqual(self.call("user.update", {"user_id": trial, "quota_pool": POOL}, ok=False)["error"]["code"], "VALIDATION")


if __name__ == "__main__":
    unittest.main()
