"""Late native samples must not move prior-cycle bytes into new quotas."""
import datetime as dt
import unittest

from dazzle import domain
from dazzle.metering import MeterSample
from dazzle.production import accept_sample
from dazzle.store import parse_time, timestamp
import test_production as fixtures


class RetiredCycleTests(unittest.TestCase):
    setUp = fixtures.ProductionTests.setUp
    call = fixtures.ProductionTests.call
    add = fixtures.ProductionTests.add
    process = fixtures.ProductionTests.process
    sample = fixtures.ProductionTests.sample
    staged = fixtures.ProductionTests.staged
    running = fixtures.ProductionTests.running

    def prepare(self, *, closing_cutoff=False):
        old_cycle = domain.ensure_cycle(self.store, self.now)
        boundary = parse_time(old_cycle["end_at"])
        self.now = boundary - dt.timedelta(seconds=2)
        self.store.now = self.now
        user = self.running()
        self.sample(user, 10, 0)
        old_worker = self.store.worker(user)
        old_user = self.store.get_user(user)
        if closing_cutoff:
            self.sample(user, 15, 0, seconds=3)
            old_user = self.store.get_user(user)
        self.now = boundary + dt.timedelta(seconds=2 if closing_cutoff else .1)
        self.store.now = self.now
        self.store.conn.execute("BEGIN IMMEDIATE")
        domain._cycle_tick(self.store, self.now)
        self.store.conn.commit()
        self.call("user.disable", {"user_id": user})
        self.assertTrue(self.process()["applied"])
        return user, old_worker, old_user, old_cycle, boundary

    def late(self, old_worker, old_user, up, at):
        self.store.conn.execute("BEGIN IMMEDIATE")
        result = accept_sample(self.store, old_worker["worker_id"], old_worker["observed_generation"],
            MeterSample(old_user["meter_epoch"], up, 0, timestamp(at)), self.now)
        self.store.conn.commit()
        return result

    def test_wholly_old_late_sample_stays_known_unallocated_after_refresh(self):
        user, worker, baseline, old_cycle, boundary = self.prepare()
        result = self.late(worker, baseline, 15, boundary - dt.timedelta(seconds=1))
        self.assertFalse(result["allocated"])
        self.assertEqual(result["upload_delta"], 5)
        current = domain.ensure_cycle(self.store, self.now)
        self.assertEqual(self.store.get_user(user)["used_upload"], 0)
        self.assertEqual(self.store.conn.execute("SELECT COALESCE(SUM(upload),0) FROM ledger WHERE cycle_id=?", (current["id"],)).fetchone()[0], 0)
        retired = self.store.conn.execute("SELECT * FROM production_retired_origins WHERE worker_id=? AND generation=?",
            (worker["worker_id"], worker["observed_generation"])).fetchone()
        self.assertEqual(retired["cycle_id"], old_cycle["id"])
        incident = self.store.conn.execute("SELECT * FROM metering_incidents WHERE user_id=? AND kind='retired_origin_unallocated'", (user,)).fetchone()
        self.assertEqual(incident["previous_at"], baseline["last_sample_at"])
        self.assertEqual(incident["sample_at"], timestamp(boundary - dt.timedelta(seconds=1)))
        self.assertEqual(incident["unallocated_upload"], 5)

    def test_straddling_delta_is_not_guessed_into_new_cycle(self):
        user, worker, baseline, _, boundary = self.prepare()
        self.now = boundary + dt.timedelta(seconds=3)
        # The generation retired before the final sample timestamp; only samples
        # taken before retirement qualify for a recoverable tail.
        self.store.conn.execute("UPDATE production_retired_origins SET retired_at=? WHERE worker_id=? AND generation=?",
            (timestamp(self.now), worker["worker_id"], worker["observed_generation"]))
        result = self.late(worker, baseline, 15, boundary + dt.timedelta(seconds=1))
        self.assertFalse(result["allocated"])
        self.assertEqual(result["upload_delta"], 5)
        self.assertEqual(self.store.get_user(user)["used_upload"], 0)

    def test_post_cutoff_known_tail_counts_once_in_current_cycle(self):
        user, worker, baseline, _, boundary = self.prepare(closing_cutoff=True)
        result = self.late(worker, baseline, 20, boundary + dt.timedelta(seconds=1.5))
        self.assertTrue(result["allocated"])
        self.assertEqual(self.store.get_user(user)["used_upload"], 5)
        duplicate = self.late(worker, baseline, 20, boundary + dt.timedelta(seconds=1.5))
        self.assertTrue(duplicate["ignored"])
        self.assertEqual(self.store.get_user(user)["used_upload"], 5)
