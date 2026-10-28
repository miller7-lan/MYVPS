"""Real stream/drain/tick and acknowledged-helper concurrency regressions.

All identities are explicit isolated probes. No host systemd, production state
or historical /tmp material is needed to run these tests.
"""
import datetime as dt
import json
import threading
import unittest
from unittest.mock import Mock, patch

from dazzle import domain
from dazzle.collector import Collectors, tick
from dazzle.metering import MeterSample
from dazzle.production import process_one_job, refresh_worker_status
from dazzle.store import timestamp
import test_production as fixtures


class StatusRaceTests(unittest.TestCase):
    setUp = fixtures.ProductionTests.setUp
    call = fixtures.ProductionTests.call
    add = fixtures.ProductionTests.add
    process = fixtures.ProductionTests.process
    sample = fixtures.ProductionTests.sample
    staged = fixtures.ProductionTests.staged
    running = fixtures.ProductionTests.running

    def trusted(self, role="member"):
        user = self.running(role=role)
        self.sample(user, 100, 200, seconds=1)
        return user

    def worker(self, user):
        return {**self.store.worker(user), "server_id": self.store.server_id}

    @staticmethod
    def same_identity(worker, pid, role):
        return {"pid": pid, "identity": str(pid) + ":1000"}

    def samples(self, user, stop):
        epoch = self.store.get_user(user)["meter_epoch"]
        now = self.now
        class API:
            def stream(self):
                yield MeterSample(epoch, 150, 260, timestamp(now + dt.timedelta(seconds=2)))
                yield MeterSample(epoch, 175, 280, timestamp(now + dt.timedelta(seconds=3)))
                stop.set()
        return lambda *_args, **_kwargs: API()

    def test_first_native_frames_reach_ledger_and_tick_without_any_helper_status(self):
        user = self.trusted()
        stop, release = threading.Event(), threading.Event()
        helper = Mock()
        # If this forbidden method is accidentally called, it would hold back
        # sampling. The test does not wait for any helper in the success path.
        helper.call.side_effect = lambda *_: release.wait(3)
        probe = Mock(side_effect=self.same_identity)
        collectors = Collectors(helper, api_factory=self.samples(user, stop), identity_probe=probe)
        self.addCleanup(collectors.close)
        thread = threading.Thread(target=collectors._read, args=(self.worker(user), stop), daemon=True)
        thread.start()
        try:
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive(), "Native stream was blocked by a management operation")
            helper.call.assert_not_called()
            self.assertEqual(probe.call_count, 2)
            self.assertEqual(collectors.drain(self.store, self.now + dt.timedelta(seconds=3)), 2)
            tick(self.store, self.now + dt.timedelta(seconds=3))
            after = self.store.get_user(user)
            self.assertEqual((after["used_upload"], after["used_download"]), (175, 280))
            self.assertTrue(after["trusted_sample"])
            self.assertNotIn("metering_failure", json.loads(after["reasons_json"]))
            self.assertFalse(self.store.conn.execute("SELECT 1 FROM production_jobs WHERE status='pending'").fetchone())
        finally:
            release.set(); stop.set(); thread.join(timeout=1)

    def test_registered_administrator_uses_its_own_cgroup_role(self):
        user = self.trusted("admin")
        stop = threading.Event(); probe = Mock(side_effect=self.same_identity)
        collectors = Collectors(self.helper, api_factory=self.samples(user, stop), identity_probe=probe)
        self.addCleanup(collectors.close)
        collectors._read(self.worker(user), stop)
        self.assertEqual([call.args[2] for call in probe.call_args_list], ["admin", "admin"])
        self.assertEqual(collectors.drain(self.store, self.now + dt.timedelta(seconds=3)), 2)

    def test_pid_or_start_ticks_change_between_opening_and_first_frame_is_rejected(self):
        user = self.trusted()
        worker = self.worker(user); pid = worker["process_id"]
        variants = ({"pid": pid + 1, "identity": str(pid + 1) + ":1000"},
                    {"pid": pid, "identity": str(pid) + ":2000"},
                    {"pid": pid, "identity": None})
        for actual in variants:
            with self.subTest(actual=actual):
                stop = threading.Event()
                probe = Mock(side_effect=[self.same_identity("fixture", pid, "member"), actual])
                collectors = Collectors(self.helper, api_factory=self.samples(user, stop), identity_probe=probe)
                collectors._read(worker, stop)
                key, kind, sample = collectors.events.get_nowait()
                self.assertEqual((key, kind, sample), ((worker["worker_id"], worker["observed_generation"]), "identity_changed", None))
                self.assertTrue(collectors.events.empty())
                collectors.close()

    def test_missing_process_identity_never_opens_api_or_falls_back_to_helper(self):
        user = self.trusted(); stop = threading.Event(); factory = Mock(); helper = Mock()
        collectors = Collectors(helper, api_factory=factory,
                                identity_probe=Mock(side_effect=OSError("isolated unreadable cgroup")))
        collectors._read(self.worker(user), stop)
        factory.assert_not_called(); helper.call.assert_not_called()
        self.assertEqual(collectors.events.get_nowait()[1], "identity_changed")
        collectors.close()

    def test_stale_generation_identity_error_cannot_pause_current_generation(self):
        user = self.trusted(); worker = self.worker(user)
        collectors = Collectors(self.helper, identity_probe=self.same_identity)
        before = self.store.get_user(user)
        collectors._emit(((worker["worker_id"], worker["observed_generation"] - 1), "identity_changed", None))
        collectors.drain(self.store, self.now + dt.timedelta(seconds=2))
        self.assertEqual(self.store.get_user(user), before)
        self.assertEqual(self.store.worker(user)["observed_generation"], worker["observed_generation"])
        collectors.close()

    def test_managed_completion_during_status_io_does_not_invent_unknown_restart(self):
        user = self.staged(); self.call("user.enable", {"user_id": user})
        original, store, now = self.helper, self.store, self.now
        outer = self
        class Completing:
            def call(self, request):
                outer.assertTrue(process_one_job(store, original, now=now)["applied"])
                return original.call(request)
        refresh_worker_status(store, Completing(), now)
        self.assertEqual(store.worker(user)["observed_state"], "running")
        self.assertNotIn("metering_failure", json.loads(store.get_user(user)["reasons_json"]))
        self.assertFalse(store.conn.execute("SELECT 1 FROM metering_incidents WHERE kind='worker_status_changed'").fetchone())

    def test_old_status_reply_cannot_rewind_a_newly_acknowledged_generation(self):
        user = self.staged(); self.call("user.enable", {"user_id": user})
        original, store, now = self.helper, self.store, self.now
        outer = self
        class Delayed:
            def call(self, request):
                captured = original.call(request)
                outer.assertTrue(process_one_job(store, original, now=now)["applied"])
                return captured
        refresh_worker_status(store, Delayed(), now)
        self.assertEqual(store.worker(user)["root_ack_generation"], original.records[user]["generation"])
        self.assertEqual(store.worker(user)["observed_state"], "running")

    def test_stream_batch_uses_real_current_time_after_each_database_transaction(self):
        user = self.trusted(); worker = self.worker(user); epoch = self.store.get_user(user)["meter_epoch"]
        collectors = Collectors(self.helper, identity_probe=self.same_identity)
        current = [self.now + dt.timedelta(seconds=2)]
        produced = [0]
        def emit_next():
            if produced[0] >= 7:
                return
            produced[0] += 1
            sample = MeterSample(epoch, 100 + produced[0]*10, 200 + produced[0]*20, timestamp(current[0]))
            collectors._emit(((worker["worker_id"], worker["observed_generation"]), "sample", sample))
        original = self.store.conn
        class AdvancingConnection:
            def __getattr__(self, name):
                return getattr(original, name)
            def commit(self):
                original.commit()
                current[0] += dt.timedelta(seconds=1)
                emit_next()
        emit_next()
        self.store.conn = AdvancingConnection()
        try:
            # Advancing after a transaction models ordinary frames arriving
            # while a slow database/lock makes the batch exceed five seconds.
            with patch("dazzle.collector.utcnow", side_effect=lambda: current[0]):
                self.assertEqual(collectors.drain(self.store), 7)
        finally:
            self.store.conn = original
            collectors.close()
        tick(self.store, current[0])
        after = self.store.get_user(user)
        self.assertEqual((after["used_upload"], after["used_download"]), (170, 340))
        self.assertTrue(after["trusted_sample"])
        self.assertNotIn("metering_failure", json.loads(after["reasons_json"]))
        self.assertFalse(self.store.conn.execute("SELECT 1 FROM production_jobs WHERE status='pending'").fetchone())

    def test_explicit_test_timestamp_still_rejects_a_future_sample(self):
        user = self.trusted(); worker = self.worker(user)
        before = self.store.get_user(user)
        sample = MeterSample(before["meter_epoch"], 150, 260,
                             timestamp(self.now + dt.timedelta(seconds=9)))
        collectors = Collectors(self.helper, identity_probe=self.same_identity)
        self.addCleanup(collectors.close)
        collectors._emit(((worker["worker_id"], worker["observed_generation"]), "sample", sample))
        # A frame stamped before the host clock stepped back by more than the
        # window is never accounted, and it no longer stops the only writer.
        self.assertEqual(collectors.drain(self.store, self.now + dt.timedelta(seconds=2)), 1)
        after = self.store.get_user(user)
        for key in ("used_upload", "used_download", "last_uplink", "last_downlink", "last_sample_at", "trusted_sample"):
            self.assertEqual(after[key], before[key])
        # Explicitly supplied samples keep strict validation.
        with self.assertRaises(domain.DomainError):
            domain._sample(self.store, {"user_id": user, "epoch": before["meter_epoch"], "uplink": 150, "downlink": 260,
                                        "at": timestamp(self.now + dt.timedelta(seconds=9))}, self.now + dt.timedelta(seconds=2))

    def clock_step_event(self, user, seconds, up, down, *, received=0.1):
        """One native frame stamped after the host clock moved to now+seconds."""
        worker = self.worker(user)
        collectors = Collectors(self.helper, identity_probe=self.same_identity)
        self.addCleanup(collectors.close)
        sample = MeterSample(self.store.get_user(user)["meter_epoch"], up, down,
                             timestamp(self.now + dt.timedelta(seconds=seconds)))
        collectors._emit(((worker["worker_id"], worker["observed_generation"]), "sample", sample))
        return collectors.drain(self.store, self.now + dt.timedelta(seconds=seconds + received))

    def test_small_clock_step_back_keeps_counting_without_stopping_the_writer(self):
        user = self.trusted()  # Last ledger frame at now+1s.
        before = self.store.get_user(user)
        incidents = self.store.conn.execute("SELECT COUNT(*) FROM metering_incidents").fetchone()[0]
        # NTP stepped the clock back 1.5s between two 1Hz frames. This used to
        # raise "Out-of-order samples" out of drain() and end the writer.
        self.assertEqual(self.clock_step_event(user, -0.5, 150, 260), 1)
        after = self.store.get_user(user)
        self.assertEqual((after["used_upload"], after["used_download"]), (150, 260))
        self.assertTrue(after["trusted_sample"])
        self.assertNotIn("metering_failure", json.loads(after["reasons_json"]))
        # The ledger follows the stepped clock at once; the next frame continues normally.
        self.assertEqual(after["last_sample_at"], timestamp(self.now - dt.timedelta(seconds=0.5)))
        self.assertNotEqual(after["last_sample_at"], before["last_sample_at"])
        self.assertEqual(self.clock_step_event(user, 0.5, 160, 270), 1)
        self.assertEqual((self.store.get_user(user)["used_upload"], self.store.get_user(user)["used_download"]), (160, 270))
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM metering_incidents").fetchone()[0], incidents)
        self.assertEqual(self.store.worker(user)["observed_state"], "running")

    def test_large_clock_step_back_is_one_user_incident_not_a_writer_failure(self):
        user = self.trusted()
        before = self.store.get_user(user)
        self.assertEqual(self.clock_step_event(user, -29, 150, 260), 1)
        self.assertEqual(self.clock_step_event(user, -28, 170, 280), 1)
        after = self.store.get_user(user)
        # The interval across the step is recorded, never charged; frames after
        # the step are counted again, but access waits for reconciliation.
        incidents = self.store.conn.execute("SELECT unallocated_upload,unallocated_download FROM metering_incidents "
                                            "WHERE user_id=? AND kind='clock_stepped_back'", (user,)).fetchall()
        self.assertEqual([tuple(row) for row in incidents], [(50, 60)])
        self.assertEqual((after["used_upload"], after["used_download"]),
                         (before["used_upload"] + 20, before["used_download"] + 20))
        self.assertIn("metering_failure", json.loads(after["reasons_json"]))
        self.assertEqual(after["meter_state"], "reconciliation_required")
        self.assertEqual(self.store.conn.execute("SELECT action FROM production_jobs WHERE status='pending'").fetchone()[0], "stage")

    def test_meter_guard_tolerates_only_a_bounded_clock_step(self):
        from dazzle.meter_guard import GuardError, age
        self.assertEqual(age(timestamp(self.now + dt.timedelta(seconds=4.9)), self.now), 0.0)
        self.assertAlmostEqual(age(timestamp(self.now - dt.timedelta(seconds=4.9)), self.now), 4.9)
        for seconds in (5.1, -5.1):
            with self.subTest(seconds=seconds), self.assertRaises(GuardError):
                age(timestamp(self.now + dt.timedelta(seconds=seconds)), self.now)


if __name__ == "__main__":
    unittest.main()
