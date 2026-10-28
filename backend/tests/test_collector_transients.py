"""Transport retry windows retain real cumulative counters and existing limits."""
import datetime as dt
import json
import unittest
from unittest.mock import patch

from dazzle.collector import Collectors
from dazzle.metering import MeteringError, MeterSample
from dazzle.store import timestamp
import test_production as fixtures


class CollectorTransientTests(unittest.TestCase):
    setUp = fixtures.ProductionTests.setUp
    call = fixtures.ProductionTests.call
    add = fixtures.ProductionTests.add
    process = fixtures.ProductionTests.process
    sample = fixtures.ProductionTests.sample
    staged = fixtures.ProductionTests.staged
    running = fixtures.ProductionTests.running

    def collector(self):
        value = Collectors(self.helper, identity_probe=lambda worker,pid,role:{"pid":pid,"identity":str(pid)+":1000"})
        self.addCleanup(value.close)
        return value

    def trusted(self):
        user = self.running()
        self.sample(user, 100, 200, seconds=1)
        return user

    def event(self, collectors, user, seconds, kind="unavailable", sample=None, generation=None):
        worker = self.store.worker(user)
        key = (worker["worker_id"], generation if generation is not None else worker["observed_generation"])
        collectors._emit((key, kind, sample))
        return collectors.drain(self.store, self.now + dt.timedelta(seconds=seconds))

    def test_short_transport_failure_preserves_connection_and_recovers_all_cumulative_bytes(self):
        user = self.trusted()
        collectors = self.collector()
        before = self.store.get_user(user)
        self.assertEqual(self.event(collectors, user, 2), 1)
        self.assertEqual(self.store.get_user(user), before)
        self.assertFalse(self.store.conn.execute("SELECT 1 FROM metering_incidents").fetchone())
        self.assertFalse(self.store.conn.execute("SELECT 1 FROM production_jobs WHERE status='pending'").fetchone())
        sample = MeterSample(before["meter_epoch"], 150, 260, timestamp(self.now + dt.timedelta(seconds=4)))
        self.event(collectors, user, 4, "sample", sample)
        after = self.store.get_user(user)
        self.assertEqual((after["used_upload"], after["used_download"]), (150, 260))
        self.assertTrue(after["trusted_sample"])
        self.assertNotIn("metering_failure", json.loads(after["reasons_json"]))
        self.assertEqual(self.store.worker(user)["observed_state"], "running")

    def test_retry_errors_do_not_extend_last_real_sample_deadline(self):
        user = self.trusted()
        collectors = self.collector()
        before = self.store.get_user(user)
        for seconds in (2, 3, 5.9, 6):
            self.event(collectors, user, seconds)
            current = self.store.get_user(user)
            self.assertEqual(current["last_sample_at"], before["last_sample_at"])
            self.assertEqual(current["meter_epoch"], before["meter_epoch"])
            self.assertEqual((current["last_uplink"], current["last_downlink"]), (100, 200))
            self.assertNotIn("metering_failure", json.loads(current["reasons_json"]))
        self.event(collectors, user, 6.01)
        after = self.store.get_user(user)
        self.assertFalse(after["trusted_sample"])
        self.assertIn("metering_failure", json.loads(after["reasons_json"]))
        self.assertEqual((after["used_upload"], after["used_download"]), (100, 200))
        self.assertEqual(self.store.worker(user)["observed_state"], "running")
        self.assertTrue(self.process(seconds=6.01)["applied"])
        self.assertEqual(self.store.worker(user)["observed_state"], "staged")

    def test_identity_change_is_immediate_even_with_a_fresh_sample(self):
        user = self.trusted()
        self.event(self.collector(), user, 2, "identity_changed")
        current = self.store.get_user(user)
        self.assertFalse(current["trusted_sample"])
        self.assertIn("metering_failure", json.loads(current["reasons_json"]))
        self.assertEqual(self.store.worker(user)["last_error"], "STATUS_RECHECK_REQUIRED")

    def assert_invalid_cumulative_sample(self, changed_epoch):
        user = self.trusted()
        before = self.store.get_user(user)
        sample = MeterSample("different-epoch" if changed_epoch else before["meter_epoch"],
                             110 if changed_epoch else 99, 210,
                             timestamp(self.now + dt.timedelta(seconds=2)))
        self.event(self.collector(), user, 2, "sample", sample)
        after = self.store.get_user(user)
        self.assertIn("metering_failure", json.loads(after["reasons_json"]))
        self.assertFalse(after["trusted_sample"])
        self.assertEqual((after["used_upload"], after["used_download"]), (100, 200))

    def test_valid_sample_epoch_change_still_fails_immediately(self):
        self.assert_invalid_cumulative_sample(True)

    def test_counter_regression_still_fails_immediately(self):
        self.assert_invalid_cumulative_sample(False)

    def test_origin_initialization_uses_root_deadline_without_inventing_a_sample(self):
        user = self.add()
        self.process()
        self.process(seconds=10)
        collectors = self.collector()
        worker = self.store.worker(user)
        self.assertTrue(worker["origin_pending"])
        self.assertIsNone(self.store.get_user(user)["last_sample_at"])
        self.event(collectors, user, 10.5)
        self.event(collectors, user, 14.9)
        current = self.store.get_user(user)
        self.assertIsNone(current["last_sample_at"])
        self.assertFalse(current["trusted_sample"])
        self.assertNotIn("metering_failure", json.loads(current["reasons_json"]))
        self.assertEqual(self.store.worker(user)["verified_at"], worker["verified_at"])
        self.assertFalse(self.store.conn.execute("SELECT 1 FROM production_jobs WHERE status='pending'").fetchone())
        sample = MeterSample("new-origin", 7, 13, timestamp(self.now + dt.timedelta(seconds=15)))
        self.event(collectors, user, 15, "sample", sample)
        current = self.store.get_user(user)
        self.assertTrue(current["trusted_sample"])
        self.assertEqual((current["used_upload"], current["used_download"]), (7, 13))
        self.assertTrue(current["manual_disabled"])

    def test_origin_initialization_errors_cannot_extend_root_deadline(self):
        user = self.add()
        self.process()
        self.process()
        collectors = self.collector()
        verified_at = self.store.worker(user)["verified_at"]
        for seconds in (1, 3, 5):
            self.event(collectors, user, seconds)
            self.assertIsNone(self.store.get_user(user)["last_sample_at"])
            self.assertEqual(self.store.worker(user)["verified_at"], verified_at)
            self.assertNotIn("metering_failure", json.loads(self.store.get_user(user)["reasons_json"]))
        self.event(collectors, user, 5.01)
        self.assertIn("metering_failure", json.loads(self.store.get_user(user)["reasons_json"]))

    def test_transport_event_does_not_clear_existing_manual_quota_or_metering_limits(self):
        user = self.trusted()
        self.call("user.disable", {"user_id": user})
        reasons = ["quota_exceeded", "metering_failure"]
        self.store.conn.execute("UPDATE users SET reasons_json=?,trusted_sample=0,meter_state='reconciliation_required' WHERE id=?",
                                (json.dumps(reasons), user))
        self.event(self.collector(), user, 2)
        current = self.store.get_user(user)
        self.assertTrue(current["manual_disabled"])
        self.assertEqual(set(json.loads(current["reasons_json"])), set(reasons))
        self.assertFalse(current["trusted_sample"])

    def test_explicit_native_integrity_error_is_immediate(self):
        user = self.trusted()
        self.event(self.collector(), user, 2, "invalid_sample")
        self.assertIn("metering_failure", json.loads(self.store.get_user(user)["reasons_json"]))
        self.assertTrue(self.store.conn.execute("SELECT 1 FROM metering_incidents WHERE kind='native_stream_integrity_failure'").fetchone())

    def test_reader_keeps_eof_timeout_and_temporary_http_failures_as_transport_events(self):
        class StopAfterRetry:
            stopped = False
            def is_set(self):
                return self.stopped
            def wait(self, _seconds):
                self.stopped = True

        errors = (
            (MeteringError("Truncated gRPC-Web frame"), "unavailable"),
            (MeteringError("gRPC-Web closed without successful trailer"), "unavailable"),
            (MeteringError("Native API connection failed"), "unavailable"),
            (TimeoutError("isolated timeout"), "unavailable"),
            (MeteringError("Worker epoch changed while opening traffic stream"), "identity_changed"),
            (MeteringError("Invalid integer payload counter"), "invalid_sample"),
            # NativeAPI also uses this wrapper for trafficAvailable=False;
            # it cannot establish an invalid counter by itself.
            (MeteringError("Native API traffic decode failed"), "unavailable"),
        )
        user = self.trusted()
        worker = self.store.worker(user)
        for error, expected in errors:
            with self.subTest(error=str(error)):
                class BrokenAPI:
                    def stream(self):
                        raise error
                collectors = self.collector()
                collectors.api_factory = lambda *_args, **_kwargs: BrokenAPI()
                collectors._read(worker, StopAfterRetry())
                _key, kind, _sample = collectors.events.get_nowait()
                self.assertEqual(kind, expected)


    def test_slow_confirmed_activation_waits_for_native_origin_without_restart_loop(self):
        from dazzle.collector import tick
        from dazzle.production import refresh_worker_status
        user = self.staged()
        self.call("user.enable", {"user_id": user})
        from dazzle.production import process_one_job
        with patch("dazzle.production.utcnow", side_effect=[self.now, self.now + dt.timedelta(seconds=10)]):
            self.assertTrue(process_one_job(self.store, self.helper)["applied"])
        worker = self.store.worker(user)
        self.assertTrue(worker["origin_pending"])
        self.event(self.collector(), user, 10.5)
        tick(self.store, self.now + dt.timedelta(seconds=10.5))
        self.assertFalse(self.store.conn.execute("SELECT 1 FROM production_jobs WHERE status='pending'").fetchone())
        self.assertEqual(self.store.worker(user)["process_id"], worker["process_id"])
        refresh_worker_status(self.store, self.helper, self.now + dt.timedelta(seconds=14.9), user_id=user)
        self.assertEqual(self.store.worker(user)["verified_at"], worker["verified_at"])
        self.assertFalse(self.store.conn.execute("SELECT 1 FROM production_jobs WHERE status='pending'").fetchone())
        tick(self.store, self.now + dt.timedelta(seconds=15.01))
        self.assertIn("metering_failure", json.loads(self.store.get_user(user)["reasons_json"]))
        self.assertEqual(self.store.conn.execute("SELECT action FROM production_jobs WHERE status='pending'").fetchone()[0], "stage")

    def test_first_origin_wait_does_not_override_a_new_manual_pause(self):
        user = self.staged()
        self.call("user.enable", {"user_id": user})
        from dazzle.production import process_one_job
        with patch("dazzle.production.utcnow", side_effect=[self.now, self.now + dt.timedelta(seconds=10)]):
            self.assertTrue(process_one_job(self.store, self.helper)["applied"])
        self.call("user.disable", {"user_id": user}, now=self.now + dt.timedelta(seconds=10.5))
        self.assertTrue(self.store.get_user(user)["manual_disabled"])
        self.assertEqual(self.store.conn.execute("SELECT action FROM production_jobs WHERE status='pending'").fetchone()[0], "stage")


if __name__ == "__main__":
    unittest.main()
