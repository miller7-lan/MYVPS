from datetime import datetime, timedelta, timezone
import io
import struct
import unittest
from dazzle.mail import _safe_text
from dazzle.provider import ProviderObservation, ProviderCycleMonitor, FixtureProvider, next_poll_seconds
from dazzle.metering import CounterTracker, MeterSample, NativeAPI, MeteringError, grpc_frames

NOW = datetime(2026, 11, 24, 8, 19, tzinfo=timezone.utc)

def observation(**changes):
    data = dict(instance_id="4920", observed_at=NOW.isoformat(), source="isolated_fixture", evidence="Fixture provider panel evidence")
    data.update(changes)
    return ProviderObservation(**data)

def frame(data, flags=0):
    return struct.pack(">BI", flags, len(data)) + data

class ProviderTests(unittest.TestCase):
    def test_unconfigured_is_explicitly_unavailable(self):
        result = ProviderCycleMonitor("4920").check(NOW)
        self.assertFalse(result["automatic_available"])
        self.assertEqual(result["quota_effect"], "none")
    def test_normal_early_delayed_resets_never_allocate_quota(self):
        for reset in (NOW, NOW-timedelta(hours=2), NOW-timedelta(days=1)):
            event = observation(kind="reset_confirmed", cycle_id=str(reset), verified=True, last_actual_reset_at=reset.isoformat())
            result = ProviderCycleMonitor("4920", FixtureProvider([event])).check(NOW)
            self.assertTrue(result["new_provider_reset"])
            self.assertEqual(result["quota_effect"], "none")
    def test_repeated_provider_cycle_is_not_new_reset(self):
        event = observation(kind="reset_confirmed", cycle_id="P1", verified=True, last_actual_reset_at=NOW.isoformat())
        monitor = ProviderCycleMonitor("4920", FixtureProvider([event,event]))
        self.assertTrue(monitor.check(NOW)["new_provider_reset"])
        self.assertFalse(monitor.check(NOW)["new_provider_reset"])
    def test_api_failure_and_bad_values_hold_confirmation(self):
        for bad in (TimeoutError(), observation(remaining_bytes=-1), observation(instance_id="wrong"), observation(total_bytes=100,remaining_bytes=101)):
            result = ProviderCycleMonitor("4920", FixtureProvider([bad])).check(NOW)
            self.assertEqual(result["sync_state"], "waiting_confirmation")
            self.assertEqual(result["quota_effect"], "none")
    def test_renewal_gift_plan_change_paid_reset_are_not_ordinary_cycles(self):
        for kind in ("renewal", "gift", "upgrade", "paid_reset"):
            result = ProviderCycleMonitor("4920", FixtureProvider([observation(kind=kind)])).check(NOW)
            self.assertFalse(result["new_provider_reset"])
    def test_actual_reset_needs_identity_and_timestamp(self):
        result = ProviderCycleMonitor("4920", FixtureProvider([observation(kind="reset_confirmed")])).check(NOW)
        self.assertEqual(result["sync_state"], "waiting_confirmation")
    def test_poll_never_exceeds_verified_rate_limit(self):
        self.assertEqual(next_poll_seconds(NOW.isoformat(), NOW, 1800), 1800)
        self.assertEqual(next_poll_seconds(None,NOW,60),3600)
        with self.assertRaises(ValueError):next_poll_seconds(None,NOW,1)
    def test_stale_observation_is_rejected(self):
        monitor = ProviderCycleMonitor("4920", FixtureProvider([observation(),observation(observed_at=(NOW-timedelta(seconds=1)).isoformat())]))
        self.assertEqual(monitor.check(NOW)["sync_state"],"unverified")
        self.assertEqual(monitor.check(NOW)["sync_state"],"waiting_confirmation")

class FrameTests(unittest.TestCase):
    def test_tuic_credentials_are_redacted_from_mail_text(self):
        text = _safe_text("tuic://example-user:private-example-password@192.0.2.10:443?alpn=h3")
        self.assertNotIn("private-example-password", text)
        self.assertNotIn("example-user", text)

    def test_frame_supports_integer_protobuf_payload(self):
        self.assertEqual(list(grpc_frames(io.BytesIO(frame(b"data")+frame(b"grpc-status: 0\r\n",128)))),[b"data"])
    def test_invalid_truncated_oversize_compressed_and_failed_status(self):
        for data in (b"\0\0",frame(b"data")[:-1],struct.pack(">BI",0,2**25),frame(b"x",1),frame(b"grpc-status: 16\r\n",128),frame(b"data")):
            with self.assertRaises(MeteringError):list(grpc_frames(io.BytesIO(data)))
    def test_disallow_external_api_and_weak_secret(self):
        for host,secret in (("192.0.2.1","x"*40),("localhost","x"*40),("127.0.0.1","short")):
            with self.assertRaises(MeteringError):NativeAPI(host,9000,secret)
    def test_secret_not_in_repr(self):
        api=NativeAPI("127.0.0.1",9000,"very-secret-value-1234567890")
        self.assertNotIn(api.secret,repr(api))
    def test_missing_traffic_and_negative_counter_fail(self):
        for sample in (MeterSample("1",-1,0,NOW.isoformat()),MeterSample("1",0,0,NOW.isoformat(),False),MeterSample("1",True,0,NOW.isoformat())):
            with self.assertRaises(MeteringError):sample.validate()
    def test_counter_restart_gap_and_regression_not_trusted(self):
        tracker=CounterTracker()
        self.assertTrue(tracker.advance(MeterSample("1",0,0,NOW.isoformat()))["trusted"])
        good=tracker.advance(MeterSample("1",100,200,(NOW+timedelta(seconds=1)).isoformat()))
        self.assertEqual((good["upload"],good["download"]),(100,200))
        self.assertFalse(tracker.advance(MeterSample("2",20,10,(NOW+timedelta(seconds=2)).isoformat()))["trusted"])
        self.assertFalse(tracker.advance(MeterSample("2",10,10,(NOW+timedelta(seconds=3)).isoformat()))["trusted"])
        self.assertFalse(tracker.advance(MeterSample("2",20,20,(NOW+timedelta(seconds=12)).isoformat()))["trusted"])

if __name__ == "__main__":unittest.main()
