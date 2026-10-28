"""A failed guard/Core start must use verified root stop evidence, never guessed trust."""
import unittest

from dazzle.production import ProductionError
import test_recovery


class ConfirmedStoppedTests(unittest.TestCase):
    setUp = test_recovery.RecoveryTests.setUp
    bootstrap = test_recovery.RecoveryTests.bootstrap
    process = test_recovery.RecoveryTests.process
    sample = test_recovery.RecoveryTests.sample
    call = test_recovery.RecoveryTests.call

    def fail_stage(self, status_override=None):
        old_worker = self.store.worker(self.member)
        other_worker = self.store.worker(self.admin)
        other_user = self.store.get_user(self.admin)
        preview = self.call('user.recovery.preview', {'user_id': self.member, 'force_restart': True})['data']['recovery']
        self.assertTrue(self.call('user.recovery.apply', {'user_id': self.member, 'force_restart': True,
            'preview_token': preview['preview_token'], 'confirm_unknown_gap': True})['ok'])
        original = self.helper.call

        def failure(request):
            if request['worker_id'] == self.member and request['action'] == 'stage':
                self.helper.records[self.member].update(generation=request['generation'], worker_state='stopped', process_id=None)
                raise ProductionError('EXECUTION', 'Isolated guard startup failed')
            result = original(request)
            if request['worker_id'] == self.member and request['action'] == 'status' and status_override:
                result.update(status_override)
            return result

        self.helper.call = failure
        self.assertFalse(self.process()['applied'])
        self.assertEqual(self.store.worker(self.admin), other_worker)
        self.assertEqual(self.store.get_user(self.admin), other_user)
        current = self.store.worker(self.member)
        self.assertEqual(current['last_error'], 'EXECUTION')
        self.assertFalse(self.store.get_user(self.member)['trusted_sample'])
        return old_worker, current

    def test_verified_empty_cgroup_records_stop_without_weakening_meter_failure(self):
        _, current = self.fail_stage()
        self.assertEqual(current['observed_state'], 'stopped')
        self.assertIsNone(current['process_id'])
        self.assertFalse(current['origin_pending'])
        incidents = self.store.conn.execute("SELECT kind FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL", (self.member,)).fetchall()
        self.assertIn('helper_operation_unconfirmed', {x[0] for x in incidents})

    def test_an_existing_pid_is_not_stopped_evidence(self):
        old, current = self.fail_stage({'process_id': 999})
        self.assertEqual(current['observed_state'], old['observed_state'])
        self.assertEqual(current['process_id'], old['process_id'])

    def test_wrong_policy_port_cannot_acknowledge_a_stop(self):
        old, current = self.fail_stage({'public_port': 24430})
        self.assertEqual(current['root_ack_generation'], old['root_ack_generation'])
        self.assertEqual(current['process_id'], old['process_id'])

    def test_unknown_cgroup_state_cannot_acknowledge_a_stop(self):
        old, current = self.fail_stage({'inactive_confirmed': False})
        self.assertEqual(current['process_id'], old['process_id'])

    def test_old_generation_cannot_acknowledge_a_stop(self):
        old, current = self.fail_stage({'generation': 0})
        self.assertEqual(current['root_ack_generation'], old['root_ack_generation'])
        self.assertEqual(current['process_id'], old['process_id'])


if __name__ == '__main__':
    unittest.main()
