import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dazzle import budget


class BudgetGuardCgroupTests(unittest.TestCase):
    worker = 'f517e1f6-c277-4656-bdd8-bc555a3173e1'

    def test_finds_guard_below_a_dedicated_systemd_slice(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'system-dazzle\\x2dvps\\x2dmeter\\x2dguard.slice' / (
                'dazzle-vps-meter-guard@' + self.worker + '.service')
            path.mkdir(parents=True)
            (path / 'cgroup.procs').write_text('123\n456\n')
            with patch.object(budget, 'CGROUP_ROOT', Path(folder)):
                self.assertEqual(budget._guard_cgroup_pids(self.worker), [123, 456])

    def test_empty_or_unreadable_guard_is_not_ready(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'system.slice' / ('dazzle-vps-meter-guard@' + self.worker + '.service')
            path.mkdir(parents=True)
            (path / 'cgroup.procs').write_text('')
            with patch.object(budget, 'CGROUP_ROOT', Path(folder)):
                self.assertEqual(budget._guard_cgroup_pids(self.worker), [])


if __name__ == '__main__':
    unittest.main()
