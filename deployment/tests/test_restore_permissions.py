"""Rollback keeps a low-privilege writer's policy readable after atomic replace."""
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock

from deployment.coordinator import Coordinator, Host, Layout
from deployment.installer import sha256


class RestorePermissionTests(unittest.TestCase):
    def coordinator(self, host, path, original, replacement, group):
        coordinator = Coordinator.__new__(Coordinator)
        coordinator.host = host
        coordinator.run_dir = path.parent / "receipt"
        coordinator.reviewed = {"files": {str(path): {
            "before_sha256": sha256(original), "after_sha256": sha256(replacement),
            "mode": "0640", "group": group,
        }}}
        return coordinator

    def test_restored_policy_retains_real_group_and_read_permissions(self):
        with tempfile.TemporaryDirectory(prefix="dazzle-restore-permissions-") as temporary:
            folder = Path(temporary).resolve()
            path = folder / "policy.json"
            path.write_bytes(b"new v2 policy\n")
            groups = sorted(set(os.getgroups()) - {os.getegid()})
            if os.geteuid() == 0:
                groups.append(65534)
            project_gid = None
            for group in groups:
                try:
                    os.chown(path, -1, group)
                except PermissionError:
                    continue
                project_gid = group
                break
            if project_gid is None:
                self.skipTest("A second permitted group is required to observe atomic inode ownership")
            path.chmod(0o640)
            host = Host(Layout(trusted_uid=os.geteuid()))
            host.group = lambda name: project_gid if name == "dazzle-vps" else None
            original = b"original v1 policy\n"
            coordinator = self.coordinator(host, path, original, path.read_bytes(), "dazzle-vps")
            coordinator.run_dir.mkdir()
            (coordinator.run_dir / "original-policy.json").write_bytes(original)

            self.assertTrue(coordinator.restore_planned(path))

            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(path.stat().st_uid, os.geteuid())
            self.assertEqual(path.stat().st_gid, project_gid)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_root_group_restore_is_explicit_and_foreign_edits_are_preserved(self):
        path, original, replacement = Path("/reviewed/policy.json"), b"old", b"new"
        host = Mock()
        coordinator = self.coordinator(host, path, original, replacement, "root")
        backup = coordinator.run_dir / "original-policy.json"
        host.read.side_effect = lambda target: replacement if target == path else original if target == backup else None

        self.assertTrue(coordinator.restore_planned(path))
        host.write.assert_called_once_with(path, original, mode=0o640, gid=0)
        host.group.assert_not_called()

        host.reset_mock()
        host.read.side_effect = lambda target: b"foreign edit"
        self.assertFalse(coordinator.restore_planned(path))
        host.write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
