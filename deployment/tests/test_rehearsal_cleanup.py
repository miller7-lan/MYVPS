"""The disposable-host rehearsal only removes accounts and groups it created itself.

Every command is recorded instead of run, and paths are inert stand-ins, so these
tests never touch a real file, unit, account or group.
"""
import unittest
from unittest.mock import patch

from deployment.tests.systemd_handoff import rehearsal


class Result:
    stdout = ""


class NoPath:
    def __init__(self, *_):
        pass

    def glob(self, _):
        return []

    def is_symlink(self):
        return False

    def is_file(self):
        return False

    def is_dir(self):
        return False


class RehearsalIdentityTests(unittest.TestCase):
    def recorder(self, groups=(), accounts=()):
        commands, existing = [], {"/usr/sbin/groupadd": groups, "/usr/sbin/useradd": accounts}
        def run(*arguments, check=True, timeout=60):
            commands.append(arguments)
            if arguments[-1] in existing.get(arguments[0], ()):
                raise AssertionError(arguments[0] + ": '" + arguments[-1] + "' already exists")
            return Result()
        return commands, run

    @staticmethod
    def removals(commands):
        return [command for command in commands if command[0] in {"/usr/sbin/userdel", "/usr/sbin/groupdel"}]

    def test_failed_setup_never_deletes_a_group_that_was_already_there(self):
        commands, run = self.recorder(groups={"dazzle-vps"})
        fixture = rehearsal.Rehearsal("success")
        with patch.object(rehearsal, "run", run), patch.object(rehearsal, "Path", NoPath), \
                patch.object(rehearsal.shutil, "rmtree"):
            with self.assertRaises(AssertionError):
                fixture.setup()
            fixture.teardown()  # As main() does in its finally block.
        self.assertEqual(self.removals(commands), [("/usr/sbin/groupdel", "dazzle-agent"),
                                                   ("/usr/sbin/groupdel", "dazzle-proxy")])

    def test_preexisting_account_is_kept_while_created_groups_are_removed(self):
        commands, run = self.recorder(accounts={"dazzle-proxy"})
        fixture = rehearsal.Rehearsal("success")
        with patch.object(rehearsal, "run", run):
            with self.assertRaises(AssertionError):
                fixture.create_identities()
            fixture.remove_identities()
        self.assertEqual(self.removals(commands), [("/usr/sbin/userdel", "dazzle-agent"),
                                                   *[("/usr/sbin/groupdel", name) for name in rehearsal.GROUPS]])

    def test_every_created_identity_is_removed(self):
        commands, run = self.recorder()
        fixture = rehearsal.Rehearsal("success")
        with patch.object(rehearsal, "run", run):
            fixture.create_identities()
            fixture.remove_identities()
        self.assertEqual(self.removals(commands), [*[("/usr/sbin/userdel", name) for name in rehearsal.ACCOUNTS],
                                                   *[("/usr/sbin/groupdel", name) for name in rehearsal.GROUPS]])

    def test_preflight_sees_a_preexisting_group_without_its_accounts(self):
        def absent(name):
            raise KeyError(name)
        def group(name):
            if name != "dazzle-vps":
                raise KeyError(name)
        with patch.object(rehearsal.pwd, "getpwnam", absent), patch.object(rehearsal.grp, "getgrnam", group):
            self.assertEqual(rehearsal.existing_identities(), ["dazzle-vps"])


if __name__ == "__main__":
    unittest.main()
