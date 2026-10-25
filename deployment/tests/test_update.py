from contextlib import ExitStack, closing
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from deployment import update
from deployment.installer import canonical, sha256
from deployment.release import build_release
from deployment.tests.test_deployment import baseline
from deployment.tests import test_repair


class ProgramUpdateTests(unittest.TestCase):
    def setUp(self):
        test_repair.ProgramOnlyRepairTests.setUp(self)
        # The deployed lock-fix tool already exists and must remain unchanged.
        for root in (self.old, self.old / "venv/lib/python3.12/site-packages"):
            shutil.copyfile(self.repo / "deployment/repair.py", root / "deployment/repair.py")
        (self.repo / "deployment/update.py").write_text("# reviewed program update fixture\n")
        self.archive = self.base / "update.tar.gz"
        build_release(self.repo, self.wheel, self.wheel_sha, self.archive)
        registry = self.etc / "registry.json"
        registry.write_text('{"tombstone":"preserved"}'); registry.chmod(0o600)
        self.backup = self.base / "immutable-backup.sqlite3"
        self.backup.touch(mode=0o600)
        with closing(sqlite3.connect(self.backup)) as connection, connection:
            connection.executescript("CREATE TABLE users(id TEXT PRIMARY KEY,revoked_at TEXT);CREATE TABLE ledger(id TEXT PRIMARY KEY,bytes INTEGER);")
            connection.execute("INSERT INTO users VALUES('revoked-user','permanent-revocation')")
            connection.execute("INSERT INTO ledger VALUES('integer-event',?)", (2**53 + 123,))
        self.backup_sha = sha256(self.backup.read_bytes())
        self.policy = json.loads((self.etc / "policy.json").read_text())
        self.admin = {"dazzle-admin@" + next(iter(self.policy["workers"])) + ".service":
                      {"active": "active", "pid": 4455, "nrestarts": 0}}

    tearDown = test_repair.ProgramOnlyRepairTests.tearDown

    def preview(self):
        return update.preview_update(self.archive, self.backup, self.backup_sha, prefix=self.prefix,
                                     etc=self.etc, trusted_uid=os.getuid(), runner=self.runner,
                                     baseline=baseline(), admin_baseline=self.admin)

    def rebuild(self):
        archive = self.base / ("changed-" + str(len(list(self.base.glob('changed-*')))) + ".tar.gz")
        build_release(self.repo, self.wheel, self.wheel_sha, archive)
        self.archive = archive

    def test_preview_binds_exact_sources_backup_and_original_authorization_without_mutation(self):
        before = {path for path in self.base.rglob("*")}
        result = self.preview()
        self.assertTrue(result["ready"])
        self.assertEqual([row["path"] for row in result["changed_files"]], ["backend/dazzle/store.py", "deployment/update.py"])
        self.assertEqual(result["backup"]["sha256"], self.backup_sha)
        self.assertEqual(result["administrator_baseline"], self.admin)
        self.assertFalse(result["production_database_opened"])
        self.assertEqual(before, {path for path in self.base.rglob("*")})
        self.runner.run.assert_not_called()

    def test_root_helper_units_protocol_and_module_deletion_are_outside_scope(self):
        for name in ("deployment/helper.py", "deployment/systemd/dazzle-vps-agent.service", "backend/dazzle/control.proto"):
            path = self.repo / name
            path.write_text("unexpected privileged or protocol change")
        (self.repo / "backend/dazzle/collector.py").unlink()
        self.rebuild()
        result = self.preview()
        self.assertFalse(result["ready"])
        for name in ("deployment/helper.py", "deployment/systemd/dazzle-vps-agent.service", "backend/dazzle/control.proto", "backend/dazzle/collector.py"):
            self.assertIn(name, result["unexpected_changes"])

    def test_backup_changes_or_sidecars_are_rejected(self):
        self.backup.write_bytes(self.backup.read_bytes() + b"changed")
        with self.assertRaises(ValueError): self.preview()
        self.backup_sha = sha256(self.backup.read_bytes())
        Path(str(self.backup) + "-wal").touch()
        with self.assertRaises(ValueError): self.preview()

    def test_backup_must_be_private_and_separate_from_production(self):
        self.backup.chmod(0o644)
        with self.assertRaises(ValueError): self.preview()
        self.backup.chmod(0o600)
        with self.assertRaises(ValueError):
            update.backup_digest(self.backup, self.backup_sha, state_dir=self.base, trusted_uid=os.getuid())

    def test_exact_preview_confirmation_required_before_any_process_operation(self):
        with self.assertRaises(ValueError):
            update.apply_update(self.archive, self.preview(), "0" * 64, prefix=self.prefix, etc=self.etc,
                                trusted_uid=os.getuid(), runner=self.runner)
        self.runner.run.assert_not_called()

    def apply_with_fake_staging(self, *, mutate_root=False, fail_migration=False, bad_admin=False):
        preview = self.preview()
        def stage(release, files, destination, *_):
            destination.mkdir()
            if mutate_root: (self.etc / "registry.json").write_text('{"unexpected":"change"}')
        with ExitStack() as stack:
            stack.enter_context(patch.object(update.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(update.platform, "system", return_value="Linux"))
            stack.enter_context(patch.object(update, "capture_baseline", return_value=baseline()))
            stack.enter_context(patch.object(update, "capture_administrator", return_value={} if bad_admin else self.admin))
            stack.enter_context(patch.object(update, "confirm_quiescent"))
            stack.enter_context(patch.object(update, "stage_release", side_effect=stage))
            stack.enter_context(patch.object(update, "check_additive_migration",
                                            side_effect=ValueError("non additive migration") if fail_migration else None,
                                            return_value={"ok": True, "production_database_opened": False}))
            return update.apply_update(self.archive, preview, sha256(canonical(preview)), prefix=self.prefix,
                                       etc=self.etc, trusted_uid=os.getuid(), runner=self.runner)

    def test_apply_switches_only_program_preserving_database_root_state_and_previous_release(self):
        state = self.base / "production-state"
        state.mkdir(); database = state / "state.sqlite3"
        database.write_bytes(b"production never opened or copied by updater")
        before = database.read_bytes(), (self.etc / "registry.json").read_bytes(), self.backup.read_bytes()
        result = self.apply_with_fake_staging()
        self.assertTrue(result["ok"])
        self.assertFalse(result["production_database_opened"])
        self.assertFalse(result["services_started"])
        self.assertFalse(result["automatic_database_restore"])
        self.assertNotEqual((self.prefix / "current").resolve(), self.old)
        self.assertTrue(self.old.is_dir())
        self.assertEqual(before, (database.read_bytes(), (self.etc / "registry.json").read_bytes(), self.backup.read_bytes()))
        self.runner.run.assert_not_called()

    def test_changed_root_registry_blocks_switch(self):
        with self.assertRaises(ValueError): self.apply_with_fake_staging(mutate_root=True)
        self.assertEqual((self.prefix / "current").resolve(), self.old)

    def test_migration_failure_keeps_current_and_never_restores_old_database(self):
        before = self.backup.read_bytes()
        with self.assertRaises(ValueError): self.apply_with_fake_staging(fail_migration=True)
        self.assertEqual((self.prefix / "current").resolve(), self.old)
        self.assertEqual(self.backup.read_bytes(), before)

    def test_administrator_pid_change_blocks_update(self):
        with self.assertRaises(ValueError): self.apply_with_fake_staging(bad_admin=True)
        self.assertEqual((self.prefix / "current").resolve(), self.old)

    def test_administrator_capture_uses_only_fixed_registered_unit(self):
        self.runner.run.return_value = subprocess.CompletedProcess([], 0, b"ActiveState=active\nMainPID=4455\nNRestarts=0\n", b"")
        self.assertEqual(update.capture_administrator(self.policy, self.runner), self.admin)
        args = self.runner.run.call_args.args[0]
        self.assertEqual(args[:2], ["/usr/bin/systemctl", "show"])
        self.assertIn(next(iter(self.admin)), args)

    def migrate_fixture(self, statements):
        folder = self.base / "migration-case"
        if folder.exists(): shutil.rmtree(folder)
        folder.mkdir()
        policy = folder / "policy.json"; policy.write_text(json.dumps(self.policy))
        data = folder / "clone"; data.mkdir()
        implementation = ("def ProductionStore(folder,policy):\n c=sqlite3.connect(folder/'state.sqlite3')\n c.executescript(" + repr(statements) + ")\n return c")
        script = update.CHECK_ADDITIVE.replace("from dazzle.production_state import ProductionStore", implementation)
        return subprocess.run([sys.executable, "-I", "-c", script, str(self.backup), str(policy), str(data)], capture_output=True, text=True)

    def test_additive_columns_tables_and_rows_preserve_exact_large_integers_and_revocations(self):
        before = self.backup.read_bytes()
        result = self.migrate_fixture("ALTER TABLE users ADD COLUMN deleted_at TEXT;CREATE TABLE mail_secrets(id INTEGER PRIMARY KEY,secret TEXT);INSERT INTO users(id) VALUES('new-default');")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["old_rows_preserved"], 2)
        self.assertEqual(self.backup.read_bytes(), before)

    def test_removed_or_rewritten_rows_are_rejected_even_when_table_still_exists(self):
        for statement in ("DELETE FROM users", "UPDATE users SET revoked_at=NULL", "UPDATE ledger SET bytes=0"):
            with self.subTest(statement=statement):
                self.assertNotEqual(self.migrate_fixture(statement).returncode, 0)

    def test_existing_column_removal_is_rejected(self):
        self.assertNotEqual(self.migrate_fixture("ALTER TABLE users DROP COLUMN revoked_at").returncode, 0)

    def test_existing_schema_index_removal_is_rejected(self):
        with closing(sqlite3.connect(self.backup)) as connection, connection:
            connection.execute("CREATE INDEX retained_ledger_index ON ledger(bytes)")
        self.assertNotEqual(self.migrate_fixture("DROP INDEX retained_ledger_index").returncode, 0)

    def test_real_new_production_store_migrates_only_temporary_clone(self):
        from dazzle.production_state import ProductionStore
        folder = self.base / "current-backend-fixture"
        store = ProductionStore(folder, policy=self.policy, initialize=True)
        store.conn.execute("INSERT INTO users(id,name,role,port,created_at,updated_at,revoked_at) VALUES('retired','Retired','member',24431,'old','old','permanent')")
        store.close()
        # Reconstruct only the old additive schema; no live database is used.
        database = folder / "state.sqlite3"
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("ALTER TABLE users DROP COLUMN deleted_at")
            connection.execute("DROP TABLE IF EXISTS mail_secrets")
            connection.execute("DROP TABLE IF EXISTS mail_private_payload")
        backup = self.base / "real-production-backup.sqlite3"
        with closing(sqlite3.connect(database)) as source, closing(sqlite3.connect(backup)) as target, target:
            source.backup(target)
        before = backup.read_bytes()
        class LocalRunner:
            def run(self, args, timeout):
                # Test-only import root: deployment's production interpreter has
                # already installed the retained backend into site-packages.
                backend = Path(__file__).resolve().parents[2] / "backend"
                script = "import sys;sys.path.insert(0," + repr(str(backend)) + ");" + args[3]
                return subprocess.run([sys.executable, "-I", "-c", script, *args[4:]], capture_output=True, timeout=timeout)
        result = update.check_additive_migration(self.old, backup, self.policy, LocalRunner())
        self.assertTrue(result["ok"])
        self.assertFalse(result["production_database_opened"])
        self.assertEqual(backup.read_bytes(), before)


if __name__ == "__main__": unittest.main()
