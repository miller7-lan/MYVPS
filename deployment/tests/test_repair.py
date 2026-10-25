from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid
import zipfile

from deployment import repair
from deployment.helper import CORE_SHA256
from deployment.installer import canonical, sha256
from deployment.release import build_release, LICENSE_FILES
from deployment.tests.test_deployment import baseline


class ProgramOnlyRepairTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.prefix, self.etc = self.base / "program", self.base / "etc"
        self.old = self.prefix / "releases" / ("a"*24)
        self.old.mkdir(parents=True, mode=0o755)
        self.etc.mkdir(mode=0o700)
        self.repo = self.base / "repository"
        for relative in ("backend/dazzle", "deployment/systemd", "third_party"):
            (self.repo / relative).mkdir(parents=True)
        for name in ("__init__.py", "production.py", "production_state.py", "collector.py", "store.py"):
            (self.repo / "backend/dazzle" / name).write_text("# old isolated source\n")
        for name in ("__init__.py", "helper.py", "certsync.py", "control.py", "release.py", "installer.py"):
            (self.repo / "deployment" / name).write_text("# unchanged isolated deploy source\n")
        for name in ("dazzle-vps-agent.service", "dazzle-vps-subscription.service"):
            (self.repo / "deployment/systemd" / name).write_text("# unchanged isolated unit\n")
        for name in LICENSE_FILES:
            (self.repo / name).write_text("isolated license\n")
        self.wheel = self.base / "protobuf-7.36.2-py3-none-any.whl"
        with zipfile.ZipFile(self.wheel, "w") as wheel:
            wheel.writestr("protobuf-7.36.2.dist-info/METADATA", "Name: protobuf\nVersion: 7.36.2\n")
            wheel.writestr("google/protobuf/__init__.py", "__version__ = '7.36.2'\n")
        self.wheel_sha = sha256(self.wheel.read_bytes())
        shutil.copytree(self.repo, self.old, dirs_exist_ok=True)
        (self.old / "wheelhouse").mkdir()
        shutil.copyfile(self.wheel, self.old / "wheelhouse" / self.wheel.name)
        (self.old / "requirements.txt").write_text("protobuf==7.36.2 --hash=sha256:" + self.wheel_sha + "\n")
        site = self.old / "venv/lib/python3.12/site-packages"
        site.mkdir(parents=True)
        shutil.copytree(self.old / "backend/dazzle", site / "dazzle")
        shutil.copytree(self.old / "deployment", site / "deployment", ignore=shutil.ignore_patterns("systemd"))
        (self.prefix / "current").symlink_to(self.old)
        self.server_id = str(uuid.uuid4())
        original = {"server_id": self.server_id, "scope": "original approved parallel install"}
        authorization = {"version": 1, "operation": "install", "approved": True,
                         "manifest_sha256": sha256(canonical(original)), "approval_id": str(uuid.uuid4())}
        receipt = {"status": "installed", "server_id": self.server_id, "manifest_sha256": authorization["manifest_sha256"],
                   "approved_id": authorization["approval_id"]}
        policy = {"version": 1, "server_id": self.server_id, "server_endpoint": "1.1.1.1", "agent_uid": 999,
                  "core_sha256": CORE_SHA256, "workers": {str(uuid.uuid4()): {"role": "admin", "public_port": 24430, "api_port": 34430}}}
        for name, value in (("review-manifest.json", original), ("install-approval.json", authorization), ("install-receipt.json", receipt), ("policy.json", policy)):
            path = self.etc / name; path.write_text(json.dumps(value)); path.chmod(0o600)
        (self.repo / "backend/dazzle/store.py").write_text("# repaired temporary fixture lock handling\n")
        (self.repo / "deployment/repair.py").write_text("# new program-only repair tool\n")
        self.archive = self.base / "repair.tar.gz"
        build_release(self.repo, self.wheel, self.wheel_sha, self.archive)
        self.runner = Mock()

    def tearDown(self): self.temporary.cleanup()

    def preview(self):
        return repair.preview_repair(self.archive, prefix=self.prefix, etc=self.etc,
                                     trusted_uid=os.getuid(), runner=self.runner, baseline=baseline())

    def test_preview_reuses_original_authorization_and_never_opens_production_db(self):
        before = set(self.base.rglob("*"))
        result = self.preview()
        self.assertTrue(result["ready"])
        self.assertEqual([row["path"] for row in result["changed_files"]], ["backend/dazzle/store.py", "deployment/repair.py"])
        self.assertFalse(result["database_opened"])
        self.assertEqual(before, set(self.base.rglob("*")))
        self.runner.run.assert_not_called()

    def test_changed_helper_or_units_are_outside_minimal_repair_scope(self):
        (self.repo / "deployment/helper.py").write_text("# unexpected helper change\n")
        another = self.base / "another.tar.gz"
        build_release(self.repo, self.wheel, self.wheel_sha, another)
        self.archive = another
        result = self.preview()
        self.assertFalse(result["ready"])
        self.assertIn("deployment/helper.py", result["unexpected_changes"])

    def test_mismatched_original_authorization_is_rejected(self):
        path = self.etc / "install-approval.json"
        original = json.loads(path.read_text()); original["approved"] = False
        path.write_text(json.dumps(original))
        with self.assertRaises(ValueError): self.preview()

    def test_installed_site_source_tamper_is_rejected(self):
        (self.old / "venv/lib/python3.12/site-packages/dazzle/store.py").write_text("# unexpected installed mismatch\n")
        with self.assertRaises(ValueError): self.preview()

    def test_current_symlink_must_stay_inside_fixed_release_namespace(self):
        (self.prefix / "current").unlink()
        (self.prefix / "current").symlink_to(self.repo)
        with self.assertRaises(ValueError): self.preview()

    def test_apply_requires_exact_review_hash_before_any_process_call(self):
        result = self.preview()
        with self.assertRaises(ValueError):
            repair.apply_repair(self.archive, result, "0"*64, prefix=self.prefix, etc=self.etc,
                                trusted_uid=os.getuid(), runner=self.runner)
        self.runner.run.assert_not_called()

    def test_atomic_pointer_switch_preserves_previous_version_and_other_state(self):
        destination = self.prefix / "releases" / ("b"*24)
        destination.mkdir()
        unrelated = self.etc / "registry.json"
        unrelated.write_text("unchanged revocations fixture")
        repair.atomic_current(self.prefix, destination, expected_previous=self.old, trusted_uid=os.getuid())
        self.assertEqual((self.prefix / "current").resolve(), destination)
        self.assertTrue(self.old.is_dir())
        self.assertEqual(unrelated.read_text(), "unchanged revocations fixture")

    def test_active_new_service_blocks_switch(self):
        self.runner.run.return_value = subprocess.CompletedProcess([], 0, b"ActiveState=active\nMainPID=321\n", b"")
        with self.assertRaises(ValueError): repair.confirm_quiescent(self.runner)

    def test_program_only_apply_with_fake_staging_never_touches_ledger_or_starts_units(self):
        preview = self.preview()
        registry = self.etc / "registry.json"
        registry.write_text("preserved root revocation fixture")
        database = self.base / "production.sqlite3"
        database.write_bytes(b"preserved database and WAL fixture")
        def stage(release, files, destination, *_):
            destination.mkdir()
            (destination / "marker").write_text("new immutable source fixture")
        with ExitStack() as stack:
            stack.enter_context(patch.object(repair.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(repair.platform, "system", return_value="Linux"))
            stack.enter_context(patch.object(repair, "capture_baseline", return_value=baseline()))
            stack.enter_context(patch.object(repair, "confirm_quiescent"))
            stack.enter_context(patch.object(repair, "stage_release", side_effect=stage))
            result = repair.apply_repair(self.archive, preview, sha256(canonical(preview)), prefix=self.prefix,
                                         etc=self.etc, trusted_uid=os.getuid(), runner=self.runner)
        self.assertTrue(result["ok"])
        self.assertFalse(result["services_started"])
        self.assertFalse(result["database_modified"])
        self.assertEqual(registry.read_text(), "preserved root revocation fixture")
        self.assertEqual(database.read_bytes(), b"preserved database and WAL fixture")
        self.assertTrue(self.old.exists())
        self.assertEqual((self.prefix / "current").resolve().name, preview["new_release_id"])


if __name__ == "__main__": unittest.main()
