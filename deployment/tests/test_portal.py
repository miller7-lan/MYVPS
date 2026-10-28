from contextlib import closing
import configparser
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid
import zipfile

from dazzle.production_state import ProductionStore, validate_policy as backend_validate
from deployment import portal_release, portal_upgrade
from deployment.helper import CORE_SHA256, HelperError, validate_policy as helper_validate
from deployment.installer import canonical, sha256, inspect_archive as inspect_original_archive
from deployment.tests import test_deployment
from deployment.tests.test_deployment import baseline


def original_policy():
    return {"version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "1.1.1.1", "agent_uid": 1200,
            "core_sha256": CORE_SHA256, "workers": {
                str(uuid.uuid4()): {"role": "admin", "public_port": 24430, "api_port": 34430},
                str(uuid.uuid4()): {"role": "member", "public_port": 24431, "api_port": 34431}}}


def approval(preview, *, maintenance=True):
    return {"version": 1, "operation": preview["operation"], "approved": True, "approval_id": str(uuid.uuid4()),
            "preview_sha256": sha256(canonical(preview)), "member_maintenance_approved": maintenance}


class ResourcePolicyTests(unittest.TestCase):
    def test_v1_remains_compatible_and_v2_adds_three_deterministic_unstarted_slots(self):
        old = original_policy(); untouched = copy.deepcopy(old)
        new = portal_upgrade.expanded_policy(old, 1201)
        self.assertEqual(old, untouched)
        self.assertEqual(new, portal_upgrade.expanded_policy(old, 1201))
        self.assertEqual(new, backend_validate(new)); self.assertEqual(new, helper_validate(new))
        self.assertEqual(len(new["workers"]), 5)
        self.assertEqual({key: new["workers"][key] for key in old["workers"]}, old["workers"])
        self.assertEqual(sorted(worker["public_port"] for worker in new["workers"].values()), list(range(24430, 24435)))

    def test_both_boundaries_reject_unapproved_ports_roles_and_web_identity(self):
        original = portal_upgrade.expanded_policy(original_policy(), 1201)
        member = next(key for key, worker in original["workers"].items() if worker["public_port"] == 24432)
        mutations = []
        for key, value in (("public_port", 24437), ("api_port", 34437), ("role", "admin")):
            changed = copy.deepcopy(original); changed["workers"][member][key] = value; mutations.append(changed)
        for uid in (0, True, 1200, "1201"):
            mutations.append(dict(original, portal_uid=uid))
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError): backend_validate(changed)
            with self.subTest(changed=changed), self.assertRaises(HelperError): helper_validate(changed)

    def test_duplicate_port_or_uuid_binding_is_not_an_extra_slot(self):
        policy = portal_upgrade.expanded_policy(original_policy(), 1201)
        slot = next(worker for worker in policy["workers"].values() if worker["public_port"] == 24432)
        policy["workers"][str(uuid.uuid4())] = dict(slot)
        with self.assertRaises(ValueError): backend_validate(policy)
        with self.assertRaises(HelperError): helper_validate(policy)

    def test_incremental_store_retains_existing_worker_generations_and_tombstones(self):
        old = original_policy(); new = portal_upgrade.expanded_policy(old, 1201)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            with ProductionStore(state, policy=old, initialize=True) as store:
                existing = next(iter(old["workers"]))
                store.conn.execute("UPDATE production_workers SET generation=17,tombstoned=1 WHERE worker_id=?", (existing,))
                before = dict(store.conn.execute("SELECT * FROM production_workers WHERE worker_id=?", (existing,)).fetchone())
            with ProductionStore(state, policy=new) as store:
                after = dict(store.conn.execute("SELECT * FROM production_workers WHERE worker_id=?", (existing,)).fetchone())
                self.assertEqual(before, after)
                fresh = [dict(row) for row in store.conn.execute("SELECT * FROM production_workers WHERE public_port>=24432")]
                self.assertEqual(len(fresh), 3)
                self.assertTrue(all(row["user_id"] is None and not row["provisioned"] and row["observed_state"] == "unprovisioned" for row in fresh))
                self.assertEqual(store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 0)
                self.assertEqual(store.conn.execute("SELECT COUNT(*) FROM production_jobs").fetchone()[0], 0)
                self.assertFalse(store.get_setting("registration_enabled"))

    def test_read_only_store_does_not_create_registration_schema(self):
        policy = original_policy()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            with ProductionStore(state, policy=policy, initialize=True) as store:
                store.conn.execute("DROP TABLE portal_accounts")
            with ProductionStore(state, policy=policy, read_only=True) as store:
                self.assertIsNone(store.conn.execute("SELECT name FROM sqlite_master WHERE name='portal_accounts'").fetchone())


class PortalPackageTests(unittest.TestCase):
    def setUp(self):
        test_deployment.ReleaseAndApprovalTests.setUp(self)
        for name in ("portal.py", "registration.py", "portal_rpc.py", "meter_guard.py"):
            (self.repo / "backend/dazzle" / name).write_text("# isolated portal fixture\n")
        static = self.repo / "backend/dazzle/portal_static"; static.mkdir()
        for name in portal_release.STATIC_FILES: (static / name).write_text("isolated static fixture\n")
        for name in portal_release.PORTAL_TOOLS: (self.repo / "deployment" / name).write_text("# isolated tool fixture\n")
        templates = self.repo / "deployment/portal-systemd"; templates.mkdir()
        actual = Path(__file__).resolve().parents[1] / "portal-systemd"
        for name in portal_release.TEMPLATES: (templates / name).write_bytes((actual / name).read_bytes())
        self.wheelhouse = self.base / "wheels"; self.wheelhouse.mkdir()
        self.lock = []
        for name in sorted(portal_release.REQUIRED_PACKAGES):
            version = "7.36.2" if name == "protobuf" else "1.0.0"
            filename = name.replace("-", "_") + "-" + version + "-py3-none-any.whl"
            target = self.wheelhouse / filename
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr(name.replace("-", "_") + "-" + version + ".dist-info/METADATA", "Name: " + name + "\nVersion: " + version + "\n")
                archive.writestr(("google/protobuf" if name == "protobuf" else name.replace("-", "_")) + "/__init__.py", "# fixture\n")
            self.lock.append({"name": name, "version": version, "filename": filename, "sha256": sha256(target.read_bytes())})
        self.portal_archive = self.base / "portal.tar.gz"

    def tearDown(self): self.temporary.cleanup()

    def build(self):
        return portal_release.build_release(self.repo, self.wheelhouse, self.lock, self.portal_archive)

    def test_archive_keeps_static_assets_templates_and_exact_offline_dependency_hashes(self):
        built = self.build(); manifest, files = portal_release.inspect_archive(self.portal_archive)
        self.assertEqual(built["release_id"], manifest["release_id"])
        self.assertEqual(manifest["schema_version"], 2)
        self.assertFalse(manifest["contains_real_credentials"])
        for name in portal_release.STATIC_FILES: self.assertIn("backend/dazzle/portal_static/" + name, files)
        self.assertEqual(files["requirements.txt"], portal_release.requirements_bytes(manifest["wheels"]))
        self.assertEqual({entry["name"] for entry in manifest["wheels"]}, portal_release.REQUIRED_PACKAGES)

    def test_hostname_templates_are_packaged_with_exact_contents_and_inventory_hashes(self):
        self.build()
        manifest, files = portal_release.inspect_archive(self.portal_archive)
        hostname_templates = {name for name in portal_release.TEMPLATES if name.startswith("hostname")}
        self.assertTrue({"hostname.conf", "hostname-certsync.service", "hostname-certsync.timer"}.issubset(hostname_templates))
        for name in hostname_templates:
            with self.subTest(template=name):
                relative = "deployment/portal-systemd/" + name
                expected = (self.repo / relative).read_bytes()
                self.assertEqual(files[relative], expected)
                self.assertEqual(manifest["files"][relative], sha256(expected))
        self.assertFalse(any(name.endswith((".pem", ".key", ".sqlite3")) for name in files))

    def test_missing_or_symlinked_hostname_template_cannot_produce_an_archive(self):
        for name in (name for name in portal_release.TEMPLATES if name.startswith("hostname")):
            path = self.repo / "deployment/portal-systemd" / name
            content = path.read_bytes()
            path.unlink()
            try:
                with self.subTest(template=name, condition="missing"), self.assertRaises(ValueError):
                    self.build()
                self.assertFalse(self.portal_archive.exists())
                path.symlink_to(path.parent / "subscription.service")
                with self.subTest(template=name, condition="symlink"), self.assertRaises(ValueError):
                    self.build()
                self.assertFalse(self.portal_archive.exists())
            finally:
                if path.is_symlink():
                    path.unlink()
                path.write_bytes(content)

    def test_hostname_renewal_runs_only_its_lineage_then_syncs_without_proxy_or_ip_operations(self):
        self.build()
        _, files = portal_release.inspect_archive(self.portal_archive)
        service_text = files["deployment/portal-systemd/hostname-renew.service"].decode()
        timer_text = files["deployment/portal-systemd/hostname-renew.timer"].decode()
        unit = configparser.ConfigParser(interpolation=None)
        unit.read_string(service_text)
        service = unit["Service"]
        renewal = shlex.split(service["ExecStart"])
        self.assertEqual(renewal[:2], ["/opt/qqg-certbot/bin/certbot", "renew"])
        self.assertEqual(renewal.count("--cert-name"), 1)
        self.assertEqual(renewal[renewal.index("--cert-name") + 1], "@HOSTNAME@")
        self.assertIn("--no-directory-hooks", renewal)
        self.assertNotIn("--force-renewal", renewal)
        copy = shlex.split(service["ExecStartPost"])
        self.assertEqual(copy[:5], ["/opt/dazzle-vps/current/venv/bin/python", "-I", "-m", "deployment.certsync",
                                   "--managed-certbot-source"])
        self.assertEqual(copy[copy.index("--hostname") + 1], "@HOSTNAME@")
        self.assertEqual(copy[copy.index("--source-cert") + 1], "/etc/letsencrypt/live/@HOSTNAME@/fullchain.pem")
        self.assertEqual(copy[copy.index("--source-key") + 1], "/etc/letsencrypt/live/@HOSTNAME@/privkey.pem")
        self.assertEqual(service["Type"], "oneshot")
        self.assertEqual(service["User"], "root")
        self.assertEqual(service["ProtectSystem"], "strict")
        self.assertLessEqual(int(service["TimeoutStartSec"]), 300)
        self.assertEqual(set(shlex.split(service["ReadWritePaths"])),
                         {"/etc/letsencrypt", "/var/lib/letsencrypt", "/var/log/letsencrypt", "/etc/dazzle-vps/web-tls"})
        for forbidden in ("qqg-ip", "systemctl", "dazzle-proxy@", "dazzle-admin@", "/etc/dazzle-vps/tls"):
            self.assertNotIn(forbidden, service_text)
        timer = configparser.ConfigParser(interpolation=None)
        timer.read_string(timer_text)
        self.assertEqual(timer["Timer"]["OnCalendar"], "*-*-* 01,13:00:00 UTC")
        self.assertEqual(timer["Timer"]["Persistent"], "true")
        self.assertEqual(timer["Install"]["WantedBy"], "timers.target")

    def test_hash_mismatch_incomplete_lock_unapproved_dependency_and_pth_are_rejected(self):
        invalid = copy.deepcopy(self.lock); invalid[0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError): portal_release.validate_locked_wheels(self.wheelhouse, invalid)
        with self.assertRaises(ValueError): portal_release.validate_locked_wheels(self.wheelhouse, self.lock[:-1])
        invalid = copy.deepcopy(self.lock); invalid[0]["name"] = "arbitrary-command-package"
        with self.assertRaises(ValueError): portal_release.validate_locked_wheels(self.wheelhouse, invalid)
        entry = next(entry for entry in self.lock if entry["name"] == "uvicorn")
        path = self.wheelhouse / entry["filename"]
        with zipfile.ZipFile(path, "a") as archive: archive.writestr("run.pth", "import unrelated\n")
        entry["sha256"] = sha256(path.read_bytes())
        with self.assertRaises(ValueError): portal_release.validate_locked_wheels(self.wheelhouse, self.lock)

    def test_template_does_not_grant_web_access_to_agent_state_or_proxy_group(self):
        self.build(); _, files = portal_release.inspect_archive(self.portal_archive)
        rendered = portal_upgrade.render_templates(portal_upgrade.expanded_policy(original_policy(), 1201), files)
        service = rendered["/etc/systemd/system/dazzle-vps-subscription.service"]
        self.assertIn("User=dazzle-web", service)
        self.assertNotIn("SupplementaryGroups=dazzle-vps", service)
        self.assertNotIn("ReadWritePaths=/var/lib/dazzle-vps", service)
        self.assertIn("--origin https://1.1.1.1:9443", service)
        self.assertNotIn("@ORIGIN@", service)

    def test_ready_preview_binds_backup_new_identity_and_existing_worker_state_without_process_calls(self):
        self.build()
        old_release, old_files = inspect_original_archive(self.archive)
        prefix = self.base / "prefix"; previous = prefix / "releases" / old_release["release_id"]
        previous.mkdir(parents=True)
        site = previous / "venv/lib/python3.12/site-packages"
        for name, body in old_files.items():
            path = previous / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body)
            if name.startswith("backend/dazzle/") or name.startswith("deployment/") and name.endswith('.py'):
                installed = site / (name.removeprefix("backend/") if name.startswith("backend/") else name)
                installed.parent.mkdir(parents=True, exist_ok=True); installed.write_bytes(body)
        (previous / "release.json").write_text(json.dumps({k: v for k, v in old_release.items() if not k.startswith('_')}))
        (prefix / "current").symlink_to(previous)
        policy = original_policy(); etc = self.base / "etc"; etc.mkdir(mode=0o700)
        original = {"server_id": policy["server_id"], "scope": "original explicit approval"}
        consent = {"version": 1, "operation": "install", "approved": True, "approval_id": str(uuid.uuid4()), "manifest_sha256": sha256(canonical(original))}
        receipt = {"status": "installed", "server_id": policy["server_id"], "manifest_sha256": consent["manifest_sha256"], "approved_id": consent["approval_id"]}
        for name, value in (("policy.json", policy), ("review-manifest.json", original), ("install-approval.json", consent), ("install-receipt.json", receipt)):
            path = etc / name; path.write_text(json.dumps(value)); path.chmod(0o600)
        backup = self.base / "snapshot.sqlite3"
        with closing(sqlite3.connect(backup)) as connection:
            connection.execute("CREATE TABLE immutable_ledger(bytes INTEGER)"); connection.commit()
        backup.chmod(0o600)
        target = {"version": 1, "legacy": baseline(), "administrator": {"admin": {"active": "active", "pid": 55}},
                  "occupied_new_ports": [], "portal_uid_available": True, "portal_gid_available": True,
                  "portal_account_name_available": True, "portal_group_name_available": True,
                  "memory_available_kib": 524288, "provider_network_verified": True, "provider_network_evidence": "verified panel evidence"}
        runner = Mock(); before = set(self.base.rglob('*'))
        preview = portal_upgrade.preview_upgrade(self.portal_archive, backup, sha256(backup.read_bytes()), 1201,
                                                  prefix=prefix, etc=etc, state_dir=self.base/'unused-state', baseline=target,
                                                  runner=runner, trusted_uid=os.getuid())
        self.assertTrue(preview["ready_for_approval"])
        self.assertEqual(len(preview["new_workers"]), 3); self.assertEqual(len(preview["new_firewall_rules"]), 6)
        self.assertFalse(preview["automatic_firewall_mutation"]); self.assertFalse(preview["registration_initially_enabled"])
        self.assertTrue(preview["member_maintenance"]["required"])
        self.assertEqual(set(self.base.rglob('*')), before); runner.run.assert_not_called()
        portal_upgrade.validate_approval(preview, approval(preview))
        changed = copy.deepcopy(preview); changed["new_account"]["uid"] += 1
        with self.assertRaises(ValueError): portal_upgrade.validate_approval(changed, approval(preview))


class PortalCertificateTests(unittest.TestCase):
    def setUp(self):
        test_deployment.CertificateSyncTests.setUp(self)
        policy = json.loads((self.etc / 'policy.json').read_text()); policy.update(version=2, portal_uid=1201)
        (self.etc / 'policy.json').write_text(json.dumps(policy))
        (self.etc / 'web-tls').mkdir(mode=0o700)

    def tearDown(self): self.temporary.cleanup()

    def sync(self, validator=None, portal_gid=None):
        from deployment.certsync import sync_certificate
        return sync_certificate(layout=self.layout, source_cert=self.cert, source_key=self.key, runner=self.runner,
                                portal_tls_gid=max(1, os.getgid()) if portal_gid is None else portal_gid,
                                validator=validator or (lambda *_: None))

    def test_validated_pair_updates_separate_web_copy_without_service_restart(self):
        self.sync()
        self.assertEqual((self.etc/'web-tls/cert.pem').read_bytes(), self.cert.read_bytes())
        self.assertEqual((self.etc/'web-tls/key.pem').read_bytes(), self.key.read_bytes())
        self.assertEqual((self.etc/'web-tls/key.pem').stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.sync()['changed']); self.runner.run.assert_not_called()

    def test_validation_failure_keeps_both_previous_project_pairs(self):
        self.sync(); self.cert.write_bytes(b'invalid next pair')
        paths = [self.etc / name / leaf for name in ('tls', 'web-tls') for leaf in ('cert.pem', 'key.pem')]
        before = [path.read_bytes() for path in paths]
        def fail(*_): raise HelperError('TLS_INVALID', 'isolated failure')
        with self.assertRaises(HelperError): self.sync(fail)
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_missing_separate_web_group_blocks_any_copy(self):
        with self.assertRaises(HelperError): self.sync(portal_gid=0)
        self.assertFalse(self.layout.tls_key.exists())
        self.assertFalse((self.etc/'web-tls/key.pem').exists())


class PortalApprovalAndRecoveryTests(unittest.TestCase):
    def test_missing_exact_approval_or_maintenance_consent_cannot_stage(self):
        preview = {"operation": "portal_resource_upgrade", "ready_for_approval": True}
        runner = Mock()
        with self.assertRaises(ValueError): portal_upgrade.stage_upgrade(None, preview, {}, runner=runner)
        with self.assertRaises(ValueError): portal_upgrade.stage_upgrade(None, preview, approval(preview, maintenance=False), runner=runner)
        runner.run.assert_not_called()

    def test_network_or_memory_unverified_marks_preview_not_ready(self):
        valid = {"version": 1, "legacy": baseline(), "administrator": {"admin": {"active": "active", "pid": 2}},
                 "occupied_new_ports": [], "portal_uid_available": True, "portal_gid_available": True,
                 "portal_account_name_available": True, "portal_group_name_available": True,
                 "memory_available_kib": 524288, "provider_network_verified": True, "provider_network_evidence": "operator panel check"}
        release = {"architecture": "x86_64"}
        self.assertEqual(portal_upgrade._baseline_issues(valid, release), [])
        for changed in ({"occupied_new_ports": [24432]}, {"memory_available_kib": 1024}, {"provider_network_verified": False}, {"portal_uid_available": False}):
            self.assertTrue(portal_upgrade._baseline_issues(valid | changed, release))

    def test_subscription_only_recovery_preserves_agent_workers_and_database(self):
        policy = portal_upgrade.expanded_policy(original_policy(), 1201)
        preview = portal_upgrade.rollback_preview(policy)
        self.assertEqual(preview["restart_units"], ["dazzle-vps-subscription.service"])
        self.assertFalse(preview["database_restore"]); self.assertFalse(preview["agent_restart"])
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); etc = base / "etc"; units = base / "units"; etc.mkdir(); units.mkdir()
            path = etc / "policy.json"; path.write_text(json.dumps(policy)); path.chmod(0o600)
            runner = Mock(); runner.run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
            with patch.object(portal_upgrade.os, "geteuid", return_value=0), patch.object(portal_upgrade.platform, "system", return_value="Linux"):
                result = portal_upgrade.apply_rollback(preview, approval(preview), etc=etc, units=units, runner=runner, trusted_uid=os.getuid())
            self.assertFalse(result["proxy_workers_restarted"])
            self.assertFalse(result["database_restored"])
            self.assertIn("--subscription-only", (units / "dazzle-vps-subscription.service.d/subscription-only.conf").read_text())
            self.assertEqual([call.args[0] for call in runner.run.call_args_list], [
                ["/usr/bin/systemctl", "daemon-reload"], ["/usr/bin/systemctl", "restart", "dazzle-vps-subscription.service"]])
            self.assertEqual(json.loads(path.read_text()), policy)

    def test_recovery_refuses_to_overwrite_an_unrelated_existing_override(self):
        policy = portal_upgrade.expanded_policy(original_policy(), 1201)
        preview = portal_upgrade.rollback_preview(policy)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); etc = base / 'etc'; units = base / 'units'; etc.mkdir(); units.mkdir()
            path = etc/'policy.json'; path.write_text(json.dumps(policy)); path.chmod(0o600)
            override = units/'dazzle-vps-subscription.service.d'; override.mkdir()
            target = override/'subscription-only.conf'; target.write_text('[Service]\nEnvironment=UNRELATED_FIXTURE=1\n'); target.chmod(0o644)
            previous = target.read_bytes(); runner = Mock()
            with patch.object(portal_upgrade.os, 'geteuid', return_value=0), patch.object(portal_upgrade.platform, 'system', return_value='Linux'), self.assertRaises(ValueError):
                portal_upgrade.apply_rollback(preview, approval(preview), etc=etc, units=units, runner=runner, trusted_uid=os.getuid())
            self.assertEqual(target.read_bytes(), previous); runner.run.assert_not_called()
