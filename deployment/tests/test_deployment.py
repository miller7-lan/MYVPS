import hashlib
import io
import json
import os
from pathlib import Path
from contextlib import ExitStack
import tarfile
import tempfile
import unittest
import subprocess
from unittest.mock import Mock, patch
import uuid
import zipfile
from types import SimpleNamespace

from deployment import installer, release
from deployment.certsync import sync_certificate
from deployment.helper import CORE_SHA256, LEGACY_CONFIG_SHA256, HelperError, Layout

REPOSITORY = Path(__file__).resolve().parents[1]


def baseline():
    return {"version": 1, "core_sha256": CORE_SHA256, "legacy_config_sha256": LEGACY_CONFIG_SHA256,
            "services": {"sing-box.service": {"active": "active", "pid": 9515, "nrestarts": 0},
                         "qqg-sub.service": {"active": "active", "pid": 11189, "nrestarts": 0}},
            "occupied_pilot_ports": [], "firewall_sha256": "f"*64,
            "platform": {"system": "Linux", "machine": "x86_64", "python": "3.12"}, "checked_at": "2026-10-25T01:00:00Z"}


class ReleaseAndApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / "repository"
        (self.repo / "backend" / "dazzle").mkdir(parents=True)
        (self.repo / "deployment" / "systemd").mkdir(parents=True)
        (self.repo / "third_party").mkdir()
        for name in release.LICENSE_FILES:
            (self.repo / name).write_text("Isolated source license fixture\n")
        for name in ("__init__.py", "production.py", "production_state.py"):
            (self.repo / "backend" / "dazzle" / name).write_text("# isolated source fixture\n")
        for name in ("__init__.py", "helper.py", "certsync.py", "control.py", "release.py", "installer.py", "repair.py", "update.py"):
            (self.repo / "deployment" / name).write_text("# isolated source fixture\n")
        for template in (REPOSITORY / "systemd").iterdir():
            (self.repo / "deployment" / "systemd" / template.name).write_bytes(template.read_bytes())
        self.wheel = self.base / "protobuf-7.36.2-py3-none-any.whl"
        with zipfile.ZipFile(self.wheel, "w") as wheel:
            wheel.writestr("protobuf-7.36.2.dist-info/METADATA", "Name: protobuf\nVersion: 7.36.2\n")
            wheel.writestr("google/protobuf/__init__.py", "__version__ = '7.36.2'\n")
        self.wheel_sha = hashlib.sha256(self.wheel.read_bytes()).hexdigest()
        self.archive = self.base / "pilot.tar.gz"
        release.build_release(self.repo, self.wheel, self.wheel_sha, self.archive)

    def tearDown(self): self.temporary.cleanup()

    def manifest(self, **changes):
        return installer.review_manifest(self.archive, "1.1.1.1", baseline=baseline(), **changes)

    def approval(self, manifest, operation="install"):
        return {"version": 1, "operation": operation, "manifest_sha256": installer.sha256(installer.canonical(manifest)),
                "approved": True, "approval_id": str(uuid.uuid4())}

    def test_allowlist_excludes_private_inputs_state_and_test_artifacts(self):
        (self.repo / "private").mkdir()
        (self.repo / "private" / "do-not-package.key").write_text("PRIVATE-FIXTURE")
        (self.repo / "backend" / "dazzle" / "state.sqlite3").write_text("DATABASE-FIXTURE")
        files = release.source_files(self.repo)
        self.assertFalse(any(".key" in name or ".sqlite3" in name or "private" in name for name in files))
        self.assertNotIn(b"PRIVATE-FIXTURE", files.values())

    def test_preview_does_not_create_new_files_or_execute_processes(self):
        before = set(self.base.rglob("*"))
        with patch.object(installer, "Runner") as runner:
            manifest = self.manifest()
        self.assertEqual(set(self.base.rglob("*")), before)
        runner.assert_not_called()
        self.assertTrue(manifest["ready_for_approval"])
        self.assertFalse(manifest["automatic_legacy_retirement"])

    def test_missing_baseline_preview_is_explicitly_not_ready(self):
        manifest = installer.review_manifest(self.archive, "1.1.1.1")
        self.assertFalse(manifest["ready_for_approval"])
        with self.assertRaises(ValueError): installer.validate_approval(manifest, self.approval(manifest))

    def test_manifest_has_only_five_exact_ipv4_rules_and_distinct_new_ids(self):
        manifest = self.manifest()
        self.assertEqual([(rule["port"], rule["protocol"]) for rule in manifest["new_ipv4_rules"]], list(installer.PILOT_RULES))
        self.assertEqual(len({manifest["server_id"], *manifest["workers"]}), 3)
        self.assertTrue(all(rule["port"] not in {22, 80, 443, 8443} for rule in manifest["new_ipv4_rules"]))
        self.assertEqual(manifest["core_copy"]["destination"], "/opt/dazzle-vps/core/sing-box")
        self.assertFalse(manifest["core_copy"]["replacement"])

    def test_pinned_core_copy_preserves_original_bytes_mode_and_hash(self):
        source, destination = self.base / "legacy-core", self.base / "new-core"
        source.write_bytes(b"isolated pinned binary fixture"); source.chmod(0o750)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        installer.copy_pinned_core(source, destination, expected_sha256=digest, trusted_uid=os.getuid())
        self.assertEqual(destination.read_bytes(), source.read_bytes())
        self.assertEqual(source.stat().st_mode & 0o777, 0o750)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
        with self.assertRaises(ValueError): installer.copy_pinned_core(source, destination, expected_sha256=digest, trusted_uid=os.getuid())

    def test_approval_is_bound_to_exact_manifest_and_operation(self):
        manifest = self.manifest()
        approval = self.approval(manifest)
        installer.validate_approval(manifest, approval)
        altered = dict(manifest, server_endpoint="192.0.2.11")
        with self.assertRaises(ValueError): installer.validate_approval(altered, approval)
        with self.assertRaises(ValueError): installer.validate_approval(manifest, approval, operation="rollback")

    def test_apply_without_exact_approval_makes_no_process_or_root_calls(self):
        manifest = self.manifest()
        runner = Mock()
        with patch.object(installer.os, "geteuid") as uid, self.assertRaises(ValueError):
            installer.apply_install(self.archive, manifest, {}, runner=runner)
        uid.assert_not_called(); runner.run.assert_not_called()

    def test_approved_install_sequence_uses_only_new_paths_and_exact_rules_with_fake_runner(self):
        manifest = self.manifest()
        firewall = b"Status: active\n[ 1] 443/tcp ALLOW IN Anywhere\n"
        manifest["baseline"]["firewall_sha256"] = installer.sha256(firewall)
        prefix, etc, state, units, control, runtime = [self.base / name for name in ("opt", "etc", "state", "units", "control-bin", "run")]
        manifest["control_entry"] = str(control)
        units.mkdir()
        calls = []
        def fake_run(args, **_):
            calls.append(args)
            if args[:3] == ["/usr/bin/python3", "-m", "venv"]:
                (Path(args[3]) / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
            payload = firewall if args[:3] == ["/usr/sbin/ufw", "status", "numbered"] else b""
            return subprocess.CompletedProcess(args, 0, payload, b"")
        runner = Mock(); runner.run.side_effect = fake_run
        def mkdir(path, mode, **_):
            path = Path(path)
            self.assertTrue(path.is_relative_to(self.base), str(path))
            path.mkdir(parents=True, exist_ok=True); path.chmod(mode)
        def atomic(path, payload, *, mode=0o600, **_):
            path = Path(path)
            self.assertTrue(path.is_relative_to(self.base), str(path))
            path.write_bytes(payload); path.chmod(mode)
        def atomic_json(path, value, *_): atomic(path, installer.canonical(value))
        account = SimpleNamespace(pw_uid=999, pw_gid=999)
        group = SimpleNamespace(gr_gid=998)
        def nonexistent(_): raise KeyError()
        with ExitStack() as stack:
            for name, value in (("PREFIX", prefix), ("ETC", etc), ("STATE", state), ("UNITS", units), ("CONTROL", control), ("RUNTIME", runtime)):
                stack.enter_context(patch.object(installer, name, value))
            stack.enter_context(patch.object(installer.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(installer.platform, "system", return_value="Linux"))
            stack.enter_context(patch.object(installer, "capture_baseline", side_effect=lambda _: dict(manifest["baseline"])))
            stack.enter_context(patch.object(installer, "_system_users", return_value=(account, account, group)))
            stack.enter_context(patch.object(installer.pwd, "getpwnam", side_effect=nonexistent))
            stack.enter_context(patch.object(installer.grp, "getgrnam", side_effect=nonexistent))
            stack.enter_context(patch.object(installer, "_mkdir", side_effect=mkdir))
            stack.enter_context(patch.object(installer, "atomic_bytes", side_effect=atomic))
            stack.enter_context(patch.object(installer, "atomic_json", side_effect=atomic_json))
            stack.enter_context(patch.object(installer, "copy_pinned_core"))
            stack.enter_context(patch("deployment.certsync.sync_certificate", return_value={"ok": True}))
            result = installer.apply_install(self.archive, manifest, self.approval(manifest), runner=runner)
        self.assertTrue(result["legacy_verified"])
        self.assertFalse(result["workers_started"])
        rules = [call for call in calls if call[:2] == ["/usr/sbin/ufw", "allow"]]
        self.assertEqual(len(rules), 5)
        self.assertTrue(all("0.0.0.0/0" in rule for rule in rules))
        self.assertFalse(any("reset" in call or "reload" in call for call in calls))
        self.assertFalse(any(unit in installer.LEGACY_UNITS for call in calls if call[:2] == ["/usr/bin/systemctl", "stop"] for unit in call))
        self.assertIn('[ "$#" -eq 1 ] && [ "$1" = rpc ]', control.read_text())
        receipt = json.loads((etc / "install-receipt.json").read_text())
        self.assertEqual(receipt["status"], "installed")

    def test_occupied_ports_unhealthy_legacy_or_wrong_core_block_review(self):
        for values in ({"occupied_pilot_ports": [24430]}, {"core_sha256": "a"*64}, {"legacy_config_sha256": "b"*64}, {"platform": {"system": "Linux", "machine": "x86_64", "python": "3.11"}}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                installer.review_manifest(self.archive, "1.1.1.1", baseline=baseline() | values)

    def test_non_public_endpoint_is_rejected_before_installation(self):
        for endpoint in ("192.0.2.10", "127.0.0.1", "10.0.0.1", "0.0.0.0"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                installer.review_manifest(self.archive, endpoint, baseline=baseline())

    def test_wheel_hash_target_and_unexpected_paths_are_rejected(self):
        with self.assertRaises(ValueError): release.validate_wheel(self.wheel, "0"*64)
        mac_wheel = self.base / "protobuf-7.36.2-cp39-abi3-macosx_10_9_universal2.whl"
        mac_wheel.write_bytes(self.wheel.read_bytes())
        with self.assertRaises(ValueError): release.validate_wheel(mac_wheel, self.wheel_sha)
        bad = self.base / "protobuf-7.36.2-py3-none-any.whl"
        with zipfile.ZipFile(bad, "a") as wheel: wheel.writestr("../../etc/evil.pth", "unsafe")
        with self.assertRaises(ValueError): release.validate_wheel(bad, hashlib.sha256(bad.read_bytes()).hexdigest())

    def test_archive_content_tamper_and_path_escape_are_rejected(self):
        malformed = self.base / "bad.tar.gz"
        with tarfile.open(malformed, "w:gz") as archive:
            payload = b"escape"
            info = tarfile.TarInfo("../../etc/passwd"); info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        with self.assertRaises(ValueError): installer.inspect_archive(malformed)

    def test_symlink_sources_and_output_overwrite_are_rejected(self):
        with self.assertRaises(ValueError): release.build_release(self.repo, self.wheel, self.wheel_sha, self.archive)
        path = self.repo / "backend" / "dazzle" / "other.py"
        path.symlink_to(self.repo / "backend" / "dazzle" / "production.py")
        with self.assertRaises(ValueError): release.source_files(self.repo)

    def test_legacy_verifier_checks_pids_restart_count_and_hashes(self):
        before, after = baseline(), baseline()
        installer.compare_legacy(before, after)
        after["services"]["sing-box.service"]["nrestarts"] += 1
        with self.assertRaises(ValueError): installer.compare_legacy(before, after)

    def test_existing_pilot_firewall_rule_cannot_be_relabelled_as_new(self):
        runner = Mock()
        payload = b"Status: active\n[ 1] 24430/tcp ALLOW IN Anywhere # existing rule\n"
        runner.run.return_value = subprocess.CompletedProcess([], 0, payload, b"")
        with self.assertRaises(ValueError): installer.firewall_preflight(runner, installer.sha256(payload))
        payload = b"Status: active\n[ 1] 443/tcp ALLOW IN Anywhere\n"
        runner.run.return_value = subprocess.CompletedProcess([], 0, payload, b"")
        installer.firewall_preflight(runner, installer.sha256(payload))

    def test_rollback_plan_preserves_state_and_rejects_unowned_firewall_rule(self):
        manifest = self.manifest()
        receipt = {"server_id": manifest["server_id"], "manifest_sha256": installer.sha256(installer.canonical(manifest)),
                   "added_rules": manifest["new_ipv4_rules"][:1]}
        plan = installer.rollback_plan(manifest, receipt)
        self.assertIn("ledger", plan["preserve"])
        self.assertFalse(any(unit in installer.LEGACY_UNITS for unit in plan["stop_units"]))
        receipt["added_rules"] = [{"port": 443, "protocol": "tcp", "comment": "legacy"}]
        with self.assertRaises(ValueError): installer.rollback_plan(manifest, receipt)

    def test_rollback_stops_callers_and_drains_helpers_before_final_worker_stop(self):
        manifest = self.manifest()
        calls = []
        def fake_run(args, **_):
            calls.append(args)
            if args[1] == "list-units": payload = b"dazzle-vps-helper@1-1-local.service loaded inactive dead helper\n"
            elif args[1] == "show":
                unit = args[2]
                payload = f"ActiveState=inactive\nMainPID=0\nControlGroup=/system.slice/{unit}\n".encode()
            else: payload = b""
            return subprocess.CompletedProcess(args, 0, payload, b"")
        runner = Mock(); runner.run.side_effect = fake_run
        with patch("deployment.helper.Path.read_text", side_effect=FileNotFoundError):
            installer.stop_new_runtime(manifest, {}, runner)
        stops = [call[2] for call in calls if call[1] == "stop"]
        self.assertEqual(stops[:2], ["dazzle-vps-agent.service", "dazzle-vps-helper.socket"])
        self.assertTrue(all(unit.startswith(("dazzle-admin@", "dazzle-proxy@")) for unit in stops[-2:]))
        drain = next(index for index, call in enumerate(calls) if call[1] == "list-units")
        last_worker_stop = next(index for index, call in enumerate(calls) if call[1] == "stop" and call[2].startswith("dazzle-admin@"))
        self.assertLess(drain, last_worker_stop)

    def test_rollback_rejects_still_active_helper_instead_of_claiming_drained(self):
        runner = Mock()
        runner.run.side_effect = [subprocess.CompletedProcess([], 0, b"dazzle-vps-helper@1.service loaded active running helper\n", b""),
                                  subprocess.CompletedProcess([], 0, b"ActiveState=active\nMainPID=123\n", b"")]
        with self.assertRaises(ValueError): installer.confirm_helper_drained(runner)


class CertificateSyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.etc = self.base / "project"
        self.etc.mkdir(mode=0o700)
        (self.etc / "tls").mkdir(mode=0o700)
        policy = {"version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "192.0.2.10", "agent_uid": 1001,
                  "core_sha256": CORE_SHA256, "workers": {str(uuid.uuid4()): {"role": "admin", "public_port": 24430, "api_port": 34430}}}
        (self.etc / "policy.json").write_text(json.dumps(policy)); (self.etc / "policy.json").chmod(0o600)
        self.cert, self.key = self.base / "source-cert", self.base / "source-key"
        self.cert.write_bytes(b"VALID-TEST-CERT"); self.key.write_bytes(b"VALID-TEST-KEY")
        self.cert.chmod(0o600); self.key.chmod(0o600)
        self.layout = Layout(etc=self.etc, trusted_uid=os.getuid())
        self.runner = Mock()

    def tearDown(self): self.temporary.cleanup()

    def sync(self, validator=None):
        return sync_certificate(layout=self.layout, source_cert=self.cert, source_key=self.key,
                                runner=self.runner, validator=validator or (lambda *_: None))

    def test_only_new_pair_is_updated_and_no_service_command_is_run(self):
        original = (self.cert.read_bytes(), self.key.read_bytes())
        result = self.sync()
        self.assertTrue(result["changed"])
        self.assertEqual((self.cert.read_bytes(), self.key.read_bytes()), original)
        self.assertEqual(self.layout.tls_certificate.read_bytes(), original[0])
        self.assertEqual(self.layout.tls_key.read_bytes(), original[1])
        self.runner.run.assert_not_called()
        self.assertFalse(result["services_restarted"])

    def test_validation_failure_keeps_previous_project_pair(self):
        self.sync()
        before = (self.layout.tls_certificate.read_bytes(), self.layout.tls_key.read_bytes())
        self.cert.write_bytes(b"INVALID-CERT")
        def fail(*_): raise HelperError("TLS_INVALID", "invalid isolated fixture")
        with self.assertRaises(HelperError): self.sync(fail)
        self.assertEqual((self.layout.tls_certificate.read_bytes(), self.layout.tls_key.read_bytes()), before)

    def test_unchanged_pair_is_not_replaced_and_private_modes_are_preserved(self):
        self.sync()
        inode = self.layout.tls_key.stat().st_ino
        result = self.sync()
        self.assertFalse(result["changed"])
        self.assertEqual(self.layout.tls_key.stat().st_ino, inode)
        self.assertEqual(self.layout.tls_key.stat().st_mode & 0o777, 0o640)

    def test_symlink_source_is_rejected_without_reading_or_writing(self):
        target = self.base / "elsewhere"
        target.write_bytes(b"secret")
        self.key.unlink(); self.key.symlink_to(target)
        with self.assertRaises(HelperError): self.sync()
        self.assertFalse(self.layout.tls_key.exists())


class ServiceTemplateTests(unittest.TestCase):
    def template(self, name): return (REPOSITORY / "systemd" / name).read_text()

    def test_socket_reboot_directory_is_traversable_but_socket_is_restricted(self):
        text = self.template("dazzle-vps-helper.socket")
        for required in ("Accept=yes", "DirectoryMode=0755", "SocketMode=0660", "SocketGroup=dazzle-vps", "MaxConnections=8"):
            self.assertIn(required, text)
        service = self.template("dazzle-vps-helper@.service")
        self.assertIn("PartOf=dazzle-vps-helper.socket", service)
        self.assertIn("After=dazzle-vps-helper.socket", service)

    def test_member_binds_agent_administrator_does_not(self):
        self.assertIn("BindsTo=dazzle-vps-agent.service", self.template("dazzle-proxy@.service"))
        self.assertNotIn("dazzle-vps-agent.service", self.template("dazzle-admin@.service"))
        self.assertIn("WatchdogSec=10", self.template("dazzle-vps-agent.service"))

    def test_worker_configs_are_systemd_credentials_not_agent_writable(self):
        for name in ("dazzle-admin@.service", "dazzle-proxy@.service"):
            text = self.template(name)
            self.assertIn("LoadCredential=worker.json:/etc/dazzle-vps/workers/%i.json", text)
            self.assertIn("Restart=no", text)
            self.assertIn("KillMode=control-group", text)
            self.assertIn("CapabilityBoundingSet=\n", text)
            self.assertIn("Slice=system.slice", text)
            self.assertIn("/opt/dazzle-vps/core/sing-box run", text)
            self.assertNotIn("/etc/s-box/sing-box", text)

    def test_no_unit_restarts_legacy_or_invokes_certbot_sudo_firewall(self):
        for path in (REPOSITORY / "systemd").iterdir():
            text = path.read_text()
            for forbidden in ("sudo", "ufw", "certbot", "restart sing-box", "restart qqg-sub", "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE"):
                self.assertNotIn(forbidden, text)


if __name__ == "__main__": unittest.main()
