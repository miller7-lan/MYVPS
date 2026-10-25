"""Managed Certbot source boundaries; all roots/keys are isolated fixtures."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from deployment import certsync
from deployment.helper import CORE_SHA256, HelperError, Layout, Runner


class ManagedCertificateSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dazzle-certbot-test-")
        self.base = Path(self.temporary.name).resolve(); self.base.chmod(0o700)
        self.etc = self.base / "project"; self.etc.mkdir(mode=0o700)
        (self.etc / "tls").mkdir(mode=0o700)
        self.policy = {"version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "192.0.2.10", "agent_uid": 1001,
                       "core_sha256": CORE_SHA256, "workers": {str(uuid.uuid4()): {"role": "admin", "public_port": 24430, "api_port": 34430}}}
        (self.etc / "policy.json").write_text(json.dumps(self.policy)); (self.etc / "policy.json").chmod(0o600)
        self.layout = Layout(etc=self.etc, trusted_uid=os.getuid())
        self.root = self.base / "letsencrypt"
        self.name = "fixture.example"
        self.live = self.root / "live" / self.name
        self.archive = self.root / "archive" / self.name
        self.live.mkdir(parents=True, mode=0o700); self.archive.mkdir(parents=True, mode=0o700)
        for folder in (self.root, self.root / "live", self.root / "archive"): folder.chmod(0o700)
        self.write_version(1)
        self.cert = self.live / "fullchain.pem"; self.key = self.live / "privkey.pem"
        self.cert.symlink_to(f"../../archive/{self.name}/fullchain1.pem")
        self.key.symlink_to(f"../../archive/{self.name}/privkey1.pem")
        self.validator = Mock()
        self.runner = Mock()

    def tearDown(self): self.temporary.cleanup()

    def write_version(self, number):
        for prefix, payload in (("fullchain", b"CERTIFICATE-"), ("privkey", b"PRIVATE-KEY-")):
            path = self.archive / f"{prefix}{number}.pem"
            path.write_bytes(payload + str(number).encode()); path.chmod(0o600)

    def sync(self, **kwargs):
        options = dict(layout=self.layout, source_cert=self.cert, source_key=self.key,
                       managed_certbot_source=True, certbot_root=self.root,
                       validator=self.validator, runner=self.runner)
        options.update(kwargs)
        return certsync.sync_certificate(**options)

    def assert_no_pair(self):
        self.assertFalse(self.layout.tls_certificate.exists()); self.assertFalse(self.layout.tls_key.exists())

    def test_only_matching_managed_archive_pair_is_copied_without_service_io(self):
        before = (os.readlink(self.cert), os.readlink(self.key), self.cert.read_bytes(), self.key.read_bytes())
        result = self.sync()
        self.assertEqual(self.layout.tls_certificate.read_bytes(), b"CERTIFICATE-1")
        self.assertEqual(self.layout.tls_key.read_bytes(), b"PRIVATE-KEY-1")
        self.assertEqual(before, (os.readlink(self.cert), os.readlink(self.key), self.cert.read_bytes(), self.key.read_bytes()))
        self.assertFalse(result["services_restarted"]); self.runner.run.assert_not_called()
        self.assertEqual(set(json.loads((self.etc / "tls/status.json").read_text())), {"certificate_sha256"})
        self.assertNotIn("PRIVATE-KEY", json.dumps(result)); self.assertEqual(self.validator.call_count, 1)
        self.assertFalse(self.sync()["changed"])

    def test_default_mode_still_refuses_managed_symlinks(self):
        with self.assertRaises(HelperError): self.sync(managed_certbot_source=False)
        self.assert_no_pair(); self.validator.assert_not_called()

    def test_real_regular_live_files_are_not_mistaken_for_managed_links(self):
        self.key.unlink(); self.key.write_bytes(b"PRIVATE-KEY-1"); self.key.chmod(0o600)
        with self.assertRaises(HelperError): self.sync()
        self.assert_no_pair()

    def test_mismatched_renewal_versions_are_rejected_before_validation(self):
        self.write_version(2); self.key.unlink(); self.key.symlink_to(f"../../archive/{self.name}/privkey2.pem")
        with self.assertRaises(HelperError): self.sync()
        self.assert_no_pair(); self.validator.assert_not_called()

    def test_separate_lineages_are_rejected(self):
        other = self.root / "live" / "other.example"; other.mkdir(mode=0o700)
        other_key = other / "privkey.pem"; other_key.symlink_to(f"../../archive/{self.name}/privkey1.pem")
        with self.assertRaises(HelperError): self.sync(source_key=other_key)
        self.assert_no_pair()

    def test_live_link_cannot_escape_to_any_other_root_owned_file(self):
        outside = self.base / "outside.pem"; outside.write_bytes(b"PRIVATE-OUTSIDE"); outside.chmod(0o600)
        self.key.unlink(); self.key.symlink_to(outside)
        with self.assertRaises(HelperError): self.sync()
        self.assert_no_pair(); self.validator.assert_not_called()

    def test_archive_parent_must_not_be_a_symlink(self):
        moved = self.root / "moved-archive"; self.archive.rename(moved); self.archive.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(HelperError): self.sync()
        self.assert_no_pair()

    def test_archive_file_must_not_be_a_symlink_even_with_matching_name(self):
        key = self.archive / "privkey1.pem"; key.rename(self.archive / "actual.pem"); key.symlink_to("actual.pem")
        with self.assertRaises(HelperError): self.sync()
        self.assert_no_pair()

    def test_untrusted_directory_or_writable_archive_file_is_rejected(self):
        for path in (self.root, self.root / "live", self.live, self.root / "archive", self.archive, self.archive / "privkey1.pem"):
            with self.subTest(path=path.relative_to(self.root)):
                before = path.stat().st_mode & 0o777; path.chmod(before | 0o020)
                try:
                    with self.assertRaises(HelperError): self.sync()
                    self.assert_no_pair()
                finally: path.chmod(before)

    def test_wrong_source_symlink_owner_is_rejected(self):
        real_lstat = os.lstat
        def altered(path, *args, **kwargs):
            value = real_lstat(path, *args, **kwargs)
            if Path(path) == self.key:
                fields = list(value); fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return value
        with patch("deployment.certsync.os.lstat", side_effect=altered):
            with self.assertRaises(HelperError): self.sync()
        self.assert_no_pair()

    def test_archive_files_cannot_be_hard_linked(self):
        os.link(self.archive / "privkey1.pem", self.base / "key-hardlink")
        with self.assertRaises(HelperError): self.sync()
        self.assert_no_pair()

    def test_managed_paths_must_be_explicit_and_have_expected_leaf_names(self):
        for changed in ({"source_cert": Path("relative/fullchain.pem")}, {"source_key": self.live / "key.pem"},
                        {"source_cert": self.archive / "fullchain1.pem"}, {"source_cert": self.live / ".." / self.name / "fullchain.pem"}):
            with self.subTest(changed=changed):
                with self.assertRaises(HelperError): self.sync(**changed)
                self.assert_no_pair()

    def test_renewal_during_validation_retains_both_previous_copies(self):
        self.sync()
        before = (self.layout.tls_certificate.read_bytes(), self.layout.tls_key.read_bytes())
        self.write_version(2); self.write_version(3)
        for link, leaf in ((self.cert, "fullchain"), (self.key, "privkey")):
            link.unlink(); link.symlink_to(f"../../archive/{self.name}/{leaf}2.pem")
        def renew(*_):
            for link, leaf in ((self.cert, "fullchain"), (self.key, "privkey")):
                link.unlink(); link.symlink_to(f"../../archive/{self.name}/{leaf}3.pem")
        with self.assertRaises(HelperError): self.sync(validator=renew)
        self.assertEqual(before, (self.layout.tls_certificate.read_bytes(), self.layout.tls_key.read_bytes()))

    def test_failed_validation_preserves_agent_and_web_pairs(self):
        self.policy.update(version=2, portal_uid=1201)
        (self.etc / "policy.json").write_text(json.dumps(self.policy)); (self.etc / "web-tls").mkdir(mode=0o700)
        gid = max(1, os.getgid())
        self.sync(portal_tls_gid=gid)
        paths = [self.etc / directory / leaf for directory in ("tls", "web-tls") for leaf in ("cert.pem", "key.pem")]
        before = [path.read_bytes() for path in paths]
        def fail(*_): raise HelperError("TLS_INVALID", "fixture mismatch")
        with self.assertRaises(HelperError): self.sync(portal_tls_gid=gid, validator=fail)
        self.assertEqual(before, [path.read_bytes() for path in paths])

    def test_default_production_ancestors_are_checked_including_etc(self):
        with patch("deployment.certsync.checked_path") as checked:
            certsync._managed_directories(Path("/etc/letsencrypt/live/fixture.example"), certsync.CERTBOT_ROOT, 0)
        self.assertEqual([call.args[0] for call in checked.call_args_list],
                         [Path("/etc"), Path("/etc/letsencrypt"), Path("/etc/letsencrypt/live"), Path("/etc/letsencrypt/live/fixture.example")])

    def test_cli_does_not_expose_test_roots_or_uid_bypass(self):
        for arguments in (["--certbot-root", str(self.root)], ["--trusted-uid", str(os.getuid())],
                          ["--source-cert", str(self.cert)], ["--managed-certbot-source"]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): certsync.main(arguments)

    def test_cli_passes_only_explicit_sources_and_managed_opt_in(self):
        with patch("deployment.certsync.os.geteuid", return_value=0), patch("deployment.certsync.read_json", return_value=self.policy), \
             patch("deployment.certsync.grp.getgrnam", return_value=type("Group", (), {"gr_gid": 1001})()), \
             patch("deployment.certsync.sync_certificate", return_value={"ok": True}) as sync, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(certsync.main(["--source-cert", str(self.cert), "--source-key", str(self.key), "--managed-certbot-source"]), 0)
        self.assertEqual(sync.call_args.kwargs["source_cert"], self.cert)
        self.assertEqual(sync.call_args.kwargs["source_key"], self.key)
        self.assertTrue(sync.call_args.kwargs["managed_certbot_source"])
        self.assertNotIn("certbot_root", sync.call_args.kwargs)


class RealPairValidationTests(unittest.TestCase):
    setUp = ManagedCertificateSourceTests.setUp
    tearDown = ManagedCertificateSourceTests.tearDown
    write_version = ManagedCertificateSourceTests.write_version
    sync = ManagedCertificateSourceTests.sync
    def test_real_matching_pair_wrong_ip_and_wrong_key_are_checked(self):
        binary = shutil.which("openssl")
        if not binary: self.skipTest("OpenSSL required")
        help_text = subprocess.run([binary, "x509", "-help"], capture_output=True, text=True).stderr
        if "-checkip" not in help_text: self.skipTest("OpenSSL with checkip required")
        configuration = self.base / "openssl.cnf"
        configuration.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=isolated-fixture\n[ext]\nsubjectAltName=IP:192.0.2.10\nbasicConstraints=critical,CA:TRUE\nkeyUsage=digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n")
        cert, key = self.archive / "fullchain1.pem", self.archive / "privkey1.pem"
        subprocess.run([binary, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                        "-days", "2", "-config", str(configuration)], check=True, capture_output=True)
        cert.chmod(0o600); key.chmod(0o600)
        class LocalOpenSSLRunner(Runner):
            def run(self, arguments, **kwargs): return super().run([binary, *arguments[1:]], **kwargs)
        runner = LocalOpenSSLRunner()
        self.sync(validator=certsync.validate_pair, runner=runner)
        before = (self.layout.tls_certificate.read_bytes(), self.layout.tls_key.read_bytes())
        self.policy["server_endpoint"] = "192.0.2.11"; (self.etc / "policy.json").write_text(json.dumps(self.policy))
        with self.assertRaises(HelperError): self.sync(validator=certsync.validate_pair, runner=runner)
        self.assertEqual(before, (self.layout.tls_certificate.read_bytes(), self.layout.tls_key.read_bytes()))
        self.policy["server_endpoint"] = "192.0.2.10"; (self.etc / "policy.json").write_text(json.dumps(self.policy))
        other_key = self.base / "other-key.pem"
        subprocess.run([binary, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(other_key)], check=True, capture_output=True)
        key.write_bytes(other_key.read_bytes()); key.chmod(0o600)
        with self.assertRaises(HelperError): self.sync(validator=certsync.validate_pair, runner=runner)
        self.assertEqual(before, (self.layout.tls_certificate.read_bytes(), self.layout.tls_key.read_bytes()))
