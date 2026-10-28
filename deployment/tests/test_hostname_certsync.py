"""Portal hostname certificates use isolated managed lineages and no network."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from dazzle.production_state import checked_hostname
from deployment import certsync
from deployment.helper import HelperError, Runner
from deployment.tests import test_certbot_sync as certificate_fixtures


class HostnameCertificateSyncTests(unittest.TestCase):
    write_version = certificate_fixtures.ManagedCertificateSourceTests.write_version
    tearDown = certificate_fixtures.ManagedCertificateSourceTests.tearDown

    def setUp(self):
        certificate_fixtures.ManagedCertificateSourceTests.setUp(self)
        self.policy.update(version=2, portal_uid=1201)
        (self.etc / "policy.json").write_text(json.dumps(self.policy))
        self.web_tls = self.etc / "web-tls"
        self.web_tls.mkdir(mode=0o700)
        self.gid = max(1, os.getgid())
        self.host_cert, self.host_key = self.web_tls / "host-cert.pem", self.web_tls / "host-key.pem"
        for directory in (self.etc / "tls", self.web_tls):
            for leaf, contents in (("cert.pem", b"EXISTING-IP-CERT"), ("key.pem", b"EXISTING-IP-KEY")):
                path = directory / leaf
                path.write_bytes(contents)
                path.chmod(0o640)
        self.ip_before = self.ip_pairs()

    def ip_pairs(self):
        return {(directory, leaf): (self.etc / directory / leaf).read_bytes()
                for directory in ("tls", "web-tls") for leaf in ("cert.pem", "key.pem")}

    def host_pair(self):
        return self.host_cert.read_bytes(), self.host_key.read_bytes()

    def sync(self, **kwargs):
        options = dict(hostname=self.name, source_cert=self.cert, source_key=self.key, layout=self.layout,
                       runner=self.runner, portal_tls_gid=self.gid, validator=self.validator, certbot_root=self.root)
        options.update(kwargs)
        return certsync.sync_hostname_certificate(**options)

    def select_version(self, number):
        self.write_version(number)
        for link, prefix in ((self.cert, "fullchain"), (self.key, "privkey")):
            link.unlink()
            link.symlink_to(f"../../archive/{self.name}/{prefix}{number}.pem")

    def test_hostname_pair_is_separate_private_idempotent_and_never_restarts_services(self):
        sources = (os.readlink(self.cert), os.readlink(self.key), self.cert.read_bytes(), self.key.read_bytes())
        def validate(cert, key, hostname, runner):
            self.assertEqual((cert.read_bytes(), key.read_bytes()), sources[2:])
            self.assertEqual(hostname, self.name)
            self.assertIs(runner, self.runner)
            for path in (cert, key):
                self.assertTrue(path.is_relative_to(self.web_tls))
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.validator.side_effect = validate
        result = self.sync()
        self.assertEqual(self.host_pair(), (b"CERTIFICATE-1", b"PRIVATE-KEY-1"))
        self.assertEqual(self.ip_pairs(), self.ip_before)
        self.assertEqual(sources, (os.readlink(self.cert), os.readlink(self.key), self.cert.read_bytes(), self.key.read_bytes()))
        for path in (self.host_cert, self.host_key):
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(path.stat().st_uid, os.getuid())
            self.assertEqual(path.stat().st_gid, self.gid)
        status = json.loads((self.web_tls / "host-status.json").read_text())
        self.assertEqual(set(status), {"hostname", "certificate_sha256"})
        self.assertEqual(status["hostname"], self.name)
        self.assertNotIn("PRIVATE-KEY", json.dumps(result) + json.dumps(status))
        self.assertFalse(result["services_restarted"])
        self.assertFalse(result["legacy_modified"])
        self.assertFalse(self.sync()["changed"])
        self.runner.run.assert_not_called()

    def test_root_and_backend_hostname_boundaries_agree(self):
        accepted = ("a.co", "vps.example.com", "xn--bcher-kva.example", "a" * 63 + ".example")
        rejected = (None, True, 42, "", "localhost", "127.0.0.1", "::1", "https://vps.example.com",
                    "Vps.example.com", "vps.example.com.", "vps.example.com:9443", "vps.example.com/path",
                    "vps..example.com", "-vps.example.com", "vps-.example.com", "vps_example.com",
                    "vps.123", "测试.example", "vps.example\n", "a" * 64 + ".example", "a." * 126 + "co")
        for hostname in accepted:
            with self.subTest(hostname=hostname):
                self.assertEqual(checked_hostname(hostname), hostname)
                self.assertTrue(self.sync(hostname=hostname)["ok"])
        for hostname in rejected:
            with self.subTest(hostname=hostname):
                with self.assertRaises(ValueError):
                    checked_hostname(hostname)
                with self.assertRaises(HelperError):
                    self.sync(hostname=hostname)
        self.assertEqual(self.ip_pairs(), self.ip_before)

    def test_v2_and_explicit_valid_portal_group_are_required_before_copying(self):
        for gid in (None, 0, -1, True, "1001"):
            with self.subTest(gid=gid), self.assertRaises(HelperError):
                self.sync(portal_tls_gid=gid)
        self.policy.pop("portal_uid")
        self.policy["version"] = 1
        (self.etc / "policy.json").write_text(json.dumps(self.policy))
        with self.assertRaises(HelperError):
            self.sync()
        self.assertFalse(self.host_cert.exists())
        self.assertFalse(self.host_key.exists())
        self.validator.assert_not_called()
        self.assertEqual(self.ip_pairs(), self.ip_before)

    def test_hostname_copy_rejects_unmanaged_or_escaping_sources(self):
        self.sync()
        before = self.host_pair()
        invalid = ({"source_cert": self.archive / "fullchain1.pem"}, {"source_key": self.live / "key.pem"},
                   {"source_cert": Path("live/fixture.example/fullchain.pem")},
                   {"source_cert": self.base / "outside/fullchain.pem"})
        for changed in invalid:
            with self.subTest(changed=changed), self.assertRaises(HelperError):
                self.sync(**changed)
            self.assertEqual(self.host_pair(), before)
        self.key.unlink()
        outside = self.base / "outside-key.pem"
        outside.write_bytes(b"OUTSIDE-KEY")
        outside.chmod(0o600)
        self.key.symlink_to(outside)
        with self.assertRaises(HelperError):
            self.sync()
        self.assertEqual(self.host_pair(), before)
        self.assertEqual(self.ip_pairs(), self.ip_before)

    def test_validation_failure_keeps_hostname_status_and_both_ip_pairs(self):
        self.sync()
        before = self.host_pair()
        status = (self.web_tls / "host-status.json").read_bytes()
        self.select_version(2)
        def fail(*_):
            raise HelperError("TLS_INVALID", "isolated invalid hostname certificate")
        with self.assertRaises(HelperError):
            self.sync(validator=fail)
        self.assertEqual(self.host_pair(), before)
        self.assertEqual((self.web_tls / "host-status.json").read_bytes(), status)
        self.assertEqual(self.ip_pairs(), self.ip_before)

    def test_managed_renewal_races_keep_existing_hostname_pair(self):
        self.sync()
        before = self.host_pair()
        self.select_version(2)
        def renewed(*_):
            self.select_version(3)
        with self.assertRaises(HelperError):
            self.sync(validator=renewed)
        self.assertEqual(self.host_pair(), before)
        self.key.unlink()
        self.key.symlink_to(f"../../archive/{self.name}/privkey2.pem")
        with self.assertRaises(HelperError):
            self.sync()
        self.assertEqual(self.host_pair(), before)
        self.assertEqual(self.ip_pairs(), self.ip_before)

    def test_untrusted_existing_hostname_key_rejects_before_certificate_replacement(self):
        self.sync()
        before = self.host_pair()
        self.select_version(2)
        self.host_key.chmod(0o666)
        with self.assertRaises(HelperError):
            self.sync()
        self.assertEqual(self.host_pair(), before)
        self.assertEqual(self.ip_pairs(), self.ip_before)

    def test_untrusted_hostname_status_rejects_before_either_certificate_target_changes(self):
        self.sync()
        before = self.host_pair()
        status = self.web_tls / "host-status.json"
        previous_status = status.read_bytes()
        self.select_version(2)
        status.chmod(0o666)
        with self.assertRaises(HelperError):
            self.sync()
        self.assertEqual(self.host_pair(), before)
        self.assertEqual(status.read_bytes(), previous_status)
        self.assertEqual(self.ip_pairs(), self.ip_before)

    def test_cli_hostname_requires_managed_sources_and_only_dispatches_hostname_copy(self):
        for arguments in (["--hostname", self.name], ["--hostname", self.name, "--managed-certbot-source"],
                          ["--hostname", self.name, "--source-cert", str(self.cert), "--source-key", str(self.key)]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                certsync.main(arguments)
        with patch.object(certsync.os, "geteuid", return_value=0), patch.object(certsync, "read_json", return_value=self.policy), \
             patch.object(certsync.grp, "getgrnam", return_value=type("Group", (), {"gr_gid": self.gid})()), \
             patch.object(certsync, "sync_hostname_certificate", return_value={"ok": True}) as host_sync, \
             patch.object(certsync, "sync_certificate") as ip_sync, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(certsync.main(["--hostname", self.name, "--managed-certbot-source",
                                           "--source-cert", str(self.cert), "--source-key", str(self.key)]), 0)
        self.assertEqual(host_sync.call_args.kwargs, {"hostname": self.name, "source_cert": self.cert,
                                                     "source_key": self.key, "portal_tls_gid": self.gid})
        ip_sync.assert_not_called()


class RealHostnameCertificateValidationTests(unittest.TestCase):
    write_version = HostnameCertificateSyncTests.write_version
    tearDown = HostnameCertificateSyncTests.tearDown
    ip_pairs = HostnameCertificateSyncTests.ip_pairs
    host_pair = HostnameCertificateSyncTests.host_pair
    sync = HostnameCertificateSyncTests.sync

    def setUp(self):
        self.binary = shutil.which("openssl")
        if not self.binary:
            self.skipTest("OpenSSL required")
        help_text = subprocess.run([self.binary, "x509", "-help"], capture_output=True, text=True).stderr
        if "-checkhost" not in help_text:
            self.skipTest("OpenSSL with checkhost required")
        HostnameCertificateSyncTests.setUp(self)
        binary = self.binary
        class LocalOpenSSLRunner(Runner):
            def run(self, arguments, **kwargs):
                return super().run([binary, *arguments[1:]], **kwargs)
        self.real_runner = LocalOpenSSLRunner()

    def generate_pair(self, *, hostname=None, san=True, days=2):
        hostname = hostname or self.name
        config = self.base / "hostname.cnf"
        text = ("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=" + hostname +
                "\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=digitalSignature,keyEncipherment,keyCertSign\n"
                "extendedKeyUsage=serverAuth\n")
        if san:
            text += "subjectAltName=" + ("DNS:" + hostname if san is True else san) + "\n"
        config.write_text(text)
        cert, key = self.archive / "fullchain1.pem", self.archive / "privkey1.pem"
        subprocess.run([self.binary, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                        "-out", str(cert), "-days", str(days), "-config", str(config)], check=True, capture_output=True)
        cert.chmod(0o600)
        key.chmod(0o600)

    def real_sync(self):
        return self.sync(validator=certsync.validate_hostname_pair, runner=self.real_runner)

    def test_real_dns_san_pair_is_accepted_and_wrong_hostname_or_key_preserves_old_pair(self):
        self.generate_pair()
        self.assertTrue(self.real_sync()["changed"])
        before = self.host_pair()
        self.generate_pair(hostname="another.example")
        with self.assertRaises(HelperError):
            self.real_sync()
        self.assertEqual(self.host_pair(), before)
        self.generate_pair()
        other_key = self.base / "other-private-key.pem"
        subprocess.run([self.binary, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(other_key)],
                       check=True, capture_output=True)
        (self.archive / "privkey1.pem").write_bytes(other_key.read_bytes())
        with self.assertRaises(HelperError):
            self.real_sync()
        self.assertEqual(self.host_pair(), before)
        self.assertEqual(self.ip_pairs(), self.ip_before)

    def test_real_certificate_without_dns_san_is_rejected_even_when_common_name_matches(self):
        self.generate_pair()
        self.real_sync()
        before = self.host_pair()
        for san in (False, "IP:192.0.2.10"):
            with self.subTest(subject_alt_name=san):
                self.generate_pair(san=san)
                with self.assertRaises(HelperError):
                    self.real_sync()
                self.assertEqual(self.host_pair(), before)
        self.assertEqual(self.ip_pairs(), self.ip_before)

    def test_real_hostname_certificate_needing_renewal_within_one_day_keeps_old_pair(self):
        self.generate_pair()
        self.real_sync()
        before = self.host_pair()
        self.generate_pair(days=1)
        with self.assertRaises(HelperError):
            self.real_sync()
        self.assertEqual(self.host_pair(), before)
        self.assertEqual(self.ip_pairs(), self.ip_before)
