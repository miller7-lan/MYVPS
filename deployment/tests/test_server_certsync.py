"""The server-local direct-ACME sync must keep working with this release's certsync.

server/certsync/ holds byte-exact copies of three files that were installed on the
target outside the release (2026-10-25): a drop-in that runs a small script with
the *current* release's interpreter, the script itself and a certbot deploy hook.
Switching `current` therefore changes the code that script imports.
"""
import ast
import contextlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from deployment import certsync, helper
from deployment.helper import CORE_SHA256, Layout

FOLDER = Path(__file__).resolve().parents[2] / "server/certsync"
SCRIPT = FOLDER / "dazzle-certsync-from-acme.py"


def load_script():
    spec = importlib.util.spec_from_file_location("dazzle_certsync_from_acme", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecordedServerFilesTests(unittest.TestCase):
    def test_script_imports_and_keywords_are_accepted_by_this_release(self):
        tree = ast.parse(SCRIPT.read_text())
        imports = {(node.module, alias.name) for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                   for alias in node.names if (node.module or "").startswith("deployment")}
        self.assertEqual(imports, {("deployment.certsync", "sync_certificate"), ("deployment.helper", "Layout"),
                                   ("deployment.helper", "read_json"), ("deployment.helper", "validate_policy")})
        keys = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "dict":
                keys |= {keyword.arg for keyword in node.keywords}
            if (isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store)
                    and getattr(node.value, "id", None) == "options"):
                keys.add(node.slice.value)
        self.assertEqual(keys, {"source_cert", "source_key", "tls_gid", "portal_tls_gid"})
        parameters = inspect.signature(certsync.sync_certificate).parameters
        self.assertTrue(all(parameters[key].kind is inspect.Parameter.KEYWORD_ONLY for key in keys))

    def test_drop_in_follows_current_so_a_release_switch_changes_its_code(self):
        drop_in = (FOLDER / "20-direct-acme.conf").read_text()
        self.assertIn("ExecStart=\nExecStart=/opt/dazzle-vps/current/venv/bin/python -I /usr/local/libexec/dazzle-certsync-from-acme.py\n", drop_in)
        self.assertIn("ReadOnlyPaths=\nReadOnlyPaths=/etc/letsencrypt/live/qqg-ip /etc/letsencrypt/archive/qqg-ip\n", drop_in)
        hook = (FOLDER / "deploy-hook-dazzle-vps-certsync").read_text()
        self.assertIn('[ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/qqg-ip ] || exit 0', hook)
        self.assertIn("/usr/bin/systemctl start dazzle-vps-certsync.service", hook)


class RecordedScriptExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dazzle-acme-script-")
        self.base = Path(self.temporary.name).resolve(); self.base.chmod(0o700)
        self.etc = self.base / "project"; self.etc.mkdir(mode=0o700)
        (self.etc / "tls").mkdir(mode=0o700)
        self.layout = Layout(etc=self.etc, trusted_uid=os.getuid())
        self.root = self.base / "letsencrypt"
        live, self.archive = self.root / "live/qqg-ip", self.root / "archive/qqg-ip"
        live.mkdir(parents=True, mode=0o700); self.archive.mkdir(parents=True, mode=0o700)
        for folder in (self.root, self.root / "live", self.root / "archive"):
            folder.chmod(0o700)
        for prefix, payload in (("fullchain", b"CERTIFICATE-1"), ("privkey", b"PRIVATE-KEY-1")):
            path = self.archive / (prefix + "1.pem"); path.write_bytes(payload); path.chmod(0o600)
        (live / "fullchain.pem").symlink_to("../../archive/qqg-ip/fullchain1.pem")
        (live / "privkey.pem").symlink_to("../../archive/qqg-ip/privkey1.pem")
        self.validator = Mock()
        self.write_policy(1)

    def tearDown(self):
        self.temporary.cleanup()

    def write_policy(self, version):
        workers = {str(uuid.uuid4()): {"role": "admin", "public_port": 24430, "api_port": 34430},
                   str(uuid.uuid4()): {"role": "member", "public_port": 24431, "api_port": 34431}}
        policy = {"version": version, "server_id": str(uuid.uuid4()), "server_endpoint": "192.0.2.10", "agent_uid": 1001,
                  "core_sha256": CORE_SHA256, "workers": workers}
        if version == 2:
            policy["portal_uid"] = 1002
            (self.etc / "web-tls").mkdir(mode=0o700, exist_ok=True)
        (self.etc / "policy.json").write_text(json.dumps(policy)); (self.etc / "policy.json").chmod(0o600)

    def run_script(self):
        module, real_path = load_script(), Path
        def mapped(value):
            text = str(value)
            return real_path(str(self.root) + text[len("/etc/letsencrypt"):]) if text.startswith("/etc/letsencrypt") else real_path(value)
        groups = Mock(); groups.getgrnam.return_value = Mock(gr_gid=os.getgid())
        output = io.StringIO()
        # Only the fixed production roots and the root/group lookups are redirected; the
        # script's own keywords reach this release's real sync_certificate unchanged.
        with patch.object(module, "Path", mapped), patch.object(module, "Layout", lambda: self.layout), \
                patch.object(module, "read_json", lambda path: helper.read_json(path, self.layout.trusted_uid)), \
                patch.object(module, "grp", groups), patch.object(module.os, "geteuid", return_value=0), \
                patch.object(module, "sync_certificate", lambda **options: certsync.sync_certificate(
                    layout=self.layout, validator=self.validator, runner=Mock(), **options)), \
                contextlib.redirect_stdout(output):
            module.main()
        return json.loads(output.getvalue())

    def test_script_copies_the_current_lineage_through_this_release(self):
        first = self.run_script()
        self.assertEqual((first["ok"], first["changed"], first["source"]), (True, True, "verified_acme_lineage"))
        self.assertEqual(self.layout.tls_certificate.read_bytes(), b"CERTIFICATE-1")
        self.assertEqual(self.layout.tls_key.read_bytes(), b"PRIVATE-KEY-1")
        self.assertFalse(self.run_script()["changed"])
        self.assertEqual(self.validator.call_args.args[2], "192.0.2.10")

    def test_v2_policy_also_refreshes_the_portal_copy(self):
        self.write_policy(2)
        self.assertTrue(self.run_script()["changed"])
        self.assertEqual((self.etc / "web-tls/cert.pem").read_bytes(), b"CERTIFICATE-1")

    def test_mismatched_generations_are_refused_before_any_copy(self):
        (self.archive / "privkey2.pem").write_bytes(b"PRIVATE-KEY-2"); (self.archive / "privkey2.pem").chmod(0o600)
        (self.root / "live/qqg-ip/privkey.pem").unlink()
        (self.root / "live/qqg-ip/privkey.pem").symlink_to("../../archive/qqg-ip/privkey2.pem")
        with self.assertRaises(RuntimeError):
            self.run_script()
        self.assertFalse(self.layout.tls_certificate.exists())


if __name__ == "__main__":
    unittest.main()
