"""The root member gate against a recorded systemctl; no unit is touched."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

from deployment import member_gate
from deployment.helper import CORE_SHA256, Layout
from deployment.member_gate import CLOSED, DROP_IN, GATE_SETTINGS, OPENED, Gate, GateError


class FakeSystemd:
    """Effective IPAddressDeny, FragmentPath and ControlGroup of one member, as systemctl reports them."""
    def __init__(self, unit, fragment):
        self.unit, self.fragment, self.deny, self.group = unit, fragment, "", "/system.slice/" + unit
        self.calls, self.fail_set, self.ignore_set = [], False, False

    def run(self, arguments, *, input=None, timeout=15):
        command = arguments[1:]
        self.calls.append(tuple(command))
        if command[0] == "show":
            value = {"--property=FragmentPath": self.fragment, "--property=IPAddressDeny": self.deny,
                     "--property=ControlGroup": self.group}[command[1]]
            return subprocess.CompletedProcess(arguments, 0, (value + "\n").encode(), b"")
        if command[0] == "set-property":
            if self.fail_set:
                return subprocess.CompletedProcess(arguments, 1, b"", b"")
            if not self.ignore_set:
                self.deny = "::/0 0.0.0.0/0" if "IPAddressDeny=any" in command else ""
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    def changes(self):
        return [call for call in self.calls if call[0] != "show"]


class MemberGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dazzle-gate-")
        base = Path(self.temporary.name).resolve(); base.chmod(0o700)
        etc, self.units = base / "etc", base / "units"
        etc.mkdir(mode=0o700); self.units.mkdir(mode=0o755)
        self.layout = Layout(etc=etc, trusted_uid=os.getuid())
        self.member, self.admin = str(uuid.uuid4()), str(uuid.uuid4())
        policy = {"version": 1, "server_id": str(uuid.uuid4()), "server_endpoint": "192.0.2.10", "agent_uid": 1001,
                  "core_sha256": CORE_SHA256, "workers": {self.admin: {"role": "admin", "public_port": 24430, "api_port": 34430},
                                                          self.member: {"role": "member", "public_port": 24431, "api_port": 34431}}}
        (etc / "policy.json").write_text(json.dumps(policy)); (etc / "policy.json").chmod(0o600)
        self.unit = "dazzle-proxy@" + self.member + ".service"
        (self.units / "dazzle-proxy@.service").write_bytes(b"[Service]\nSlice=system.slice\n")
        (self.units / self.unit).write_bytes(b"[Service]\nSlice=system.slice\n")
        self.systemd = FakeSystemd(self.unit, str(self.units / self.unit))

    def tearDown(self):
        self.temporary.cleanup()

    def gate(self):
        return Gate(self.layout, self.systemd, units=self.units)

    def adopt(self, content=GATE_SETTINGS):
        folder = self.units / (self.unit + ".d"); folder.mkdir(exist_ok=True)
        (folder / DROP_IN).write_bytes(content)

    def test_an_ungated_member_is_never_touched(self):
        # A guard started before adoption, or stopped after a revert.
        self.assertEqual(self.gate().open(self.member), "not_gated")
        self.assertEqual(self.gate().close(self.member, "75"), "not_gated")
        self.assertEqual(self.systemd.changes(), [])

    def test_adopted_member_opens_after_ready_and_closes_on_any_guard_exit(self):
        self.adopt()
        self.assertEqual(self.gate().open(self.member), "open")
        self.assertEqual(self.systemd.changes(), [("set-property", "--runtime", self.unit, *OPENED)])
        for status in ("75", "", "6"):  # stale meter, clean stop, watchdog abort
            with self.subTest(status=status):
                self.assertEqual(self.gate().close(self.member, status), "closed")
                self.assertEqual(self.systemd.changes()[-1], ("set-property", "--runtime", self.unit, *CLOSED))
        self.assertFalse(any(call[0] == "stop" for call in self.systemd.calls))

    def test_a_future_member_is_gated_by_the_guarded_template(self):
        (self.units / "dazzle-proxy@.service").write_bytes(b"[Service]\nIPAddressAllow=localhost\nIPAddressDeny=any\n")
        self.systemd.fragment = str(self.units / "dazzle-proxy@.service")
        self.assertEqual(self.gate().close(self.member, "75"), "closed")
        self.assertEqual(self.gate().open(self.member), "open")

    def test_fatal_guard_exit_stops_the_core_instead_of_closing(self):
        self.adopt()
        self.assertEqual(self.gate().close(self.member, "3"), "core_stopped")
        self.assertEqual(self.systemd.changes(), [("stop", "--no-block", self.unit)])

    def test_a_gate_that_cannot_be_confirmed_closed_stops_the_core(self):
        self.adopt()
        for failure in ("fail_set", "ignore_set"):
            with self.subTest(failure=failure):
                self.systemd.calls.clear(); self.systemd.deny = ""
                setattr(self.systemd, failure, True)
                self.assertEqual(self.gate().close(self.member, "75"), "core_stopped_gate_unconfirmed")
                self.assertEqual(self.systemd.changes()[-1], ("stop", "--no-block", self.unit))
                setattr(self.systemd, failure, False)

    def test_open_refuses_a_nested_slice_or_an_unconfirmed_opening(self):
        self.adopt()
        self.systemd.group = "/system.slice/system-dazzle\\x2dproxy.slice/" + self.unit
        with self.assertRaises(GateError):
            self.gate().open(self.member)
        self.systemd.group, self.systemd.ignore_set, self.systemd.deny = "", True, "::/0 0.0.0.0/0"
        with self.assertRaises(GateError):
            self.gate().open(self.member)

    def test_only_registered_members_with_the_reviewed_drop_in(self):
        for identifier in (self.admin, str(uuid.uuid4())):
            with self.subTest(identifier=identifier), self.assertRaises(GateError):
                self.gate().close(identifier, "75")
        self.adopt(b"[Service]\nIPAddressDeny=\n")
        with self.assertRaises(GateError):
            self.gate().open(self.member)
        self.assertEqual(self.systemd.changes(), [])

    def test_main_reports_without_values_and_reads_the_guard_exit_status(self):
        self.adopt()
        output = io.StringIO()
        with patch.object(member_gate, "Gate", lambda: self.gate()), patch.dict(os.environ, {"EXIT_STATUS": "3"}), \
                contextlib.redirect_stdout(output):
            self.assertEqual(member_gate.main(["close", self.member]), 0)
        self.assertEqual(json.loads(output.getvalue()), {"ok": True, "action": "close", "gate": "core_stopped"})
        output = io.StringIO()
        with patch.object(member_gate, "Gate", lambda: self.gate()), contextlib.redirect_stdout(output):
            self.assertEqual(member_gate.main(["open", self.admin]), 1)
        self.assertEqual(json.loads(output.getvalue()), {"ok": False, "action": "open"})


if __name__ == "__main__":
    unittest.main()
