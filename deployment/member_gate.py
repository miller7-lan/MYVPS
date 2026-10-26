"""Root-only network gate of one registered member Core, run from its guard's unit.

ExecStartPost opens it once the guard is READY; ExecStopPost closes it whenever
the guard process ends. Closing pauses only public traffic: the Core keeps its
process, its counters and its loopback stats API, so the writer can still sample
it and the next guard reopens without a restart. Only the guard's fatal exit
stops the Core, and so does a gate that cannot be confirmed closed; the result is
never less safe than the former BindsTo.

A member is gated when its unit carries the gate: an adopted existing member has
the gate drop-in, and a future member uses the guarded template. Anything else is
left alone, so a guard started before adoption, or stopped after a revert, never
pauses traffic.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .helper import HelperError, Layout, Runner, canonical_uuid, read_json, validate_policy

UNITS = Path("/etc/systemd/system")
SYSTEMCTL = "/usr/bin/systemctl"
TEMPLATE = "dazzle-proxy@.service"
DROP_IN = "40-dazzle-member-gate.conf"
GATE_SETTINGS = b"[Service]\nIPAddressAllow=localhost\nIPAddressDeny=any\n"
CLOSED = ("IPAddressDeny=any", "IPAddressAllow=localhost")
OPENED = ("IPAddressDeny=", "IPAddressAllow=")
FATAL_STATUS = "3"  # dazzle.meter_guard.EXIT_FATAL


class GateError(Exception):
    pass


def member_unit(identifier):
    return "dazzle-proxy@" + canonical_uuid(identifier) + ".service"


class Gate:
    def __init__(self, layout=None, runner=None, units=UNITS):
        self.layout, self.runner, self.units = layout or Layout(), runner or Runner(), Path(units)

    def _systemctl(self, *arguments):
        return self.runner.run([SYSTEMCTL, *arguments], timeout=10)

    def _show(self, unit, name):
        result = self._systemctl("show", "--property=" + name, "--value", unit)
        if result.returncode:
            raise GateError("Member unit state is unavailable")
        return result.stdout.decode().strip()

    def member(self, identifier):
        policy = read_json(self.layout.policy, self.layout.trusted_uid)
        validate_policy(policy)
        worker = policy["workers"].get(canonical_uuid(identifier))
        if not worker or worker["role"] != "member":
            raise GateError("Only a registered member has a gate")
        return member_unit(identifier)

    def gated(self, unit):
        fragment = self._show(unit, "FragmentPath")
        if fragment == str(self.units / TEMPLATE):
            return b"\nIPAddressDeny=any\n" in Path(fragment).read_bytes()
        drop_in = self.units / (unit + ".d") / DROP_IN
        if not drop_in.exists():
            return False
        if not drop_in.is_file() or drop_in.is_symlink() or drop_in.read_bytes() != GATE_SETTINGS:
            raise GateError("The member gate drop-in is not the reviewed one")
        return True

    def _set(self, unit, values, *, closed):
        if self._systemctl("set-property", "--runtime", unit, *values).returncode:
            return False
        return bool(self._show(unit, "IPAddressDeny")) == closed

    def open(self, identifier):
        unit = self.member(identifier)
        if not self.gated(unit):
            return "not_gated"
        if self._show(unit, "ControlGroup") not in ("", "/system.slice/" + unit):
            # In a nested slice systemd 255 keeps the closed filter after a reset.
            raise GateError("A gated member must run directly in system.slice")
        if not self._set(unit, OPENED, closed=False):
            raise GateError("The member gate did not open")
        return "open"

    def close(self, identifier, exit_status=""):
        unit = self.member(identifier)
        if not self.gated(unit):
            return "not_gated"
        if exit_status == FATAL_STATUS:
            self.stop(unit)
            return "core_stopped"
        if self._set(unit, CLOSED, closed=True):
            return "closed"
        self.stop(unit)
        return "core_stopped_gate_unconfirmed"

    def stop(self, unit):
        self._systemctl("stop", "--no-block", unit)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Open or close one member's network gate (root, from its guard unit)")
    parser.add_argument("action", choices=("open", "close"))
    parser.add_argument("worker_id")
    args = parser.parse_args(argv)
    try:
        gate = Gate()
        result = gate.open(args.worker_id) if args.action == "open" else gate.close(args.worker_id, os.environ.get("EXIT_STATUS", ""))
    except (GateError, HelperError, OSError, ValueError, KeyError):
        # A failed open fails the guard's start, which runs the close; a failed close
        # leaves the unit's last resort, which stops a gated Core.
        print(json.dumps({"ok": False, "action": args.action}))
        return 1
    print(json.dumps({"ok": True, "action": args.action, "gate": result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
