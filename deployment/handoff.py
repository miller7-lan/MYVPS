"""Pure review/render helpers for the live writer handoff. No mutation here.

The executing coordinator is deployment.coordinator. Unlike the historical
maintenance updater, absent legacy resources are recorded honestly and may be
preserved as absent after explicit administrator retirement. Nothing here stops
a member Core or rebuilds retired legacy services.
"""
from __future__ import annotations

from pathlib import Path
import re

from .helper import CORE_SHA256, Runner, canonical_uuid, validate_policy
from .installer import sha256

OLD_WRITER = "dazzle-vps-agent.service"
WRITER_TEMPLATE = "dazzle-vps-writer@.service"
GUARD_TEMPLATE = "dazzle-vps-meter-guard@.service"
OLD_POLICY_SNAPSHOT = "/etc/dazzle-vps/handoff/previous-policy-v1.json"
LEGACY_UNITS = ("sing-box.service", "qqg-sub.service")
LEGACY_FILES = ("/etc/s-box/sing-box", "/etc/s-box/sb.json")


def show_unit(runner, unit):
    if not re.fullmatch(r"[A-Za-z0-9@_.-]+\.service", unit): raise ValueError("Untrusted unit name")
    result = runner.run(["/usr/bin/systemctl", "show", unit, "--property=LoadState,ActiveState,MainPID,NRestarts,FragmentPath,DropInPaths,BindsTo"], timeout=10)
    fields = dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)
    if result.returncode not in {0, 1, 4} or fields.get("LoadState") not in {"loaded", "not-found", "masked"}:
        raise ValueError("Unit state could not be observed")
    return {"load_state": fields["LoadState"], "active_state": fields["ActiveState"],
            "pid": int(fields["MainPID"]), "restarts": int(fields["NRestarts"]),
            "fragment": fields.get("FragmentPath", ""), "dropins": fields.get("DropInPaths", ""),
            "binds_to": sorted(fields.get("BindsTo", "").split())}


def observe_file(path):
    path = Path(path)
    if path.is_symlink(): raise ValueError("Observed project path is a symlink")
    if not path.exists(): return {"present": False, "sha256": None}
    if not path.is_file(): raise ValueError("Observed project path is not regular")
    return {"present": True, "sha256": sha256(path.read_bytes())}


def capture_environment(policy, *, runner=None):
    runner = runner or Runner(); policy = validate_policy(policy)
    workers = {}
    for identifier, worker in policy["workers"].items():
        name = ("dazzle-admin" if worker["role"] == "admin" else "dazzle-proxy") + "@" + identifier + ".service"
        workers[identifier] = {"unit": name, "role": worker["role"], **show_unit(runner, name)}
    return {"version": 1, "legacy_services": {name: show_unit(runner, name) for name in LEGACY_UNITS},
            "legacy_files": {name: observe_file(name) for name in LEGACY_FILES},
            "core_copy": observe_file("/opt/dazzle-vps/core/sing-box"),
            "old_writer": show_unit(runner, OLD_WRITER), "workers": workers}


def validate_environment(environment, retirement_confirmation=None):
    if not isinstance(environment, dict) or environment.get("version") != 1 or set(environment.get("legacy_services", {})) != set(LEGACY_UNITS) or set(environment.get("legacy_files", {})) != set(LEGACY_FILES):
        raise ValueError("An honest observed environment is required")
    if environment.get("core_copy") != {"present": True, "sha256": CORE_SHA256}:
        raise ValueError("The independently pinned new core is unavailable")
    absent = [name for name, row in environment["legacy_services"].items() if row["active_state"] != "active" or row["pid"] <= 0]
    missing = [name for name, row in environment["legacy_files"].items() if not row["present"]]
    if absent or missing:
        if (not isinstance(retirement_confirmation, dict) or set(retirement_confirmation) != {"administrator_confirmed", "evidence", "preserve_absence"}
                or retirement_confirmation["administrator_confirmed"] is not True or retirement_confirmation["preserve_absence"] is not True
                or not isinstance(retirement_confirmation["evidence"], str) or not retirement_confirmation["evidence"].strip()):
            raise ValueError("Legacy absence requires explicit administrator retirement evidence; never fabricate healthy state")
    old = environment.get("old_writer", {})
    if old.get("active_state") != "active" or old.get("pid", 0) <= 0:
        raise ValueError("The original writer must remain alive throughout preparation")
    for worker in environment.get("workers", {}).values():
        if worker.get("role") == "admin" and (worker.get("active_state") != "active" or worker.get("pid", 0) <= 0):
            raise ValueError("The administrator must remain independently active")
    return {"legacy_mode": "administrator_retired" if absent or missing else "observed_present",
            "retirement_confirmation": retirement_confirmation, "restore_legacy": False}


def guard_name(identifier):
    return "dazzle-vps-meter-guard@" + canonical_uuid(identifier) + ".service"


def render_existing_member(original, identifier):
    """Complete instance override: change only BindsTo/After in known source.

    Dependencies cannot be cleared in a drop-in. Unknown dependency drop-ins are
    rejected separately instead of pretending an empty BindsTo resets them.
    """
    identifier = canonical_uuid(identifier)
    source = original.decode("utf-8") if isinstance(original, bytes) else original
    lines = source.splitlines(keepends=True); section = None; bound = 0; ordered = 0; result = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'): section = stripped
        if section == '[Unit]' and stripped.startswith('BindsTo='):
            values = stripped.split('=', 1)[1].split()
            if OLD_WRITER not in values: raise ValueError("Original member dependency differs from reviewed binding")
            values = [guard_name(identifier) if value == OLD_WRITER else value for value in values]
            line = 'BindsTo=' + ' '.join(dict.fromkeys(values)) + '\n'; bound += 1
        elif section == '[Unit]' and stripped.startswith('After='):
            values = stripped.split('=', 1)[1].split()
            values = [guard_name(identifier) if value == OLD_WRITER else value for value in values]
            if guard_name(identifier) not in values: values.append(guard_name(identifier))
            line = 'After=' + ' '.join(dict.fromkeys(values)) + '\n'; ordered += 1
        result.append(line)
    if bound != 1 or ordered != 1 or '[Service]' not in source:
        raise ValueError("Expected one complete reviewed member unit")
    rendered = ''.join(result)
    if source.split('[Service]', 1)[1] != rendered.split('[Service]', 1)[1]:
        raise ValueError("Member service execution/configuration was changed")
    return rendered


def verify_member_observation(before, after, identifier):
    if before.get("pid", 0) <= 0 or before.get("active_state") != 'active': raise ValueError("Member was not running")
    if after.get("pid") != before["pid"] or after.get("active_state") != 'active' or after.get("restarts") != before["restarts"]:
        raise ValueError("Member core changed during dependency adoption")
    if OLD_WRITER in after.get('binds_to', []) or guard_name(identifier) not in after.get('binds_to', []):
        raise ValueError("Actual systemd dependency was not migrated")


def render_old_writer_fallback(original, previous_release_id):
    if not re.fullmatch(r'[a-f0-9]{24}', previous_release_id): raise ValueError('An immutable previous release is required')
    source = original.decode('utf-8') if isinstance(original, bytes) else original
    result = []; section = None; count = 0
    for line in source.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'): section = stripped
        if section == '[Service]' and stripped.startswith('ExecStart='):
            count += 1
            if ' -m dazzle.production ' not in stripped or not stripped.endswith(' agent'):
                raise ValueError('Unexpected original writer command')
            line = ('ExecStart=/opt/dazzle-vps/releases/' + previous_release_id +
                    '/venv/bin/python -I -m dazzle.production --policy ' + OLD_POLICY_SNAPSHOT +
                    ' --state-dir /var/lib/dazzle-vps agent\n')
        result.append(line)
    if count != 1: raise ValueError('Exactly one original writer command is required')
    return ''.join(result)


def writer_unit(release_id):
    if not re.fullmatch(r'[a-f0-9]{24}', release_id or ''): raise ValueError('An immutable release identifier is required')
    return WRITER_TEMPLATE.replace('@.service', '@' + release_id + '.service')
