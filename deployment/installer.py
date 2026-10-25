#!/usr/bin/env python3
"""Review-first, additive pilot installer. There is no legacy retirement command.

Default --preview performs no mutations. --apply/--rollback require a separate
approval JSON bound to the exact canonical review manifest, archive and baseline.
Never imports a simulation database, invokes SSH, upgrades packages, reloads UFW,
or targets legacy units. Live execution is an explicit operator action only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import grp
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import tarfile
import tempfile
import uuid

from .helper import CORE_SHA256, LEGACY_CONFIG_SHA256, Helper, HelperError, Layout, Runner, atomic_bytes, atomic_json, canonical_uuid, checked_path, read_json, validate_policy
from .release import LICENSE_FILES, PROTOBUF_VERSION, validate_wheel

PREFIX = Path("/opt/dazzle-vps")
ETC = Path("/etc/dazzle-vps")
STATE = Path("/var/lib/dazzle-vps")
UNITS = Path("/etc/systemd/system")
CONTROL = Path("/usr/local/bin/dazzle-vps-control")
RUNTIME = Path("/run/dazzle-vps")
LEGACY_UNITS = ("sing-box.service", "qqg-sub.service")
START_UNITS = ("dazzle-vps-helper.socket", "dazzle-vps-agent.service", "dazzle-vps-subscription.service", "dazzle-vps-certsync.timer")
PILOT_RULES = ((24430, "tcp"), (24430, "udp"), (24431, "tcp"), (24431, "udp"), (9443, "tcp"))
BASELINE_KEYS = {"version", "core_sha256", "legacy_config_sha256", "services", "occupied_pilot_ports", "firewall_sha256", "platform", "checked_at"}


def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
def sha256(data): return hashlib.sha256(data).hexdigest()


def run(runner, args, *, timeout=30):
    result = runner.run(args, timeout=timeout)
    if result.returncode:
        raise ValueError("An explicit project operation failed")
    return result.stdout


def capture_baseline(runner=None):
    runner = runner or Runner()
    core, config = Path("/etc/s-box/sing-box"), Path("/etc/s-box/sb.json")
    services = {}
    for unit in LEGACY_UNITS:
        output = run(runner, ["/usr/bin/systemctl", "show", unit, "--property=ActiveState,MainPID,NRestarts"])
        fields = dict(line.split("=", 1) for line in output.decode().splitlines() if "=" in line)
        services[unit] = {"active": fields["ActiveState"], "pid": int(fields["MainPID"]), "nrestarts": int(fields["NRestarts"])}
    listeners = run(runner, ["/usr/bin/ss", "-H", "-lntu"]).decode()
    occupied = []
    for port in (24430, 24431, 9443, 34430, 34431):
        if re.search(r":\b" + str(port) + r"\b", listeners): occupied.append(port)
    return {"version": 1, "core_sha256": sha256(core.read_bytes()), "legacy_config_sha256": sha256(config.read_bytes()),
            "services": services, "occupied_pilot_ports": occupied,
            "firewall_sha256": sha256(run(runner, ["/usr/sbin/ufw", "status", "numbered"])),
            "platform": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()[:4]},
            "checked_at": datetime.now(timezone.utc).isoformat()}


def validate_baseline(baseline):
    if not isinstance(baseline, dict) or set(baseline) != BASELINE_KEYS or baseline["version"] != 1:
        raise ValueError("A complete read-only baseline is required")
    if baseline["core_sha256"] != CORE_SHA256 or baseline["legacy_config_sha256"] != LEGACY_CONFIG_SHA256:
        raise ValueError("Legacy core or config does not match the reviewed pilot baseline")
    if set(baseline["services"]) != set(LEGACY_UNITS): raise ValueError("Legacy service baseline is incomplete")
    for service in baseline["services"].values():
        if set(service) != {"active", "pid", "nrestarts"} or service["active"] != "active" or type(service["pid"]) is not int or service["pid"] <= 0 or type(service["nrestarts"]) is not int or service["nrestarts"] < 0:
            raise ValueError("Legacy services must be healthy at approval")
    if baseline["occupied_pilot_ports"] != []:
        raise ValueError("A pilot or private API port is already occupied")
    if not re.fullmatch(r"[a-f0-9]{64}", str(baseline["firewall_sha256"])):
        raise ValueError("A firewall baseline digest is required")
    if baseline["platform"] not in ({"system": "Linux", "machine": "x86_64", "python": "3.12"}, {"system": "Linux", "machine": "aarch64", "python": "3.12"}):
        raise ValueError("The pilot requires the reviewed Linux Python 3.12 platform")
    return baseline


def inspect_archive(archive):
    archive = Path(archive)
    if archive.is_symlink() or not archive.is_file(): raise ValueError("A regular release archive is required")
    if archive.stat().st_size > 32 * 1024 * 1024: raise ValueError("Release archive is too large")
    payload = archive.read_bytes()
    if len(payload) > 32 * 1024 * 1024: raise ValueError("Release archive is too large")
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as source:
        for member in source.getmembers():
            path = Path(member.name)
            if not member.isfile() or path.is_absolute() or ".." in path.parts or member.name in files:
                raise ValueError("Unsafe release member")
            if member.size > 16 * 1024 * 1024 or member.size < 0:
                raise ValueError("Release member is too large")
            total += member.size
            if total > 64 * 1024 * 1024: raise ValueError("Expanded release is too large")
            if member.name not in ("release.json", "requirements.txt", *LICENSE_FILES) and not member.name.startswith(("backend/dazzle/", "deployment/", "wheelhouse/")):
                raise ValueError("Unexpected release path")
            if member.name.endswith((".sqlite3", ".pem", ".key", ".json")) and member.name != "release.json":
                raise ValueError("State or credentials cannot be included in a release")
            files[member.name] = source.extractfile(member).read()
    manifest = json.loads(files.pop("release.json"))
    if set(manifest) != {"schema_version", "release_id", "python", "architecture", "protobuf_version", "wheel_filename", "wheel_sha256", "files", "contains_production_state", "contains_real_credentials"}:
        raise ValueError("Invalid release metadata")
    inventory = {name: sha256(payload) for name, payload in sorted(files.items())}
    if manifest["files"] != inventory or manifest["release_id"] != sha256(canonical(inventory))[:24]:
        raise ValueError("Release inventory does not match its contents")
    if manifest["schema_version"] != 1 or manifest["python"] != "3.12" or manifest["protobuf_version"] != PROTOBUF_VERSION or manifest["contains_production_state"] is not False or manifest["contains_real_credentials"] is not False:
        raise ValueError("Unsupported release metadata")
    wheel_path = "wheelhouse/" + manifest["wheel_filename"]
    if wheel_path not in files or sha256(files[wheel_path]) != manifest["wheel_sha256"]:
        raise ValueError("Release wheel digest does not match")
    required = {"backend/dazzle/production.py", "backend/dazzle/production_state.py", "deployment/helper.py", "deployment/certsync.py", "deployment/control.py", "requirements.txt", *LICENSE_FILES}
    if not required.issubset(files): raise ValueError("Required production source is missing")
    expected_requirements = ("protobuf==" + PROTOBUF_VERSION + " --hash=sha256:" + manifest["wheel_sha256"] + "\n").encode()
    if files["requirements.txt"] != expected_requirements: raise ValueError("Only the pinned protobuf runtime may be installed")
    # Digest is bound to the same immutable bytes that were parsed, preventing
    # an archive swap between approval checks and copying validated contents.
    manifest["_archive_sha256"] = sha256(payload)
    return manifest, files


def review_manifest(archive, endpoint, *, baseline=None, server_id=None, admin_id=None, member_id=None):
    release, files = inspect_archive(archive)
    address = ipaddress.IPv4Address(endpoint)
    if not address.is_global: raise ValueError("A globally routable reviewed server IPv4 endpoint is required")
    endpoint = str(address)
    server_id, admin_id, member_id = [canonical_uuid(value or str(uuid.uuid4())) for value in (server_id, admin_id, member_id)]
    if len({server_id, admin_id, member_id}) != 3: raise ValueError("Deployment identities must be distinct")
    if baseline is not None:
        validate_baseline(baseline)
        if release["architecture"] != baseline["platform"]["machine"]: raise ValueError("Release target does not match server architecture")
    workers = {admin_id: {"role": "admin", "public_port": 24430, "api_port": 34430},
               member_id: {"role": "member", "public_port": 24431, "api_port": 34431}}
    templates = sorted(name.removeprefix("deployment/systemd/") for name in files if name.startswith("deployment/systemd/"))
    return {"version": 1, "operation": "parallel_pilot_install", "release_id": release["release_id"],
            "archive_sha256": release["_archive_sha256"], "server_id": server_id, "server_endpoint": endpoint,
            "workers": workers, "accounts": ["dazzle-agent", "dazzle-proxy"], "tls_group": "dazzle-vps",
            "directories": ["/opt/dazzle-vps", "/etc/dazzle-vps", "/var/lib/dazzle-vps", "/run/dazzle-vps"],
            "control_entry": str(CONTROL), "systemd_templates": templates,
            "core_copy": {"source": "/etc/s-box/sing-box", "destination": "/opt/dazzle-vps/core/sing-box", "sha256": CORE_SHA256, "replacement": False},
            "enable_units": list(START_UNITS),
            "new_ipv4_rules": [{"port": port, "protocol": protocol, "comment": f"dazzle-vps:{server_id}:{port}:{protocol}"} for port, protocol in PILOT_RULES],
            "legacy_preserved": ["TCP/UDP443", "TCP8443", "SSH22", "HTTP80", "/etc/s-box", "sing-box.service", "qqg-sub.service", "legacy certificate hook", "SSH configuration", "all existing firewall rules"],
            "baseline": baseline, "ready_for_approval": baseline is not None,
            "credentials_included": False, "automatic_legacy_retirement": False,
            "rollback_scope": "Only new units and exact added rules; preserve production state, revocations and TLS"}


def validate_approval(manifest, approval, *, operation="install"):
    required = {"version", "operation", "manifest_sha256", "approved", "approval_id"}
    if not isinstance(approval, dict) or set(approval) != required or approval["version"] != 1 or approval["operation"] != operation or approval["approved"] is not True:
        raise ValueError("A separate explicit approval is required")
    canonical_uuid(approval["approval_id"])
    if approval["manifest_sha256"] != sha256(canonical(manifest)):
        raise ValueError("Approval is not bound to this exact review manifest")
    if not manifest.get("ready_for_approval") or manifest.get("automatic_legacy_retirement") is not False:
        raise ValueError("Read-only baseline and additive-only scope must be reviewed first")


def compare_legacy(before, after):
    for key in ("core_sha256", "legacy_config_sha256", "services"):
        if before[key] != after[key]:
            raise ValueError("Legacy service PID, restart count or file digest changed; stop acceptance and investigate")


def firewall_preflight(runner, expected_sha256):
    output = run(runner, ["/usr/sbin/ufw", "status", "numbered"])
    if sha256(output) != expected_sha256:
        raise ValueError("Firewall changed since the reviewed baseline")
    text = output.decode()
    # UFW can update an existing matching rule's comment instead of adding a new
    # rule. Reject any pre-existing pilot-port mention so rollback cannot delete
    # a pre-existing allow rule whose comment was merely replaced.
    if re.search(r"(?<!\d)(?:24430|24431|9443)(?!\d)", text):
        raise ValueError("A pilot firewall rule already exists; review it separately")


def _mkdir(path, mode, *, uid=0, gid=0):
    path = Path(path)
    if path.is_symlink(): raise ValueError("Installation paths cannot be symlinks")
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    os.chmod(path, mode); os.chown(path, uid, gid)


def _system_users(runner):
    for name in ("dazzle-agent", "dazzle-proxy", "dazzle-vps"):
        try: grp.getgrnam(name)
        except KeyError: run(runner, ["/usr/sbin/groupadd", "--system", name])
    for name in ("dazzle-agent", "dazzle-proxy"):
        try: pwd.getpwnam(name)
        except KeyError:
            run(runner, ["/usr/sbin/useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--gid", name, "--groups", "dazzle-vps", name])
    return pwd.getpwnam("dazzle-agent"), pwd.getpwnam("dazzle-proxy"), grp.getgrnam("dazzle-vps")


def copy_pinned_core(source, destination, *, expected_sha256=CORE_SHA256, trusted_uid=0):
    checked_path(source, trusted_uid)
    payload = Path(source).read_bytes()
    if sha256(payload) != expected_sha256: raise ValueError("Existing core digest changed before project copy")
    if Path(destination).exists() or Path(destination).is_symlink(): raise ValueError("Project core copy already exists")
    atomic_bytes(destination, payload, mode=0o755, trusted_uid=trusted_uid)
    if sha256(Path(destination).read_bytes()) != expected_sha256 or sha256(Path(source).read_bytes()) != expected_sha256:
        raise ValueError("Project core copy did not preserve the pinned digest")


def apply_install(archive, manifest, approval, *, runner=None):
    # Every approval and content check precedes the first mutation.
    runner = runner or Runner()
    validate_approval(manifest, approval)
    actual_review = review_manifest(archive, manifest["server_endpoint"], baseline=manifest["baseline"],
                                   server_id=manifest["server_id"], admin_id=next(k for k, v in manifest["workers"].items() if v["role"] == "admin"),
                                   member_id=next(k for k, v in manifest["workers"].items() if v["role"] == "member"))
    if actual_review != manifest: raise ValueError("Review manifest does not match the release")
    if os.geteuid() != 0 or platform.system() != "Linux": raise ValueError("Approved apply must run explicitly as root on the target Linux server")
    baseline = capture_baseline(runner)
    validate_baseline(baseline)
    for key in BASELINE_KEYS - {"checked_at"}:
        if baseline[key] != manifest["baseline"][key]: raise ValueError("Target changed since the approved read-only baseline")
    firewall_preflight(runner, baseline["firewall_sha256"])
    for path in (PREFIX, ETC, STATE, RUNTIME, CONTROL):
        if path.exists() or path.is_symlink(): raise ValueError("A project path already exists; use a separately reviewed upgrade or recovery")
    for name in ("dazzle-agent", "dazzle-proxy"):
        try: pwd.getpwnam(name)
        except KeyError: continue
        raise ValueError("Project account already exists without a matching deployment receipt")
    for name in ("dazzle-agent", "dazzle-proxy", "dazzle-vps"):
        try: grp.getgrnam(name)
        except KeyError: continue
        raise ValueError("Project group already exists without a matching deployment receipt")
    release, files = inspect_archive(archive)
    if release["_archive_sha256"] != manifest["archive_sha256"] or release["release_id"] != manifest["release_id"]:
        raise ValueError("Release archive changed after the approved preview")
    for name in manifest["systemd_templates"]:
        if (UNITS / name).exists() or (UNITS / name).is_symlink(): raise ValueError("A project unit already exists")
    # A local operator may resume partial installation only after reviewing a new
    # plan. No automatic cleanup can delete persistent ledger or TLS material.
    receipt = {"version": 1, "manifest_sha256": sha256(canonical(manifest)), "server_id": manifest["server_id"],
               "release_id": release["release_id"], "approved_id": approval["approval_id"],
               "status": "installing", "added_rules": [], "enabled_units": [], "legacy_baseline": baseline}
    agent, proxy, tls = _system_users(runner)
    _mkdir(PREFIX, 0o755); _mkdir(PREFIX / "releases", 0o755)
    _mkdir(PREFIX / "core", 0o755)
    copy_pinned_core(Path("/etc/s-box/sing-box"), PREFIX / "core" / "sing-box")
    _mkdir(ETC, 0o750, gid=tls.gr_gid); _mkdir(ETC / "workers", 0o700)
    _mkdir(ETC / "tls", 0o750, gid=tls.gr_gid)
    atomic_json(ETC / "install-receipt.json", receipt)
    atomic_json(ETC / "review-manifest.json", manifest)
    atomic_json(ETC / "install-approval.json", approval)
    release_dir = PREFIX / "releases" / release["release_id"]
    _mkdir(release_dir, 0o755)
    for name, payload in files.items():
        destination = release_dir / name
        _mkdir(destination.parent, 0o755)
        atomic_bytes(destination, payload, mode=0o644)
    wheel_path = release_dir / "wheelhouse" / release["wheel_filename"]
    validate_wheel(wheel_path, release["wheel_sha256"], release["architecture"])
    run(runner, ["/usr/bin/python3", "-m", "venv", str(release_dir / "venv")], timeout=60)
    python = str(release_dir / "venv" / "bin" / "python")
    run(runner, [python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", "--no-cache-dir", "--disable-pip-version-check", "--require-hashes", "--find-links", str(release_dir / "wheelhouse"), "-r", str(release_dir / "requirements.txt")], timeout=60)
    site = release_dir / "venv" / "lib" / "python3.12" / "site-packages"
    shutil.copytree(release_dir / "backend" / "dazzle", site / "dazzle")
    shutil.copytree(release_dir / "deployment", site / "deployment", ignore=shutil.ignore_patterns("systemd"))
    run(runner, [python, "-I", "-c", "import google.protobuf; from dazzle.proto.traffic_pb2 import Status; assert google.protobuf.__version__=='7.36.2'; assert Status(uplinkTotal=9007199254740993).uplinkTotal==9007199254740993"], timeout=15)
    policy = {"version": 1, "server_id": manifest["server_id"], "server_endpoint": manifest["server_endpoint"],
              "agent_uid": agent.pw_uid, "core_sha256": CORE_SHA256, "workers": manifest["workers"]}
    atomic_bytes(ETC / "policy.json", canonical(policy) + b"\n", mode=0o640, gid=tls.gr_gid)
    atomic_json(ETC / "registry.json", {"version": 1, "server_id": manifest["server_id"], "workers": {}})
    (PREFIX / "current").symlink_to(release_dir)
    _mkdir(STATE, 0o700, uid=agent.pw_uid, gid=agent.pw_gid)
    _mkdir(RUNTIME, 0o755, gid=tls.gr_gid)
    run(runner, [python, "-I", "-m", "dazzle.production", "--policy", str(ETC / "policy.json"), "--state-dir", str(STATE), "initialize"])
    for path in STATE.iterdir():
        if path.is_symlink() or not path.is_file(): raise ValueError("Unexpected initialized state path")
        os.chown(path, agent.pw_uid, agent.pw_gid); os.chmod(path, 0o600)
    from .certsync import sync_certificate
    sync_certificate(tls_gid=tls.gr_gid)
    launcher = b'#!/bin/sh\n[ "$#" -eq 1 ] && [ "$1" = rpc ] || exit 1\nexec /opt/dazzle-vps/current/venv/bin/python -I -m deployment.control\n'
    atomic_bytes(CONTROL, launcher, mode=0o755)
    for name in manifest["systemd_templates"]:
        payload = files["deployment/systemd/" + name]
        atomic_bytes(UNITS / name, payload, mode=0o644)
    run(runner, ["/usr/bin/systemctl", "daemon-reload"])
    firewall_preflight(runner, baseline["firewall_sha256"])
    for rule in manifest["new_ipv4_rules"]:
        run(runner, ["/usr/sbin/ufw", "allow", "proto", rule["protocol"], "from", "0.0.0.0/0", "to", "any", "port", str(rule["port"]), "comment", rule["comment"]])
        receipt["added_rules"].append(rule); atomic_json(ETC / "install-receipt.json", receipt)
    for unit in START_UNITS:
        run(runner, ["/usr/bin/systemctl", "enable", "--now", unit])
        receipt["enabled_units"].append(unit); atomic_json(ETC / "install-receipt.json", receipt)
    after = capture_baseline(runner)
    compare_legacy(baseline, after)
    receipt.update(status="installed", legacy_verified=True)
    atomic_json(ETC / "install-receipt.json", receipt)
    return {"ok": True, "server_id": manifest["server_id"], "release_id": release["release_id"],
            "legacy_verified": True, "workers_started": False, "credentials_imported": False,
            "notice": "New program installed in parallel; legacy services retained; pilot users must be explicitly created"}


def rollback_plan(manifest, receipt):
    if receipt.get("server_id") != manifest.get("server_id") or receipt.get("manifest_sha256") != sha256(canonical(manifest)):
        raise ValueError("Receipt does not belong to this reviewed deployment")
    validate_policy({"version": 1, "server_id": manifest["server_id"], "server_endpoint": manifest["server_endpoint"],
                     "agent_uid": 1, "core_sha256": CORE_SHA256, "workers": manifest["workers"]})
    expected_rules = [{"port": port, "protocol": protocol, "comment": f"dazzle-vps:{manifest['server_id']}:{port}:{protocol}"} for port, protocol in PILOT_RULES]
    if manifest.get("new_ipv4_rules") != expected_rules or not isinstance(receipt.get("added_rules"), list) or any(rule not in expected_rules for rule in receipt["added_rules"]):
        raise ValueError("Rollback cannot touch rules outside this exact pilot")
    return {"version": 1, "operation": "parallel_pilot_rollback", "source_manifest_sha256": sha256(canonical(manifest)),
            "server_id": manifest["server_id"], "ready_for_approval": True, "automatic_legacy_retirement": False,
            "stop_units": ["dazzle-vps-agent.service", "dazzle-vps-helper.socket", "dazzle-vps-subscription.service", "dazzle-vps-certsync.timer", "dazzle-vps-certsync.service",
                           *[("dazzle-admin" if worker["role"] == "admin" else "dazzle-proxy") + "@" + identifier + ".service" for identifier, worker in manifest["workers"].items()]],
            "remove_exact_rules": receipt["added_rules"],
            "preserve": [str(STATE), str(ETC), str(PREFIX), "accounts", "ledger", "revocations", "mail dedup", "TLS", "all legacy services/files/rules"]}


def inactive_unit(runner, unit):
    output = run(runner, ["/usr/bin/systemctl", "show", unit, "--property=ActiveState,MainPID"])
    values = dict(line.split("=", 1) for line in output.decode().splitlines() if "=" in line)
    if values.get("ActiveState") not in {"inactive", "failed"} or values.get("MainPID") != "0":
        raise ValueError("A project unit is not confirmed inactive")


def confirm_helper_drained(runner):
    output = run(runner, ["/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", "--type=service"])
    for line in output.decode().splitlines():
        fields = line.split()
        if not fields: continue
        unit = fields[0]
        if unit.startswith("dazzle-vps-helper@") and unit.endswith(".service"):
            if not re.fullmatch(r"dazzle-vps-helper@[A-Za-z0-9_.:@\\-]+\.service", unit):
                raise ValueError("Unexpected project helper instance identity")
            inactive_unit(runner, unit)


def stop_new_runtime(manifest, plan, runner):
    """Drain callers/helpers before the final worker stop and cgroup proof."""
    run(runner, ["/usr/bin/systemctl", "stop", "dazzle-vps-agent.service"])
    inactive_unit(runner, "dazzle-vps-agent.service")
    run(runner, ["/usr/bin/systemctl", "stop", "dazzle-vps-helper.socket"])
    confirm_helper_drained(runner)
    for unit in ("dazzle-vps-subscription.service", "dazzle-vps-certsync.timer", "dazzle-vps-certsync.service"):
        run(runner, ["/usr/bin/systemctl", "stop", unit])
        if unit.endswith(".service"): inactive_unit(runner, unit)
    helper = Helper(runner=runner)
    for identifier, worker in manifest["workers"].items():
        # Derive exact targets only from root-reviewed canonical slots.
        actual = helper._stop(identifier, worker)
        if not actual["inactive"]: raise ValueError("A project worker remains active")
    for unit in START_UNITS:
        run(runner, ["/usr/bin/systemctl", "disable", unit])


def apply_rollback(manifest, receipt, approval, *, runner=None):
    runner = runner or Runner()
    plan = rollback_plan(manifest, receipt)
    validate_approval(plan, approval, operation="rollback")
    if os.geteuid() != 0 or platform.system() != "Linux": raise ValueError("Approved rollback requires root on the target Linux server")
    before = capture_baseline(runner)
    compare_legacy(receipt["legacy_baseline"], before)
    # Persist a root-only hold under the same lock as all helper mutations. A
    # previously accepted connection can no longer activate a late worker.
    with Helper().serialized():
        registry = read_json(ETC / "registry.json")
        if registry.get("server_id") != manifest["server_id"]: raise ValueError("Root registry identity mismatch")
        registry["maintenance"] = True
        atomic_json(ETC / "registry.json", registry)
    stop_new_runtime(manifest, plan, runner)
    for rule in plan["remove_exact_rules"]:
        if rule not in manifest["new_ipv4_rules"]: raise ValueError("Rollback rule is outside the approved scope")
        run(runner, ["/usr/sbin/ufw", "--force", "delete", "allow", "proto", rule["protocol"], "from", "0.0.0.0/0", "to", "any", "port", str(rule["port"]), "comment", rule["comment"]])
    compare_legacy(before, capture_baseline(runner))
    receipt.update(status="stopped_preserved", rollback_approval_id=approval["approval_id"])
    atomic_json(ETC / "install-receipt.json", receipt)
    return {"ok": True, "new_units_stopped": True, "legacy_verified": True, "persistent_state_preserved": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Preview-first additive parallel pilot installation")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--rollback", action="store_true")
    mode.add_argument("--capture-baseline", action="store_true")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--server-endpoint")
    parser.add_argument("--baseline-file", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.capture_baseline:
            result = capture_baseline()
        elif args.rollback:
            if not args.manifest or not args.receipt: raise ValueError("Rollback needs the original manifest and receipt")
            manifest, receipt = json.loads(args.manifest.read_text()), json.loads(args.receipt.read_text())
            result = apply_rollback(manifest, receipt, json.loads(args.approval.read_text())) if args.approval else rollback_plan(manifest, receipt)
        elif args.apply:
            if not args.archive or not args.manifest or not args.approval: raise ValueError("Apply requires release, exact review manifest and separate approval")
            result = apply_install(args.archive, json.loads(args.manifest.read_text()), json.loads(args.approval.read_text()))
        else:
            if not args.archive or not args.server_endpoint: raise ValueError("Preview requires a release and approved endpoint")
            baseline = json.loads(args.baseline_file.read_text()) if args.baseline_file else None
            if args.manifest:
                old = json.loads(args.manifest.read_text())
                result = review_manifest(args.archive, args.server_endpoint, baseline=baseline or old.get("baseline"), server_id=old["server_id"],
                    admin_id=next(k for k, v in old["workers"].items() if v["role"] == "admin"), member_id=next(k for k, v in old["workers"].items() if v["role"] == "member"))
            else: result = review_manifest(args.archive, args.server_endpoint, baseline=baseline)
            result = {"mode": "preview", "production_modified": False, "manifest_sha256": sha256(canonical(result)), "manifest": result}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception:
        # Do not print exception text: command responses may contain credentials.
        print(json.dumps({"ok": False, "error": "Deployment checks failed; inspect the private review inputs and preserved receipt", "legacy_retirement_available": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
