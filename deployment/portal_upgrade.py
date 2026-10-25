"""Read-only upgrade review, offline staging, and subscription-only recovery.

The upgrade review is NOT an installer. Accounts, five exact port grants,
agent/member maintenance and the service switch require the separate operator
checklist and human approval. Staging never changes current, policy or live DB.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import tempfile
import uuid

from .helper import CORE_SHA256, Runner, atomic_bytes, checked_path, read_json, validate_policy
from .installer import PREFIX, ETC, STATE, UNITS, canonical, capture_baseline, compare_legacy, run, sha256
from .portal_release import inspect_archive
from .repair import current_release, installed_inventory, original_authorization, validate_legacy
from .update import backup_digest, capture_administrator, check_additive_migration

NEW_PUBLIC_PORTS = tuple(range(24432, 24437))
NEW_API_PORTS = tuple(range(34432, 34437))
PORTAL_SOCKET = "/run/dazzle-vps-portal/agent.sock"
PORTAL_TLS = "/etc/dazzle-vps/web-tls"
PORTAL_SERVICE = "dazzle-vps-subscription.service"


def expanded_policy(previous, portal_uid):
    previous = validate_policy(copy.deepcopy(previous))
    if previous["version"] != 1 or len(previous["workers"]) != 2 or {worker["role"] for worker in previous["workers"].values()} != {"admin", "member"}:
        raise ValueError("The reviewed two-worker original policy is required")
    result = copy.deepcopy(previous)
    result.update(version=2, portal_uid=portal_uid)
    for public, api in zip(NEW_PUBLIC_PORTS, NEW_API_PORTS):
        identifier = str(uuid.uuid5(uuid.UUID(result["server_id"]), "portal-member:" + str(public)))
        if identifier in result["workers"] or identifier == result["server_id"]:
            raise ValueError("A new resource identity collides with existing state")
        result["workers"][identifier] = {"role": "member", "public_port": public, "api_port": api}
    return validate_policy(result)


def render_templates(policy, files):
    policy = validate_policy(policy)
    if policy["version"] != 2: raise ValueError("Portal services require reviewed v2 policy")
    replacements = {"@ORIGIN@": "https://" + policy["server_endpoint"] + ":9443"}
    result = {}
    for source, destination in (
        ("subscription.service", "/etc/systemd/system/dazzle-vps-subscription.service"),
        ("agent.conf", "/etc/systemd/system/dazzle-vps-agent.service.d/portal.conf"),
        ("certsync.conf", "/etc/systemd/system/dazzle-vps-certsync.service.d/portal.conf"),
        ("tmpfiles.conf", "/etc/tmpfiles.d/dazzle-vps-portal.conf"),
    ):
        body = files["deployment/portal-systemd/" + source].decode()
        for key, value in replacements.items(): body = body.replace(key, value)
        if re.search(r"@[A-Z_]+@", body): raise ValueError("Unresolved service template variable")
        result[destination] = body
    return result


def capture_portal_baseline(policy, portal_uid, *, runner=None):
    runner = runner or Runner()
    legacy = capture_baseline(runner)
    listeners = run(runner, ["/usr/bin/ss", "-H", "-lntu"]).decode()
    firewall = run(runner, ["/usr/sbin/ufw", "status", "numbered"]).decode()
    occupied = [port for port in (*NEW_PUBLIC_PORTS, *NEW_API_PORTS) if re.search(r":" + str(port) + r"(?:\s|$)", listeners)]
    def available(lookup, key):
        try: lookup(key); return False
        except KeyError: return True
    memory = Path("/proc/meminfo").read_text()
    match = re.search(r"^MemAvailable:\s+(\d+)\s+kB$", memory, re.M)
    return {"version": 1, "legacy": legacy, "administrator": capture_administrator(policy, runner),
            "occupied_new_ports": occupied, "portal_uid_available": available(pwd.getpwuid, portal_uid),
            "existing_new_port_rules": [port for port in NEW_PUBLIC_PORTS if re.search(r"(?<!\d)" + str(port) + r"(?!\d)", firewall)],
            "portal_gid_available": available(grp.getgrgid, portal_uid),
            "portal_account_name_available": available(pwd.getpwnam, "dazzle-web"),
            "portal_group_name_available": available(grp.getgrnam, "dazzle-web"),
            "memory_available_kib": int(match[1]) if match else None,
            "provider_network_verified": False, "provider_network_evidence": None,
            "checked_at": datetime.now(timezone.utc).isoformat()}


def _baseline_issues(baseline, release):
    if not isinstance(baseline, dict): return ["Fresh target read-only baseline is missing"]
    validate_legacy(baseline.get("legacy", {}))
    issues = []
    if baseline.get("version") != 1: issues.append("Unsupported portal baseline")
    if baseline.get("occupied_new_ports") != []: issues.append("New public or loopback API port is occupied")
    if baseline.get("existing_new_port_rules"): issues.append("Matching firewall rules already exist; review them without relabelling or deleting existing rules")
    for name in ("portal_uid_available", "portal_gid_available", "portal_account_name_available", "portal_group_name_available"):
        if baseline.get(name) is not True: issues.append("Portal account/group identity must be unused: " + name)
    if type(baseline.get("memory_available_kib")) is not int or baseline["memory_available_kib"] < 262144:
        issues.append("At least 256MiB currently available memory must be confirmed")
    if baseline.get("provider_network_verified") is not True or not baseline.get("provider_network_evidence"):
        issues.append("Provider network/security-group conditions are unverified; no provider settings will be changed")
    platform_info = baseline["legacy"].get("platform", {})
    if platform_info.get("machine") != release["architecture"] or platform_info.get("python") != "3.12" or platform_info.get("system") != "Linux":
        issues.append("Release architecture/Python does not match target")
    if not baseline.get("administrator") or any(row.get("active") != "active" or row.get("pid", 0) <= 0 for row in baseline["administrator"].values()):
        issues.append("The existing administrator worker must remain active")
    return issues


def preview_upgrade(archive, backup, backup_sha256, portal_uid, *, prefix=PREFIX, etc=ETC, state_dir=STATE,
                    baseline=None, runner=None, trusted_uid=0):
    runner = runner or Runner()
    previous = current_release(prefix, trusted_uid)
    installed = installed_inventory(previous, trusted_uid)
    receipt, authorization, policy = original_authorization(etc, trusted_uid)
    expanded = expanded_policy(policy, portal_uid)
    release, files = inspect_archive(archive)
    backup_digest(backup, backup_sha256, state_dir=state_dir, trusted_uid=trusted_uid)
    baseline = baseline if baseline is not None else capture_portal_baseline(policy, portal_uid, runner=runner)
    issues = _baseline_issues(baseline, release)
    templates = render_templates(expanded, files)
    added = {key: worker for key, worker in expanded["workers"].items() if key not in policy["workers"]}
    return {"version": 1, "operation": "portal_resource_upgrade", "ready_for_approval": not issues,
            "issues": issues, "server_id": policy["server_id"], "original_authorization_id": authorization["approval_id"],
            "original_manifest_sha256": receipt["manifest_sha256"], "previous_release_id": previous.name,
            "new_release_id": release["release_id"], "archive_sha256": release["_archive_sha256"],
            "current_inventory_sha256": sha256(canonical(installed)), "previous_policy_sha256": sha256(canonical(policy)),
            "expanded_policy": expanded, "new_workers": added,
            "new_account": {"name": "dazzle-web", "uid": portal_uid, "gid": portal_uid, "shell": "/usr/sbin/nologin", "home": "/nonexistent", "supplementary_groups": []},
            "new_firewall_rules": [{"port": port, "protocol": protocol, "comment": f"dazzle-portal:{policy['server_id']}:{port}:{protocol}"} for port in NEW_PUBLIC_PORTS for protocol in ("tcp", "udp")],
            "loopback_only_ports": list(NEW_API_PORTS), "public_https_port": 9443,
            "directories": [{"path": "/run/dazzle-vps-portal", "owner": "dazzle-agent", "group": "dazzle-web", "mode": "2750"},
                            {"path": PORTAL_TLS, "owner": "root", "group": "dazzle-web", "mode": "0750"}],
            "service_files": templates, "portal_socket": PORTAL_SOCKET,
            "backup": {"path": str(Path(backup).resolve()), "sha256": backup_sha256, "automatic_restore": False},
            "baseline": baseline, "registration_initially_enabled": False,
            "member_maintenance": {"required": True, "reason": "Existing member BindsTo agent: restarting the agent stops member workers",
                                   "approval_required": True, "record_original_states": True, "restore_only_unchanged_authorized_users": True},
            "preserve": ["old443/8443 and administrator PIDs", "SSH/settings/keys", "all pre-existing firewall rules", "core binary", "worker UUID/port bindings", "ledger and revocation/deletion tombstones", "current valid certificates", "existing subscriptions"],
            "changed_source_files": [{"path": name, "old_sha256": installed.get(name), "new_sha256": release["files"].get(name)} for name in sorted(set(installed) | set(release["files"])) if installed.get(name) != release["files"].get(name)],
            "production_database_opened": False, "services_started": False, "automatic_firewall_mutation": False,
            "automatic_legacy_retirement": False, "apply_mode": "offline_staging_only; reviewed operator checklist required for live switch"}


def validate_approval(preview, approval):
    fields = {"version", "operation", "approved", "approval_id", "preview_sha256", "member_maintenance_approved"}
    if not isinstance(approval, dict) or set(approval) != fields or approval["version"] != 1 or approval["operation"] != preview.get("operation") or approval["approved"] is not True:
        raise ValueError("Separate explicit portal approval is required")
    if str(uuid.UUID(approval["approval_id"])) != approval["approval_id"] or approval["preview_sha256"] != sha256(canonical(preview)) or not preview.get("ready_for_approval"):
        raise ValueError("Approval must bind the exact ready preview")
    if preview["operation"] == "portal_resource_upgrade" and approval["member_maintenance_approved"] is not True:
        raise ValueError("The known member maintenance interruption requires explicit approval")


def stage_upgrade(archive, preview, approval, *, prefix=PREFIX, etc=ETC, state_dir=STATE, runner=None, trusted_uid=0):
    validate_approval(preview, approval)
    if preview.get("operation") != "portal_resource_upgrade": raise ValueError("Wrong approval operation")
    if os.geteuid() != 0 or platform.system() != "Linux": raise ValueError("Explicit target root staging is required")
    runner = runner or Runner()
    fresh = preview_upgrade(archive, preview["backup"]["path"], preview["backup"]["sha256"], preview["expanded_policy"]["portal_uid"],
                            prefix=prefix, etc=etc, state_dir=state_dir, baseline=preview["baseline"], runner=runner, trusted_uid=trusted_uid)
    if fresh != preview: raise ValueError("Reviewed upgrade inputs changed")
    current_baseline = capture_baseline(runner)
    compare_legacy(preview["baseline"]["legacy"], current_baseline)
    if current_baseline["firewall_sha256"] != preview["baseline"]["legacy"]["firewall_sha256"]:
        raise ValueError("Firewall changed since review; nothing was automatically modified")
    if capture_administrator(preview["expanded_policy"], runner) != preview["baseline"]["administrator"]:
        raise ValueError("Administrator process changed since review")
    release, files = inspect_archive(archive)
    destination = Path(prefix) / "releases" / release["release_id"]
    checked_path(destination.parent, trusted_uid, directory=True)
    if destination.exists() or destination.is_symlink(): raise ValueError("Keep and inspect any existing partial stage")
    destination.mkdir(mode=0o755)
    for name, body in files.items():
        path = destination / name; path.parent.mkdir(parents=True, exist_ok=True)
        atomic_bytes(path, body, mode=0o644, trusted_uid=trusted_uid)
    atomic_bytes(destination / "release.json", json.dumps({k: v for k, v in release.items() if not k.startswith('_')}, sort_keys=True, indent=2).encode() + b"\n", mode=0o644, trusted_uid=trusted_uid)
    run(runner, ["/usr/bin/python3", "-m", "venv", str(destination / "venv")])
    run(runner, [str(destination / "venv/bin/python"), "-I", "-m", "pip", "install", "--no-index", "--only-binary=:all:", "--require-hashes", "--find-links", str(destination / "wheelhouse"), "-r", str(destination / "requirements.txt")], timeout=60)
    site = destination / "venv/lib/python3.12/site-packages"
    shutil.copytree(destination / "backend/dazzle", site / "dazzle")
    shutil.copytree(destination / "deployment", site / "deployment", ignore=shutil.ignore_patterns("systemd", "portal-systemd"))
    result = check_additive_migration(destination, preview["backup"]["path"], preview["expanded_policy"], runner)
    backup_digest(preview["backup"]["path"], preview["backup"]["sha256"], state_dir=state_dir, trusted_uid=trusted_uid)
    after = capture_baseline(runner)
    compare_legacy(current_baseline, after)
    if after["firewall_sha256"] != current_baseline["firewall_sha256"] or capture_administrator(preview["expanded_policy"], runner) != preview["baseline"]["administrator"]:
        raise ValueError("Protected runtime changed during offline staging; retain the stage and investigate")
    return {"ok": True, "staged_release_id": release["release_id"], "additive_migration": result,
            "current_switched": False, "production_database_opened": False, "accounts_created": False,
            "firewall_modified": False, "services_started": False,
            "notice": "Only an immutable offline stage was created. Follow the separately approved maintenance checklist for policy/accounts/service switch."}


def rollback_preview(policy):
    policy = validate_policy(copy.deepcopy(policy))
    if policy["version"] != 2: raise ValueError("Subscription-only recovery requires portal v2")
    origin = "https://" + policy["server_endpoint"] + ":9443"
    body = "[Service]\nExecStart=\nExecStart=/opt/dazzle-vps/current/venv/bin/python -I -m dazzle.portal --socket " + PORTAL_SOCKET + " --host 0.0.0.0 --port 9443 --cert " + PORTAL_TLS + "/cert.pem --key " + PORTAL_TLS + "/key.pem --origin " + origin + " --subscription-only\n"
    return {"version": 1, "operation": "portal_subscription_only", "ready_for_approval": True,
            "server_id": policy["server_id"], "policy_sha256": sha256(canonical(policy)),
            "dropin_path": "/etc/systemd/system/dazzle-vps-subscription.service.d/subscription-only.conf", "dropin": body,
            "restart_units": [PORTAL_SERVICE], "public_registration_and_login": False,
            "preserve": ["all active proxies", "subscription URLs", "agent and metering", "worker pool/policy", "ledger", "revocations", "SSH", "firewall", "TLS"],
            "database_restore": False, "agent_restart": False}


def apply_rollback(preview, approval, *, etc=ETC, units=UNITS, runner=None, trusted_uid=0):
    validate_approval(preview, approval)
    if preview.get("operation") != "portal_subscription_only": raise ValueError("Wrong recovery operation")
    if os.geteuid() != 0 or platform.system() != "Linux": raise ValueError("Explicit target root recovery is required")
    policy = validate_policy(read_json(Path(etc) / "policy.json", trusted_uid))
    if rollback_preview(policy) != preview: raise ValueError("Recovery policy changed since review")
    runner = runner or Runner()
    directory = Path(units) / (PORTAL_SERVICE + ".d")
    if directory.is_symlink(): raise ValueError("Unsafe service override directory")
    directory.mkdir(mode=0o755, exist_ok=True)
    target = directory / "subscription-only.conf"
    if target.exists() or target.is_symlink():
        checked_path(target, trusted_uid)
        if target.read_bytes() != preview["dropin"].encode():
            raise ValueError("An unrelated subscription-only override already exists; preserve and review it")
    atomic_bytes(target, preview["dropin"].encode(), mode=0o644, trusted_uid=trusted_uid)
    run(runner, ["/usr/bin/systemctl", "daemon-reload"])
    run(runner, ["/usr/bin/systemctl", "restart", PORTAL_SERVICE])
    return {"ok": True, "public_registration_and_login": False, "agent_restarted": False,
            "proxy_workers_restarted": False, "database_restored": False, "firewall_modified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review-only portal expansion and exact-approved offline staging/recovery")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--database-backup", type=Path)
    parser.add_argument("--backup-sha256")
    parser.add_argument("--portal-uid", type=int)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--stage", type=Path, help="Exact saved upgrade preview; requires --approval")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--approval", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.rollback:
            preview = rollback_preview(read_json(ETC / "policy.json"))
            result = apply_rollback(preview, json.loads(args.approval.read_text())) if args.approval else {"mode": "preview", "preview_sha256": sha256(canonical(preview)), "preview": preview}
        elif args.stage:
            if not args.archive or not args.approval: raise ValueError("Staging needs an archive, saved preview and explicit approval")
            result = stage_upgrade(args.archive, json.loads(args.stage.read_text()), json.loads(args.approval.read_text()))
        else:
            if not args.archive or not args.database_backup or not args.backup_sha256 or not args.portal_uid: raise ValueError("Missing review inputs")
            preview = preview_upgrade(args.archive, args.database_backup, args.backup_sha256, args.portal_uid, baseline=json.loads(args.baseline.read_text()) if args.baseline else None)
            result = {"mode": "preview", "production_modified": False, "preview_sha256": sha256(canonical(preview)), "preview": preview}
        print(json.dumps(result, ensure_ascii=False, indent=2)); return 0
    except Exception:
        print(json.dumps({"ok": False, "error": "Portal review/staging/recovery validation failed; no automatic database restore or legacy retirement exists"})); return 1


if __name__ == "__main__": raise SystemExit(main())
