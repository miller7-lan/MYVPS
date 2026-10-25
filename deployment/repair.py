#!/usr/bin/env python3
"""Minimal program-only repair under the original parallel-install authorization.

The operator first preserves damaged WAL/SHM and stops ONLY new agent,
subscription and helper socket. This tool never opens the production database,
edits units/policy/registry/TLS/firewall/accounts, or starts/stops services.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import uuid

from .helper import CORE_SHA256, LEGACY_CONFIG_SHA256, Runner, atomic_bytes, atomic_json, checked_path, read_json, validate_policy
from .installer import (PREFIX, ETC, canonical, capture_baseline, compare_legacy,
                        confirm_helper_drained, inactive_unit, inspect_archive, run, sha256)
from .release import LICENSE_FILES, validate_wheel

SCOPE = {"backend/dazzle/store.py", "deployment/repair.py", "deployment/release.py"}
QUIESCENT_UNITS = ("dazzle-vps-agent.service", "dazzle-vps-subscription.service", "dazzle-vps-helper.socket")


def current_release(prefix, trusted_uid=0):
    prefix = Path(prefix)
    checked_path(prefix, trusted_uid, directory=True)
    current = prefix / "current"
    info = current.lstat()
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != trusted_uid:
        raise ValueError("Current release must be a root-controlled symlink")
    target = current.resolve(strict=True)
    if target.parent != (prefix / "releases").resolve() or not re.fullmatch(r"[a-f0-9]{24}", target.name):
        raise ValueError("Current release is outside the immutable project release directory")
    checked_path(target, trusted_uid, directory=True)
    return target


def installed_inventory(release_dir, trusted_uid=0):
    inventory = {}
    for relative in ("backend/dazzle", "deployment", "wheelhouse", "third_party"):
        parent = release_dir / relative
        if not parent.is_dir(): raise ValueError("Installed source inventory is incomplete")
        for path in sorted(parent.rglob("*")):
            if "__pycache__" in path.parts: continue
            if path.is_symlink(): raise ValueError("Installed source inventory contains a symlink")
            if path.is_file():
                checked_path(path, trusted_uid)
                name = path.relative_to(release_dir).as_posix()
                inventory[name] = sha256(path.read_bytes())
    requirements = release_dir / "requirements.txt"
    checked_path(requirements, trusted_uid)
    inventory["requirements.txt"] = sha256(requirements.read_bytes())
    # Executed site-packages must agree with the separately retained source.
    site = release_dir / "venv" / "lib" / "python3.12" / "site-packages"
    for name, digest in inventory.items():
        installed = None
        if name.startswith("backend/dazzle/") and name.endswith((".py", ".proto")):
            installed = site / name.removeprefix("backend/")
        elif name.startswith("deployment/") and name.endswith(".py") and "/systemd/" not in name:
            installed = site / name
        if installed is not None:
            checked_path(installed, trusted_uid)
            if sha256(installed.read_bytes()) != digest:
                raise ValueError("Installed executable source differs from the release inventory")
    return inventory


def original_authorization(etc, trusted_uid=0):
    receipt = read_json(Path(etc) / "install-receipt.json", trusted_uid)
    authorization = read_json(Path(etc) / "install-approval.json", trusted_uid)
    manifest = read_json(Path(etc) / "review-manifest.json", trusted_uid)
    policy = validate_policy(read_json(Path(etc) / "policy.json", trusted_uid))
    if authorization.get("version") != 1 or authorization.get("operation") != "install" or authorization.get("approved") is not True:
        raise ValueError("The original approved parallel-install authorization is required")
    digest = sha256(canonical(manifest))
    if receipt.get("status") != "installed" or authorization.get("manifest_sha256") != digest or receipt.get("manifest_sha256") != digest:
        raise ValueError("Original install authorization and receipt do not match")
    if receipt.get("approved_id") != authorization.get("approval_id") or receipt.get("server_id") != policy["server_id"]:
        raise ValueError("Original authorization identity does not match this installation")
    return receipt, authorization, policy


def validate_legacy(baseline):
    if baseline.get("core_sha256") != CORE_SHA256 or baseline.get("legacy_config_sha256") != LEGACY_CONFIG_SHA256:
        raise ValueError("Legacy baseline changed")
    for unit in ("sing-box.service", "qqg-sub.service"):
        row = baseline["services"][unit]
        if row["active"] != "active" or row["pid"] <= 0:
            raise ValueError("Legacy services must remain healthy during repair")


def preview_repair(archive, *, prefix=PREFIX, etc=ETC, runner=None, trusted_uid=0, baseline=None):
    runner = runner or Runner()
    old = current_release(prefix, trusted_uid)
    installed = installed_inventory(old, trusted_uid)
    release, files = inspect_archive(archive)
    receipt, authorization, policy = original_authorization(etc, trusted_uid)
    baseline = baseline if baseline is not None else capture_baseline(runner)
    validate_legacy(baseline)
    differences = [{"path": name, "old_sha256": installed.get(name), "new_sha256": release["files"].get(name)}
                   for name in sorted(set(installed) | set(release["files"]))
                   if installed.get(name) != release["files"].get(name)]
    unexpected = [row["path"] for row in differences if row["path"] not in SCOPE]
    if release["release_id"] == old.name: raise ValueError("Repair release must be a new immutable version")
    if baseline["platform"]["machine"] != release["architecture"] or baseline["platform"]["python"] != "3.12":
        raise ValueError("Repair runtime does not match the installed platform")
    return {"version": 1, "operation": "parallel_program_lock_repair", "server_id": policy["server_id"],
            "original_authorization_id": authorization["approval_id"], "original_manifest_sha256": receipt["manifest_sha256"],
            "previous_release_id": old.name, "new_release_id": release["release_id"],
            "archive_sha256": release["_archive_sha256"], "changed_files": differences,
            "unexpected_changes": unexpected, "ready": not unexpected,
            "required_inactive_units": list(QUIESCENT_UNITS),
            "legacy_baseline": baseline, "current_inventory_sha256": sha256(canonical(installed)),
            "preserve": ["production database/WAL/SHM", "root registry/revocations", "policy", "units", "TLS", "core copy", "firewall", "accounts", "previous release", "legacy services"],
            "database_opened": False, "services_started": False, "automatic_rollback": False}


def confirm_quiescent(runner):
    for unit in QUIESCENT_UNITS[:2]: inactive_unit(runner, unit)
    output = run(runner, ["/usr/bin/systemctl", "show", "dazzle-vps-helper.socket", "--property=ActiveState"])
    if output.decode().strip() != "ActiveState=inactive":
        raise ValueError("New helper socket must be stopped before repair")
    confirm_helper_drained(runner)


def stage_release(release, files, destination, runner, trusted_uid=0):
    destination.mkdir(mode=0o755)
    for name, payload in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        atomic_bytes(target, payload, mode=0o644, trusted_uid=trusted_uid)
    wheel = destination / "wheelhouse" / release["wheel_filename"]
    validate_wheel(wheel, release["wheel_sha256"], release["architecture"])
    run(runner, ["/usr/bin/python3", "-m", "venv", str(destination / "venv")], timeout=60)
    python = str(destination / "venv" / "bin" / "python")
    run(runner, [python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", "--no-cache-dir", "--disable-pip-version-check",
                 "--require-hashes", "--find-links", str(destination / "wheelhouse"), "-r", str(destination / "requirements.txt")], timeout=60)
    site = destination / "venv" / "lib" / "python3.12" / "site-packages"
    shutil.copytree(destination / "backend" / "dazzle", site / "dazzle")
    shutil.copytree(destination / "deployment", site / "deployment", ignore=shutil.ignore_patterns("systemd"))
    # Only temporary SQLite state is opened; the production path is absent.
    check = ("import tempfile,google.protobuf; from dazzle.store import Store; from dazzle import production,collector; "
             "assert google.protobuf.__version__=='7.36.2'; "
             "temporary=tempfile.TemporaryDirectory(); a=Store(temporary.name); b=Store(temporary.name); "
             "assert a.conn.execute('PRAGMA quick_check').fetchone()[0]=='ok'; "
             "a.close(); b.close(); temporary.cleanup()")
    run(runner, [python, "-I", "-c", check], timeout=20)
    installed_inventory(destination, trusted_uid)


def atomic_current(prefix, destination, *, expected_previous, trusted_uid=0):
    prefix, destination = Path(prefix), Path(destination)
    if current_release(prefix, trusted_uid) != Path(expected_previous):
        raise ValueError("Current release changed since repair preview")
    temporary = prefix / (".current-" + uuid.uuid4().hex)
    try:
        temporary.symlink_to(destination)
        os.replace(temporary, prefix / "current")
        descriptor = os.open(prefix, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally:
        if temporary.is_symlink(): temporary.unlink()


def apply_repair(archive, preview, confirm_preview_sha256, *, prefix=PREFIX, etc=ETC, runner=None, trusted_uid=0):
    runner = runner or Runner()
    if confirm_preview_sha256 != sha256(canonical(preview)) or not preview.get("ready"):
        raise ValueError("The operator must confirm the exact ready repair preview hash")
    if os.geteuid() != 0 or platform.system() != "Linux":
        raise ValueError("Repair apply is target-root only")
    fresh = preview_repair(archive, prefix=prefix, etc=etc, runner=runner, trusted_uid=trusted_uid, baseline=preview["legacy_baseline"])
    if fresh != preview:
        raise ValueError("Repair inputs changed after preview")
    before = capture_baseline(runner)
    validate_legacy(before)
    compare_legacy(preview["legacy_baseline"], before)
    if before["firewall_sha256"] != preview["legacy_baseline"]["firewall_sha256"]:
        raise ValueError("Firewall changed after repair preview")
    confirm_quiescent(runner)
    release, files = inspect_archive(archive)
    if release["_archive_sha256"] != preview["archive_sha256"]:
        raise ValueError("Repair archive changed after review")
    previous = current_release(prefix, trusted_uid)
    destination = Path(prefix) / "releases" / release["release_id"]
    if destination.exists() or destination.is_symlink():
        raise ValueError("Repair target already exists; inspect the retained partial version")
    receipt = {"version": 1, "operation": preview["operation"], "original_authorization_id": preview["original_authorization_id"],
               "review_sha256": confirm_preview_sha256, "previous_release_id": previous.name,
               "new_release_id": release["release_id"], "changed_files": preview["changed_files"],
               "status": "staging", "database_modified": False, "services_started": False,
               "at": datetime.now(timezone.utc).isoformat()}
    receipts = Path(etc) / "repairs"
    if receipts.is_symlink(): raise ValueError("Repair receipt directory cannot be a symlink")
    receipts.mkdir(mode=0o700, exist_ok=True)
    checked_path(receipts, trusted_uid, directory=True)
    receipt_path = receipts / (release["release_id"] + ".json")
    atomic_json(receipt_path, receipt, trusted_uid)
    stage_release(release, files, destination, runner, trusted_uid)
    confirm_quiescent(runner)
    atomic_current(prefix, destination, expected_previous=previous, trusted_uid=trusted_uid)
    receipt["status"] = "switched_services_still_stopped"
    atomic_json(receipt_path, receipt, trusted_uid)
    compare_legacy(before, capture_baseline(runner))
    return {"ok": True, "previous_release_id": previous.name, "current_release_id": destination.name,
            "database_modified": False, "services_started": False,
            "notice": "Program switched only. Operator must separately start the already-approved new services and verify state."}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Original-authorization-bound program-only lock repair")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--preview", type=Path, help="Saved inner repair preview for apply")
    parser.add_argument("--confirm-preview-sha256")
    args = parser.parse_args(argv)
    try:
        if args.apply:
            if not args.preview or not args.confirm_preview_sha256: raise ValueError()
            result = apply_repair(args.archive, json.loads(args.preview.read_text()), args.confirm_preview_sha256)
        else:
            preview = preview_repair(args.archive)
            result = {"mode": "preview", "production_modified": False, "preview_sha256": sha256(canonical(preview)), "preview": preview}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception:
        print(json.dumps({"ok": False, "error": "Program-only repair checks failed; previous program and state were not automatically rolled back"}))
        return 1


if __name__ == "__main__": raise SystemExit(main())
