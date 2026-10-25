#!/usr/bin/env python3
"""Reviewed program-only update; production state is never opened or restored.

The operator first pauses control RPC, disables the maintenance member through
the existing RPC, stops only the new agent/subscription/helper, and makes an
immutable SQLite backup. This tool tests additive migrations on a private copy
of that backup, then switches the immutable program release. Starting the new
services and selectively restoring the maintenance member remain explicit
operator actions. Administrator and legacy proxy processes must stay intact.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import tempfile

from .helper import Runner, atomic_json, checked_path
from .installer import PREFIX, ETC, STATE, canonical, capture_baseline, compare_legacy, inspect_archive, run, sha256
from .repair import (atomic_current, confirm_quiescent, current_release,
                     installed_inventory, original_authorization, stage_release, validate_legacy)

PURPOSE = "mail_and_user_delete"
TOOLS = {"deployment/update.py", "deployment/release.py"}
PYTHON_SOURCE = re.compile(r"backend/dazzle/(?:[A-Za-z_][A-Za-z0-9_]*/)*[A-Za-z_][A-Za-z0-9_]*\.py\Z")

# Executed solely by the new release's isolated interpreter, on a temporary copy
# of an operator-provided backup. It neither imports the agent loop nor opens
# the production database, helper socket, SMTP transport or a public listener.
CHECK_ADDITIVE = r'''
import json,pathlib,sqlite3,sys
from dazzle.production_state import ProductionStore
backup,policy_path,folder=map(pathlib.Path,sys.argv[1:])
policy=json.loads(policy_path.read_text())
source=sqlite3.connect(backup.resolve().as_uri()+"?mode=ro",uri=True)
target=sqlite3.connect(folder/"state.sqlite3")
try: source.backup(target)
finally: source.close();target.close()
store=ProductionStore(folder,policy=policy)
store.close()
after=sqlite3.connect(folder/"state.sqlite3",uri=True)
try:
 after.execute("ATTACH DATABASE ? AS prior",(backup.resolve().as_uri()+"?mode=ro",))
 if after.execute("PRAGMA main.quick_check").fetchone()[0]!="ok":raise ValueError("Integrity failure")
 def q(value):return '"'+value.replace('"','""')+'"'
 tables=[r[0] for r in after.execute("SELECT name FROM prior.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
 preserved=0
 for table in tables:
  old=list(after.execute("PRAGMA prior.table_info("+q(table)+")"))
  new={r[1]:r for r in after.execute("PRAGMA main.table_info("+q(table)+")")}
  if any(r[1] not in new or tuple(r[1:])!=tuple(new[r[1]][1:]) for r in old):raise ValueError("Existing column changed")
  columns=[r[1] for r in old]
  projection=','.join(q(c)+' AS v'+str(i) for i,c in enumerate(columns))
  group=','.join(q(c) for c in columns)
  old_group='SELECT '+projection+',COUNT(*) AS preserved_n FROM prior.'+q(table)+' GROUP BY '+group
  new_group='SELECT '+projection+',COUNT(*) AS preserved_n FROM main.'+q(table)+' GROUP BY '+group
  on=' AND '.join('a.v'+str(i)+' IS b.v'+str(i) for i in range(len(columns)))
  missing='SELECT 1 FROM ('+old_group+') a LEFT JOIN ('+new_group+') b ON '+on+' WHERE b.preserved_n IS NULL OR b.preserved_n<a.preserved_n LIMIT 1'
  if after.execute(missing).fetchone():raise ValueError("Existing rows changed or removed")
  preserved+=after.execute('SELECT COUNT(*) FROM prior.'+q(table)).fetchone()[0]
 old_objects=list(after.execute("SELECT type,name,sql FROM prior.sqlite_master WHERE type IN ('index','view','trigger') AND sql IS NOT NULL"))
 for kind,name,sql in old_objects:
  if after.execute("SELECT sql FROM main.sqlite_master WHERE type=? AND name=?",(kind,name)).fetchone()!=(sql,):raise ValueError("Existing schema object changed")
 if after.execute("PRAGMA main.foreign_key_check").fetchone():raise ValueError("Foreign key failure")
 print(json.dumps({"ok":True,"old_tables_preserved":len(tables),"old_rows_preserved":preserved,"production_database_opened":False}))
finally:after.close()
'''


def backup_digest(path, expected, *, state_dir=STATE, trusted_uid=0):
    path = Path(path)
    if not re.fullmatch(r"[a-f0-9]{64}", expected or ""):
        raise ValueError("An explicit immutable backup SHA256 is required")
    parent = checked_path(path.parent, trusted_uid, directory=True)
    info = checked_path(path, trusted_uid)
    if parent.st_mode & 0o077 or info.st_mode & 0o077 or Path(state_dir).resolve() in path.resolve().parents:
        raise ValueError("Backup must be private, separate from production state, and operator owned")
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise ValueError("Backup must be a self-contained SQLite snapshot without sidecars")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): digest.update(block)
    if digest.hexdigest() != expected:
        raise ValueError("Immutable backup changed")
    return expected


def capture_administrator(policy, runner):
    result = {}
    for identifier, worker in policy["workers"].items():
        if worker["role"] != "admin": continue
        unit = "dazzle-admin@" + identifier + ".service"
        raw = run(runner, ["/usr/bin/systemctl", "show", unit, "--property=ActiveState,MainPID,NRestarts"])
        fields = dict(line.split("=", 1) for line in raw.decode().splitlines() if "=" in line)
        result[unit] = {"active": fields["ActiveState"], "pid": int(fields["MainPID"]), "nrestarts": int(fields["NRestarts"])}
    if not result or any(row["active"] != "active" or row["pid"] <= 0 for row in result.values()):
        raise ValueError("Existing administrator worker must remain active during update")
    return result


def preserved_root_files(etc, trusted_uid):
    result = {}
    for name in ("policy.json", "registry.json", "install-approval.json", "install-receipt.json", "review-manifest.json"):
        path = Path(etc) / name
        checked_path(path, trusted_uid)
        result[name] = sha256(path.read_bytes())
    return result


def preview_update(archive, backup, backup_sha256, *, prefix=PREFIX, etc=ETC,
                   state_dir=STATE, runner=None, trusted_uid=0, baseline=None, admin_baseline=None):
    runner = runner or Runner()
    old = current_release(prefix, trusted_uid)
    installed = installed_inventory(old, trusted_uid)
    release, _ = inspect_archive(archive)
    receipt, authorization, policy = original_authorization(etc, trusted_uid)
    backup_digest(backup, backup_sha256, state_dir=state_dir, trusted_uid=trusted_uid)
    baseline = baseline if baseline is not None else capture_baseline(runner)
    validate_legacy(baseline)
    admin = admin_baseline if admin_baseline is not None else capture_administrator(policy, runner)
    differences = [{"path": name, "old_sha256": installed.get(name), "new_sha256": release["files"].get(name)}
                   for name in sorted(set(installed) | set(release["files"]))
                   if installed.get(name) != release["files"].get(name)]
    # Pure Python controller changes are reviewable. Deleting a module, changing
    # protocol definitions, root helper, units, wheel or requirements is not.
    unexpected = [row["path"] for row in differences if row["new_sha256"] is None or
                  (row["path"] not in TOOLS and not PYTHON_SOURCE.fullmatch(row["path"]))]
    if release["release_id"] == old.name or not differences:
        raise ValueError("Update must be a distinct immutable program release")
    if baseline["platform"]["machine"] != release["architecture"] or baseline["platform"]["python"] != "3.12":
        raise ValueError("Update runtime does not match the installed platform")
    return {"version": 1, "operation": "parallel_program_update", "purpose": PURPOSE,
            "server_id": policy["server_id"], "original_authorization_id": authorization["approval_id"],
            "original_manifest_sha256": receipt["manifest_sha256"],
            "previous_release_id": old.name, "new_release_id": release["release_id"],
            "archive_sha256": release["_archive_sha256"], "current_inventory_sha256": sha256(canonical(installed)),
            "changed_files": differences, "unexpected_changes": unexpected, "ready": not unexpected,
            "backup": {"path": str(Path(backup).resolve()), "sha256": backup_sha256,
                       "purpose": "immutable maintenance recovery evidence; never automatic database rollback"},
            "legacy_baseline": baseline, "administrator_baseline": admin,
            "maintenance_preconditions": ["control RPC and App polling paused", "member disabled with existing RPC and original state/revision recorded",
                                          "fresh consistent SQLite backup after member pause", "new agent/subscription/helper socket inactive and helper instances drained"],
            "schema_check": "new ProductionStore opens only a disposable backup copy; existing tables, columns, rows and schema objects preserved",
            "preserve": ["production database and ledger", "deleted/revoked tombstones", "worker identities and generations", "root registry and policy", "administrator process", "legacy processes", "units", "TLS", "core", "firewall", "accounts", "previous release"],
            "production_database_opened": False, "services_started": False, "automatic_rollback": False,
            "authorization_note": "Exact review confirmation records operator review; it does not manufacture human authorization for feature changes."}


def check_additive_migration(destination, backup, policy, runner):
    with tempfile.TemporaryDirectory(prefix=".dazzle-update-") as folder:
        folder = Path(folder)
        folder.chmod(0o700)
        policy_path = folder / "policy.json"
        policy_path.write_text(json.dumps(policy)); policy_path.chmod(0o600)
        data = folder / "clone"
        data.mkdir(mode=0o700)
        raw = run(runner, [str(Path(destination) / "venv/bin/python"), "-I", "-c", CHECK_ADDITIVE,
                           str(Path(backup).resolve()), str(policy_path), str(data)], timeout=60)
        result = json.loads(raw)
        if result.get("ok") is not True or result.get("production_database_opened") is not False:
            raise ValueError("Additive migration verification failed")
        return result


def apply_update(archive, preview, confirm_preview_sha256, *, prefix=PREFIX, etc=ETC,
                 state_dir=STATE, runner=None, trusted_uid=0):
    runner = runner or Runner()
    if confirm_preview_sha256 != sha256(canonical(preview)) or not preview.get("ready"):
        raise ValueError("The operator must confirm the exact ready update preview")
    if os.geteuid() != 0 or platform.system() != "Linux":
        raise ValueError("Update apply is target-root only")
    backup, digest = preview["backup"]["path"], preview["backup"]["sha256"]
    fresh = preview_update(archive, backup, digest, prefix=prefix, etc=etc, state_dir=state_dir,
                           runner=runner, trusted_uid=trusted_uid, baseline=preview["legacy_baseline"],
                           admin_baseline=preview["administrator_baseline"])
    if fresh != preview: raise ValueError("Update inputs changed after review")
    _, _, policy = original_authorization(etc, trusted_uid)
    before = capture_baseline(runner)
    validate_legacy(before); compare_legacy(preview["legacy_baseline"], before)
    if before["firewall_sha256"] != preview["legacy_baseline"]["firewall_sha256"]:
        raise ValueError("Firewall changed after update review")
    if capture_administrator(policy, runner) != preview["administrator_baseline"]:
        raise ValueError("Administrator worker changed after review")
    confirm_quiescent(runner)
    root_files = preserved_root_files(etc, trusted_uid)
    release, files = inspect_archive(archive)
    if release["_archive_sha256"] != preview["archive_sha256"]: raise ValueError("Update archive changed")
    previous = current_release(prefix, trusted_uid)
    destination = Path(prefix) / "releases" / release["release_id"]
    if destination.exists() or destination.is_symlink(): raise ValueError("Target release already exists; retain and inspect partial staging")
    receipts = Path(etc) / "updates"
    if receipts.is_symlink(): raise ValueError("Unsafe update receipt directory")
    receipts.mkdir(mode=0o700, exist_ok=True)
    checked_path(receipts, trusted_uid, directory=True)
    receipt = {"version": 1, "operation": preview["operation"], "purpose": PURPOSE,
               "original_authorization_id": preview["original_authorization_id"], "review_sha256": confirm_preview_sha256,
               "previous_release_id": previous.name, "new_release_id": release["release_id"],
               "changed_files": preview["changed_files"], "backup_sha256": digest, "status": "staging",
               "production_database_opened": False, "services_started": False, "automatic_database_restore": False,
               "at": datetime.now(timezone.utc).isoformat()}
    receipt_path = receipts / (release["release_id"] + ".json")
    atomic_json(receipt_path, receipt, trusted_uid)
    stage_release(release, files, destination, runner, trusted_uid)
    receipt["additive_migration"] = check_additive_migration(destination, backup, policy, runner)
    backup_digest(backup, digest, state_dir=state_dir, trusted_uid=trusted_uid)
    confirm_quiescent(runner)
    if preserved_root_files(etc, trusted_uid) != root_files:
        raise ValueError("Protected root state changed during staging")
    compare_legacy(before, capture_baseline(runner))
    if capture_administrator(policy, runner) != preview["administrator_baseline"]:
        raise ValueError("Administrator worker changed during staging")
    atomic_current(prefix, destination, expected_previous=previous, trusted_uid=trusted_uid)
    receipt["status"] = "switched_services_still_stopped"
    atomic_json(receipt_path, receipt, trusted_uid)
    compare_legacy(before, capture_baseline(runner))
    if capture_administrator(policy, runner) != preview["administrator_baseline"]:
        raise ValueError("Administrator worker changed after program switch; retain state and investigate")
    return {"ok": True, "previous_release_id": previous.name, "current_release_id": destination.name,
            "production_database_opened": False, "services_started": False, "automatic_database_restore": False,
            "notice": "Operator starts existing new services, verifies additive production startup, then selectively restores only this maintenance member if later user changes permit. Preserve administrator and legacy processes."}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Exact-review-bound program update without production database restoration")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--database-backup", type=Path)
    parser.add_argument("--backup-sha256")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--preview", type=Path, help="Saved inner update preview for apply")
    parser.add_argument("--confirm-preview-sha256")
    args = parser.parse_args(argv)
    try:
        if args.apply:
            if not args.preview or not args.confirm_preview_sha256: raise ValueError("Missing review")
            result = apply_update(args.archive, json.loads(args.preview.read_text()), args.confirm_preview_sha256)
        else:
            if not args.database_backup or not args.backup_sha256: raise ValueError("Missing immutable backup")
            preview = preview_update(args.archive, args.database_backup, args.backup_sha256)
            result = {"mode": "preview", "production_modified": False, "preview_sha256": sha256(canonical(preview)), "preview": preview}
        print(json.dumps(result, ensure_ascii=False, indent=2)); return 0
    except Exception:
        print(json.dumps({"ok": False, "error": "Program update checks failed; no automatic database restore or service restart was attempted"})); return 1


if __name__ == "__main__": raise SystemExit(main())
