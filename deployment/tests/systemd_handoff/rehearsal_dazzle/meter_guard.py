"""Rehearsal guard: read-only ledger freshness plus the member's real cgroup PID.

Like the production guard it keeps one persistent read-only connection, so a
closing writer cannot delete the WAL pair underneath its read-only mount.
"""
from __future__ import annotations

import argparse
import sys
import time

from .common import FRESHNESS, age, cgroup_pid, connect, notify, read_policy, stop_event


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--worker-id", required=True)
    # Model the real template's bounded administrator preparation, never a bypass.
    parser.add_argument("--prepare-administrator", action="store_true")
    args = parser.parse_args(argv)
    role = read_policy(args.policy)["workers"][args.worker_id]["role"]
    if role != 'member' and not args.prepare_administrator:
        return 1
    stopped, ready, began = stop_event(), False, time.monotonic()
    reader = connect(args.state_dir, read_only=True)
    try:
        while not stopped.is_set():
            healthy = False
            try:
                reader.execute("BEGIN")
                try:
                    worker = reader.execute("SELECT * FROM production_workers WHERE worker_id=?", (args.worker_id,)).fetchone()
                    user = reader.execute("SELECT * FROM users WHERE id=?", (worker["user_id"],)).fetchone()
                finally:
                    reader.execute("ROLLBACK")
                pid = cgroup_pid(role, args.worker_id)
                healthy = bool(pid and pid == worker["process_id"] and user["trusted_sample"] and age(user["last_sample_at"]) <= FRESHNESS)
                preparing = role == 'admin' and bool(user['unlimited'])
                if preparing:
                    from pathlib import Path
                    import json, hashlib
                    marker=json.loads(Path('/etc/dazzle-vps/admin-budget-guard.json').read_text())
                    unit=Path('/etc/systemd/system/dazzle-admin@'+args.worker_id+'.service').read_bytes()
                    healthy=healthy and marker['approved'] is True and marker['worker_id']==args.worker_id and marker['reviewed_unit_sha256']==hashlib.sha256(unit).hexdigest()
                    if time.monotonic()-began >= 60:
                        return 1
            except Exception:
                healthy = False
            if healthy:
                if not ready:
                    notify("READY=1\nSTATUS=member-guard-ready; worker=%s; phase=%s" % (args.worker_id,'admin-preparing' if preparing else 'running'))
                    ready = True
                else:
                    notify("STATUS=member-guard-ready; worker=%s; phase=%s" % (args.worker_id,'admin-preparing' if preparing else 'running'))
                notify("WATCHDOG=1")
            elif ready or time.monotonic() - began > FRESHNESS:
                return 1
            stopped.wait(0.25)
    finally:
        reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
