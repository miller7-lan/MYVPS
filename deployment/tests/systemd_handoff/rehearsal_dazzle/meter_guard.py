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
    args = parser.parse_args(argv)
    if read_policy(args.policy)["workers"][args.worker_id]["role"] != "member":
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
                pid = cgroup_pid("member", args.worker_id)
                healthy = bool(pid and pid == worker["process_id"] and user["trusted_sample"] and age(user["last_sample_at"]) <= FRESHNESS)
            except Exception:
                healthy = False
            if healthy:
                if not ready:
                    notify("READY=1\nSTATUS=member-guard-ready; worker=%s; phase=running" % args.worker_id)
                    ready = True
                notify("WATCHDOG=1")
            elif ready or time.monotonic() - began > FRESHNESS:
                return 1
            stopped.wait(0.25)
    finally:
        reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
