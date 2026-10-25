"""Rehearsal writer and warmed standby with the production unit's argv and notify protocol."""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import stat
import sys
import time

from .common import MODE, age, api_sample, cgroup_pid, connect, notify, now, persist, read_policy, stop_event, workers


def sample_all(connection):
    result = []
    for worker in workers(connection):
        pid, sample = cgroup_pid(worker["role"], worker["worker_id"]), api_sample(worker["api_port"])
        if pid and sample:
            result.append((worker, sample, pid))
    return result


PHASE, DRAIN_LAG = 0.45, 0.35


def write_loop(connection, stopped, origin):
    """Production cadence: each worker's 1 s frame at its own phase, persisted only on a
    later drain tick and stamped with the frame time, so persisted ages never all reach zero."""
    schedule, pending = {}, []
    while not stopped.is_set():
        now = time.monotonic()
        for index, worker in enumerate(workers(connection)):
            due = schedule.setdefault(worker["worker_id"], origin + 1.0 + PHASE * index)
            if now >= due:
                schedule[worker["worker_id"]] = due + 1.0
                pid, sample = cgroup_pid(worker["role"], worker["worker_id"]), api_sample(worker["api_port"])
                if pid and sample:
                    pending.append((now + DRAIN_LAG, worker, sample, pid))
        ready = [(worker, sample, pid) for due, worker, sample, pid in pending if due <= now]
        if ready:
            persist(connection, ready)
            pending = [item for item in pending if item[0] > now]
        notify("WATCHDOG=1")
        stopped.wait(0.05)


def warm(state_dir):
    """Read-only proof: fresh trusted ledger, same Core PID and native epoch per worker."""
    try:
        reader = connect(state_dir, read_only=True)
    except Exception:
        return False
    try:
        rows = workers(reader)
        for worker in rows:
            user = reader.execute("SELECT * FROM users WHERE id=?", (worker["user_id"],)).fetchone()
            sample = api_sample(worker["api_port"])
            if (not user or not user["trusted_sample"] or age(user["last_sample_at"]) > 5.0 or not sample
                    or sample["epoch"] != user["meter_epoch"] or cgroup_pid(worker["role"], worker["worker_id"]) != worker["process_id"]):
                return False
        return bool(rows)
    finally:
        reader.close()


def standby(state_dir, stopped):
    lock = os.open(Path(state_dir) / "agent.lock", os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(lock)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        return 2
    ready, last_status = False, 0.0
    while not stopped.is_set():
        if warm(state_dir):
            if not ready or time.monotonic() - last_status >= 0.5:
                notify("STATUS=standby-ready; writer=false; pid=%d; lock_inode=%d; checked_ns=%d" % (os.getpid(), info.st_ino, time.monotonic_ns()))
                ready, last_status = True, time.monotonic()
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                stopped.wait(0.1)
                continue
            mode = MODE.read_text().strip() if MODE.exists() else ""
            if mode == "fail-takeover":
                return 23
            if mode == "hang-takeover":
                stopped.wait(3600)
                return 0
            connection = connect(state_dir, read_only=False)
            acquired = now()
            while not stopped.is_set():
                samples = sample_all(connection)
                if samples and all(sample["at"] > acquired.isoformat() for _, sample, _ in samples):
                    break
                stopped.wait(0.02)
            persist(connection, samples)
            notify("READY=1\nSTATUS=writer-ready; trusted-samples=true")
            write_loop(connection, stopped, time.monotonic())
            connection.close()
            return 0
        if ready:
            notify("STATUS=standby-warming; writer=false")
            ready = False
        stopped.wait(0.1)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("command", choices=["agent"])
    parser.add_argument("--standby", action="store_true")
    parser.add_argument("--allow-no-core-recovery", action="store_true")
    args = parser.parse_args(argv)
    read_policy(args.policy)
    stopped = stop_event()
    if args.standby:
        return standby(args.state_dir, stopped)
    lock = os.open(Path(args.state_dir) / "agent.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return 1
    connection = connect(args.state_dir, read_only=False)
    persist(connection, sample_all(connection))
    notify("READY=1\nSTATUS=writer-ready; trusted-samples=true")
    write_loop(connection, stopped, time.monotonic())
    connection.close()
    os.close(lock)
    return 0


if __name__ == "__main__":
    sys.exit(main())
