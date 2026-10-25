"""Standalone LOCAL scheduler. No Mac App dependency and no production executor.

Run --once for deterministic simulation, or a bounded/foreground loop. This is
not installed as a daemon during phase 1. It has no signal that can reset provider
billing, and no shell/systemd/SSH transport.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import signal
import time

from .domain import handle_action
from .store import Store, parse_time


def run_once(store: Store, now: datetime | None = None) -> dict:
    if store.get_meta("mode") != "simulation":
        raise ValueError("Phase 1 scheduler only accepts isolated simulation state")
    store.now = parse_time(now) if now else datetime.now(timezone.utc)
    results = {}
    for action in ("cycle.tick", "runtime.process", "mail.process"):
        store.conn.execute("BEGIN IMMEDIATE")
        try:
            handle_action(store, action, {}, store.now)
            # Internal ticks do not persist full RPC snapshots/idempotency responses.
            # Cycle IDs, sample baselines and mail event keys provide task idempotency.
            store.set_meta("revision", store.revision + 1)
            store.conn.commit()
        except BaseException:
            store.conn.rollback()
            raise
        results[action] = "completed"
    return {"mode": "simulation", "at": store.now.isoformat(), "tasks": results,
            "production_changed": False, "revision": store.revision}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Local simulation scheduler; no production installation")
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--at", help="Explicit timezone-aware simulation clock; requires --once")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--iterations", type=int, default=0, help="0 means run foreground until terminated")
    args = parser.parse_args(argv)
    if not 0.25 <= args.interval <= 60 or args.iterations < 0 or (args.at and not args.once):
        parser.error("Use interval0.25..60, nonnegative iterations, and --at only with --once")
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with Store(args.state_dir) as store:
        count = 0
        while running:
            started = time.monotonic()
            print(json.dumps(run_once(store, parse_time(args.at) if args.at else None)), flush=True)
            count += 1
            if args.once or (args.iterations and count >= args.iterations):
                break
            time.sleep(max(0.0, args.interval - (time.monotonic() - started)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
