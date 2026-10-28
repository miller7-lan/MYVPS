"""Rehearsal-only stand-ins for the dazzle runtime. Never part of a release."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import threading
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, role TEXT, manual_disabled INTEGER, revoked_at TEXT, deleted_at TEXT,
 reasons_json TEXT, trusted_sample INTEGER, meter_state TEXT, meter_epoch TEXT, last_sample_at TEXT, last_uplink INTEGER,
 last_downlink INTEGER, used_upload INTEGER, used_download INTEGER, quota_bytes INTEGER, topup_bytes INTEGER, unlimited INTEGER,
 credential_version INTEGER, quota_pool TEXT);
CREATE TABLE IF NOT EXISTS production_workers (worker_id TEXT PRIMARY KEY, role TEXT, user_id TEXT, public_port INTEGER,
 api_port INTEGER, generation INTEGER, root_ack_generation INTEGER, observed_generation INTEGER, observed_state TEXT,
 process_id INTEGER, origin_pending INTEGER, last_error TEXT, tombstoned INTEGER, credential_version INTEGER, provisioned INTEGER);
CREATE TABLE IF NOT EXISTS production_jobs (id TEXT PRIMARY KEY, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS metering_incidents (id TEXT PRIMARY KEY, user_id TEXT, kind TEXT, detected_at TEXT, resolved_at TEXT);
CREATE TABLE IF NOT EXISTS cycles (id TEXT PRIMARY KEY, start_at TEXT, end_at TEXT, status TEXT);
"""
SEED = Path("/etc/dazzle-vps/fixture-seed.json")
MODE = Path("/etc/dazzle-vps/fixture-mode")
FRESHNESS = 5.0


def now():
    return dt.datetime.now(dt.timezone.utc)


def age(value):
    return (now() - dt.datetime.fromisoformat(value)).total_seconds() if value else float("inf")


def notify(message):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
        client.sendto(message.encode(), address)


def stop_event():
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    return stopped


def read_policy(path):
    return json.loads(Path(path).read_text())  # Proves the unit can read the exact policy file it was given.


def unit_name(role, worker_id):
    return ("dazzle-admin@" if role == "admin" else "dazzle-proxy@") + worker_id + ".service"


def cgroup_pid(role, worker_id):
    try:
        values = Path("/sys/fs/cgroup/system.slice", unit_name(role, worker_id), "cgroup.procs").read_text().split()
    except FileNotFoundError:
        return None
    return int(values[0]) if len(values) == 1 else None


def api_sample(port):
    """Stand-in for the loopback native counter API: one cumulative JSON frame."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5) as connection:
            line = connection.makefile("rb").readline()
        value = json.loads(line)
        return {"epoch": str(value["epoch"]), "up": int(value["up"]), "down": int(value["down"]), "at": now().isoformat()}
    except (OSError, ValueError, KeyError):
        return None


def connect(state_dir, *, read_only):
    path = Path(state_dir) / "state.sqlite3"
    if read_only:
        connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1, isolation_level=None)
    else:
        connection = sqlite3.connect(path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(SCHEMA)
        if not connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            seed = json.loads(SEED.read_text())
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT INTO settings VALUES('registration_enabled','false')")
            for key, value in seed["meta"].items():
                connection.execute("INSERT INTO meta VALUES(?,?)", (key, json.dumps(value)))
            for table in ("users", "production_workers", "cycles"):
                for row in seed[table]:
                    connection.execute("INSERT INTO " + table + "(" + ",".join(row) + ") VALUES(" + ",".join("?" * len(row)) + ")", tuple(row.values()))
            connection.execute("COMMIT")
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=3000")
    return connection


def workers(connection):
    return [dict(row) for row in connection.execute("SELECT * FROM production_workers WHERE user_id IS NOT NULL AND observed_state='running'")]


def persist(connection, samples):
    """Exact cumulative deltas; a gap beyond five seconds is an incident, never trusted."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        for worker, sample, pid in samples:
            user = dict(connection.execute("SELECT * FROM users WHERE id=?", (worker["user_id"],)).fetchone())
            initial = user["meter_epoch"] is None  # First observed origin of a freshly seeded rehearsal Core.
            same = (not initial and user["meter_epoch"] == sample["epoch"] and sample["up"] >= user["last_uplink"]
                    and sample["down"] >= user["last_downlink"])
            trusted = initial or (same and age(user["last_sample_at"]) <= FRESHNESS)
            if not trusted:
                connection.execute("INSERT INTO metering_incidents VALUES(?,?,?,?,NULL)", (str(uuid.uuid4()), user["id"], "sample_gap", now().isoformat()))
            delta_up = sample["up"] - user["last_uplink"] if trusted and not initial else 0
            delta_down = sample["down"] - user["last_downlink"] if trusted and not initial else 0
            connection.execute("UPDATE users SET meter_epoch=?,last_uplink=?,last_downlink=?,last_sample_at=?,used_upload=used_upload+?,"
                               "used_download=used_download+?,trusted_sample=?,meter_state=? WHERE id=?",
                               (sample["epoch"], sample["up"], sample["down"], sample["at"], delta_up, delta_down, int(trusted),
                                "trusted" if trusted else "reconciliation_required", user["id"]))
            connection.execute("UPDATE production_workers SET process_id=? WHERE worker_id=?", (pid, worker["worker_id"]))
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise
