"""Private SQLite state; caller owns domain transactions."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
from typing import Any

UTC = dt.timezone.utc
_DATABASE_CREATION_LOCK = threading.Lock()


def utcnow() -> dt.datetime:
    return dt.datetime.now(UTC)


def timestamp(value: dt.datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: str | dt.datetime) -> dt.datetime:
    if isinstance(value, dt.datetime):
        result = value
    elif isinstance(value, str):
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("Expected an ISO 8601 timestamp")
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone")
    return result.astimezone(UTC)


DEFAULT_SETTINGS = {
    "quota_policy": "administrator_schedule", "day": 24, "time": "16:19",
    "timezone": "Asia/Shanghai", "default_quota_bytes": 100_000_000_000,
    "admin_reserve_bytes": None, "safety_margin_bytes": None,
}

DEFAULT_PROVIDER = {
    "name": "QQG.NET", "instance_id": "4920", "plan": "1C1G-9929-500G",
    "total_display": "500GB", "remaining_display": "493.36GB",
    "total_bytes": None, "remaining_bytes": None, "unit_verified": False,
    "expected_reset_date": "2026-11-24", "expected_reset_at": None,
    "timezone": None, "cycle_id": None, "cycle_start_at": None,
    "last_actual_reset_at": None, "observed_at": None,
    "source": "historical_manual_snapshot", "sync_state": "unverified",
    "automatic_available": False, "evidence": "Historical browser observation; not live",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('member','admin')),
 port INTEGER NOT NULL UNIQUE, manual_disabled INTEGER NOT NULL DEFAULT 1,
 reasons_json TEXT NOT NULL DEFAULT '[]', quota_bytes INTEGER, unlimited INTEGER NOT NULL DEFAULT 0,
 topup_bytes INTEGER NOT NULL DEFAULT 0, used_upload INTEGER NOT NULL DEFAULT 0,
 used_download INTEGER NOT NULL DEFAULT 0, credential_version INTEGER NOT NULL DEFAULT 1,
 auto_restore INTEGER NOT NULL DEFAULT 1, threshold_percent INTEGER NOT NULL DEFAULT 80,
 email TEXT, email_verified INTEGER NOT NULL DEFAULT 0, meter_state TEXT NOT NULL DEFAULT 'unknown',
 last_sample_at TEXT, meter_epoch TEXT, last_uplink INTEGER, last_downlink INTEGER,
 trusted_sample INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 revoked_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_live_administrator ON users(role)
 WHERE role='admin' AND revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS credentials (
 user_id TEXT PRIMARY KEY REFERENCES users(id), version INTEGER NOT NULL,
 vless_uuid TEXT NOT NULL, tuic_uuid TEXT NOT NULL, tuic_password TEXT NOT NULL,
 subscription_token TEXT NOT NULL, reality_public_key TEXT NOT NULL,
 short_id TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), cycle_id TEXT NOT NULL,
 epoch TEXT NOT NULL, upload INTEGER NOT NULL, download INTEGER NOT NULL,
 sample_at TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS metering_incidents (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), kind TEXT NOT NULL,
 previous_epoch TEXT, sample_epoch TEXT, previous_at TEXT, sample_at TEXT,
 previous_uplink INTEGER, previous_downlink INTEGER, sample_uplink INTEGER, sample_downlink INTEGER,
 unallocated_upload INTEGER, unallocated_download INTEGER, delta_unknown INTEGER NOT NULL,
 detected_at TEXT NOT NULL, resolved_at TEXT, evidence TEXT, operator TEXT, resolution TEXT
);
CREATE INDEX IF NOT EXISTS metering_incidents_user ON metering_incidents(user_id,detected_at);
CREATE TABLE IF NOT EXISTS cycles (
 id TEXT PRIMARY KEY, start_at TEXT NOT NULL, end_at TEXT NOT NULL, source TEXT NOT NULL,
 status TEXT NOT NULL, report_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS requests (
 request_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, response_json TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
 id TEXT PRIMARY KEY, action TEXT NOT NULL, status TEXT NOT NULL,
 created_at TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_queue (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, verb TEXT NOT NULL, status TEXT NOT NULL,
 reason TEXT NOT NULL, created_at TEXT NOT NULL, applied_at TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS runtime_state (
 user_id TEXT PRIMARY KEY, status TEXT NOT NULL, runtime_version INTEGER NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_snapshots (
 name TEXT PRIMARY KEY, state_json TEXT NOT NULL, created_at TEXT NOT NULL
);
"""


class Store:
    def __init__(self, state_dir: str | Path | None = None, *, now: dt.datetime | None = None,
                 memory: bool = False, mode: str = "simulation"):
        self.now = parse_time(now) if now is not None else utcnow()
        self.memory_responses: dict[str, tuple[str, dict]] = {}
        self.state_dir = Path(state_dir) if state_dir is not None else None
        if memory or state_dir is None:
            self.path = None
            self.conn = sqlite3.connect(":memory:", isolation_level=None)
        else:
            self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not stat.S_ISDIR(self.state_dir.lstat().st_mode):
                raise ValueError("State directory must not be a symlink")
            self.state_dir.chmod(0o700)
            self.path = self.state_dir / "state.sqlite3"
            # Closing ANY raw descriptor for an existing SQLite database drops
            # this process's POSIX locks, including locks owned by other SQLite
            # connections. Only create a missing file; SQLite alone opens every
            # existing database. Serialize the brief first-create window so a
            # second thread cannot connect before the creator closes its fd.
            with _DATABASE_CREATION_LOCK:
                try:
                    info = self.path.lstat()
                except FileNotFoundError:
                    try:
                        descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                    except FileExistsError:
                        pass  # Another process won creation; never reopen it raw.
                    else:
                        os.close(descriptor)
                    info = self.path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("State database must be a regular file, not a symlink")
                os.chmod(self.path, 0o600, follow_symlinks=False)
                self.conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        if self.path is not None:
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript(SCHEMA)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            for key, value in DEFAULT_SETTINGS.items():
                self.conn.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (key, json.dumps(value)))
            for key, value in {"revision": 1, "mode": mode, "provider": DEFAULT_PROVIDER,
                               "metering_failure_seconds": 5}.items():
                self.conn.execute("INSERT OR IGNORE INTO meta VALUES (?,?)", (key, json.dumps(value)))
            try:
                from .mail import ensure_schema
            except ImportError:
                ensure_schema = None
            if ensure_schema is not None:
                ensure_schema(self)
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise

    @classmethod
    def preview(cls, state_dir: str | Path, *, now: dt.datetime | None = None) -> "Store":
        """Clone state in memory without creating/changing the requested directory."""
        store = cls(memory=True, now=now)
        source = Path(state_dir) / "state.sqlite3"
        if source.is_file():
            connection = sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)
            try:
                connection.backup(store.conn)
            finally:
                connection.close()
        return store

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute("INSERT INTO meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          (key, json.dumps(value, ensure_ascii=False)))

    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_setting(self, key: str, value: Any) -> None:
        self.conn.execute("INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          (key, json.dumps(value, ensure_ascii=False)))

    @property
    def revision(self) -> int:
        return self.get_meta("revision", 1)

    def get_user(self, user_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None:
            raise KeyError("User not found")
        return dict(row)

    def get_credentials(self, user_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM credentials WHERE user_id=?", (user_id,)).fetchone()
        if row is None:
            raise KeyError("User credentials not found")
        return dict(row)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
