"""Isolated production state and root-policy identity. No implicit deployment."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

from .store import Store, parse_time, utcnow

POLICY_PATH = "/etc/dazzle-vps/policy.json"
STATE_DIR = "/var/lib/dazzle-vps"
HELPER_SOCKET = "/run/dazzle-vps/helper.sock"
TLS_CERT = "/etc/dazzle-vps/tls/cert.pem"
TLS_KEY = "/etc/dazzle-vps/tls/key.pem"
SUBSCRIPTION_PORT = 9443
CORE_SHA256 = "1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a"

SCHEMA = """
CREATE TABLE IF NOT EXISTS production_workers (
 worker_id TEXT PRIMARY KEY, user_id TEXT UNIQUE, role TEXT NOT NULL,
 public_port INTEGER NOT NULL UNIQUE, api_port INTEGER NOT NULL UNIQUE,
 generation INTEGER NOT NULL DEFAULT 0, root_ack_generation INTEGER NOT NULL DEFAULT 0,
 observed_generation INTEGER NOT NULL DEFAULT 0,
 credential_version INTEGER NOT NULL DEFAULT 0,
 observed_state TEXT NOT NULL DEFAULT 'unprovisioned', provisioned INTEGER NOT NULL DEFAULT 0,
 api_secret TEXT, public_key TEXT, process_id INTEGER, origin_pending INTEGER NOT NULL DEFAULT 0,
 origin_epoch TEXT, verified_at TEXT, last_error TEXT, tombstoned INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS production_jobs (
 id TEXT PRIMARY KEY, worker_id TEXT NOT NULL, generation INTEGER NOT NULL,
 credential_version INTEGER NOT NULL, action TEXT NOT NULL, payload_json TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, completed_at TEXT, error_code TEXT
);
CREATE INDEX IF NOT EXISTS production_jobs_pending ON production_jobs(status,created_at);
CREATE UNIQUE INDEX IF NOT EXISTS production_one_pending_generation ON production_jobs(worker_id,generation)
 WHERE status IN ('pending','executing');
CREATE TABLE IF NOT EXISTS production_retired_origins (
 worker_id TEXT NOT NULL,generation INTEGER NOT NULL,user_id TEXT NOT NULL,epoch TEXT NOT NULL,
 last_upload INTEGER NOT NULL,last_download INTEGER NOT NULL,last_at TEXT NOT NULL,
 retired_at TEXT NOT NULL,cycle_id TEXT NOT NULL,PRIMARY KEY(worker_id,generation)
);
"""


def validate_policy(policy: dict) -> dict:
    required = {"version", "server_id", "server_endpoint", "agent_uid", "core_sha256", "workers"}
    if not isinstance(policy, dict) or set(policy) != required or type(policy.get("version")) is not int or policy["version"] != 1:
        raise ValueError("Invalid root policy version")
    try:
        if str(uuid.UUID(policy["server_id"])) != policy["server_id"]:
            raise ValueError()
        endpoint = ipaddress.ip_address(policy["server_endpoint"])
        if endpoint.version != 4 or not endpoint.is_global:
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise ValueError("Root policy identity or endpoint is invalid") from None
    if policy.get("core_sha256") != CORE_SHA256 or type(policy.get("agent_uid")) is not int or policy["agent_uid"] <= 0:
        raise ValueError("Root policy core or agent identity is invalid")
    workers = policy.get("workers")
    if not isinstance(workers, dict) or not workers:
        raise ValueError("No approved workers")
    occupied, roles = {22, 80, 443, 8443, SUBSCRIPTION_PORT}, set()
    for identifier, worker in workers.items():
        if str(uuid.UUID(identifier)) != identifier or not isinstance(worker, dict):
            raise ValueError("Invalid registered worker")
        if set(worker) != {"role", "public_port", "api_port"} or worker.get("role") not in {"admin", "member"} or worker["role"] in roles:
            raise ValueError("Invalid registered role")
        expected = {"admin": (24430, 34430), "member": (24431, 34431)}[worker["role"]]
        if (worker["public_port"], worker["api_port"]) != expected:
            raise ValueError("Worker is outside the approved pilot ports")
        roles.add(worker["role"])
        for key in ("public_port", "api_port"):
            port = worker.get(key)
            if type(port) is not int or not 1024 <= port <= 65535 or port in occupied:
                raise ValueError("Unapproved or conflicting port")
            occupied.add(port)
    return policy


def load_policy(path: str | Path = POLICY_PATH, *, require_root: bool = True) -> dict:
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or (require_root and info.st_uid != 0):
        raise ValueError("Policy must be a root-owned regular file without group/other writes")
    if info.st_size > 1024 * 1024:
        raise ValueError("Policy exceeds size limit")
    return validate_policy(json.loads(path.read_text()))


class ProductionStore(Store):
    def __init__(self, state_dir: str | Path, *, policy: dict, initialize: bool = False, read_only: bool = False, now=None):
        self.policy = validate_policy(policy)
        folder = Path(state_dir)
        database = folder / "state.sqlite3"
        if database.exists():
            if database.is_symlink() or not database.is_file():
                raise ValueError("Production database must be a regular file")
            connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
            try:
                mode = connection.execute("SELECT value FROM meta WHERE key='mode'").fetchone()
                identity = connection.execute("SELECT value FROM meta WHERE key='server_id'").fetchone()
                if not mode or json.loads(mode[0]) != "production" or not identity or json.loads(identity[0]) != policy["server_id"]:
                    raise ValueError("Production database identity mismatch; simulation import is forbidden")
            finally:
                connection.close()
        elif not initialize:
            raise ValueError("Production state has not been explicitly initialized")
        if folder.is_symlink():
            raise ValueError("Production directory must not be a symlink")
        if read_only:
            if not database.is_file():
                raise ValueError("Production database is unavailable")
            self.state_dir, self.path = folder, database
            self.now = parse_time(now) if now else utcnow()
            self.memory_responses = {}
            self.conn = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, isolation_level=None)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA busy_timeout=3000")
            return
        super().__init__(folder, mode="production", now=now)
        self.conn.executescript(SCHEMA)
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(production_workers)")}
        if "observed_generation" not in columns:
            self.conn.execute("ALTER TABLE production_workers ADD COLUMN observed_generation INTEGER NOT NULL DEFAULT 0")
        if "root_ack_generation" not in columns:
            self.conn.execute("ALTER TABLE production_workers ADD COLUMN root_ack_generation INTEGER NOT NULL DEFAULT 0")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.set_meta("server_id", policy["server_id"])
            for identifier, worker in policy["workers"].items():
                old = self.conn.execute("SELECT role,public_port,api_port FROM production_workers WHERE worker_id=?", (identifier,)).fetchone()
                if old and tuple(old) != (worker["role"], worker["public_port"], worker["api_port"]):
                    raise ValueError("Registered worker binding changed")
                self.conn.execute("INSERT OR IGNORE INTO production_workers(worker_id,role,public_port,api_port) VALUES(?,?,?,?)",
                                  (identifier, worker["role"], worker["public_port"], worker["api_port"]))
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            self.close()
            raise

    @property
    def server_id(self) -> str:
        return self.policy["server_id"]

    def worker(self, user_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM production_workers WHERE user_id=?", (user_id,)).fetchone()
        if row is None:
            raise KeyError("No registered production worker")
        return dict(row)
