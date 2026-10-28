"""One read-only, fail-closed meter guard per registered member.

The guard never takes agent.lock, updates SQLite, controls a service, or sends
mail. Its systemd unit is bound only to its own member; an error exits this one
process. Native observations are evidence, never substituted ledger heartbeats.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import threading
import time
import uuid

from . import domain
from .metering import NativeAPI
from .production_state import POLICY_PATH, STATE_DIR, ProductionStore, load_policy
from .store import parse_time, utcnow

MAX_AGE = 5.0
PROOF_DIR = "/etc/dazzle-vps/guard-proofs"


class GuardError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def notify(message):
    destination = os.environ.get("NOTIFY_SOCKET")
    if not destination:
        return
    if destination.startswith("@"):
        destination = "\0" + destination[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as connection:
        connection.settimeout(0.2)
        connection.sendto(message.encode("ascii"), destination)


def age(value, now):
    if not value:
        raise GuardError("MISSING_TIMESTAMP")
    result = (now - parse_time(value)).total_seconds()
    # A host clock stepped back by at most MAX_AGE makes the observation written
    # just before the step look slightly ahead, until the writer records its next
    # frame on the new clock. A larger step has no bound, so it fails closed.
    if not -MAX_AGE <= result <= MAX_AGE:
        raise GuardError("STALE_OBSERVATION")
    return max(0.0, result)


def boot_id(path="/proc/sys/kernel/random/boot_id"):
    value = Path(path).read_text().strip()
    if str(uuid.UUID(value)) != value:
        raise GuardError("BOOT_ID_INVALID")
    return value


class RuntimeProbe:
    def __init__(self, *, proc_root="/proc", cgroup_root="/sys/fs/cgroup"):
        self.proc_root, self.cgroup_root = Path(proc_root), Path(cgroup_root)

    def __call__(self, worker_id, expected_pid, role="member"):
        group = self.cgroup_root / "system.slice" / (("dazzle-admin@" if role == "admin" else "dazzle-proxy@") + worker_id + ".service")
        for path in (group, group / "cgroup.procs"):
            if path.is_symlink():
                raise GuardError("UNTRUSTED_CGROUP")
        try:
            pids = [int(value) for value in (group / "cgroup.procs").read_text().split()]
        except FileNotFoundError:
            pids = []
        except (ValueError, OSError):
            raise GuardError("CGROUP_UNREADABLE") from None
        if any(pid <= 0 for pid in pids):
            raise GuardError("CGROUP_INVALID")
        if not pids:
            return {"pid": None, "identity": None}
        pid = expected_pid if expected_pid in pids else pids[0] if len(pids) == 1 else None
        if not pid:
            raise GuardError("PID_UNCONFIRMED")
        try:
            path = self.proc_root / str(pid) / "stat"
            raw = path.read_text()
            if int(raw.split("(", 1)[0].strip()) != pid:
                raise ValueError()
            fields = raw[raw.rfind(")") + 2:].split()
            if fields[0] == "Z":
                raise ValueError()
            started = int(fields[19])
        except (OSError, ValueError, IndexError):
            raise GuardError("PID_UNCONFIRMED") from None
        return {"pid": pid, "identity": str(pid) + ":" + str(started)}


def read_proof(policy, worker_id, *, directory=PROOF_DIR, current_boot=None, monotonic_ns=None, trusted_uid=0):
    directory = Path(directory)
    if not directory.exists():
        return None
    for path in (directory, directory / (worker_id + ".json")):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(info.st_mode) or info.st_uid != trusted_uid or info.st_mode & 0o022:
            raise GuardError("UNTRUSTED_ROOT_PROOF")
    path = directory / (worker_id + ".json")
    if not path.is_file() or path.stat().st_size > 4096:
        raise GuardError("INVALID_ROOT_PROOF")
    try:
        value = json.loads(path.read_text())
        required = {"version", "server_id", "worker_id", "generation", "mode", "phase", "config_sha256", "process_id", "boot_id", "prepared_monotonic_ns", "observed_monotonic_ns"}
        if (not isinstance(value, dict) or set(value) != required or type(value["version"]) is not int or value["version"] != 1 or
                value["server_id"] != policy["server_id"] or value["worker_id"] != worker_id or
                type(value["generation"]) is not int or value["generation"] <= 0 or
                value["mode"] not in {"staged", "running"} or value["phase"] not in {"prepared", "complete"} or
                not re.fullmatch(r"[a-f0-9]{64}", value["config_sha256"]) or
                value["boot_id"] != (current_boot if current_boot is not None else boot_id()) or
                type(value["prepared_monotonic_ns"]) is not int or type(value["observed_monotonic_ns"]) is not int or
                not 0 < value["prepared_monotonic_ns"] <= value["observed_monotonic_ns"] or
                (value["process_id"] is not None and (type(value["process_id"]) is not int or value["process_id"] <= 0))):
            raise ValueError()
        elapsed = ((time.monotonic_ns() if monotonic_ns is None else monotonic_ns) - value["prepared_monotonic_ns"]) / 1e9
        if elapsed < 0:
            raise ValueError()
        return {**value, "age": elapsed}
    except (ValueError, TypeError, KeyError, OSError):
        raise GuardError("INVALID_ROOT_PROOF") from None


def read_view(store, worker_id):
    row = store.conn.execute("SELECT * FROM production_workers WHERE worker_id=?", (worker_id,)).fetchone()
    if row is None:
        raise GuardError("WORKER_UNREGISTERED")
    worker = dict(row)
    expected = store.policy["workers"].get(worker_id)
    if not expected or expected["role"] != worker["role"] or any(worker[key] != expected[key] for key in ("public_port", "api_port")):
        raise GuardError("WORKER_POLICY_MISMATCH")
    user = store.get_user(worker["user_id"]) if worker["user_id"] else None
    job = store.conn.execute("SELECT id,action,generation FROM production_jobs WHERE worker_id=? AND status='executing' ORDER BY generation DESC LIMIT 1", (worker_id,)).fetchone()
    return {"worker": worker, "user": user, "job": dict(job) if job else None}


class NativeWitness:
    """Real loopback streams; no SQLite access and no manufactured samples."""
    def __init__(self, api_factory=NativeAPI):
        self.api_factory, self.lock = api_factory, threading.Lock()
        self.records = {}

    def configure(self, worker):
        identifier = worker["worker_id"]
        key = (worker["observed_generation"], worker["process_id"], worker["api_secret"])
        with self.lock:
            old = self.records.get(identifier)
            if old and old["key"] == key:
                return
            if old:
                old["stop"].set()
            record = {"key": key, "stop": threading.Event(), "sample": None, "error": None}
            self.records[identifier] = record
        if not worker["api_secret"]:
            return
        def observe():
            while not record["stop"].is_set():
                try:
                    api = self.api_factory("127.0.0.1", worker["api_port"], worker["api_secret"], timeout=1)
                    for sample in api.stream():
                        if record["stop"].is_set():
                            return
                        sample.validate()
                        with self.lock:
                            record["sample"], record["error"] = sample, None
                except Exception:
                    with self.lock:
                        record["error"] = "NATIVE_UNAVAILABLE"
                record["stop"].wait(0.2)
        threading.Thread(target=observe, daemon=True, name="dazzle-guard-native").start()

    def sample(self, worker):
        self.configure(worker)
        with self.lock:
            return self.records[worker["worker_id"]]["sample"]

    def close(self):
        with self.lock:
            for record in self.records.values():
                record["stop"].set()


def evaluate(view, actual, sample, now, proof=None, *, prepare_administrator=False):
    worker, user, job = view["worker"], view["user"], view["job"]
    preparing = bool(prepare_administrator and worker['role']=='admin' and user and user['unlimited'])
    if preparing:
        user=dict(user,unlimited=0,quota_bytes=2**63-1,topup_bytes=0)
    if worker["role"] != "member" and not (worker['role'] == 'admin' and user and not user['unlimited']):
        raise GuardError("MEMBER_ONLY")
    if worker["tombstoned"] or (user and (user["revoked_at"] or user.get("deleted_at"))):
        raise GuardError("AUTHORIZATION_REVOKED")
    no_pid = actual["pid"] in (None, 0)
    never_started = not user or (not user["meter_epoch"] and not user["last_sample_at"])
    if no_pid and never_started and worker["observed_state"] in {"unprovisioned", "provisioned"}:
        return {"phase": "bootstrap-inactive", "ledger_age": None, "native_age": None}
    if (proof and proof["phase"] == "complete" and not no_pid and
            proof["process_id"] != actual["pid"] and proof["generation"] >= worker["root_ack_generation"]):
        raise GuardError("ROOT_PROOF_PID_MISMATCH")
    transition = bool(proof and proof["age"] <= MAX_AGE and job and job["action"] in {"stage", "activate"} and
                      job["generation"] == proof["generation"] and proof["mode"] == {"stage": "staged", "activate": "running"}[job["action"]])
    if transition and proof["mode"] == "staged":
        return {"phase": "api-only-transition", "ledger_age": None, "native_age": None}
    if not user:
        raise GuardError("UNASSIGNED_PROCESS")
    if transition and proof["mode"] == "running" and user["trusted_sample"] and not domain.disabled_reasons(user):
        return {"phase": "activation-transition", "ledger_age": None, "native_age": None}
    pid = worker["process_id"]
    if no_pid or type(pid) is not int or pid <= 0 or pid != actual["pid"]:
        raise GuardError("PID_MISMATCH")
    # A root-proven API-only worker cannot carry public proxy traffic, even
    # while a historical ledger incident awaits an explicit reconciliation.
    api_only = bool(proof and proof["phase"] == "complete" and proof["mode"] == "staged" and
                    proof["generation"] == worker["observed_generation"] and proof["process_id"] == pid and
                    worker["observed_state"] == "staged")
    if api_only and proof["age"] <= MAX_AGE and worker["origin_pending"]:
        return {"phase": "api-only-origin", "ledger_age": None, "native_age": None}
    origin_grace = bool(proof and proof["phase"] == "complete" and proof["mode"] == "running" and
                        proof["age"] <= MAX_AGE and proof["generation"] == worker["observed_generation"] and
                        proof["process_id"] == pid and worker["origin_pending"] and user["trusted_sample"] and
                        not domain.disabled_reasons(user))
    if origin_grace:
        return {"phase": "activation-origin", "ledger_age": None, "native_age": None}
    if sample is None:
        raise GuardError("NATIVE_WARMING")
    native_age = age(sample.at, now)
    if api_only:
        return {"phase": "api-only", "ledger_age": None, "native_age": native_age}
    if worker["observed_state"] != "running" or not user["trusted_sample"] or not domain.eligible(user, now):
        raise GuardError("UNTRUSTED_AUTHORIZATION_OR_METER")
    ledger_age = age(user["last_sample_at"], now)
    if not user["meter_epoch"] or sample.epoch != user["meter_epoch"]:
        raise GuardError("EPOCH_MISMATCH")
    if worker["credential_version"] != user["credential_version"] or worker["observed_generation"] != worker["root_ack_generation"]:
        raise GuardError("GENERATION_MISMATCH")
    return {"phase": "admin-preparing" if preparing else "running", "ledger_age": ledger_age, "native_age": native_age}


def run_guard(state_dir, policy, worker_id, *, stop=None, witness=None, runtime_probe=None, proof_reader=None, ready=notify, prepare_administrator=False):
    if worker_id not in policy["workers"] or policy["workers"][worker_id]["role"] not in {"member", "admin"}:
        raise GuardError("MEMBER_ONLY")
    stop, witness = stop or threading.Event(), witness or NativeWitness()
    runtime_probe = runtime_probe or RuntimeProbe()
    proof_reader = proof_reader or (lambda: read_proof(policy, worker_id))
    announced, warming_deadline, identity = False, time.monotonic() + MAX_AGE, None
    admin_deadline=time.monotonic()+60
    if policy['workers'][worker_id]['role']=='admin':
        from .budget import guard_approval
        if not guard_approval(policy):
            raise GuardError('ADMIN_GUARD_APPROVAL_REQUIRED')
    try:
        # One persistent read-only connection. When the last other connection of
        # a WAL database closes, SQLite deletes -wal/-shm, and a read-only mount
        # cannot recreate them: a guard that reopened per check would then fail
        # instantly during a writer handoff. Holding this connection keeps the
        # pair alive, so only the unchanged five-second ledger age decides.
        with ProductionStore(state_dir, policy=policy, read_only=True) as store:
            while not stop.is_set():
                store.conn.execute("BEGIN")
                try:
                    view = read_view(store, worker_id)
                finally:
                    store.conn.execute("ROLLBACK")  # Never hold a snapshot across waits.
                actual = runtime_probe(worker_id, view["worker"]["process_id"], view['worker']['role']) if view['worker']['role'] == 'admin' else runtime_probe(worker_id, view['worker']['process_id'])
                sample = witness.sample(view["worker"])
                proof = proof_reader()
                now = utcnow()  # A reader thread may have produced its frame just now.
                try:
                    if view['worker']['role']=='admin' and view['user'] and view['user']['unlimited'] and time.monotonic()>=admin_deadline:
                        raise GuardError('ADMIN_PREPARATION_EXPIRED')
                    evidence = evaluate(view, actual, sample, now, proof, prepare_administrator=prepare_administrator)
                except GuardError as exc:
                    if not announced and exc.code == "NATIVE_WARMING" and time.monotonic() < warming_deadline:
                        stop.wait(0.1)
                        continue
                    raise
                key = (actual["pid"], view["worker"]["observed_generation"])
                epoch = sample.epoch if sample else None
                if identity and identity[0] == key:
                    if identity[1] != actual["identity"]:
                        raise GuardError("PID_REUSED")
                    if identity[2] is not None and epoch is not None and identity[2] != epoch:
                        raise GuardError("EPOCH_CHANGED_WITHOUT_GENERATION")
                identity = key, actual["identity"], epoch
                if not announced:
                    ready("READY=1\nSTATUS=member-guard-ready; worker=" + worker_id + "; phase=" + evidence["phase"])
                    announced = True
                ready("WATCHDOG=1")
                stop.wait(0.25)
    finally:
        witness.close()
        if announced:
            ready("STOPPING=1")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only guard for exactly one registered member")
    parser.add_argument("--policy", default=POLICY_PATH)
    parser.add_argument("--state-dir", default=STATE_DIR)
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--prepare-administrator", action='store_true')
    args = parser.parse_args(argv)
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    try:
        run_guard(args.state_dir, load_policy(args.policy), args.worker_id, stop=stopped, prepare_administrator=args.prepare_administrator)
        return 0
    except Exception:
        return 1  # Guard failure is local to its BindsTo member; no sensitive logs.


if __name__ == "__main__":
    raise SystemExit(main())
