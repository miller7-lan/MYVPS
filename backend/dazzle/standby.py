"""Read-only prewarming and same-inode flock handoff to the sole ledger writer."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import stat
import subprocess
import threading
import time

from . import domain
from .meter_guard import GuardError, RuntimeProbe, age, read_proof
from .production_state import ProductionStore
from .store import parse_time, utcnow


class HandoffError(Exception):
    pass


class WarmCollectors:
    """Reuse live streams without persisting a pre-lock frame or filling a queue."""
    def __init__(self, helper=None, api_factory=None, runtime_probe=None):
        from .collector import Collectors
        self.runtime_probe = runtime_probe or RuntimeProbe()
        self.collector = Collectors(helper, **({"api_factory": api_factory} if api_factory else {}),
                                    verify_helper=False, identity_probe=self.runtime_probe)
        self.lock, self.latest = threading.RLock(), {}
        self.writer = False
        self.reader_generation = 0
        self.collector._emit = lambda value: self._emit_generation(0, value)

    def _emit_generation(self, generation, value):
        with self.lock:
            if generation != self.reader_generation:
                return
            self._emit(value)

    def _emit(self, value):
        key, kind, sample = value
        with self.lock:
            if self.writer:
                try:
                    self.collector.events.put(value, timeout=0.2)
                except queue.Full:
                    self.collector.overflow.set()
            else:
                self.latest[key] = (kind, sample)

    def synchronize(self, store):
        self.collector.synchronize(store)

    def restart_after_lock(self, store):
        from .collector import Collectors
        previous = self.collector
        previous.close()
        with self.lock:
            self.reader_generation += 1
            generation = self.reader_generation
            self.latest.clear()
            self.collector = Collectors(previous.helper, api_factory=previous.api_factory, verify_helper=False,
                                        identity_probe=self.runtime_probe)
            self.collector._emit = lambda value: self._emit_generation(generation, value)
        self.synchronize(store)

    def verify(self, store, *, after=None):
        if store.conn.execute("SELECT 1 FROM production_jobs WHERE status IN ('pending','executing') LIMIT 1").fetchone():
            raise HandoffError("Managed operations are pending; handoff is not quiescent")
        rows = [dict(row) for row in store.conn.execute("SELECT * FROM production_workers WHERE user_id IS NOT NULL AND observed_state IN ('running','staged') AND tombstoned=0")]
        seeds, evidence = [], []
        for worker in rows:
            expected = store.policy["workers"].get(worker["worker_id"])
            if not expected or any(worker[key] != expected[key] for key in ("role", "api_port", "public_port")):
                raise HandoffError("Worker policy mismatch")
            user = store.get_user(worker["user_id"])
            now = utcnow()
            # An API-only stage with an unresolved incident is not automatically
            # reconciled or activated by an upgrade. It may stay staged, but a
            # running member must have fully trusted current authorisation.
            if worker["observed_state"] == "running" and worker["role"] == "member" and not domain.eligible(user, now):
                raise HandoffError("A running member is not trusted and authorized")
            if not user["trusted_sample"] or not user["meter_epoch"] or worker["origin_pending"]:
                raise HandoffError("Ledger origin is not ready")
            try:
                ledger_age = age(user["last_sample_at"], now)
            except GuardError:
                raise HandoffError("Ledger sample is not fresh") from None
            actual = self.runtime_probe(worker["worker_id"], worker["process_id"], worker["role"])
            if actual["pid"] != worker["process_id"] or not actual["pid"]:
                raise HandoffError("Registered process identity changed")
            key = (worker["worker_id"], worker["observed_generation"])
            with self.lock:
                value = self.latest.get(key)
            if not value or value[0] != "sample":
                raise HandoffError("Native stream is not warm")
            sample = value[1]
            sample.validate()
            now = utcnow()
            try:
                ledger_age = age(user["last_sample_at"], now)
                native_age = age(sample.at, now)
            except GuardError:
                raise HandoffError("Native sample is not fresh") from None
            if sample.epoch != user["meter_epoch"]:
                raise HandoffError("Native epoch differs from ledger")
            if after is not None and (parse_time(sample.at) < after or parse_time(sample.at) <= parse_time(user["last_sample_at"]) or sample.uplink < user["last_uplink"] or sample.downlink < user["last_downlink"]):
                raise HandoffError("Waiting for a post-writer cumulative sample")
            seeds.append((worker["worker_id"], worker["observed_generation"], sample))
            evidence.append({"worker_id": worker["worker_id"], "role": worker["role"], "pid": worker["process_id"],
                             "generation": worker["observed_generation"], "epoch_hash": hashlib.sha256(sample.epoch.encode()).hexdigest(),
                             "ledger_age": round(ledger_age, 3), "native_age": round(native_age, 3)})
        return seeds, evidence

    def arm(self):
        with self.lock:
            self.writer = True
            self.collector.verify_helper = True
        return self.collector

    def close(self):
        self.collector.close()



def registered_unit(worker_id):
    """Read-only systemd query; never infer absence from an API failure."""
    command = ["/usr/bin/systemctl", "show", "dazzle-proxy@" + worker_id + ".service",
               "--property=LoadState,ActiveState,MainPID,ControlGroup"]
    try:
        result = subprocess.run(command, capture_output=True, timeout=2)
        fields = dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)
        if result.returncode or fields["LoadState"] != "loaded":
            raise ValueError()
        pid = int(fields["MainPID"])
        expected = "/system.slice/dazzle-proxy@" + worker_id + ".service"
        if pid < 0 or fields["ControlGroup"] not in {"", expected}:
            raise ValueError()
        return {"active": fields["ActiveState"], "pid": pid}
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError):
        raise HandoffError("Registered unit state is unknown") from None


def recovery_evidence(store, warm, *, unit_probe=registered_unit, proof_reader=read_proof):
    """Prove that recovery cannot start over an existing public member proxy."""
    if store.conn.execute("SELECT 1 FROM production_jobs j JOIN production_workers w ON w.worker_id=j.worker_id WHERE w.role='member' AND j.status='executing' AND j.action='activate' LIMIT 1").fetchone():
        raise HandoffError("An activation may still be executing")
    evidence = []
    for row in store.conn.execute("SELECT * FROM production_workers WHERE role='member'"):
        worker = dict(row)
        unit = unit_probe(worker["worker_id"])
        actual = warm.runtime_probe(worker["worker_id"], worker["process_id"], "member")
        if actual["pid"] in {None, 0}:
            if unit["active"] not in {"inactive", "failed"} or unit["pid"] != 0:
                raise HandoffError("Core absence is not confirmed")
            evidence.append({"worker_id": worker["worker_id"], "phase": "confirmed-inactive", "pid": None})
            continue
        if unit["active"] != "active" or unit["pid"] != actual["pid"]:
            raise HandoffError("Registered process state conflicts")
        try:
            proof = proof_reader(store.policy, worker["worker_id"])
        except GuardError:
            raise HandoffError("API-only proof is unavailable") from None
        if (not proof or proof["mode"] != "staged" or proof["phase"] != "complete" or
                proof["process_id"] != actual["pid"] or proof["generation"] != worker["observed_generation"]):
            raise HandoffError("A member may still provide public proxy access")
        with warm.lock:
            latest = warm.latest.get((worker["worker_id"], worker["observed_generation"]))
        if not latest or latest[0] != "sample":
            raise HandoffError("Live API-only observation is unavailable")
        try:
            sample_age = age(latest[1].at, utcnow())
        except GuardError:
            raise HandoffError("Live API-only observation is stale") from None
        evidence.append({"worker_id": worker["worker_id"], "phase": "root-proven-api-only", "pid": actual["pid"], "native_age": sample_age})
    return evidence


def prepare_recovery(store):
    """Preserve totals and old incidents; never turn an unknown gap into zero."""
    now = utcnow()
    store.conn.execute("BEGIN IMMEDIATE")
    try:
        store.set_meta("agent_recovery_only", True)
        holds = store.get_meta("agent_recovery_holds", {})
        for row in store.conn.execute("SELECT * FROM users WHERE role='member' AND revoked_at IS NULL").fetchall():
            user = dict(row)
            holds[user["id"]] = {"created_at": user.get("last_sample_at"), "reason": "cold_writer_continuity_review"}
            domain._incident(store, user, "writer_recovery_requires_reconciliation", now,
                             context="No active public member Core; prior ledger continuity requires explicit review")
            domain._set_reasons(store, user["id"], set(json.loads(user["reasons_json"])) | {"metering_failure"}, now)
            store.conn.execute("UPDATE users SET trusted_sample=0,meter_state='reconciliation_required' WHERE id=?", (user["id"],))
        store.set_meta("agent_recovery_holds", holds)
        store.conn.commit()
    except BaseException:
        store.conn.rollback()
        raise


def _open_existing_lock(state_dir):
    path = Path(state_dir) / "agent.lock"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
        os.close(descriptor)
        raise HandoffError("Existing writer lock is not trusted")
    return descriptor


def _same_inode(state_dir, descriptor):
    path = Path(state_dir) / "agent.lock"
    info, current = os.fstat(descriptor), path.lstat()
    if stat.S_ISLNK(current.st_mode) or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino) or current.st_nlink != 1:
        raise HandoffError("Writer lock inode changed")
    return info.st_ino


def run_standby(state_dir, policy, *, helper=None, stop=None, warm=None, notify=None, emit=None, run_writer=None,
                allow_no_core_recovery=False, unit_probe=registered_unit, proof_reader=read_proof):
    from .collector import notify as service_notify, run
    from .production import accept_sample
    notify, emit = notify or service_notify, emit or (lambda evidence: print(json.dumps(evidence, separators=(",", ":")), flush=True))
    stop = stop or threading.Event()
    warm = warm or WarmCollectors(helper)
    run_writer = run_writer or run
    descriptor = _open_existing_lock(state_dir)
    ready_once, acquired = False, False
    last_status = 0.0
    try:
        while not stop.is_set():
            inode = _same_inode(state_dir, descriptor)
            try:
                with ProductionStore(state_dir, policy=policy, read_only=True) as reader:
                    reader.conn.execute("BEGIN")
                    warm.synchronize(reader)
                    _, evidence = warm.verify(reader)
            except HandoffError:
                if ready_once:
                    notify("STATUS=standby-warming; writer=false")
                ready_once = False
                if allow_no_core_recovery:
                    try:
                        with ProductionStore(state_dir, policy=policy, read_only=True) as reader:
                            reader.conn.execute("BEGIN")
                            evidence = recovery_evidence(reader, warm, unit_probe=unit_probe, proof_reader=proof_reader)
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except (HandoffError, BlockingIOError):
                        stop.wait(0.1)
                        continue
                    acquired = True
                    _same_inode(state_dir, descriptor)
                    with ProductionStore(state_dir, policy=policy) as writer:
                        # Repeat physical evidence after exclusive ownership.
                        recovery_evidence(writer, warm, unit_probe=unit_probe, proof_reader=proof_reader)
                        prepare_recovery(writer)
                        emit({"phase": "writer-recovery", "writer": True, "pid": os.getpid(), "server_id": policy["server_id"],
                              "lock_inode": inode, "member_proxy_grants": False, "workers": evidence})
                        notify("STATUS=writer-recovery; writer=true; member_proxy_grants=false")
                        run_writer(writer, helper, acquired_lock=descriptor, stop=stop, recovery=True)
                    return
                stop.wait(0.1)
                continue
            if not ready_once:
                emit({"phase": "standby-ready", "writer": False, "pid": os.getpid(), "server_id": policy["server_id"], "lock_inode": inode, "workers": evidence})
                notify("STATUS=standby-ready; writer=false; pid=" + str(os.getpid()) + "; lock_inode=" + str(inode))
                ready_once = True
            if time.monotonic() - last_status >= 0.5:
                notify("STATUS=standby-ready; writer=false; pid=" + str(os.getpid()) + "; lock_inode=" + str(inode) + "; checked_ns=" + str(time.monotonic_ns()))
                last_status = time.monotonic()
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                stop.wait(0.1)
                continue
            acquired = True
            # Only after exclusive ownership may ProductionStore migrate or any
            # cumulative observation be persisted. Never restart a proxy here.
            acquired_at, acquired_wall = time.monotonic(), utcnow()
            with ProductionStore(state_dir, policy=policy) as writer:
                warm.restart_after_lock(writer)
                while not stop.is_set():
                    try:
                        seeds, evidence = warm.verify(writer, after=acquired_wall)
                        break
                    except HandoffError:
                        if time.monotonic() - acquired_at >= 5:
                            raise HandoffError("First trusted handoff sample exceeded five seconds")
                        stop.wait(0.05)
                else:
                    return
                collectors = warm.arm()
                writer.conn.execute("BEGIN IMMEDIATE")
                try:
                    for worker_id, generation, sample in seeds:
                        result = accept_sample(writer, worker_id, generation, sample, utcnow())
                        if result.get("ignored"):
                            raise HandoffError("Seed sample was not accepted")
                    writer.set_meta("agent_recovery_only", bool(writer.get_meta("agent_recovery_holds", {})))
                    writer.conn.commit()
                except BaseException:
                    writer.conn.rollback()
                    raise
                emit({"phase": "writer-ready", "writer": True, "pid": os.getpid(), "server_id": policy["server_id"], "lock_inode": inode, "workers": evidence})
                notify("STATUS=writer-ready; writer=true; lock_inode=" + str(inode))
                run_writer(writer, helper, acquired_lock=descriptor, collectors=collectors, stop=stop, takeover=True)
            return
    finally:
        warm.close()
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
