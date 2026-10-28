"""Bounded native streams and one durable writer for the parallel namespace."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
import queue
import signal
import socket
import threading
import time

from . import domain
from .metering import MeteringError, NativeAPI
from .production import (HelperClient, ProductionError, accept_sample, plan_jobs,
                         process_one_job, refresh_worker_status)
from .production_state import ProductionStore
from .store import parse_time, utcnow


# Transport closures also use MeteringError. Only these explicit native-data
# failures bypass the existing bounded reconnect window.
NATIVE_INTEGRITY_ERRORS = frozenset({
    "Missing instance epoch", "Missing worker start epoch", "Invalid worker start epoch",
    "Invalid integer payload counter", "Native API epoch decode failed",
})


class NativeIdentityError(Exception):
    """Local process identity cannot establish a trusted Native stream."""


class Collectors:
    """Reader threads never access SQLite. Queue overflow is an explicit fault."""
    def __init__(self, helper=None, api_factory=NativeAPI, max_events=256, verify_helper=True, identity_probe=None):
        self.helper = helper or HelperClient()
        # Keep the historical flag name for WarmCollectors.arm compatibility.
        # Verification now reads cgroup/proc; it never waits for a helper RPC.
        self.verify_helper = verify_helper
        self.identity_probe = identity_probe
        self.api_factory = api_factory
        self.events = queue.Queue(maxsize=max_events)
        self.overflow = threading.Event()
        self.readers = {}

    def _process_identity(self, worker):
        try:
            pid = worker["process_id"]
            if (worker["role"] not in {"admin", "member"} or worker["observed_state"] not in {"staged", "running"} or
                    type(pid) is not int or pid <= 0):
                raise NativeIdentityError()
            if self.identity_probe is None:
                from .meter_guard import RuntimeProbe
                self.identity_probe = RuntimeProbe()
            actual = self.identity_probe(worker["worker_id"], pid, worker["role"])
            identity = actual.get("identity")
            if (type(actual.get("pid")) is not int or actual["pid"] != pid or not isinstance(identity, str) or
                    not identity.startswith(str(pid) + ":") or not identity[len(str(pid)) + 1:].isascii() or
                    not identity[len(str(pid)) + 1:].isdigit()):
                raise NativeIdentityError()
            return identity
        except Exception:
            raise NativeIdentityError() from None

    def _emit(self, value):
        try:
            self.events.put(value, timeout=0.2)
        except queue.Full:
            self.overflow.set()

    def _read(self, worker, stop):
        key = (worker["worker_id"], worker["observed_generation"])
        while not stop.is_set():
            try:
                verify_identity = self.verify_helper
                before = self._process_identity(worker) if verify_identity else None
                api = self.api_factory("127.0.0.1", worker["api_port"], worker["api_secret"], timeout=2)
                first = True
                for sample in api.stream():
                    if stop.is_set():
                        return
                    if first and verify_identity:
                        # Pin PID/start ticks before opening and after the first
                        # frame. Serial helper operations cannot hold back a real
                        # Native sample; the API also fences its start epoch.
                        if self._process_identity(worker) != before:
                            self._emit((key, "identity_changed", None))
                            return
                    first = False
                    self._emit((key, "sample", sample))
            except NativeIdentityError:
                self._emit((key, "identity_changed", None))
                return
            except Exception as exc:
                kind = "unavailable"
                if isinstance(exc, MeteringError):
                    if str(exc) == "Worker epoch changed while opening traffic stream":
                        # Use the existing fence, including its explicit
                        # exception for a helper-managed process transition.
                        kind = "identity_changed"
                    elif str(exc) in NATIVE_INTEGRITY_ERRORS:
                        kind = "invalid_sample"
                self._emit((key, kind, None))
            stop.wait(0.5)

    @staticmethod
    def _within_reconnect_window(worker, user, now):
        if (worker["observed_state"] not in {"staged", "running"} or worker["tombstoned"] or
                worker["last_error"] or not worker["verified_at"] or not worker["process_id"] or
                worker["observed_generation"] != worker["root_ack_generation"] or
                "metering_failure" in json.loads(user["reasons_json"])):
            return False
        if worker["origin_pending"]:
            # Root has confirmed this new process. Old counters are not a
            # heartbeat for it; only the original verification deadline applies.
            anchor = worker["verified_at"]
        elif user["trusted_sample"] and user["meter_epoch"] and user["last_sample_at"]:
            anchor = user["last_sample_at"]
        else:
            return False
        return 0 <= (now - parse_time(anchor)).total_seconds() <= 5

    def synchronize(self, store):
        rows = [dict(row) for row in store.conn.execute(
            "SELECT * FROM production_workers WHERE user_id IS NOT NULL AND observed_state IN ('staged','running') AND tombstoned=0")]
        wanted = {(row["worker_id"], row["observed_generation"]): row for row in rows}
        for key in list(self.readers):
            if key not in wanted:
                self.readers.pop(key)[0].set()
        for key, row in wanted.items():
            if key in self.readers and self.readers[key][2] != row["process_id"]:
                self.readers.pop(key)[0].set()
            if key not in self.readers:
                row["server_id"] = store.server_id
                stop = threading.Event()
                thread = threading.Thread(target=self._read, args=(row, stop), daemon=True,
                                          name="dazzle-native-reader")
                self.readers[key] = (stop, thread, row["process_id"])
                thread.start()

    def drain(self, store, now=None):
        fixed_now = parse_time(now) if now else None
        if self.overflow.is_set():
            raise ProductionError("COLLECTOR_OVERFLOW", "Native counter queue overflowed; member workers must stop")
        handled = 0
        # A bounded batch prevents a producer from starving the watchdog/tick.
        for _ in range(self.events.maxsize):
            try:
                (worker_id, generation), kind, sample = self.events.get_nowait()
            except queue.Empty:
                break
            store.conn.execute("BEGIN IMMEDIATE")
            try:
                # A lock or a previous frame may have taken time. Compare a real
                # frame with current wall time after acquiring this transaction,
                # not with a stale timestamp from before the whole batch.
                now = fixed_now if fixed_now is not None else utcnow()
                current = store.conn.execute("SELECT * FROM production_workers WHERE worker_id=?", (worker_id,)).fetchone()
                if current is None or current["user_id"] is None:
                    store.conn.commit()
                    continue
                worker = dict(current)
                if kind == "sample":
                    accept_sample(store, worker_id, generation, sample, now)
                elif generation == worker["observed_generation"]:
                    user = store.get_user(worker["user_id"])
                    if user["revoked_at"]:
                        store.conn.commit()
                        continue
                    if kind == "unavailable" and self._within_reconnect_window(worker, user, now):
                        # Keep the last real cumulative baseline untouched. A
                        # later sample must still cover the same five seconds;
                        # retries never extend it or create a trusted heartbeat.
                        store.conn.commit()
                        handled += 1
                        continue
                    if kind == "identity_changed":
                        planned = store.conn.execute("SELECT 1 FROM production_jobs WHERE worker_id=? AND status='executing' AND action IN ('stage','activate')", (worker_id,)).fetchone()
                        if planned:
                            # A managed transition will return origin proof. Do
                            # not mistake its intermediate PID for a crash; the
                            # regular 5s guard still applies if it does not finish.
                            store.conn.commit()
                            continue
                        domain._incident(store, user, "worker_identity_changed", now, context=str(generation))
                        domain._set_reasons(store, user["id"], set(json.loads(user["reasons_json"])) | {"metering_failure"}, now)
                        store.conn.execute("UPDATE users SET trusted_sample=0,meter_state='reconciliation_required' WHERE id=?", (user["id"],))
                        store.conn.execute("UPDATE production_workers SET origin_pending=0,last_error='STATUS_RECHECK_REQUIRED' WHERE worker_id=?", (worker_id,))
                    elif kind == "invalid_sample":
                        domain._incident(store, user, "native_stream_integrity_failure", now, context=str(generation))
                        domain._set_reasons(store, user["id"], set(json.loads(user["reasons_json"])) | {"metering_failure"}, now)
                        store.conn.execute("UPDATE users SET trusted_sample=0,meter_state='reconciliation_required' WHERE id=?", (user["id"],))
                    else:
                        domain.handle_action(store, "meter.failure", {"user_id": user["id"]}, now)
                    plan_jobs(store, now)
                store.conn.commit()
                handled += 1
            except BaseException:
                store.conn.rollback()
                raise
        return handled

    def close(self):
        for stop, _, _ in self.readers.values():
            stop.set()
        self.readers.clear()


def tick(store, now=None):
    now = parse_time(now) if now else utcnow()
    store.now = now
    store.conn.execute("BEGIN IMMEDIATE")
    try:
        result = domain._cycle_tick(store, now)
        from . import recovery, trials
        trials.advance(store, now)
        recovery.advance(store, now)
        plan_jobs(store, now)
        from .registration import queue_activation_notices
        queue_activation_notices(store, now)
        if result["transitioned"]:
            store.set_meta("revision", store.revision + 1)
        store.conn.commit()
    except BaseException:
        store.conn.rollback()
        raise
    return result


def notify(message):
    destination = os.environ.get("NOTIFY_SOCKET")
    if not destination:
        return
    if destination.startswith("@"):
        destination = "\0" + destination[1:]
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        connection.settimeout(0.2)
        connection.sendto(message.encode("ascii"), destination)
    finally:
        connection.close()


class HelperExecutor:
    """One helper job at a time. Long systemd waits never block sample ingestion."""
    def __init__(self, store, helper=None):
        self.state_dir, self.policy = store.state_dir, store.policy
        self.helper = helper or HelperClient()
        self.stopped, self.wake = threading.Event(), threading.Event()
        self.fatal = threading.Event()
        self.results = queue.Queue(maxsize=16)
        self.thread = threading.Thread(target=self._run, daemon=True, name="dazzle-helper-executor")

    def _run(self):
        try:
            with ProductionStore(self.state_dir, policy=self.policy) as connection:
                while not self.stopped.is_set():
                    self.wake.wait(0.5)
                    self.wake.clear()
                    if self.stopped.is_set():
                        return
                    for row in connection.conn.execute("SELECT user_id FROM production_workers WHERE last_error='STATUS_RECHECK_REQUIRED' AND user_id IS NOT NULL").fetchall():
                        refresh_worker_status(connection, self.helper, user_id=row[0])
                    result = process_one_job(connection, self.helper)
                    if result.get("processed"):
                        try:
                            self.results.put(result, timeout=0.2)
                        except queue.Full:
                            self.fatal.set()
                            return
        except Exception:
            self.fatal.set()

    def start(self):
        self.thread.start()

    def close(self):
        self.stopped.set()
        self.wake.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=0.2)


@contextmanager
def single_agent(store, acquired_lock=None):
    if acquired_lock is not None:
        # Ownership was already acquired on this same inode by the standby.
        os.fstat(acquired_lock)
        yield
        return
    descriptor = os.open(store.state_dir / "agent.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def run(store, helper=None, *, acquired_lock=None, collectors=None, stop=None, takeover=False, recovery=False):
    helper = helper or HelperClient()
    collectors = collectors or Collectors(helper)
    stopped = stop or threading.Event()
    executor = HelperExecutor(store, helper)
    from .mail import MailExecutor
    mail_executor = MailExecutor(store)
    from .portal_rpc import PortalExecutor
    portal_executor = PortalExecutor(store)
    from .provider_sync import ProviderExecutor
    provider_executor = ProviderExecutor(store)
    def request_stop(*_):
        stopped.set()
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
    with single_agent(store, acquired_lock):
        try:
            if not takeover:
                refresh_worker_status(store, helper)
            tick(store)
            executor.start()
            mail_executor.start()
            try:
                portal_executor.start()
            except Exception:
                portal_executor.failed.set()  # Portal failure must not stop existing proxy workers.
            try:
                provider_executor.start()
            except Exception:
                provider_executor.failed.set()  # Nor may a QQG reader failure.
            recovery = recovery or bool(store.get_meta("agent_recovery_only", False))
            notify("READY=1\nSTATUS=writer-recovery; reconciliation-required=true" if recovery else "READY=1\nSTATUS=writer-ready; trusted-samples=true")
            last_recovery = recovery
            while not stopped.is_set():
                began = time.monotonic()
                collectors.synchronize(store)
                collectors.drain(store)
                tick(store)
                executor.wake.set()
                mail_state = "error" if mail_executor.failed.is_set() else "running"
                if store.get_meta("mail_worker_status") != mail_state:
                    store.set_meta("mail_worker_status", mail_state)
                portal_state = "not_enabled" if not portal_executor.enabled else "error" if portal_executor.failed.is_set() else "running"
                if store.get_meta("portal_worker_status") != portal_state:
                    store.set_meta("portal_worker_status", portal_state)
                provider_state = "error" if provider_executor.failed.is_set() else "running"
                if store.get_meta("provider_worker_status") != provider_state:
                    store.set_meta("provider_worker_status", provider_state)
                if executor.fatal.is_set():
                    raise ProductionError("HELPER_EXECUTOR_FAILED", "Registered worker executor failed")
                results = []
                while not executor.results.empty():
                    results.append(executor.results.get_nowait())
                if any(result.get("applied") is False for result in results):
                    # Ending the agent causes systemd BindsTo to stop only member
                    # workers independently; administrator has no such binding.
                    endangered = any(row["role"] == "member" and row["observed_state"] == "running" and
                                     not domain.eligible(store.get_user(row["user_id"]), utcnow())
                                     for row in store.conn.execute("SELECT * FROM production_workers WHERE user_id IS NOT NULL"))
                    if endangered:
                        raise ProductionError("PAUSE_UNCONFIRMED", "A member pause could not be confirmed")
                current_recovery = bool(store.get_meta("agent_recovery_only", False))
                if current_recovery != last_recovery:
                    notify("STATUS=writer-recovery; reconciliation-required=true" if current_recovery else "STATUS=writer-ready; recovery-holds-cleared=true")
                    last_recovery = current_recovery
                notify("WATCHDOG=1")
                stopped.wait(max(0, 0.5 - (time.monotonic() - began)))
        finally:
            portal_executor.close()
            provider_executor.close()
            mail_executor.close()
            executor.close()
            collectors.close()
            notify("STOPPING=1")
