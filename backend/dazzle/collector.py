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
import uuid

from . import domain
from .metering import NativeAPI
from .production import (HelperClient, ProductionError, accept_sample, plan_jobs,
                         process_one_job, refresh_worker_status)
from .production_state import ProductionStore
from .store import parse_time, utcnow


class Collectors:
    """Reader threads never access SQLite. Queue overflow is an explicit fault."""
    def __init__(self, helper=None, api_factory=NativeAPI, max_events=256):
        self.helper = helper or HelperClient()
        self.api_factory = api_factory
        self.events = queue.Queue(maxsize=max_events)
        self.overflow = threading.Event()
        self.readers = {}

    def _emit(self, value):
        try:
            self.events.put(value, timeout=0.2)
        except queue.Full:
            self.overflow.set()

    def _read(self, worker, stop):
        key = (worker["worker_id"], worker["observed_generation"])
        while not stop.is_set():
            try:
                api = self.api_factory("127.0.0.1", worker["api_port"], worker["api_secret"], timeout=2)
                first = True
                for sample in api.stream():
                    if stop.is_set():
                        return
                    if first:
                        # Status after the first frame fences a restart between
                        # helper activation and opening the native API stream.
                        result = self.helper.call({"version": 1, "request_id": str(uuid.uuid4()),
                                                   "action": "status", "worker_id": worker["worker_id"],
                                                   "generation": 0, "params": {}})
                        if (result.get("server_id") != worker["server_id"] or result.get("worker_id") != worker["worker_id"] or
                                result.get("process_id") != worker["process_id"] or
                                result.get("worker_state") != worker["observed_state"]):
                            self._emit((key, "identity_changed", None))
                            return
                        first = False
                    self._emit((key, "sample", sample))
            except Exception:
                self._emit((key, "unavailable", None))
            stop.wait(0.5)

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
        now = parse_time(now) if now else utcnow()
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
                worker = store.worker(worker_id)
                if kind == "sample":
                    accept_sample(store, worker_id, generation, sample, now)
                elif generation == worker["observed_generation"]:
                    user = store.get_user(worker["user_id"])
                    if user["revoked_at"]:
                        store.conn.commit()
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
        plan_jobs(store, now)
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
                    if connection.conn.execute("SELECT 1 FROM production_workers WHERE last_error='STATUS_RECHECK_REQUIRED' LIMIT 1").fetchone():
                        refresh_worker_status(connection, self.helper)
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
def single_agent(store):
    descriptor = os.open(store.state_dir / "agent.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def run(store, helper=None):
    helper = helper or HelperClient()
    collectors = Collectors(helper)
    stopped = threading.Event()
    executor = HelperExecutor(store, helper)
    from .mail import MailExecutor
    mail_executor = MailExecutor(store)
    def stop(*_):
        stopped.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with single_agent(store):
        try:
            refresh_worker_status(store, helper)
            tick(store)
            executor.start()
            mail_executor.start()
            notify("READY=1")
            while not stopped.is_set():
                began = time.monotonic()
                collectors.synchronize(store)
                collectors.drain(store)
                tick(store)
                executor.wake.set()
                mail_state = "error" if mail_executor.failed.is_set() else "running"
                if store.get_meta("mail_worker_status") != mail_state:
                    store.set_meta("mail_worker_status", mail_state)
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
                notify("WATCHDOG=1")
                stopped.wait(max(0, 0.5 - (time.monotonic() - began)))
        finally:
            mail_executor.close()
            executor.close()
            collectors.close()
            notify("STOPPING=1")
