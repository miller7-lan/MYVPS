"""Narrow peer-authenticated Unix API for the unprivileged HTTPS process."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import threading
import uuid

from . import registration
from .production_state import ProductionStore
from .store import utcnow

SOCKET_PATH = "/run/dazzle-vps-portal/agent.sock"
MAX_MESSAGE = 16384
READ_OPERATIONS = frozenset({"session.me", "subscription.fetch"})


def peer_uid(connection):
    if hasattr(socket, "SO_PEERCRED"):
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", raw)[1]
    if hasattr(connection, "getpeereid"):
        return connection.getpeereid()[0]
    raise PermissionError("Peer identity is unavailable")


def response(identifier, *, data=None, code=None, message=None):
    return {"ok": code is None, "request_id": identifier, "data": data if code is None else None,
            "error": None if code is None else {"code": code, "message": message}}


def dispatch(store, request, *, now=None):
    identifier = request.get("request_id") if isinstance(request, dict) else None
    try:
        if (not isinstance(request, dict) or set(request) != {"version", "request_id", "operation", "params", "peer_ip"}
                or type(request["version"]) is not int or request["version"] != 1
                or str(uuid.UUID(identifier)) != identifier):
            raise registration.PortalError("VALIDATION", "Invalid portal request")
        store.conn.execute("BEGIN" if request["operation"] in READ_OPERATIONS else "BEGIN IMMEDIATE")
        result = registration.handle_public(store, request["operation"], request["params"], request["peer_ip"], now or utcnow())
        store.conn.commit()
        return response(identifier, data=result)
    except registration.PortalError as exc:
        if store.conn.in_transaction:
            store.conn.commit() if exc.commit else store.conn.rollback()
        return response(identifier, code=exc.code, message=str(exc))
    except (ValueError, TypeError, KeyError, registration.domain.DomainError):
        if store.conn.in_transaction:
            store.conn.rollback()
        return response(identifier, code="VALIDATION", message="Invalid portal request")
    except Exception:
        if store.conn.in_transaction:
            store.conn.rollback()
        return response(identifier, code="UNAVAILABLE", message="Portal is temporarily unavailable")


class PortalServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 8
    block_on_close = False

    def __init__(self, path, *, state_dir, policy):
        self.state_dir, self.policy = state_dir, policy
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(path, PortalHandler)

    def verify_request(self, connection, address):
        try:
            return peer_uid(connection) == self.policy["portal_uid"]
        except (OSError, PermissionError):
            return False

    def process_request(self, connection, address):
        if not self.slots.acquire(False):
            self.shutdown_request(connection)
            return
        try:
            super().process_request(connection, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, connection, address):
        try:
            super().process_request_thread(connection, address)
        finally:
            self.slots.release()

    def handle_error(self, *_):
        pass  # Never log bodies, authentication codes, sessions or subscription URLs.


class PortalHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        raw = self.rfile.readline(MAX_MESSAGE + 1)
        if not raw.endswith(b"\n") or len(raw) > MAX_MESSAGE:
            return
        try:
            request = json.loads(raw)
        except (ValueError, UnicodeError):
            return
        operation = request.get("operation") if isinstance(request, dict) else None
        read_only = isinstance(operation, str) and operation in READ_OPERATIONS
        with ProductionStore(self.server.state_dir, policy=self.server.policy, read_only=read_only) as store:
            result = dispatch(store, request)
        encoded = json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
        # Subscription responses may be larger than the input cap, but remain bounded.
        if len(encoded) <= 3_000_000:
            self.wfile.write(encoded)


class PortalExecutor:
    def __init__(self, store, path=SOCKET_PATH):
        self.policy, self.state_dir, self.path = store.policy, store.state_dir, Path(path)
        self.server = self.thread = None
        self.failed = threading.Event()
        self.enabled = self.policy.get("version") == 2 and bool(self.policy.get("portal_uid"))

    def start(self):
        if self.policy.get("version") != 2 or not self.policy.get("portal_uid"):
            return
        parent = self.path.parent
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o027 or not info.st_mode & stat.S_ISGID):
            raise PermissionError("Portal runtime directory is not private")
        if self.path.exists() or self.path.is_symlink():
            info = self.path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                raise PermissionError("Refusing to replace untrusted socket")
            self.path.unlink()
        self.server = PortalServer(str(self.path), state_dir=self.state_dir, policy=self.policy)
        os.chmod(self.path, 0o660)
        # The root-created setgid runtime directory supplies the web-only group.
        self.thread = threading.Thread(target=self._run, daemon=True, name="dazzle-portal-api")
        self.thread.start()

    def _run(self):
        try:
            self.server.serve_forever(poll_interval=0.2)
        except Exception:
            self.failed.set()

    def close(self):
        if self.server:
            if self.thread and self.thread.is_alive():
                self.server.shutdown()
            self.server.server_close()
            if self.path.exists() and stat.S_ISSOCK(self.path.lstat().st_mode):
                self.path.unlink()
        if self.thread:
            self.thread.join(timeout=1)
