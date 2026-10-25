#!/usr/bin/env python3
"""One socket-activated, peer-authenticated root operation on registered workers.

No shell, sudoers, arbitrary unit/path/command, legacy modification, or implicit
installation. The production entry point uses Layout() only. Tests inject a
temporary Layout and fake Runner; no test calls systemctl.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid

MAX_REQUEST = 1024 * 1024
CORE_SHA256 = "1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a"
LEGACY_CONFIG_SHA256 = "6098e06774d74e9e08fd7ad22a974d65671fc64d6258e39915a06cc6bd2567c6"
CREDENTIAL_KEYS = {"vless_uuid", "tuic_uuid", "tuic_password", "short_id", "api_secret"}
VERBS = {"status", "provision", "stage", "activate", "stop", "revoke"}


class HelperError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


@dataclass(frozen=True)
class Layout:
    etc: Path = Path("/etc/dazzle-vps")
    core: Path = Path("/opt/dazzle-vps/core/sing-box")
    cgroup_root: Path = Path("/sys/fs/cgroup")
    trusted_uid: int = 0

    @property
    def policy(self): return self.etc / "policy.json"
    @property
    def registry(self): return self.etc / "registry.json"
    @property
    def lock(self): return self.etc / "registry.lock"
    @property
    def workers(self): return self.etc / "workers"
    @property
    def tls_certificate(self): return self.etc / "tls" / "cert.pem"
    @property
    def tls_key(self): return self.etc / "tls" / "key.pem"


class Runner:
    def run(self, arguments, *, input=None, timeout=15):
        return subprocess.run(arguments, input=input, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, check=False,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})


def canonical_uuid(value):
    if not isinstance(value, str):
        raise HelperError("VALIDATION", "A canonical UUID is required")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        raise HelperError("VALIDATION", "A canonical UUID is required") from None
    return value


def checked_path(path, trusted_uid=0, *, directory=False, missing=False):
    """Root-owned, non-writable-by-others, non-symlink path components."""
    path = Path(path)
    for part in [*reversed(path.parents), path]:
        if part == Path("/"):
            continue
        try:
            info = part.lstat()
        except FileNotFoundError:
            if missing and part == path:
                return None
            raise HelperError("FILESYSTEM", "Required project file is unavailable") from None
        if stat.S_ISLNK(info.st_mode):
            raise HelperError("FILESYSTEM", "Symlink paths are not permitted")
        # Test roots can live beneath /tmp, but project-owned paths are always checked.
        if part == path:
            expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
            if not expected or info.st_uid != trusted_uid or info.st_mode & 0o022:
                raise HelperError("FILESYSTEM", "Unsafe project file ownership or mode")
            if not directory and info.st_nlink != 1:
                raise HelperError("FILESYSTEM", "Hard-linked project files are not permitted")
    return info


def read_json(path, trusted_uid=0):
    checked_path(path, trusted_uid)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        payload = stream.read(MAX_REQUEST + 1)
    if len(payload) > MAX_REQUEST:
        raise HelperError("FILESYSTEM", "Project state exceeds its size limit")
    try:
        return json.loads(payload, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError):
        raise HelperError("FILESYSTEM", "Project state is invalid") from None


def atomic_bytes(path, payload, *, mode=0o600, trusted_uid=0, gid=None):
    path = Path(path)
    checked_path(path.parent, trusted_uid, directory=True)
    checked_path(path, trusted_uid, missing=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".dazzle-", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        if gid is not None:
            os.fchown(descriptor, trusted_uid, gid)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def atomic_json(path, value, trusted_uid=0):
    atomic_bytes(path, json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n", trusted_uid=trusted_uid)


def validate_policy(value):
    required = {"version", "server_id", "server_endpoint", "agent_uid", "core_sha256", "workers"}
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] not in {1, 2}:
        raise HelperError("POLICY", "Unsupported root policy")
    if value["version"] == 2:
        required.add("portal_uid")
    if set(value) != required:
        raise HelperError("POLICY", "Unexpected root policy fields")
    canonical_uuid(value["server_id"])
    try:
        endpoint = ipaddress.ip_address(value["server_endpoint"])
        if endpoint.version != 4 or endpoint.is_loopback or endpoint.is_unspecified or endpoint.is_multicast:
            raise ValueError()
    except ValueError:
        raise HelperError("POLICY", "Root policy requires an approved IPv4 endpoint") from None
    if type(value["agent_uid"]) is not int or value["agent_uid"] <= 0:
        raise HelperError("POLICY", "Root policy requires an installed agent UID")
    if value["version"] == 2 and (type(value.get("portal_uid")) is not int or value["portal_uid"] <= 0 or value["portal_uid"] == value["agent_uid"]):
        raise HelperError("POLICY", "A distinct installed portal UID is required")
    if value["core_sha256"] != CORE_SHA256:
        raise HelperError("POLICY", "Root policy has an invalid core digest")
    if not isinstance(value["workers"], dict) or not value["workers"]:
        raise HelperError("POLICY", "Root policy has no registered workers")
    occupied, roles = set(), []
    for worker_id, worker in value["workers"].items():
        canonical_uuid(worker_id)
        if not isinstance(worker, dict) or set(worker) != {"role", "public_port", "api_port"}:
            raise HelperError("POLICY", "Invalid registered worker")
        role = worker["role"]
        expected = {"admin": (24430, 34430), "member": (24431, 34431)}.get(role)
        if value["version"] == 2 and role == "member":
            public = worker["public_port"]
            if type(public) is not int or not 24431 <= public <= 24436:
                raise HelperError("POLICY", "Worker is outside the approved resource pool")
            expected = (public, public + 10000)
        if expected is None or type(worker["public_port"]) is not int or type(worker["api_port"]) is not int or (worker["public_port"], worker["api_port"]) != expected:
            raise HelperError("POLICY", "Worker ports are outside the approved pilot")
        if (role in roles and (value["version"] == 1 or role == "admin")) or any(port in occupied for port in expected):
            raise HelperError("POLICY", "Duplicate pilot slot")
        roles.append(role); occupied.update(expected)
    return value


def validate_credentials(params):
    if not isinstance(params, dict) or set(params) != CREDENTIAL_KEYS:
        raise HelperError("VALIDATION", "Exactly the typed worker credentials are required")
    canonical_uuid(params["vless_uuid"]); canonical_uuid(params["tuic_uuid"])
    for key in ("tuic_password", "api_secret"):
        if not isinstance(params[key], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", params[key]):
            raise HelperError("VALIDATION", "Worker credentials have an invalid shape")
    if not isinstance(params["short_id"], str) or not re.fullmatch(r"[a-f0-9]{16}", params["short_id"]):
        raise HelperError("VALIDATION", "Worker credentials have an invalid shape")
    return dict(params)


class Helper:
    def __init__(self, layout=None, runner=None):
        self.layout, self.runner = layout or Layout(), runner or Runner()

    @contextmanager
    def serialized(self):
        checked_path(self.layout.etc, self.layout.trusted_uid, directory=True)
        descriptor = os.open(self.layout.lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.layout.trusted_uid or info.st_mode & 0o077 or info.st_nlink != 1:
                raise HelperError("FILESYSTEM", "Unsafe registry lock")
            deadline = time.monotonic() + 8
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB); break
                except BlockingIOError:
                    if time.monotonic() >= deadline: raise HelperError("BUSY", "Worker operation is busy") from None
                    time.sleep(0.025)
            yield
        finally:
            os.close(descriptor)

    def _run(self, args, *, input=None, timeout=15):
        try:
            result = self.runner.run(args, input=input, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            raise HelperError("EXECUTION", "The owned worker operation failed") from None
        if result.returncode:
            raise HelperError("EXECUTION", "The owned worker operation failed")
        return result.stdout

    def _core(self, policy):
        checked_path(self.layout.core, self.layout.trusted_uid)
        if hashlib.sha256(self.layout.core.read_bytes()).hexdigest() != policy["core_sha256"]:
            raise HelperError("CORE_CHANGED", "Pinned proxy core no longer matches the policy")

    def _unit(self, worker_id, worker):
        prefix = "dazzle-admin" if worker["role"] == "admin" else "dazzle-proxy"
        return prefix + "@" + canonical_uuid(worker_id) + ".service"

    def _actual(self, worker_id, worker):
        unit = self._unit(worker_id, worker)
        raw = self._run(["/usr/bin/systemctl", "show", unit, "--property=ActiveState,SubState,MainPID,ControlGroup"])
        try:
            fields = dict(line.split("=", 1) for line in raw.decode().splitlines() if "=" in line)
            active, pid, cgroup = fields["ActiveState"], int(fields["MainPID"]), fields["ControlGroup"]
            if active not in {"active", "inactive", "failed", "activating", "deactivating", "reloading"} or pid < 0:
                raise ValueError()
            expected_group = "/system.slice/" + unit
            if cgroup not in ("", expected_group): raise ValueError()
            inactive = active in {"inactive", "failed"} and pid == 0
            if inactive and cgroup:
                path = self.layout.cgroup_root / cgroup.lstrip("/") / "cgroup.procs"
                for part in [path, *path.parents]:
                    if part == self.layout.cgroup_root.parent: break
                    if part.is_symlink(): raise ValueError()
                try: inactive = not path.read_text().strip()
                except FileNotFoundError: inactive = True  # systemd already removed this exact cgroup
            return {"active": active == "active" and pid > 0, "pid": pid or None,
                    "inactive": inactive, "unit": unit}
        except (ValueError, KeyError, UnicodeError, OSError):
            raise HelperError("STATE", "Owned worker state could not be verified") from None

    def _stop(self, worker_id, worker):
        self._run(["/usr/bin/systemctl", "stop", self._unit(worker_id, worker)])
        for _ in range(20):
            actual = self._actual(worker_id, worker)
            if actual["inactive"]: return actual
            time.sleep(0.05)
        raise HelperError("STOP_FAILED", "Owned worker cgroup is not confirmed inactive")

    def _config(self, worker_id, worker, credentials, private_key, *, active):
        config = {
            "log": {"level": "warn", "timestamp": True},
            "services": [{"type": "api", "tag": "private-meter", "listen": "127.0.0.1",
                          "listen_port": worker["api_port"], "secret": credentials["api_secret"],
                          "dashboard": {"enabled": False}, "access_control_allow_origin": ["https://invalid.example"],
                          "access_control_allow_private_network": False}],
            "inbounds": [], "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"rules": [{"ip_is_private": True, "action": "reject"}], "final": "direct"},
        }
        if active:
            config["inbounds"] = [
                {"type": "vless", "tag": "vless", "listen": "0.0.0.0", "listen_port": worker["public_port"],
                 "users": [{"name": worker_id, "uuid": credentials["vless_uuid"], "flow": "xtls-rprx-vision"}],
                 "tls": {"enabled": True, "server_name": "www.microsoft.com", "reality": {"enabled": True,
                          "handshake": {"server": "www.microsoft.com", "server_port": 443},
                          "private_key": private_key, "short_id": [credentials["short_id"]]}}},
                {"type": "tuic", "tag": "tuic", "listen": "0.0.0.0", "listen_port": worker["public_port"],
                 "users": [{"name": worker_id, "uuid": credentials["tuic_uuid"], "password": credentials["tuic_password"]}],
                 "congestion_control": "bbr", "zero_rtt_handshake": False, "auth_timeout": "3s",
                 "tls": {"enabled": True, "min_version": "1.3", "alpn": ["h3"],
                          "certificate_path": str(self.layout.tls_certificate), "key_path": str(self.layout.tls_key)}}]
        return config

    def _install_config(self, worker_id, config, policy):
        self._core(policy)
        checked_path(self.layout.workers, self.layout.trusted_uid, directory=True)
        target = self.layout.workers / (worker_id + ".json")
        checked_path(target, self.layout.trusted_uid, missing=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".validate-", suffix=".json", dir=self.layout.workers)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(json.dumps(config, separators=(",", ":")).encode()); stream.flush(); os.fsync(stream.fileno())
            self._run([str(self.layout.core), "check", "-c", temporary])
            os.replace(temporary, target)
            parent = os.open(self.layout.workers, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(parent)
            finally: os.close(parent)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)

    def _data(self, policy, worker_id, worker, record, actual, *, origin=False):
        if record.get("tombstoned"):
            state = "revoked" if actual["inactive"] else "stop_failed"
        elif actual["active"]:
            state = record.get("mode") if record.get("mode") in {"staged", "running"} else "unexpected_running"
        elif record.get("mode") in {"unprovisioned", "provisioned"}:
            state = record["mode"]
        else:
            state = "stopped" if actual["inactive"] else "stop_pending"
        return {"server_id": policy["server_id"], "worker_id": worker_id, "role": worker["role"],
                "worker_state": state, "generation": record.get("generation", 0),
                "public_key": record.get("public_key"), "process_id": actual["pid"],
                "api_port": worker["api_port"], "public_port": worker["public_port"],
                "managed_origin_zero": bool(origin and actual["active"]),
                "tombstoned": bool(record.get("tombstoned")), "inactive_confirmed": actual["inactive"],
                "recovery_required": record.get("operation", {}).get("status") in {"pending", "failed"}}

    def dispatch(self, request, *, peer_uid):
        identifier = request.get("request_id") if isinstance(request, dict) else None
        try:
            if not isinstance(request, dict) or set(request) != {"version", "request_id", "action", "worker_id", "generation", "params"} or type(request["version"]) is not int or request["version"] != 1:
                raise HelperError("VALIDATION", "Unsupported helper request")
            canonical_uuid(identifier); worker_id = canonical_uuid(request["worker_id"])
            action, generation, params = request["action"], request["generation"], request["params"]
            if action not in VERBS or type(generation) is not int or generation < 0 or generation > 2**63 - 1 or not isinstance(params, dict):
                raise HelperError("VALIDATION", "Invalid helper operation")
            if action in {"provision", "stage", "activate"}: credentials = validate_credentials(params)
            elif params: raise HelperError("VALIDATION", "This operation accepts no parameters")
            else: credentials = None
            with self.serialized():
                policy = validate_policy(read_json(self.layout.policy, self.layout.trusted_uid))
                if peer_uid not in {0, policy["agent_uid"]}:
                    raise HelperError("FORBIDDEN", "Helper peer is not authorized")
                if worker_id not in policy["workers"]:
                    raise HelperError("FORBIDDEN", "Worker is not registered in root policy")
                worker = policy["workers"][worker_id]
                if self.layout.registry.exists(): registry = read_json(self.layout.registry, self.layout.trusted_uid)
                else: registry = {"version": 1, "server_id": policy["server_id"], "workers": {}}
                if registry.get("version") != 1 or registry.get("server_id") != policy["server_id"] or not isinstance(registry.get("workers"), dict):
                    raise HelperError("STATE", "Root registry identity mismatch")
                record = registry["workers"].setdefault(worker_id, {"generation": 0, "mode": "unprovisioned", "tombstoned": False})
                actual = self._actual(worker_id, worker)
                if action == "status":
                    return self._response(identifier, self._data(policy, worker_id, worker, record, actual))
                if registry.get("maintenance") and action not in {"stop", "revoke"}:
                    raise HelperError("MAINTENANCE", "Project runtime is held for an explicitly reviewed recovery")
                fingerprint = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                operation = record.get("operation", {})
                if generation < record["generation"] or generation == 0:
                    raise HelperError("STALE_GENERATION", "Worker generation is stale")
                if generation == record["generation"]:
                    if operation.get("fingerprint") != fingerprint:
                        raise HelperError("STALE_GENERATION", "Worker generation was already used")
                    if operation.get("status") == "complete":
                        prior = operation["response"]
                        if action in {"stop", "revoke"} and not actual["inactive"]:
                            raise HelperError("STOP_FAILED", "Owned worker cgroup is no longer inactive")
                        if prior["managed_origin_zero"] and (not actual["active"] or actual["pid"] != prior["process_id"]):
                            raise HelperError("RECOVERY_REQUIRED", "Worker origin changed after the completed operation")
                        return self._response(identifier, prior)
                    if action == "activate" and actual["active"]:
                        raise HelperError("RECOVERY_REQUIRED", "Interrupted activation requires an explicit owned stop")
                elif generation != record["generation"] + 1:
                    raise HelperError("STALE_GENERATION", "Worker generation must advance exactly once")
                if record.get("tombstoned") and action not in {"revoke", "stop"}:
                    raise HelperError("REVOKED", "Permanently revoked worker cannot be started")
                if action in {"stage", "activate"} and not record.get("private_key"):
                    raise HelperError("STATE", "Worker must be provisioned before starting")
                if action == "activate" and record.get("mode") not in {"staged", "running"}:
                    raise HelperError("STATE", "Activation requires an API-only stage first")
                if action in {"provision", "stage", "activate"}:
                    self._core(policy)
                record["generation"] = generation
                record["operation"] = {"request_id": identifier, "fingerprint": fingerprint, "action": action, "status": "pending"}
                if action == "revoke": record["tombstoned"] = True
                atomic_json(self.layout.registry, registry, self.layout.trusted_uid)
                try:
                    origin = False
                    if action == "provision":
                        if actual["active"]:
                            raise HelperError("STATE", "Stop the worker before provisioning")
                        if not record.get("private_key"):
                            output = self._run([str(self.layout.core), "generate", "reality-keypair"])
                            try:
                                keys = dict(line.split(":", 1) for line in output.decode().splitlines() if ":" in line)
                                private_key, public_key = keys["PrivateKey"].strip(), keys["PublicKey"].strip()
                                if not all(re.fullmatch(r"[A-Za-z0-9_-]{43}", key) for key in (private_key, public_key)): raise ValueError()
                            except (ValueError, KeyError, UnicodeError):
                                raise HelperError("EXECUTION", "Proxy key generation failed") from None
                            record.update(private_key=private_key, public_key=public_key)
                        record.update(credentials=credentials, mode="provisioned")
                    elif action in {"stage", "activate"}:
                        if action == "activate":
                            checked_path(self.layout.tls_certificate, self.layout.trusted_uid)
                            checked_path(self.layout.tls_key, self.layout.trusted_uid)
                        config = self._config(worker_id, worker, credentials, record["private_key"], active=action == "activate")
                        self._install_config(worker_id, config, policy)
                        record.update(credentials=credentials, mode="running" if action == "activate" else "staged")
                        atomic_json(self.layout.registry, registry, self.layout.trusted_uid)
                        self._run(["/usr/bin/systemctl", "restart", self._unit(worker_id, worker)])
                        actual = self._actual(worker_id, worker)
                        if not actual["active"]: raise HelperError("START_FAILED", "Owned worker did not become active")
                        origin = True
                    else:
                        actual = self._stop(worker_id, worker)
                        record["mode"] = "revoked" if record.get("tombstoned") else "stopped"
                    record["operation"]["status"] = "complete"
                    data = self._data(policy, worker_id, worker, record, actual, origin=origin)
                    record["operation"]["response"] = data
                    atomic_json(self.layout.registry, registry, self.layout.trusted_uid)
                    return self._response(identifier, data)
                except HelperError:
                    record["operation"]["status"] = "failed"
                    atomic_json(self.layout.registry, registry, self.layout.trusted_uid)
                    raise
        except HelperError as exc:
            return self._response(identifier, error=exc)
        except Exception:
            return self._response(identifier, error=HelperError("INTERNAL", "The owned operation could not be completed"))

    @staticmethod
    def _response(identifier, data=None, error=None):
        return {"ok": error is None, "request_id": identifier, "data": data if error is None else None,
                "error": {"code": error.code, "message": error.message} if error else None}


def serve_connection(connection, helper=None):
    helper = helper or Helper()
    connection.settimeout(40)
    request_id = None
    try:
        _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        payload = bytearray()
        while b"\n" not in payload:
            chunk = connection.recv(min(65536, MAX_REQUEST + 1 - len(payload)))
            if not chunk: break
            payload.extend(chunk)
            if len(payload) > MAX_REQUEST: raise HelperError("VALIDATION", "Helper request exceeds size limit")
        line, _, trailing = bytes(payload).partition(b"\n")
        if trailing.strip(): raise HelperError("VALIDATION", "Only one helper request is permitted")
        request = json.loads(line, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        request_id = request.get("request_id") if isinstance(request, dict) else None
        response = helper.dispatch(request, peer_uid=uid)
    except HelperError as exc:
        response = Helper._response(request_id, error=exc)
    except Exception:
        response = Helper._response(request_id, error=HelperError("VALIDATION", "Helper request could not be read"))
    try: connection.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")
    except OSError: pass


def main():
    # Accept=yes hands exactly one AF_UNIX connection to stdin/stdout.
    connection = socket.fromfd(0, socket.AF_UNIX, socket.SOCK_STREAM)
    try: serve_connection(connection)
    finally: connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
