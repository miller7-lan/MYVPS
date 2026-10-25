"""Explicit parallel production controller. Never manages legacy services.

Imports have no side effects. Helper/network I/O is outside SQLite transactions.
The fixed installed wrapper, not arbitrary RPC parameters, chooses policy/state.
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

from . import domain
from .production_state import (HELPER_SOCKET, POLICY_PATH, STATE_DIR, SUBSCRIPTION_PORT,
                               TLS_CERT, TLS_KEY, ProductionStore, load_policy)
from .store import parse_time, timestamp, utcnow

READS = {"doctor", "status", "snapshot", "user.list", "user.resolve", "user.export", "deploy.preview", "rollback.preview", "mail.status"}
WRITES = {"user.add", "user.enable", "user.disable", "user.revoke", "user.rotate", "user.update",
          "user.topup", "user.delete", "settings.update", "provider.observe", "meter.reconcile",
          "mail.configure", "mail.verify.send", "mail.verify.confirm", "mail.test", "mail.preferences"}
ALLOWED_ACTIONS = READS | WRITES
MAX_MESSAGE = 1024 * 1024
PARAMETERS = {
    "snapshot": set(), "status": set(), "doctor": set(), "user.list": {"include_deleted"}, "mail.status": set(),
    "user.resolve": {"user_id", "name"}, "user.export": {"user_id", "format"},
    "deploy.preview": set(), "rollback.preview": {"target"},
    "user.add": {"name", "role", "quota_bytes"},
    **{action: {"user_id"} for action in ("user.enable", "user.disable", "user.revoke", "user.rotate", "user.delete")},
    "mail.configure": {"host", "port", "security", "username", "sender", "admin_email", "secret"},
    "mail.verify.send": {"user_id", "email"}, "mail.verify.confirm": {"user_id", "email", "code"},
    "mail.test": {"user_id"}, "mail.preferences": {"enabled", "cooldown_seconds", "max_attempts"},
    "user.update": {"user_id", "name", "quota_bytes", "unlimited", "auto_restore", "threshold_percent", "email"},
    "user.topup": {"user_id", "bytes"}, "meter.reconcile": {"user_id", "evidence"},
    "settings.update": {"default_quota_bytes", "admin_reserve_bytes", "safety_margin_bytes", "day", "time", "timezone"},
    "provider.observe": {"instance_id", "remaining_display", "total_display", "expected_reset_date", "evidence", "kind",
                         "external_cycle_id", "last_actual_reset_at", "cycle_start_at", "expected_reset_at", "timezone",
                         "unit_verified", "total_bytes", "remaining_bytes"},
}


class ProductionError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class HelperClient:
    def __init__(self, path: str = HELPER_SOCKET, timeout: float = 30):
        self.path, self.timeout = path, timeout

    def call(self, request: dict) -> dict:
        raw = json.dumps(request, separators=(",", ":")).encode() + b"\n"
        if len(raw) > MAX_MESSAGE:
            raise ProductionError("VALIDATION", "Helper request exceeds limit")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(self.path)
            connection.sendall(raw)
            connection.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                chunk = connection.recv(min(65536, MAX_MESSAGE + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > MAX_MESSAGE:
                    raise ValueError()
            envelope = json.loads(response)
            if envelope.get("request_id") != request["request_id"]:
                raise ValueError()
            if envelope.get("ok") is not True:
                code = envelope.get("error", {}).get("code", "HELPER_FAILED")
                raise ProductionError(code if isinstance(code, str) and code.isupper() else "HELPER_FAILED",
                                      "Registered worker operation was not confirmed")
            data = envelope.get("data")
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except ProductionError:
            raise
        except Exception:
            raise ProductionError("HELPER_UNAVAILABLE", "Private worker helper is unavailable") from None
        finally:
            connection.close()


def _worker_public(row: dict) -> dict:
    keys = ("worker_id", "role", "public_port", "api_port", "generation", "root_ack_generation", "observed_generation", "observed_state",
            "process_id", "verified_at", "last_error", "tombstoned")
    return {key: row[key] for key in keys}


def snapshot(store: ProductionStore, now=None) -> dict:
    now = parse_time(now) if now else store.now
    value = domain.snapshot(store, now)
    value.update({"mode": "production", "environment": "production", "server_id": store.server_id,
                  "capabilities": {"controller": "root_policy", "allowed_actions": sorted(ALLOWED_ACTIONS),
                                   "production_mutations": True, "legacy_retirement": False},
                  "legacy": {"managed": False, "ports": [443, 8443], "retirement_supported": False},
                  "accounting_scope": "New registered workers only; legacy443 and provider NIC billing excluded"})
    for user in value["users"] + value["deleted_users"]:
        worker = store.worker(user["id"])
        state = worker["observed_state"]
        blocked = bool(user["disabled_reasons"])
        if user["status"] == "revoked" and state != "revoked":
            state = "stop_failed" if worker["last_error"] else "stop_pending"
        elif blocked and state == "running":
            state = "stop_failed" if worker["last_error"] else "stop_pending"
        elif not blocked and state in {"staged", "provisioned"}:
            state = "starting"
        user.update({"requested_authorization": "revoked" if user["status"] == "revoked" else
                     "disabled" if store.get_user(user["id"])["manual_disabled"] else "enabled",
                     "runtime_state": state, "runtime_verified_at": worker["verified_at"],
                     "last_error": worker["last_error"], "worker": _worker_public(worker)})
    from .mail import snapshot_mail
    value["mail"] = snapshot_mail(store)
    value["health"].update({"proxy": "parallel_workers", "metering": "native_payload",
                            "mail": "smtp" if value["mail"]["configured"] else "not_enabled", "ssh": "fixed_control_entry"})
    return value


def _add_user(store: ProductionStore, params: dict, now) -> dict:
    role = params.get("role", "member")
    if role not in {"member", "admin"}:
        raise domain.DomainError("VALIDATION", "Invalid user role")
    row = store.conn.execute("SELECT * FROM production_workers WHERE role=? AND user_id IS NULL AND tombstoned=0 ORDER BY public_port LIMIT 1", (role,)).fetchone()
    if row is None:
        raise domain.DomainError("APPROVAL_REQUIRED", "No unused approved slot for this role; expand the root manifest first")
    if role == "admin" and store.conn.execute("SELECT 1 FROM users WHERE role='admin' AND revoked_at IS NULL").fetchone():
        raise domain.DomainError("VALIDATION", "One live administrator is permitted")
    identifier = row["worker_id"]
    quota = None if role == "admin" else domain.integer(params.get("quota_bytes", store.get_setting("default_quota_bytes")), "quota_bytes", 1)
    store.conn.execute("INSERT INTO users(id,name,role,port,quota_bytes,unlimited,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                       (identifier, domain.text(params.get("name"), "name"), role, row["public_port"], quota,
                        int(role == "admin"), timestamp(now), timestamp(now)))
    domain._new_credentials(store, identifier, 1, now)
    store.conn.execute("UPDATE credentials SET reality_public_key='' WHERE user_id=?", (identifier,))
    store.conn.execute("UPDATE production_workers SET user_id=?,api_secret=? WHERE worker_id=?",
                       (identifier, secrets.token_urlsafe(36), identifier))
    return {"user": domain._public_user(store, store.get_user(identifier), now)}


def _response(identifier, revision, *, data=None, code=None, message=None):
    return {"ok": code is None, "request_id": identifier, "revision": revision,
            "data": data if code is None else None,
            "error": None if code is None else {"code": code, "message": message}}


def handle_request(store: ProductionStore, request: dict, now=None) -> dict:
    identifier = request.get("request_id") if isinstance(request, dict) else None
    try:
        if not isinstance(store, ProductionStore) or store.get_meta("mode") != "production":
            raise domain.DomainError("READ_ONLY", "An isolated production store and root policy are required")
        from .rpc import _validate
        identifier, action, params = _validate(request)
        if action not in ALLOWED_ACTIONS:
            raise domain.DomainError("READ_ONLY", "This action is not available in production")
        if set(params) - PARAMETERS[action]:
            raise domain.DomainError("VALIDATION", "Unknown production action parameters")
        if set(request) - {"api_version", "request_id", "action", "expected_revision", "params", "server_id"}:
            raise domain.DomainError("VALIDATION", "Unknown production envelope fields")
        if set(params) & {"at", "now", "clock", "epoch", "uplink", "downlink"}:
            raise domain.DomainError("VALIDATION", "Production clocks and meter samples cannot be injected")
        sensitive = action == "user.export"
        private_request = (action == "mail.configure" and "secret" in params) or action == "mail.verify.confirm"
        if (action in WRITES or sensitive) and request.get("server_id") != store.server_id:
            raise domain.DomainError("SERVER_ID_MISMATCH", "Refresh and confirm the registered server identity")
        if request.get("server_id") is not None and request["server_id"] != store.server_id:
            raise domain.DomainError("SERVER_ID_MISMATCH", "Registered server identity mismatch")
        now = parse_time(now) if now else utcnow()
        store.now = now
        fingerprint = hashlib.sha256(json.dumps({"server_id": store.server_id, "action": action, "params": params},
                                                sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if sensitive and identifier in store.memory_responses:
            cached = store.memory_responses[identifier]
            if cached[0] != fingerprint:
                raise domain.DomainError("VALIDATION", "Request identifier was reused")
            return copy.deepcopy(cached[1])
        store.conn.execute("BEGIN IMMEDIATE")
        cached = store.conn.execute("SELECT fingerprint,response_json FROM requests WHERE request_id=?", (identifier,)).fetchone()
        if cached:
            if cached["fingerprint"] != fingerprint:
                raise domain.DomainError("VALIDATION", "Request identifier was reused")
            store.conn.rollback()
            return json.loads(cached["response_json"])
        if action in WRITES or sensitive:
            if type(request.get("expected_revision")) is not int or request["expected_revision"] != store.revision:
                raise domain.DomainError("REVISION_CONFLICT", "Refresh before applying this change")
        domain.ensure_cycle(store, now)
        if action in {"snapshot", "status"}:
            data = snapshot(store, now)
        elif action == "doctor":
            data = {"mode": "production", "server_id": store.server_id, "schema_version": 1,
                    "database": "ready", "health": snapshot(store, now)["health"],
                    "capabilities": snapshot(store, now)["capabilities"]}
        elif action == "user.list":
            include = params.get("include_deleted", False)
            if type(include) is not bool:
                raise domain.DomainError("VALIDATION", "include_deleted must be boolean")
            current = snapshot(store, now)
            data = {"users": current["users"] + (current["deleted_users"] if include else []),
                    "deleted_users": current["deleted_users"]}
        elif action == "user.resolve":
            selected = params.get("user_id", params.get("name"))
            users = [u for u in snapshot(store, now)["users"] if u["id"] == selected or u["name"] == selected]
            if len(users) != 1:
                raise domain.DomainError("NOT_FOUND", "A unique registered user was not found")
            data = {"user": users[0]}
        elif action in {"deploy.preview", "rollback.preview"}:
            if action == "rollback.preview" and params.get("target", "last_good") not in {"last_good", "baseline"}:
                raise domain.DomainError("VALIDATION", "Unknown rollback target")
            data = {"mode": "production", "applied": False, "legacy_retirement": False,
                    "target": params.get("target", "last_good"),
                    "preserve": ["legacy443", "legacy8443", "SSH", "ledger", "revocations"],
                    "workers": [_worker_public(dict(row)) for row in store.conn.execute("SELECT * FROM production_workers")]}
        elif action == "user.export":
            data = render_export(store, domain._user(store, params), params.get("format", "shadowrocket"))
        elif action == "user.add":
            data = _add_user(store, params, now)
        else:
            data = domain.handle_action(store, action, params, now)
        if action in WRITES:
            if params.get("user_id") and action in {"user.enable", "user.disable", "user.revoke", "user.delete", "meter.reconcile"}:
                store.conn.execute("UPDATE production_workers SET last_error=NULL WHERE user_id=?", (params["user_id"],))
            plan_jobs(store, now)
            store.set_meta("revision", store.revision + 1)
            store.conn.execute("INSERT INTO operations VALUES(?,?,?,?,?)", (str(uuid.uuid4()), action, "requested",
                                timestamp(now), "Parallel project only; legacy services are outside control"))
            data = {**data, "snapshot": snapshot(store, now)}
        response = _response(identifier, store.revision, data=data)
        if action in WRITES and not private_request:
            store.conn.execute("INSERT INTO requests VALUES(?,?,?,?)", (identifier, fingerprint,
                                json.dumps(response, ensure_ascii=False), timestamp(now)))
        store.conn.commit()
        if sensitive:
            store.memory_responses[identifier] = (fingerprint, copy.deepcopy(response))
        return response
    except (domain.DomainError, ProductionError) as exc:
        if store.conn.in_transaction:
            store.conn.rollback()
        return _response(identifier, store.revision, code=exc.code, message=str(exc))
    except ValueError:
        if store.conn.in_transaction:
            store.conn.rollback()
        return _response(identifier, store.revision, code="VALIDATION", message="Invalid mail or user settings")
    except Exception:
        if store.conn.in_transaction:
            store.conn.rollback()
        return _response(identifier, store.revision, code="INTERNAL", message="The registered production operation could not be completed")


def _parameters(store, worker):
    credentials = store.get_credentials(worker["user_id"])
    return {key: credentials[key] for key in ("vless_uuid", "tuic_uuid", "tuic_password", "short_id")} | {"api_secret": worker["api_secret"]}


def refresh_worker_status(store: ProductionStore, helper=None, now=None) -> None:
    """Reconcile root registry/cgroup facts after agent restart, never assume DB running."""
    if store.conn.in_transaction:
        raise RuntimeError("Status probe cannot run inside a SQLite transaction")
    helper = helper or HelperClient()
    now = parse_time(now) if now else utcnow()
    workers = [dict(row) for row in store.conn.execute("SELECT * FROM production_workers WHERE user_id IS NOT NULL")]
    for worker in workers:
        result = helper.call({"version": 1, "request_id": str(uuid.uuid4()), "action": "status",
                              "worker_id": worker["worker_id"], "generation": 0, "params": {}})
        if (result.get("server_id") != store.server_id or result.get("worker_id") != worker["worker_id"] or
                result.get("role") != worker["role"] or result.get("public_port") != worker["public_port"] or
                result.get("api_port") != worker["api_port"] or type(result.get("generation")) is not int):
            raise ProductionError("HELPER_IDENTITY_MISMATCH", "Registered status probe identity mismatch")
        store.conn.execute("BEGIN IMMEDIATE")
        try:
            user = store.get_user(worker["user_id"])
            if result.get("tombstoned"):
                store.conn.execute("UPDATE users SET revoked_at=COALESCE(revoked_at,?),manual_disabled=1 WHERE id=?", (timestamp(now), user["id"]))
                store.conn.execute("DELETE FROM credentials WHERE user_id=?", (user["id"],))
                store.conn.execute("UPDATE production_workers SET tombstoned=1,observed_state=?,generation=?,root_ack_generation=?,verified_at=? WHERE worker_id=?",
                                   ("revoked" if result.get("inactive_confirmed") else "stop_failed", result["generation"], result["generation"], timestamp(now), worker["worker_id"]))
                store.conn.execute("UPDATE production_jobs SET status='cancelled',completed_at=? WHERE worker_id=? AND action!='revoke' AND status IN ('pending','executing')", (timestamp(now), worker["worker_id"]))
            else:
                pending = store.conn.execute("SELECT * FROM production_jobs WHERE worker_id=? AND generation=? AND status IN ('pending','executing')",
                                             (worker["worker_id"], result["generation"])).fetchone()
                # An accepted operation must be replayed with its original request
                # to recover managed origin proof. status alone never invents it.
                if pending and not result.get("recovery_required"):
                    store.conn.commit()
                    continue
                state = result.get("worker_state")
                if state not in {"unprovisioned", "provisioned", "staged", "running", "stopped", "stop_failed"}:
                    raise ProductionError("HELPER_STATE_UNCONFIRMED", "Root worker state is invalid")
                changed = (worker["observed_state"] in {"running", "staged"} and
                           (result.get("process_id") != worker["process_id"] or state != worker["observed_state"]))
                rollback = result["generation"] < worker["root_ack_generation"]
                if rollback:
                    raise ProductionError("ROOT_REGISTRY_ROLLBACK", "Root registry generation went backwards")
                if changed or result.get("recovery_required") or result["generation"] > worker["generation"]:
                    domain._incident(store, user, "worker_status_changed", now, context=str(result["generation"]))
                    domain._set_reasons(store, user["id"], set(json.loads(user["reasons_json"])) | {"metering_failure"}, now)
                    store.conn.execute("UPDATE users SET trusted_sample=0,meter_state='reconciliation_required' WHERE id=?", (user["id"],))
                store.conn.execute("UPDATE production_workers SET generation=?,root_ack_generation=?,observed_generation=?,observed_state=?,process_id=?,"
                                   "verified_at=?,origin_pending=CASE WHEN ? THEN 0 ELSE origin_pending END,last_error=? WHERE worker_id=?",
                                   (result["generation"], result["generation"], result["generation"], state, result.get("process_id"), timestamp(now),
                                    int(changed), "RECOVERY_REQUIRED" if result.get("recovery_required") else None, worker["worker_id"]))
            plan_jobs(store, now)
            store.conn.commit()
        except BaseException:
            store.conn.rollback()
            raise


def plan_jobs(store: ProductionStore, now) -> None:
    for row in store.conn.execute("SELECT * FROM production_workers WHERE user_id IS NOT NULL").fetchall():
        worker = dict(row)
        if store.conn.execute("SELECT 1 FROM production_jobs WHERE worker_id=? AND status IN ('pending','executing')", (worker["worker_id"],)).fetchone():
            continue
        user = store.get_user(worker["user_id"])
        if worker["tombstoned"] or user["revoked_at"]:
            action = "revoke" if worker["observed_state"] != "revoked" else None
        elif worker["last_error"] == "RECOVERY_REQUIRED":
            action = "stop"
        elif worker["last_error"]:
            continue
        elif not worker["provisioned"]:
            action = "provision"
        elif worker["observed_state"] in {"provisioned", "stopped", "stop_failed"}:
            action = "stage"
        elif worker["credential_version"] != user["credential_version"]:
            action = "stage"
        elif domain.eligible(user, now):
            action = "activate" if worker["observed_state"] == "staged" and user["trusted_sample"] else None
        else:
            action = "stage" if worker["observed_state"] == "running" else None
        if not action:
            continue
        generation = worker["root_ack_generation"] + 1
        identifier = str(uuid.uuid4())
        request = {"version": 1, "request_id": identifier, "action": action, "worker_id": worker["worker_id"],
                   "generation": generation, "params": _parameters(store, worker) if action in {"provision", "stage", "activate"} else {}}
        store.conn.execute("INSERT INTO production_jobs(id,worker_id,generation,credential_version,action,payload_json,created_at) VALUES(?,?,?,?,?,?,?)",
                           (identifier, worker["worker_id"], generation, user["credential_version"], action,
                            json.dumps(request, separators=(",", ":")), timestamp(now)))
        store.conn.execute("UPDATE production_workers SET generation=? WHERE worker_id=?", (generation, worker["worker_id"]))


def process_one_job(store: ProductionStore, helper=None, now=None) -> dict:
    """Claim/commit, perform bounded I/O, then confirm/commit. Never hold DB over I/O."""
    helper = helper or HelperClient()
    explicit_clock = now is not None
    now = parse_time(now) if explicit_clock else utcnow()
    if store.conn.in_transaction:
        raise RuntimeError("Helper I/O cannot run inside a SQLite transaction")
    store.conn.execute("BEGIN IMMEDIATE")
    plan_jobs(store, now)
    row = store.conn.execute("SELECT * FROM production_jobs WHERE status IN ('pending','executing') ORDER BY rowid LIMIT 1").fetchone()
    if row is None:
        store.conn.commit()
        return {"processed": False}
    job = dict(row)
    worker = dict(store.conn.execute("SELECT * FROM production_workers WHERE worker_id=?", (job["worker_id"],)).fetchone())
    user = store.get_user(worker["user_id"])
    stale = job["credential_version"] != user["credential_version"] or (
        job["action"] == "activate" and not domain.eligible(user, now)) or (
        job["action"] != "revoke" and bool(user["revoked_at"]))
    if stale:
        if job["attempts"] > 0:
            store.conn.rollback()
            # The call may have reached root before the response was lost. Read
            # root truth before cancelling, never reuse an uncertain generation.
            status = helper.call({"version": 1, "request_id": str(uuid.uuid4()), "action": "status",
                                  "worker_id": worker["worker_id"], "generation": 0, "params": {}})
            if status.get("server_id") != store.server_id or status.get("worker_id") != worker["worker_id"] or type(status.get("generation")) is not int:
                raise ProductionError("HELPER_IDENTITY_MISMATCH", "Uncertain generation could not be reconciled")
            store.conn.execute("BEGIN IMMEDIATE")
            if status["generation"] >= job["generation"]:
                domain._incident(store, store.get_user(worker["user_id"]), "uncertain_helper_transition", now, context=job["id"])
                store.conn.execute("UPDATE production_workers SET root_ack_generation=?,generation=?,observed_state=?,origin_pending=0,last_error='RECOVERY_REQUIRED' WHERE worker_id=?",
                                   (status["generation"], status["generation"], status.get("worker_state", "stop_failed"), worker["worker_id"]))
                store.conn.execute("UPDATE users SET trusted_sample=0,meter_state='reconciliation_required' WHERE id=?", (worker["user_id"],))
        store.conn.execute("UPDATE production_jobs SET status='cancelled',completed_at=? WHERE id=?", (timestamp(now), job["id"]))
        store.conn.execute("UPDATE production_workers SET generation=root_ack_generation WHERE worker_id=?", (worker["worker_id"],))
        store.conn.commit()
        return {"processed": False, "cancelled": True}
    store.conn.execute("UPDATE production_jobs SET status='executing',attempts=attempts+1 WHERE id=?", (job["id"],))
    store.conn.commit()
    try:
        result = helper.call(json.loads(job["payload_json"]))
        if (result.get("server_id") != store.server_id or result.get("worker_id") != worker["worker_id"] or
                result.get("generation") != job["generation"] or result.get("role") != worker["role"] or
                result.get("public_port") != worker["public_port"] or result.get("api_port") != worker["api_port"]):
            raise ProductionError("HELPER_IDENTITY_MISMATCH", "Worker helper identity did not match root policy")
        desired = {"provision": "provisioned", "stage": "staged", "activate": "running", "stop": "stopped", "revoke": "revoked"}[job["action"]]
        if result.get("worker_state") != desired or (job["action"] in {"stop", "revoke"} and result.get("inactive_confirmed") is not True):
            raise ProductionError("HELPER_STATE_UNCONFIRMED", "Worker state was not confirmed")
        if job["action"] in {"stage", "activate"} and (result.get("managed_origin_zero") is not True or type(result.get("process_id")) is not int):
            raise ProductionError("ORIGIN_UNCONFIRMED", "Managed worker origin was not confirmed")
    except Exception as exc:
        code = exc.code if isinstance(exc, ProductionError) else "HELPER_FAILED"
        acknowledged = None
        if code != "HELPER_UNAVAILABLE":
            try:
                status = helper.call({"version": 1, "request_id": str(uuid.uuid4()), "action": "status",
                                      "worker_id": worker["worker_id"], "generation": 0, "params": {}})
                if (status.get("server_id") == store.server_id and status.get("worker_id") == worker["worker_id"] and
                        type(status.get("generation")) is int and status["generation"] >= worker["root_ack_generation"]):
                    acknowledged = status["generation"]
            except Exception:
                pass
        store.conn.execute("BEGIN IMMEDIATE")
        retry = code == "HELPER_UNAVAILABLE" and job["attempts"] < 2
        store.conn.execute("UPDATE production_jobs SET status=?,completed_at=?,error_code=? WHERE id=?", ("pending" if retry else "failed", timestamp(now), code, job["id"]))
        store.conn.execute("UPDATE production_workers SET last_error=? WHERE worker_id=?", (code, worker["worker_id"]))
        if acknowledged is not None:
            store.conn.execute("UPDATE production_workers SET root_ack_generation=?,generation=? WHERE worker_id=?",
                               (acknowledged, acknowledged, worker["worker_id"]))
        if not retry:
            domain._incident(store, store.get_user(worker["user_id"]), "helper_operation_unconfirmed", now, context=job["id"])
            store.conn.execute("UPDATE users SET trusted_sample=0,meter_state='reconciliation_required' WHERE id=?", (worker["user_id"],))
            domain._set_reasons(store, worker["user_id"], set(json.loads(store.get_user(worker["user_id"])["reasons_json"])) | {"metering_failure"}, now)
        store.conn.commit()
        return {"processed": True, "applied": False, "error_code": code}
    now = now if explicit_clock else utcnow()
    store.conn.execute("BEGIN IMMEDIATE")
    try:
        current_user = store.get_user(worker["user_id"])
        if worker["observed_state"] == "running" and job["action"] in {"stage", "stop", "revoke"}:
            domain._incident(store, current_user, "managed_stop_tail", now, context=job["id"])
        if (job["action"] in {"stage", "activate", "stop", "revoke"} and current_user["meter_epoch"] and
                current_user["last_sample_at"] and worker["observed_generation"] > 0):
            store.conn.execute("INSERT OR REPLACE INTO production_retired_origins VALUES(?,?,?,?,?,?,?,?,?)",
                               (worker["worker_id"], worker["observed_generation"], worker["user_id"], current_user["meter_epoch"],
                                current_user["last_uplink"], current_user["last_downlink"], current_user["last_sample_at"],
                                timestamp(now), domain.ensure_cycle(store, now)["id"]))
        origin = int(job["action"] in {"stage", "activate"})
        public_key = result.get("public_key") or worker["public_key"]
        if job["action"] not in {"stop", "revoke"} and (not isinstance(public_key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key)):
            raise ProductionError("INVALID_PUBLIC_KEY", "No usable registered REALITY public key")
        store.conn.execute("UPDATE production_workers SET observed_state=?,observed_generation=?,root_ack_generation=?,provisioned=1,credential_version=?,"
                           "public_key=?,process_id=?,origin_pending=?,origin_epoch=NULL,verified_at=?,last_error=NULL,tombstoned=? WHERE worker_id=?",
                           (desired, job["generation"], job["generation"], job["credential_version"], public_key, result.get("process_id"), origin,
                            timestamp(now), int(job["action"] == "revoke" or result.get("tombstoned", False)), worker["worker_id"]))
        store.conn.execute("UPDATE credentials SET reality_public_key=? WHERE user_id=?", (public_key, worker["user_id"]))
        store.conn.execute("INSERT INTO runtime_state VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET status=excluded.status,runtime_version=excluded.runtime_version,updated_at=excluded.updated_at",
                           (worker["user_id"], "running" if desired == "running" else "stopped", job["credential_version"], timestamp(now)))
        store.conn.execute("UPDATE runtime_queue SET status='applied',applied_at=?,detail=? WHERE user_id=? AND status='pending'",
                           (timestamp(now), "Confirmed registered worker: " + desired, worker["user_id"]))
        store.conn.execute("UPDATE production_jobs SET status='applied',completed_at=?,payload_json='{}' WHERE id=?", (timestamp(now), job["id"]))
        # If permissions changed during bounded helper I/O, queue a compensating
        # stage/revoke immediately; never report the stale start as authorized.
        # Do not issue another restart until the collector observed this origin.
        if not origin:
            plan_jobs(store, now)
        store.conn.commit()
    except BaseException:
        store.conn.rollback()
        raise
    return {"processed": True, "applied": True, "worker_state": desired}


def accept_sample(store: ProductionStore, worker_id: str, generation: int, sample, now=None) -> dict:
    now = parse_time(now) if now else utcnow()
    sample.validate()
    worker = dict(store.conn.execute("SELECT * FROM production_workers WHERE worker_id=?", (worker_id,)).fetchone())
    if worker["observed_generation"] != generation or worker["observed_state"] not in {"staged", "running"}:
        return _retired_sample(store, worker, generation, sample, now)
    user = store.get_user(worker["user_id"])
    if worker["tombstoned"]:
        return {"ignored": True, "reason": "revoked"}
    if worker["origin_pending"]:
        if (not worker["verified_at"] or parse_time(sample.at) < parse_time(worker["verified_at"]) or
                (now - parse_time(sample.at)).total_seconds() > 5):
            return {"ignored": True, "reason": "origin_sample_outside_window"}
        # Only a successful helper-controlled process creation opens this gate.
        # First cumulative sample may be nonzero: charge every byte from origin0.
        blocking = store.conn.execute("SELECT 1 FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL AND kind!='managed_stop_tail' LIMIT 1", (user["id"],)).fetchone()
        reasons = set(json.loads(user["reasons_json"]))
        if not blocking:
            reasons.discard("metering_failure")
        domain._set_reasons(store, user["id"], reasons, now)
        store.conn.execute("UPDATE users SET meter_epoch=?,last_uplink=0,last_downlink=0,last_sample_at=?,trusted_sample=1,meter_state=? WHERE id=?",
                           (sample.epoch, sample.at, "reconciliation_required" if "metering_failure" in reasons else "trusted", user["id"]))
        store.conn.execute("UPDATE production_workers SET origin_pending=0,origin_epoch=? WHERE worker_id=?", (sample.epoch, worker_id))
    result = domain._sample(store, {"user_id": user["id"], "epoch": sample.epoch, "uplink": sample.uplink,
                                    "downlink": sample.downlink, "at": sample.at}, now, allow_revoked=True)
    plan_jobs(store, now)
    return result


def _retired_sample(store, worker, generation, sample, now):
    retired = store.conn.execute("SELECT * FROM production_retired_origins WHERE worker_id=? AND generation=?",
                                 (worker["worker_id"], generation)).fetchone()
    if not retired or sample.epoch != retired["epoch"]:
        return {"ignored": True, "reason": "fenced_generation"}
    at, previous = parse_time(sample.at), parse_time(retired["last_at"])
    if at <= previous or at > parse_time(retired["retired_at"]):
        return {"ignored": True, "reason": "retired_sample_outside_window"}
    up, down = sample.uplink - retired["last_upload"], sample.downlink - retired["last_download"]
    user = store.get_user(worker["user_id"])
    known = up >= 0 and down >= 0
    current_cycle = domain.ensure_cycle(store, now)["id"]
    if known and (at - previous).total_seconds() <= 5 and current_cycle == retired["cycle_id"]:
        if user["used_upload"] + user["used_download"] + up + down > domain.MAX_INT:
            raise ProductionError("COUNTER_OVERFLOW", "Recorded usage exceeds supported range")
        minute = at.replace(second=0, microsecond=0)
        bucket = hashlib.sha256(f"{user['id']}:{current_cycle}:{sample.epoch}:{timestamp(minute)}".encode()).hexdigest()
        if up or down:
            store.conn.execute("INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET upload=ledger.upload+excluded.upload,download=ledger.download+excluded.download,sample_at=excluded.sample_at",
                               (bucket, user["id"], current_cycle, sample.epoch, up, down, sample.at, timestamp(now)))
            store.conn.execute("UPDATE users SET used_upload=used_upload+?,used_download=used_download+? WHERE id=?", (up, down, user["id"]))
            domain._quota(store, user["id"], now)
        allocated = True
    else:
        domain._incident(store, user, "retired_origin_unallocated", now, epoch=sample.epoch, at=at,
                         upload=sample.uplink, download=sample.downlink,
                         known_delta=(up, down) if known else None, context=str(generation))
        allocated = False
    store.conn.execute("UPDATE production_retired_origins SET last_upload=?,last_download=?,last_at=? WHERE worker_id=? AND generation=?",
                       (sample.uplink, sample.downlink, sample.at, worker["worker_id"], generation))
    return {"retired": True, "allocated": allocated, "upload_delta": up if known else None, "download_delta": down if known else None}


def render_export(store: ProductionStore, user: dict, format_name: str) -> dict:
    if format_name not in {"shadowrocket", "mihomo", "uris"}:
        raise domain.DomainError("VALIDATION", "Unsupported export format")
    worker = store.worker(user["id"])
    if user["revoked_at"] or worker["tombstoned"]:
        raise domain.DomainError("REVOKED", "Revoked credentials cannot be exported")
    if not worker["provisioned"] or not worker["public_key"] or worker["credential_version"] != user["credential_version"]:
        raise domain.DomainError("NOT_PROVISIONED", "Wait for the registered worker to be provisioned")
    from . import rendering
    endpoint = store.policy["server_endpoint"]
    options = {"endpoint": endpoint, "public_key": worker["public_key"], "production": True}
    nodes = rendering.node_uris(store, user, **options)
    if format_name == "mihomo":
        content = json.dumps(rendering.mihomo(store, user, **options), ensure_ascii=False, indent=2) + "\n"
        extension = "yaml"
    elif format_name == "shadowrocket":
        content, extension = rendering.shadowrocket(store, user, **options), "conf"
    else:
        content, extension = "\n".join(nodes) + "\n", "txt"
    token = store.get_credentials(user["id"])["subscription_token"]
    base = f"https://{endpoint}:{SUBSCRIPTION_PORT}/{token}/"
    return {"sensitive": True, "environment": "production", "server_id": store.server_id, "deployed": True,
            "runtime_state": worker["observed_state"], "filename": "Dazzle-VPS." + extension,
            "content": content, "nodes": list(nodes), "nodes_url": base + "nodes.txt", "config_url": base + "config.conf",
            "subscription_url": base + ("config.yaml" if format_name == "mihomo" else "nodes.txt")}


def subscription_response(store: ProductionStore, token: str, route: str, now=None) -> dict:
    now = parse_time(now) if now else utcnow()
    user_id = None
    if isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_-]{24,128}", token):
        for row in store.conn.execute("SELECT user_id,subscription_token FROM credentials"):
            if secrets.compare_digest(row["subscription_token"], token):
                user_id = row["user_id"]
    headers = {"Cache-Control": "no-store"}
    if user_id is None or route not in {"nodes.txt", "config.conf", "config.yaml"}:
        return {"status": 404, "headers": headers, "body": b""}
    user = store.get_user(user_id)
    worker = store.worker(user_id)
    if not domain.eligible(user, now) or worker["observed_state"] != "running" or worker["tombstoned"]:
        return {"status": 403, "headers": headers, "body": b""}
    artifact = render_export(store, user, {"nodes.txt": "uris", "config.conf": "shadowrocket", "config.yaml": "mihomo"}[route])
    allowance = 0 if user["unlimited"] else user["quota_bytes"] + user["topup_bytes"]
    headers["Subscription-Userinfo"] = f"upload={user['used_upload']}; download={user['used_download']}; total={allowance}"
    headers["Profile-Title"] = "Dazzle'VPS (personal payload)"
    headers["profile-update-interval"] = "1"
    body = artifact["content"].encode()
    if route == "nodes.txt":
        body = base64.b64encode(body)
    return {"status": 200, "headers": headers, "body": body}


class RateLimit:
    def __init__(self, limit=100, window=60, capacity=1024):
        self.limit, self.window, self.capacity = limit, window, capacity
        self.values = {}
        self.lock = threading.Lock()

    def allow(self, address, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            self.values = {key: value for key, value in self.values.items() if now - value[0] < self.window}
            if address not in self.values:
                if len(self.values) >= self.capacity:
                    return False
                self.values[address] = (now, 0)
            start, count = self.values[address]
            self.values[address] = (start, count + 1)
            return count < self.limit


class TLSContexts:
    """New connections reload a validated pair; an intermediate mismatch keeps old context."""
    def __init__(self, cert=TLS_CERT, key=TLS_KEY):
        self.cert, self.key = cert, key
        self.context = None
        self.fingerprint = None
        self.lock = threading.Lock()
        self.get()

    def get(self):
        with self.lock:
            try:
                fingerprint = tuple((os.stat(path).st_ino, os.stat(path).st_mtime_ns, os.stat(path).st_size)
                                    for path in (self.cert, self.key))
                if fingerprint != self.fingerprint:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.load_cert_chain(self.cert, self.key)
                    self.context, self.fingerprint = context, fingerprint
            except (OSError, ssl.SSLError):
                if self.context is None:
                    raise
            return self.context


class SubscriptionServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16
    allow_reuse_address = True
    def __init__(self, address, handler, contexts, max_connections=16):
        self.contexts = contexts
        self.slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        try:
            connection = self.contexts.get().wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
            return connection, address
        except Exception:
            connection.close()
            raise

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, *_):
        pass  # Request targets and tokens must never appear in tracebacks/logs.


def subscription_handler(policy, state_dir):
    limiter = RateLimit()
    class Handler(BaseHTTPRequestHandler):
        server_version = ""
        sys_version = ""
        def setup(self):
            super().setup()
            self.connection.settimeout(5)
        def log_message(self, *_):
            pass
        def send_error(self, code, message=None, explain=None):
            self.send_response(code)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
        def version_string(self):
            return ""
        def do_GET(self):
            parts = self.path.split("/")
            status, headers, body = 404, {"Cache-Control": "no-store"}, b""
            if not limiter.allow(self.client_address[0]):
                status = 429
            elif (len(parts) == 3 and re.fullmatch(r"[A-Za-z0-9_-]{24,128}", parts[1]) and
                    parts[2] in {"nodes.txt", "config.conf", "config.yaml"}):
                try:
                    with ProductionStore(state_dir, policy=policy, read_only=True) as store:
                        store.conn.execute("BEGIN")
                        response = subscription_response(store, parts[1], parts[2])
                        status, headers, body = response["status"], response["headers"], response["body"]
                except Exception:
                    status = 503
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
    return Handler


def serve_subscription(policy, state_dir):
    server = SubscriptionServer(("0.0.0.0", SUBSCRIPTION_PORT), subscription_handler(policy, state_dir), TLSContexts())
    server.serve_forever(poll_interval=0.5)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Explicit isolated parallel controller")
    parser.add_argument("--policy", default=POLICY_PATH)
    parser.add_argument("--state-dir", default=STATE_DIR)
    parser.add_argument("command", choices=["initialize", "rpc", "agent", "subscription"])
    args = parser.parse_args(argv)
    request = None
    try:
        policy = load_policy(args.policy)
        if args.command == "initialize":
            if os.geteuid() != 0:
                raise ValueError("Initialization is installer-only")
            with ProductionStore(args.state_dir, policy=policy, initialize=True):
                pass
            return 0
        if args.command == "subscription":
            serve_subscription(policy, args.state_dir)
            return 0
        with ProductionStore(args.state_dir, policy=policy) as store:
            if args.command == "agent":
                from .collector import run
                run(store)
                return 0
            raw = sys.stdin.buffer.read(MAX_MESSAGE + 1)
            if len(raw) > MAX_MESSAGE:
                raise ValueError()
            request = json.loads(raw)
            response = handle_request(store, request)
            print(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
            return 0 if response["ok"] else 1
    except Exception:
        if args.command == "rpc":
            print(json.dumps(_response(request.get("request_id") if isinstance(request, dict) else None, 0,
                                       code="UNAVAILABLE", message="The registered production controller is unavailable")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
