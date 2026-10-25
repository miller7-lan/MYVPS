"""One-request JSON RPC, optimistic revisions, durable mutation idempotency."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import re
import sqlite3
import uuid

from .domain import DomainError, ensure_cycle, handle_action, snapshot
from .store import Store, parse_time, timestamp

MAX_REQUEST_BYTES = 1024 * 1024
SENSITIVE_ACTIONS = {"user.export", "mail.simulated_inbox"}
READ_ACTIONS = {"snapshot", "status", "user.export", "mail.status", "mail.simulated_inbox", "deploy.preview", "rollback.preview", "history.preview", "doctor", "user.list", "user.resolve"}
MUTATIONS = {"user.add", "user.enable", "user.disable", "user.revoke", "user.rotate", "user.update", "user.topup", "user.delete",
             "settings.update", "provider.observe", "cycle.tick", "meter.sample", "meter.failure", "meter.reconcile",
             "mail.configure", "mail.verify.send", "mail.verify.confirm", "mail.test", "mail.preferences", "mail.process",
             "rollback.apply", "runtime.process", "demo.initialize"}


def _response(request_id, revision: int, *, data=None, code=None, message=None) -> dict:
    return {"ok": code is None, "request_id": request_id, "revision": revision,
            "data": data if code is None else None,
            "error": None if code is None else {"code": code, "message": message}}


def _validate(request: dict) -> tuple[str, str, dict]:
    if not isinstance(request, dict) or request.get("api_version") != 1 or type(request.get("api_version")) is not int:
        raise DomainError("VALIDATION", "api_version must be 1")
    identifier = request.get("request_id")
    if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", identifier):
        raise DomainError("VALIDATION", "request_id must be a safe opaque identifier")
    action = request.get("action")
    if not isinstance(action, str) or action not in READ_ACTIONS | MUTATIONS:
        raise DomainError("UNSUPPORTED", "Unsupported action")
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise DomainError("VALIDATION", "params must be a JSON object")
    if len(json.dumps(request, ensure_ascii=False).encode("utf-8")) > MAX_REQUEST_BYTES:
        raise DomainError("VALIDATION", "Request exceeds the size limit")
    return identifier, action, params


def handle_request(store: Store, request: dict, now: dt.datetime | None = None) -> dict:
    identifier = request.get("request_id") if isinstance(request, dict) else None
    try:
        identifier, action, params = _validate(request)
        now = parse_time(now) if now is not None else store.now
        fingerprint = hashlib.sha256(json.dumps({"action": action, "params": params}, ensure_ascii=False,
                                                sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    except DomainError as exc:
        return _response(identifier, store.revision, code=exc.code, message=exc.message)
    except (ValueError, TypeError, OverflowError):
        return _response(identifier, store.revision, code="VALIDATION", message="Invalid request encoding or timestamp")
    cached = store.memory_responses.get(identifier)
    if cached is not None:
        if cached[0] != fingerprint:
            return _response(identifier, store.revision, code="VALIDATION", message="request_id was already used for a different operation")
        return copy.deepcopy(cached[1])
    store.conn.execute("BEGIN IMMEDIATE")
    try:
        durable = store.conn.execute("SELECT fingerprint,response_json FROM requests WHERE request_id=?", (identifier,)).fetchone()
        if durable is not None:
            if durable["fingerprint"] != fingerprint:
                raise DomainError("VALIDATION", "request_id was already used for a different operation")
            store.conn.rollback()
            return json.loads(durable["response_json"])
        expected = request.get("expected_revision")
        if action in MUTATIONS or action in SENSITIVE_ACTIONS:
            if type(expected) is not int or expected < 1:
                raise DomainError("VALIDATION", "expected_revision is required for this operation")
            if expected != store.revision:
                raise DomainError("REVISION_CONFLICT", "State changed; refresh before retrying")
        if action in MUTATIONS and store.get_meta("mode") != "simulation":
            raise DomainError("READ_ONLY", "Production mutations are not available in this phase")
        if action not in {"deploy.preview", "rollback.preview", "history.preview"}:
            ensure_cycle(store, now)
        if action == "doctor":
            data = {"mode": store.get_meta("mode"), "schema_version": 1, "database": "ready",
                    "production_mutations": False, "health": snapshot(store, now)["health"]}
        elif action == "user.list":
            data = {"users": snapshot(store, now)["users"]}
        elif action == "user.resolve":
            selector = params.get("user_id", params.get("name"))
            candidates = [user for user in snapshot(store, now)["users"]
                          if user["id"] == selector or user["name"] == selector]
            if len(candidates) != 1:
                raise DomainError("NOT_FOUND" if not candidates else "VALIDATION", "A unique user could not be resolved")
            data = {"user": candidates[0]}
        else:
            data = handle_action(store, action, params, now)
        if action in MUTATIONS:
            store.set_meta("revision", store.revision + 1)
            store.conn.execute("INSERT INTO operations VALUES (?,?,?,?,?)",
                               (str(uuid.uuid4()), action, "simulated", timestamp(now), "Local simulation; no production change"))
            data = dict(data)
            data["snapshot"] = snapshot(store, store.now if action == "cycle.tick" else now)
        response = _response(identifier, store.revision, data=data)
        if action in MUTATIONS:
            store.conn.execute("INSERT INTO requests VALUES (?,?,?,?)",
                               (identifier, fingerprint, json.dumps(response, ensure_ascii=False, separators=(",", ":")), timestamp(now)))
        store.conn.commit()
        store.memory_responses[identifier] = (fingerprint, copy.deepcopy(response))
        return response
    except DomainError as exc:
        store.conn.rollback()
        return _response(identifier, store.revision, code=exc.code, message=exc.message)
    except KeyError:
        store.conn.rollback()
        return _response(identifier, store.revision, code="NOT_FOUND", message="Requested object was not found")
    except (ValueError, TypeError, OverflowError):
        store.conn.rollback()
        return _response(identifier, store.revision, code="VALIDATION", message="Request validation failed")
    except sqlite3.IntegrityError:
        store.conn.rollback()
        return _response(identifier, store.revision, code="VALIDATION", message="A state constraint prevented this action")
    except Exception:
        store.conn.rollback()
        return _response(identifier, store.revision, code="INTERNAL", message="The local operation could not be completed")


dispatch = handle_request
