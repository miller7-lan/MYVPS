"""Targeted, preview-bound recovery without resetting identity or usage.

Preview is a read-only decision. Apply only records bounded work; the existing
worker executor performs registered API-only staging outside DB transactions.
No function in this module contacts a helper, a proxy or another network service.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import secrets
import uuid

from . import domain
from .store import parse_time, timestamp

PREVIEW_SECONDS = 60
RECOVERY_SECONDS = 60
ACTIVE_STATES = frozenset({"checking", "recovering", "starting"})
UNSAFE_ERRORS = frozenset({"HELPER_IDENTITY_MISMATCH", "ROOT_REGISTRY_ROLLBACK", "INVALID_PUBLIC_KEY",
                           "POLICY_MISMATCH", "WORKER_POLICY_MISMATCH", "REVOKED"})


def ensure_schema(store):
    store.conn.execute("""CREATE TABLE IF NOT EXISTS user_recoveries (
      id TEXT PRIMARY KEY,user_id TEXT NOT NULL,preview_hash TEXT NOT NULL UNIQUE,
      state TEXT NOT NULL,credential_version INTEGER NOT NULL,confirm_unknown_gap INTEGER NOT NULL,
      force_stage INTEGER NOT NULL DEFAULT 1,stage_generation INTEGER,
      created_at TEXT NOT NULL,updated_at TEXT NOT NULL,deadline_at TEXT NOT NULL,error_code TEXT)""")
    store.conn.execute("CREATE INDEX IF NOT EXISTS user_recoveries_target ON user_recoveries(user_id,created_at)")


def _exists(store):
    return bool(store.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_recoveries'").fetchone())


def _latest(store, user_id):
    if not _exists(store):
        return None
    row = store.conn.execute("SELECT * FROM user_recoveries WHERE user_id=? ORDER BY rowid DESC LIMIT 1", (user_id,)).fetchone()
    return dict(row) if row else None


def _fresh(user, now):
    try:
        age = (now - parse_time(user["last_sample_at"])).total_seconds()
        return bool(user["trusted_sample"] and user["meter_epoch"] and 0 <= age <= 5)
    except (ValueError, TypeError, KeyError):
        return False


def _expired(store, user, now):
    try:
        from .trials import is_expired
    except ImportError:
        return False
    return is_expired(store, user, now)


def blockers(store, user, worker, now):
    reasons = set(domain.disabled_reasons(user, now)) - {"metering_failure"}
    if user["manual_disabled"]:
        reasons.add("manual_disabled")
    if user["revoked_at"] or worker["tombstoned"]:
        reasons.add("revoked")
    if user.get("deleted_at"):
        reasons.add("deleted")
    if _expired(store, user, now):
        reasons.add("expired")
    if not user["unlimited"] and user["used_upload"] + user["used_download"] >= (user["quota_bytes"] or 0) + user["topup_bytes"]:
        reasons.add("quota_exceeded")
    if worker["last_error"] in UNSAFE_ERRORS:
        reasons.add("runtime_integrity")
    if worker["observed_generation"] > worker["root_ack_generation"]:
        reasons.add("runtime_integrity")
    return sorted(reasons)


def _pending(store, user_id):
    return bool(store.conn.execute("SELECT 1 FROM production_jobs j JOIN production_workers w ON w.worker_id=j.worker_id WHERE w.user_id=? AND j.status IN ('pending','executing') LIMIT 1", (user_id,)).fetchone())


def _unknown_gap(store, user):
    unresolved = store.conn.execute("SELECT 1 FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL LIMIT 1", (user["id"],)).fetchone()
    # Any previously used origin that must be staged may have a final tail.
    return bool(unresolved or user["meter_epoch"] or user["last_sample_at"] or user["used_upload"] or user["used_download"])


def _unresolved_gap(store, user_id):
    return bool(store.conn.execute("SELECT 1 FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL LIMIT 1", (user_id,)).fetchone())


def gap_summary(store, user, now):
    """Bounded, secret-free evidence for the explicit unknown-byte decision."""
    rows = store.conn.execute(
        "SELECT kind,previous_at,sample_at,detected_at,unallocated_upload,unallocated_download,delta_unknown "
        "FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL ORDER BY detected_at,id LIMIT 20",
        (user["id"],)).fetchall()
    count = store.conn.execute("SELECT COUNT(*) FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL",
                               (user["id"],)).fetchone()[0]
    incidents = [{"kind": row["kind"], "from_at": row["previous_at"], "to_at": row["sample_at"],
                  "detected_at": row["detected_at"], "delta_unknown": bool(row["delta_unknown"]),
                  "known_upload_bytes": row["unallocated_upload"],
                  "known_download_bytes": row["unallocated_download"]} for row in rows]
    return {"last_trusted_at": user["last_sample_at"], "observed_at": timestamp(now),
            "unresolved_count": count, "incidents": incidents, "omitted_count": max(0, count - len(rows)),
            "may_restart_target": True, "preserves_recorded_usage": True,
            "recorded_upload_bytes": user["used_upload"], "recorded_download_bytes": user["used_download"],
            "notice": "区间内未知用量无法补算，不按零处理；确认会记录对账依据，保留已用量和凭据。恢复过程中可能产生目标用户的停止尾部间隙。"}


def ready(store, user, worker, now):
    return bool(not blockers(store, user, worker, now) and not domain.disabled_reasons(user, now) and
                worker["observed_state"] == "running" and not worker["origin_pending"] and
                worker["process_id"] and worker["credential_version"] == user["credential_version"] and
                worker["observed_generation"] == worker["root_ack_generation"] and
                not worker["last_error"] and _fresh(user, now))


def status(store, user, worker=None, now=None, *, force_restart=False):
    now = parse_time(now) if now else store.now
    worker = worker or store.worker(user["id"])
    blocked = blockers(store, user, worker, now)
    operation = _latest(store, user["id"])
    healthy = ready(store, user, worker, now)
    active = operation and operation["state"] in ACTIVE_STATES
    if healthy:
        state = "succeeded" if operation and operation["state"] == "succeeded" else "healthy"
    elif blocked:
        state = "blocked"
    elif active:
        state = operation["state"]
    elif operation and operation["state"] == "failed":
        state = "failed"
    else:
        state = "idle"
    busy = _pending(store, user["id"])
    if busy and not active and (not healthy or force_restart):
        blocked = sorted(set(blocked) | {"operation_in_progress"})
        state = "blocked"
    return {"user_id": user["id"], "state": state,
            "can_apply": (not healthy or force_restart) and not blocked and not active,
            "force_restart": force_restart,
            "blocked_reasons": blocked, "requires_unknown_gap_confirmation": (not healthy or force_restart) and _unknown_gap(store, user),
            "operation_id": operation["id"] if operation else None,
            "error_code": operation["error_code"] if operation and state == "failed" else None,
            "updated_at": operation["updated_at"] if operation else None}


def _fingerprint(store, user, worker, now):
    value = {key: user.get(key) for key in ("id", "role", "manual_disabled", "quota_bytes", "topup_bytes", "unlimited",
                                                   "credential_version", "revoked_at", "deleted_at")}
    value["worker"] = {key: worker[key] for key in ("worker_id", "generation", "root_ack_generation", "observed_generation",
                                                    "observed_state", "process_id", "tombstoned", "last_error")}
    value["expired"] = _expired(store, user, now)
    # A newly discovered gap must not be acknowledged by an older preview.
    value["incidents"] = [tuple(row) for row in store.conn.execute(
        "SELECT id,kind,detected_at,previous_at,sample_at,unallocated_upload,unallocated_download,delta_unknown "
        "FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL ORDER BY id", (user["id"],))]
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _key(store, user):
    credentials = store.get_credentials(user["id"])
    return hashlib.sha256(("dazzle-user-recovery-v1:" + store.server_id + ":" + credentials["subscription_token"]).encode()).digest()


def _encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def preview(store, params, now):
    user = domain._user(store, params, live=False)
    worker = store.worker(user["id"])
    force_restart = domain.boolean(params.get("force_restart", False), "force_restart")
    result = status(store, user, worker, now, force_restart=force_restart)
    result.update(preview_token=None, expires_at=None, expected_revision=store.revision)
    result["gap_summary"] = gap_summary(store, user, now) if result["requires_unknown_gap_confirmation"] else None
    if result["can_apply"]:
        expires = timestamp(now + dt.timedelta(seconds=PREVIEW_SECONDS))
        payload = {"version": 1, "user_id": user["id"], "revision": store.revision,
                   "force_restart": force_restart,
                   "fingerprint": _fingerprint(store, user, worker, now), "issued_at": timestamp(now),
                   "expires_at": expires, "nonce": secrets.token_urlsafe(18)}
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        result["preview_token"] = _encode(raw) + "." + _encode(hmac.digest(_key(store, user), raw, "sha256"))
        result["expires_at"] = expires
    return {"recovery": result}


def _verify_preview(store, user, worker, token, now, *, force_restart=False):
    try:
        if not isinstance(token, str) or len(token) > 2048:
            raise ValueError()
        encoded, signature = token.split(".")
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        supplied = base64.b64decode(signature + "=" * (-len(signature) % 4), altchars=b"-_", validate=True)
        if not hmac.compare_digest(supplied, hmac.digest(_key(store, user), raw, "sha256")):
            raise ValueError()
        value = json.loads(raw)
        fields = {"version", "user_id", "revision", "fingerprint", "issued_at", "expires_at", "nonce"}
        if set(value) not in (fields, fields | {"force_restart"}) or value["version"] != 1 or value["user_id"] != user["id"]:
            raise ValueError()
        if type(value.get("force_restart", False)) is not bool or value.get("force_restart", False) != force_restart:
            raise ValueError()
        issued, expires = parse_time(value["issued_at"]), parse_time(value["expires_at"])
        if not issued <= now < expires or (expires - issued).total_seconds() != PREVIEW_SECONDS:
            raise domain.DomainError("RECOVERY_PREVIEW_EXPIRED", "Recovery preview has expired; review the current user state again")
        if value["revision"] != store.revision or value["fingerprint"] != _fingerprint(store, user, worker, now):
            raise domain.DomainError("RECOVERY_PREVIEW_CHANGED", "The reviewed user changed; request a fresh recovery preview")
    except domain.DomainError:
        raise
    except (ValueError, TypeError, KeyError):
        raise domain.DomainError("VALIDATION", "Invalid recovery preview") from None


def applied_preview(store, params):
    if not _exists(store) or not isinstance(params.get("preview_token"), str):
        return False
    force_restart = domain.boolean(params.get("force_restart", False), "force_restart")
    try:
        encoded, _ = params["preview_token"].split(".")
        payload = json.loads(base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True))
        if type(payload.get("force_restart", False)) is not bool or payload.get("force_restart", False) != force_restart:
            return False
    except (ValueError, TypeError, KeyError):
        return False
    digest = hashlib.sha256(params["preview_token"].encode()).hexdigest()
    row = store.conn.execute("SELECT user_id,confirm_unknown_gap FROM user_recoveries WHERE preview_hash=?", (digest,)).fetchone()
    return bool(row and row["user_id"] == params.get("user_id") and type(params.get("confirm_unknown_gap", False)) is bool and row["confirm_unknown_gap"] == int(params.get("confirm_unknown_gap", False)))


def apply(store, params, now):
    ensure_schema(store)
    user = domain._user(store, params, live=False)
    worker = store.worker(user["id"])
    if applied_preview(store, params):
        return {"recovery": status(store, user, worker, now), "already_applied": True}
    force_restart = domain.boolean(params.get("force_restart", False), "force_restart")
    _verify_preview(store, user, worker, params.get("preview_token"), now, force_restart=force_restart)
    current = status(store, user, worker, now, force_restart=force_restart)
    if current["state"] in {"healthy", "succeeded"} and not force_restart:
        return {"recovery": current, "already_healthy": True}
    if not current["can_apply"]:
        raise domain.DomainError("RECOVERY_BLOCKED", "Recovery cannot bypass an authorization, quota, integrity or active-operation restriction")
    confirmed = domain.boolean(params.get("confirm_unknown_gap", False), "confirm_unknown_gap")
    if current["requires_unknown_gap_confirmation"] and not confirmed:
        raise domain.DomainError("RECOVERY_CONFIRMATION_REQUIRED", "Confirm the recorded unallocated metering gap before recovery")
    identifier = str(uuid.uuid4())
    at = timestamp(now)
    store.conn.execute("INSERT INTO user_recoveries(id,user_id,preview_hash,state,credential_version,confirm_unknown_gap,created_at,updated_at,deadline_at) VALUES(?,?,?,'checking',?,?,?,?,?)",
                       (identifier, user["id"], hashlib.sha256(params["preview_token"].encode()).hexdigest(), user["credential_version"], int(confirmed), at, at,
                        timestamp(now + dt.timedelta(seconds=RECOVERY_SECONDS))))
    reasons = set(json.loads(user["reasons_json"])) | {"metering_failure"}
    domain._set_reasons(store, user["id"], reasons, now)
    # A failed helper call may already have advanced root generation. The
    # existing executor re-probes root truth before issuing a new operation.
    if worker["last_error"]:
        store.conn.execute("UPDATE production_workers SET last_error='STATUS_RECHECK_REQUIRED' WHERE user_id=?", (user["id"],))
    return {"recovery": status(store, store.get_user(user["id"]), now=now), "already_applied": False}


def force_api_stage(store, user_id):
    operation = _latest(store, user_id)
    return bool(operation and operation["state"] in {"checking", "recovering"} and operation["force_stage"])


def activation_held(store, user_id):
    operation = _latest(store, user_id)
    return bool(operation and operation["state"] in {"checking", "recovering"})


def stage_planned(store, user_id, generation, now):
    operation = _latest(store, user_id)
    if operation and operation["state"] in {"checking", "recovering"} and operation["force_stage"]:
        store.conn.execute("UPDATE user_recoveries SET state='recovering',force_stage=0,stage_generation=?,updated_at=? WHERE id=?",
                           (generation, timestamp(now), operation["id"]))


def _finish(store, operation, state, now, error=None):
    store.conn.execute("UPDATE user_recoveries SET state=?,force_stage=0,error_code=?,updated_at=? WHERE id=?",
                       (state, error, timestamp(now), operation["id"]))


def advance(store, now):
    """Advance pending target operations inside the agent's existing transaction."""
    if not store.conn.in_transaction:
        raise RuntimeError("Recovery advancement requires the agent transaction")
    ensure_schema(store)
    for row in store.conn.execute("SELECT * FROM user_recoveries WHERE state IN ('checking','recovering','starting') ORDER BY rowid").fetchall():
        operation = dict(row)
        user = store.get_user(operation["user_id"])
        worker = store.worker(user["id"])
        if blockers(store, user, worker, now):
            _finish(store, operation, "blocked", now, "RECOVERY_BLOCKED")
            continue
        if user["credential_version"] != operation["credential_version"]:
            _finish(store, operation, "failed", now, "RECOVERY_USER_CHANGED")
            continue
        if parse_time(operation["deadline_at"]) <= now:
            _finish(store, operation, "failed", now, "RECOVERY_TIMEOUT")
            continue
        if ready(store, user, worker, now):
            _finish(store, operation, "succeeded", now)
            from .mail import enqueue_notification
            from .mail_templates import render
            template = render('recovery_success', name=user['name'])
            enqueue_notification(store,event_key='recovery:'+operation['id'],user_id=user['id'],kind='recovery_success',
                                 subject=template.subject,body=template.body,now=now,cooldown_seconds=0)
            continue
        if worker["last_error"] and worker["last_error"] != "STATUS_RECHECK_REQUIRED":
            _finish(store, operation, "failed", now, "RECOVERY_RUNTIME_FAILED")
            continue
        if operation["state"] == "starting":
            continue
        if (worker["observed_state"] != "staged" or worker["origin_pending"] or not _fresh(user, now) or
                worker["observed_generation"] != worker["root_ack_generation"] or
                operation["stage_generation"] != worker["observed_generation"] or _pending(store, user["id"])):
            continue
        if _unresolved_gap(store, user["id"]) and not operation["confirm_unknown_gap"]:
            _finish(store, operation, "failed", now, "RECOVERY_CONFIRMATION_REQUIRED")
            continue
        # Reuse domain validation: a real fresh origin is mandatory. Acknowledge
        # unknown bytes explicitly; neither counters nor credentials are changed.
        domain.handle_action(store, "meter.reconcile", {"user_id": user["id"],
                             "evidence": "Mac administrator confirmed the recorded unallocated metering gap during preview-bound user recovery; usage and credentials retained."}, now)
        holds = store.get_meta("agent_recovery_holds", {})
        if user["id"] in holds:
            holds.pop(user["id"])
            store.set_meta("agent_recovery_holds", holds)
            store.set_meta("agent_recovery_only", bool(holds))
        store.conn.execute("UPDATE production_workers SET last_error=NULL WHERE user_id=?", (user["id"],))
        store.conn.execute("UPDATE user_recoveries SET state='starting',updated_at=? WHERE id=?", (timestamp(now), operation["id"]))
