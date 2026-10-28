"""Finite authorisations and safe reclamation of an existing approved slot."""
from __future__ import annotations

import datetime as dt
import json
import uuid

from .store import parse_time, timestamp


def ensure_schema(store):
    store.conn.execute("""CREATE TABLE IF NOT EXISTS trials (
        user_id TEXT PRIMARY KEY, duration_days INTEGER NOT NULL, started_at TEXT,
        expires_at TEXT, ended_at TEXT, end_reason TEXT, status TEXT NOT NULL DEFAULT 'starting')""")
    store.conn.execute("""CREATE TABLE IF NOT EXISTS resource_leases (
        id TEXT PRIMARY KEY,worker_id TEXT NOT NULL,user_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL,created_at TEXT NOT NULL,closed_at TEXT,released_at TEXT,
        settled_upload INTEGER,settled_download INTEGER,worker_json TEXT)""")
    if "worker_json" not in {r[1] for r in store.conn.execute("PRAGMA table_info(resource_leases)")}:
        store.conn.execute("ALTER TABLE resource_leases ADD COLUMN worker_json TEXT")


def get(store, user_id):
    if not store.conn.execute("SELECT 1 FROM sqlite_master WHERE name='trials'").fetchone():
        return None
    row = store.conn.execute("SELECT * FROM trials WHERE user_id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def is_expired(store, user, now):
    value = get(store, user["id"])
    return bool(value and (value["ended_at"] or (value["expires_at"] and parse_time(value["expires_at"]) <= now)))


def create(store, params, now):
    from . import budget, domain
    from .production import _add_user
    quota = params.get("quota_bytes", 5 * budget.GB)
    budget.validate_allowance(store, quota, trial=True)
    days = domain.integer(params.get("duration_days", 3), "duration_days", 1, 365)
    result = _add_user(store, {"name": params.get("name", "临时体验"), "role": "member", "quota_bytes": quota}, now, trial=True)
    user_id = result["user"]["id"]
    store.conn.execute("INSERT INTO trials(user_id,duration_days) VALUES(?,?)", (user_id, days))
    store.conn.execute("UPDATE users SET manual_disabled=0,auto_restore=0 WHERE id=?", (user_id,))
    return {"user": domain._public_user(store, store.get_user(user_id), now)}


def update(store, params, now):
    from . import budget, domain
    user = domain._user(store, params)
    value = get(store, user["id"])
    if not value or is_expired(store, user, now):
        raise domain.DomainError("EXPIRED", "体验已结束，不能恢复旧凭据，请创建新体验")
    if "quota_bytes" not in params and "duration_days" not in params:
        raise domain.DomainError("VALIDATION", "没有可修改的体验设置")
    if "quota_bytes" in params:
        budget.validate_allowance(store, params["quota_bytes"], user=user, trial=True)
        store.conn.execute("UPDATE users SET quota_bytes=?,topup_bytes=0 WHERE id=?", (params["quota_bytes"], user["id"]))
    if "duration_days" in params:
        days = domain.integer(params["duration_days"], "duration_days", 1, 365)
        expiry = parse_time(value["started_at"]) + dt.timedelta(days=days) if value["started_at"] else None
        if expiry and expiry <= now:
            raise domain.DomainError("VALIDATION", "修改后的到期时间必须晚于当前时间")
        store.conn.execute("UPDATE trials SET duration_days=?,expires_at=? WHERE user_id=?", (days, timestamp(expiry) if expiry else None, user["id"]))
    return {"user": domain._public_user(store, store.get_user(user["id"]), now)}


def advance(store, now):
    from . import domain
    for row in store.conn.execute("SELECT * FROM trials WHERE ended_at IS NULL").fetchall():
        trial = dict(row)
        user, worker = store.get_user(trial["user_id"]), store.worker(trial["user_id"])
        if user["revoked_at"] or user.get("deleted_at"):
            reason = "deleted" if user.get("deleted_at") else "revoked"
            store.conn.execute("UPDATE trials SET ended_at=?,end_reason=?,status='cleaning' WHERE user_id=?", (timestamp(now), reason, user["id"]))
            continue
        if (not trial["started_at"] and worker["observed_state"] == "running" and
                not worker["origin_pending"] and not worker["last_error"] and
                worker["observed_generation"] == worker["root_ack_generation"] and
                user["trusted_sample"] and domain.eligible(user, now)):
            store.conn.execute("UPDATE trials SET started_at=?,expires_at=?,status='active' WHERE user_id=?",
                               (timestamp(now), timestamp(now + dt.timedelta(days=trial["duration_days"])), user["id"]))
            trial = get(store, user["id"])
            _notice(store, user, 'trial_started', now, expires_at=trial['expires_at'])
        if trial['expires_at'] and dt.timedelta(0) < parse_time(trial['expires_at']) - now <= dt.timedelta(hours=24):
            _notice(store, user, 'trial_expiring', now, expires_at=trial['expires_at'])
        exhausted = user["used_upload"] + user["used_download"] >= user["quota_bytes"] + user["topup_bytes"]
        expired = trial["expires_at"] and parse_time(trial["expires_at"]) <= now
        if exhausted or expired:
            reason = "exhausted" if exhausted else "expired"
            _notice(store, user, 'trial_exhausted' if exhausted else 'trial_expired', now, expires_at=trial['expires_at'])
            # HTTP checks the deadline on every request; this tick also removes
            # cached client access by scheduling actual instance revocation.
            store.conn.execute("UPDATE trials SET ended_at=?,end_reason=?,status='cleaning' WHERE user_id=?", (timestamp(now), reason, user["id"]))
            domain.handle_action(store, "user.delete", {"user_id": user["id"]}, now)
            from .registration import sync_user
            sync_user(store, user["id"], now)
    for row in store.conn.execute("SELECT user_id FROM trials WHERE status IN ('cleaning','cleanup_failed')").fetchall():
        worker = store.worker(row[0]) if store.conn.execute("SELECT 1 FROM production_workers WHERE user_id=?", (row[0],)).fetchone() else None
        if worker is None:
            store.conn.execute("UPDATE trials SET status='cleaned' WHERE user_id=?", (row[0],))
        elif worker["last_error"]:
            store.conn.execute("UPDATE trials SET status='cleanup_failed' WHERE user_id=?", (row[0],))


def register_lease(store, worker_id, user_id, now):
    store.conn.execute("INSERT INTO resource_leases(id,worker_id,user_id,status,created_at) VALUES(?,?,?,'active',?)",
                       (user_id, worker_id, user_id, timestamp(now)))


def releasable(store, worker):
    if worker["role"] != "member" or not worker["user_id"]:
        return False
    user = store.get_user(worker["user_id"])
    # Permanent revocation closes an authorisation just as deletion does. Its
    # history may stay visible while the independently fenced resource is reused.
    return bool((user["revoked_at"] or user.get("deleted_at")) and worker["tombstoned"] and worker["observed_state"] == "revoked" and
                worker["process_id"] in (None, 0) and not worker["last_error"] and not worker["origin_pending"] and
                not store.conn.execute("SELECT 1 FROM credentials WHERE user_id=?", (user["id"],)).fetchone() and
                not store.conn.execute("SELECT 1 FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL", (user["id"],)).fetchone())


def finish_release(store, worker, now):
    user = store.get_user(worker["user_id"])
    archived = dict(worker)
    archived.update(observed_state='revoked', tombstoned=1, process_id=None, last_error=None, origin_pending=0, api_secret=None)
    store.conn.execute("UPDATE resource_leases SET status='released',closed_at=COALESCE(closed_at,?),released_at=?,settled_upload=?,settled_download=?,worker_json=? WHERE user_id=?",
                       (timestamp(now), timestamp(now), user["used_upload"], user["used_download"], json.dumps(archived), user["id"]))
    store.conn.execute("UPDATE trials SET status='cleaned' WHERE user_id=?", (user["id"],))
    # Old users and their generations remain archived. The slot is a resource,
    # while the permanently revoked authorisation is never reused.
    store.conn.execute("UPDATE production_workers SET user_id=NULL,observed_state='unprovisioned',provisioned=0,credential_version=0,api_secret=NULL,public_key=NULL,process_id=NULL,origin_pending=0,origin_epoch=NULL,last_error=NULL,tombstoned=0 WHERE worker_id=?", (worker["worker_id"],))


def cleanup_status(store, user, worker):
    if not (user["revoked_at"] or user.get("deleted_at")):
        return None
    lease = store.conn.execute("SELECT status FROM resource_leases WHERE user_id=?", (user["id"],)).fetchone()
    if lease and lease[0] == 'released':
        return {"state": "released", "requires_unknown_gap_confirmation": False}
    if worker['observed_state'] != 'revoked' or worker['process_id'] not in (None, 0) or worker['last_error']:
        return {"state": "waiting_stop", "requires_unknown_gap_confirmation": False}
    unknown = bool(store.conn.execute("SELECT 1 FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL", (user["id"],)).fetchone())
    return {"state": "waiting_reconciliation" if unknown else "releasing", "requires_unknown_gap_confirmation": unknown}


def confirm_cleanup(store, params, now):
    from . import domain
    user = domain._user(store, params, live=False)
    worker = store.worker(user['id'])
    status = cleanup_status(store, user, worker)
    if not status or status['state'] != 'waiting_reconciliation' or params.get('confirm_unknown_gap') is not True:
        raise domain.DomainError('CLEANUP_NOT_READY', '仅可确认已停止且授权已撤销用户的未知尾部记录')
    if store.conn.execute("SELECT 1 FROM production_jobs WHERE worker_id=? AND status IN ('pending','executing')", (worker['worker_id'],)).fetchone():
        raise domain.DomainError('CLEANUP_NOT_READY', '请等待目标实例的操作结束')
    store.conn.execute("UPDATE metering_incidents SET resolved_at=?,operator='authenticated_administrator',resolution='acknowledged_archived_gap',evidence='管理员明确确认归档用户未知尾部；未清零、未虚构用量' WHERE user_id=? AND resolved_at IS NULL", (timestamp(now), user['id']))
    return {'cleanup': cleanup_status(store, user, worker)}


def _notice(store, user, kind, now, *, expires_at=None):
    from .mail import enqueue_notification
    from .mail_templates import render
    template = render(kind, name=user['name'], used_bytes=user['used_upload']+user['used_download'],
                      allowance_bytes=user['quota_bytes']+user['topup_bytes'], expires_at=expires_at)
    enqueue_notification(store,event_key=kind+':'+user['id']+':'+str(expires_at),user_id=None,kind=kind,
                         subject=template.subject,body=template.body,now=now,cooldown_seconds=0)
