"""Private account admission; no public operation can grant proxy access.

All functions use the caller's transaction. The agent owns this state; the web
process receives only its narrowly authenticated result over a local socket.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import uuid

from . import domain, mail
from .mail_templates import render as render_mail
from .production_state import public_origin
from .store import parse_time, timestamp, utcnow

SESSION_TTL = dt.timedelta(days=7)
REJECTED_RETENTION = dt.timedelta(hours=72)
FULL_MESSAGE = "人员已满，稍后再试"
DECOY = ""  # account_id of a challenge answered for an address that receives no code.
RESEND_COOLDOWN_SECONDS = 300
RESEND_DAILY_LIMIT = 5
PUBLIC_PARAMETERS = {
    "registration.status": (set(), set()),
    "auth.request_code": ({"email"}, {"nickname", "challenge_id"}),
    "auth.verify": ({"challenge_id", "code"}, set()),
    "session.me": ({"session_token"}, set()),
    "session.subscription": ({"session_token", "format"}, set()),
    "session.resend_subscription": ({"session_token"}, set()),
    "session.logout": ({"session_token"}, set()),
    "subscription.fetch": ({"token", "route"}, set()),
}


class PortalError(Exception):
    def __init__(self, code, message, *, commit=False):
        super().__init__(message)
        self.code, self.commit = code, commit


def ensure_schema(store):
    statements = [
        """CREATE TABLE IF NOT EXISTS portal_accounts (
          id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,nickname TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'unverified',email_verified_at TEXT,
          subscription_token TEXT UNIQUE,proxy_user_id TEXT UNIQUE,
          created_at TEXT NOT NULL,updated_at TEXT NOT NULL,welcome_queued_at TEXT,
          rejection_reason TEXT,activation_notified_at TEXT,activation_attempt INTEGER NOT NULL DEFAULT 0)""",
        """CREATE TABLE IF NOT EXISTS portal_challenges (
          id TEXT PRIMARY KEY,account_id TEXT NOT NULL,salt TEXT NOT NULL,code_hash TEXT NOT NULL,
          sent_at TEXT NOT NULL,expires_at TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,used_at TEXT)""",
        "CREATE INDEX IF NOT EXISTS portal_challenges_account ON portal_challenges(account_id,sent_at)",
        """CREATE TABLE IF NOT EXISTS portal_sessions (
          token_hash TEXT PRIMARY KEY,account_id TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,revoked_at TEXT)""",
        """CREATE TABLE IF NOT EXISTS portal_mail (
          outbox_id TEXT PRIMARY KEY,account_id TEXT NOT NULL,kind TEXT NOT NULL,challenge_id TEXT,token_hash TEXT)""",
        """CREATE TABLE IF NOT EXISTS portal_rate (
          bucket TEXT NOT NULL,window INTEGER NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(bucket,window))""",
    ]
    for statement in statements:
        store.conn.execute(statement)
    columns = {row[1] for row in store.conn.execute("PRAGMA table_info(portal_accounts)")}
    if "activation_notified_at" not in columns:
        store.conn.execute("ALTER TABLE portal_accounts ADD COLUMN activation_notified_at TEXT")
    if "activation_attempt" not in columns:
        store.conn.execute("ALTER TABLE portal_accounts ADD COLUMN activation_attempt INTEGER NOT NULL DEFAULT 0")
    if "binding_issue" not in columns:
        store.conn.execute("ALTER TABLE portal_accounts ADD COLUMN binding_issue TEXT")
    if store.get_setting("registration_enabled") is None:
        store.set_setting("registration_enabled", False)


def _exists(store):
    return bool(store.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='portal_accounts'").fetchone())


def rejected_delete_at(account):
    if account["status"] != "rejected" or account["proxy_user_id"]:
        return None
    try:
        return parse_time(account["updated_at"]) + REJECTED_RETENTION
    except (TypeError, ValueError):
        return None


def prune_rejected(store, now):
    """Expire unallocated applications in the writer transaction; keep user ledgers.

    updated_at is the rejection transition time. Signing in does not change it,
    and re-rejecting an already rejected application must not extend retention.
    Historical notification/audit records retain their existing retention policy.
    """
    if not _exists(store):
        return 0
    rows = store.conn.execute(
        "SELECT * FROM portal_accounts WHERE status='rejected' AND proxy_user_id IS NULL "
        "AND julianday(updated_at)<=julianday(?) ORDER BY updated_at,id LIMIT 100",
        (timestamp(now - REJECTED_RETENTION),)).fetchall()
    removed = 0
    for row in rows:
        account = dict(row)
        deadline = rejected_delete_at(account)
        if deadline is None or deadline > now:
            continue
        # The SMTP lease is owned by another thread; finish that send first.
        if store.conn.execute("SELECT 1 FROM portal_mail m JOIN mail_outbox o ON m.outbox_id=o.id "
                              "WHERE m.account_id=? AND o.status='sending' LIMIT 1", (account["id"],)).fetchone():
            continue
        parameters = (account["id"],)
        outbox = "SELECT outbox_id FROM portal_mail WHERE account_id=?"
        store.conn.execute("UPDATE mail_outbox SET status='cancelled',completed_at=?,error_code='REGISTRATION_RETENTION_EXPIRED' "
                           "WHERE status IN ('queued','retry') AND id IN (" + outbox + ")", (timestamp(now), *parameters))
        store.conn.execute("DELETE FROM mail_private_payload WHERE outbox_id IN (" + outbox + ")", parameters)
        for table in ("portal_challenges", "portal_sessions", "portal_mail"):
            store.conn.execute("DELETE FROM " + table + " WHERE account_id=?", parameters)
        store.conn.execute("DELETE FROM portal_accounts WHERE id=?", parameters)
        removed += 1
    return removed


def _existing_identity(store, email):
    """An address already recorded for a live user is an existing person awaiting
    sign-in or binding review, never a new seat (binding grants no extra slot)."""
    for row in store.conn.execute("SELECT email FROM users WHERE email IS NOT NULL AND revoked_at IS NULL AND deleted_at IS NULL"):
        try:
            if _email(row["email"]) == email:
                return True
        except (ValueError, TypeError):
            continue
    return False


REGISTRATION_PORTS = frozenset({24432, 24433, 24434})


def member_slots(store):
    """New v2 authorizations use only the three approved registration seats.

    The historical 24431 worker remains managed, even after release, but never
    becomes a fourth registration/trial slot. v1 supports legacy initialization.
    """
    rows = store.conn.execute("SELECT * FROM production_workers WHERE role='member' ORDER BY public_port").fetchall()
    if store.policy["version"] == 1:
        return rows
    approved = {identifier: worker for identifier, worker in store.policy["workers"].items()
                if worker["role"] == "member" and worker["public_port"] in REGISTRATION_PORTS}
    return [row for row in rows if row["worker_id"] in approved
            and row["public_port"] == approved[row["worker_id"]]["public_port"]
            and row["api_port"] == approved[row["worker_id"]]["api_port"]]


def capacity(store):
    """Seats are the unassigned approved member slots; every verified application
    still awaiting review holds one, so applicants never outnumber the slots."""
    free = sum(row["user_id"] is None and not row["tombstoned"] for row in member_slots(store))
    waiting = store.conn.execute("SELECT COUNT(*) FROM portal_accounts WHERE proxy_user_id IS NULL AND email_verified_at IS NOT NULL "
                                 "AND status IN ('pending','waiting_resources')").fetchone()[0] if _exists(store) else 0
    return {"free_slots": free, "waiting": waiting, "full": waiting >= free}


def require_slot_capacity(store, *, reserved_account_id=None):
    """All member creation shares the same transaction-local admission gate.

    Approval converts only its own verified pending reservation; manual users
    and trials must leave every other applicant's reservation intact.
    """
    info = capacity(store)
    own_reservation = False
    if reserved_account_id is not None and _exists(store):
        own_reservation = store.conn.execute(
            "SELECT 1 FROM portal_accounts WHERE id=? AND proxy_user_id IS NULL "
            "AND email_verified_at IS NOT NULL AND status IN ('pending','waiting_resources')",
            (reserved_account_id,)).fetchone() is not None
    if info["waiting"] - int(own_reservation) >= info["free_slots"]:
        raise domain.DomainError("REGISTRATION_FULL", "人员已满，稍后再试")


def _email(value):
    value = mail._address(value)
    local, host = value.rsplit("@", 1)
    return local.lower() + "@" + host.lower()


def _account(store, identifier):
    row = store.conn.execute("SELECT * FROM portal_accounts WHERE id=?", (identifier,)).fetchone()
    if row is None:
        raise PortalError("NOT_FOUND", "Account not found")
    return dict(row)


def _binding_candidate(store, email, *, account_id=None):
    """Only one previously verified live email identity may expose old secrets.

    Unverified or duplicate addresses are never a public claim of a proxy user.
    Matching is evaluated again inside the OTP verification transaction, rather
    than trusting a hint supplied when the code was requested.
    """
    matches = []
    for row in store.conn.execute("SELECT * FROM users WHERE email IS NOT NULL"):
        try:
            same = _email(row["email"]) == email
        except (ValueError, TypeError):
            same = False
        if same:
            matches.append(dict(row))
    if not matches:
        return None, None
    if len(matches) != 1:
        return None, "email_conflict"
    user = matches[0]
    if not user.get("email_verified"):
        return None, "email_not_verified"
    if user.get("revoked_at") or user.get("deleted_at"):
        return None, "previous_authorization_revoked"
    claimed = store.conn.execute("SELECT id FROM portal_accounts WHERE proxy_user_id=?", (user["id"],)).fetchone()
    if claimed and claimed[0] != account_id:
        return None, "already_linked"
    try:
        credentials, worker = store.get_credentials(user["id"]), store.worker(user["id"])
    except KeyError:
        return None, "authorization_unavailable"
    if not credentials["subscription_token"] or worker.get("tombstoned"):
        return None, "authorization_unavailable"
    return user, None


def _link_existing(store, account, now, *, selected_user_id=None):
    user, issue = _binding_candidate(store, account["email"], account_id=account["id"])
    if selected_user_id is not None and (not user or user["id"] != selected_user_id):
        raise domain.DomainError("VALIDATION", "Only a unique verified matching email may be linked")
    if user is None:
        if issue:
            store.conn.execute("UPDATE portal_accounts SET status='needs_confirmation',binding_issue=?,updated_at=? WHERE id=?",
                               (issue, timestamp(now), account["id"]))
        return False
    token = store.get_credentials(user["id"])["subscription_token"]
    # Linking a pre-existing account is not a new activation. Keep all original
    # identities, byte totals and worker state, and do not send a first-use mail.
    store.conn.execute("UPDATE portal_accounts SET proxy_user_id=?,subscription_token=?,status='approved',binding_issue=NULL,activation_notified_at=COALESCE(activation_notified_at,?),updated_at=? WHERE id=?",
                       (user["id"], token, timestamp(now), timestamp(now), account["id"]))
    return True


def _status(store, account, now):
    if not account["proxy_user_id"]:
        return account["status"]
    try:
        user, worker = store.get_user(account["proxy_user_id"]), store.worker(account["proxy_user_id"])
    except KeyError:
        return "failed"
    if user.get("revoked_at") or user.get("deleted_at") or worker.get("tombstoned"):
        return "revoked"
    if user["manual_disabled"]:
        return "disabled"
    if worker.get("last_error") or worker["observed_state"] in {"failed", "stop_failed"}:
        return "failed"
    if (worker["observed_state"] == "running" and not worker["origin_pending"] and worker["process_id"] and
            worker["credential_version"] == user["credential_version"] and
            worker["observed_generation"] == worker["root_ack_generation"] and
            user["trusted_sample"] and user["meter_state"] == "trusted" and domain.eligible(user, now)):
        return "active"
    if not domain.eligible(user, now) and user.get("trusted_sample"):
        return "disabled"
    return "provisioning"


def _public(store, account, now):
    user = store.get_user(account["proxy_user_id"]) if account["proxy_user_id"] else None
    worker = store.worker(account["proxy_user_id"]) if user else None
    quota = user["quota_bytes"] if user else store.get_setting("default_quota_bytes")
    unlimited = bool(user["unlimited"]) if user else False
    topup = user["topup_bytes"] if user else 0
    return {"id": account["id"], "email": account["email"], "nickname": account["nickname"],
            "status": _status(store, account, now), "created_at": account["created_at"],
            "proxy_user_id": account["proxy_user_id"], "quota_bytes": quota,
            "unlimited": unlimited, "topup_bytes": topup, "allowance_bytes": None if unlimited else quota + topup,
            "used_upload": user["used_upload"] if user else 0, "used_download": user["used_download"] if user else 0,
            "last_error": worker.get("last_error") if worker else None,
            "binding_issue": account.get("binding_issue"),
            "rejected_delete_at": timestamp(deadline) if (deadline := rejected_delete_at(account)) else None,
            "expires_at": (user.get("authorization_expires_at") or user.get("trial_expires_at") or user.get("expires_at")) if user else None,
            "node_names": ["Dazzle'VPS-VLESS（常用）", "Dazzle'VPS-TUIC5（迅速）"] if user else [],
            "configuration_available": _status(store, account, now) == "active"}


def snapshot(store, now=None):
    now = parse_time(now) if now else utcnow()
    if not _exists(store):
        return {"enabled": False, "pending_count": 0, "accounts": [], "pool": {"available": 0, "total": 0}}
    accounts = []
    for row in store.conn.execute("SELECT * FROM portal_accounts WHERE email_verified_at IS NOT NULL ORDER BY created_at,id"):
        account = dict(row)
        public = _public(store, account, now)
        # This review metadata belongs only to the authenticated administrator
        # snapshot. Public session.me must never enumerate matching identities.
        public["binding_candidates"] = []
        if not account["proxy_user_id"] and account["status"] == "needs_confirmation":
            candidate, issue = _binding_candidate(store, account["email"], account_id=account["id"])
            for user in store.conn.execute("SELECT * FROM users WHERE email IS NOT NULL ORDER BY created_at,id"):
                try:
                    matches = _email(user["email"]) == account["email"]
                except (ValueError, TypeError):
                    matches = False
                if not matches:
                    continue
                public["binding_candidates"].append({"user_id": user["id"], "name": user["name"],
                    "email": user["email"], "email_verified": bool(user["email_verified"]),
                    "reason": issue, "can_bind": candidate is not None and candidate["id"] == user["id"]})
                if len(public["binding_candidates"]) >= 50:
                    break
        accounts.append(public)
    slots = member_slots(store)
    return {"enabled": bool(store.get_setting("registration_enabled", False)),
            "portal_url": public_origin(store) + "/portal/", "public_hostname": store.get_setting("public_hostname"),
            "pending_count": sum(a["status"] in {"pending", "waiting_resources", "needs_confirmation"} for a in accounts),
            "accounts": accounts,
            "pool": {"available": sum(r["user_id"] is None and not r["tombstoned"] for r in slots), "total": len(slots)},
            "capacity": capacity(store), "rejected_retention_hours": 72}


def _links(store, account):
    token = account["subscription_token"]
    if not token or account["status"] in {"revoked", "needs_confirmation"}:
        return {"clash": None, "shadowrocket": None}
    base = f"{public_origin(store)}/{token}/"
    return {"clash": base + "config.yaml", "shadowrocket": base + "nodes.txt"}


def subscription_email_availability(store, user_id, now):
    """Only current, verified recipients may receive reusable access links."""
    try:
        user, worker = store.get_user(user_id), store.worker(user_id)
        if (user.get("revoked_at") or user.get("deleted_at") or not domain.eligible(user, now) or
                not user["trusted_sample"] or user["meter_state"] != "trusted" or
                worker["observed_state"] != "running" or worker["tombstoned"] or
                worker["origin_pending"] or worker["last_error"] or not worker["process_id"] or
                worker["credential_version"] != user["credential_version"] or
                worker["observed_generation"] != worker["root_ack_generation"]):
            return False, "NOT_ACTIVE"
        if not user["email_verified"]:
            return False, "EMAIL_NOT_VERIFIED"
        _email(user["email"])
        configured, transport, _, preferences = mail._config(store)
        secret = store.conn.execute("SELECT 1 FROM mail_secrets WHERE id=1").fetchone()
        if not configured or not preferences["enabled"] or (transport == "smtp" and not secret):
            return False, "MAIL_NOT_CONFIGURED"
        return True, None
    except (KeyError, TypeError, ValueError):
        return False, "EMAIL_NOT_VERIFIED"


def _subscription_mail_binding(store, user):
    credentials = store.get_credentials(user["id"])
    token = credentials["subscription_token"]
    if not token:
        raise domain.DomainError("NOT_ACTIVE", "Access is unavailable")
    value = [user["id"], user["credential_version"], _email(user["email"]), token]
    return "subscription:" + hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def queue_subscription_email(store, params, now, *, requested_by="administrator"):
    user = domain._user(store, params)
    allowed, reason = subscription_email_availability(store, user["id"], now)
    if not allowed:
        raise domain.DomainError(reason, "The current user and verified email must be available before sending")
    if store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE status IN ('queued','retry','sending')").fetchone()[0] >= 200:
        raise domain.DomainError("RATE_LIMITED", "Mail queue is temporarily full")
    token = store.get_credentials(user["id"])["subscription_token"]
    base = f"{public_origin(store)}/{token}/"
    links = {"clash": base + "config.yaml", "shadowrocket": base + "nodes.txt"}
    template = render_mail("subscription_resend", name=user["name"], links=links, requested_by=requested_by)
    result = mail._enqueue(store, event_key="subscription-resend:" + str(uuid.uuid4()),
        user_id=user["id"], cycle_id=_subscription_mail_binding(store, user),
        recipient=_email(user["email"]), kind="subscription_resend", subject=template.subject,
        body=template.public_body, private_body=template.body, now=now, cooldown_seconds=60)
    return {"mail": {**result, "state": "queued" if result.get("queued") else result.get("reason", "pending")}}


def authorize_subscription_email(store, message, now):
    allowed, _ = subscription_email_availability(store, message.get("user_id"), now)
    if not allowed:
        return False
    try:
        user = store.get_user(message["user_id"])
        return bool(_email(user["email"]) == message["recipient"] and
                    hmac.compare_digest(_subscription_mail_binding(store, user), message.get("cycle_id") or ""))
    except (KeyError, TypeError, ValueError, domain.DomainError):
        return False


def _queue(store, account, *, kind, event_key, subject, public_body, private_body, now, challenge_id=None):
    result = mail._enqueue(store, event_key=event_key, user_id=None, cycle_id=None,
                           recipient=account["email"], kind=kind, subject=subject,
                           body=public_body, private_body=private_body, now=now)
    if result.get("queued"):
        store.conn.execute("INSERT INTO portal_mail VALUES(?,?,?,?,?)", (result["id"], account["id"], kind, challenge_id, hashlib.sha256(account["subscription_token"].encode()).hexdigest() if kind == "portal_activated" else None))
    return result


def authorize_mail(store, message, now):
    if not _exists(store):
        return False
    row = store.conn.execute("SELECT * FROM portal_mail WHERE outbox_id=?", (message["id"],)).fetchone()
    if not row:
        return False
    account = _account(store, row["account_id"])
    if account["email"] != message["recipient"] or _status(store, account, now) == "revoked":
        return False
    if row["kind"] == "portal_verification":
        challenge = store.conn.execute("SELECT * FROM portal_challenges WHERE id=?", (row["challenge_id"],)).fetchone()
        latest = store.conn.execute("SELECT id FROM portal_challenges WHERE account_id=? ORDER BY sent_at DESC,id DESC LIMIT 1", (account["id"],)).fetchone()
        return bool(challenge and latest and latest[0] == challenge["id"] and not challenge["used_at"]
                    and challenge["attempts"] < mail.VERIFY_MAX_ATTEMPTS and parse_time(challenge["expires_at"]) > now)
    if row["kind"] == "portal_activated":
        if (account["activation_notified_at"] or not activation_ready(store, account, now) or not account["subscription_token"] or
                not hmac.compare_digest(row["token_hash"] or "", hashlib.sha256(account["subscription_token"].encode()).hexdigest())):
            return False
    return bool(account["email_verified_at"] and mail._config(store)[3]["enabled"])



def activation_ready(store, account, now):
    """A helper acknowledgement alone is insufficient: require its sampled origin."""
    if (not account["proxy_user_id"] or not account["email_verified_at"] or
            account["status"] == "revoked" or not account["subscription_token"]):
        return False
    try:
        user, worker = store.get_user(account["proxy_user_id"]), store.worker(account["proxy_user_id"])
    except KeyError:
        return False
    try:
        if not user["email_verified"] or _email(user["email"]) != account["email"]:
            return False
    except (TypeError, ValueError):
        return False
    return bool(worker["observed_state"] == "running" and not worker["tombstoned"] and
                not worker["origin_pending"] and not worker["last_error"] and user["trusted_sample"] and
                worker["credential_version"] == user["credential_version"] and
                worker["observed_generation"] == worker["root_ack_generation"] and domain.eligible(user, now))


def queue_activation_notices(store, now):
    """Called by the VPS tick inside its transaction, independently of the Mac."""
    if not _exists(store) or not mail._config(store)[0] or not mail._config(store)[3]["enabled"]:
        return 0
    queued = 0
    for row in store.conn.execute("SELECT * FROM portal_accounts WHERE proxy_user_id IS NOT NULL AND activation_notified_at IS NULL").fetchall():
        account = dict(row)
        if not activation_ready(store, account, now):
            continue
        token_hash = hashlib.sha256(account["subscription_token"].encode()).hexdigest()
        previous = store.conn.execute("SELECT o.status FROM portal_mail m JOIN mail_outbox o ON m.outbox_id=o.id WHERE m.account_id=? AND m.kind='portal_activated' AND m.token_hash=? AND o.status IN ('queued','retry','sending','sent','dead') LIMIT 1", (account["id"], token_hash)).fetchone()
        if previous:
            continue
        attempt = account["activation_attempt"] + 1
        links = _links(store, account)
        template = render_mail("portal_activated", name=account["nickname"], links=links)
        result = _queue(store, account, kind="portal_activated", event_key="portal-activated:" + account["id"] + ":" + str(attempt),
               subject=template.subject, public_body=template.public_body,
               private_body=template.body, now=now)
        if result.get("queued"):
            store.conn.execute("UPDATE portal_accounts SET activation_attempt=? WHERE id=?", (attempt, account["id"]))
            queued += 1
    return queued


def mail_accepted(store, message_id, now):
    """Record SMTP acceptance atomically; it does not claim final inbox delivery."""
    if not _exists(store):
        return
    row = store.conn.execute("SELECT * FROM portal_mail WHERE outbox_id=? AND kind='portal_activated'", (message_id,)).fetchone()
    if not row:
        return
    account = _account(store, row["account_id"])
    if (account["status"] != "revoked" and account["subscription_token"] and
            hmac.compare_digest(row["token_hash"] or "", hashlib.sha256(account["subscription_token"].encode()).hexdigest())):
        store.conn.execute("UPDATE portal_accounts SET activation_notified_at=COALESCE(activation_notified_at,?) WHERE id=?", (timestamp(now), account["id"]))


def _rate(store, account_email, peer_ip, now, *, known):
    """Count every public code request alike, whether or not a code is sent.

    Addresses that may already sign in have their own daily budget, so new
    addresses cannot exhaust it and lock existing users out until midnight.
    """
    try:
        ip = str(ipaddress.ip_address(peer_ip))
    except (ValueError, TypeError):
        raise PortalError("VALIDATION", "Invalid connection source") from None
    second = int(now.timestamp())
    email_key = hashlib.sha256(account_email.encode()).hexdigest()
    ip_key = hashlib.sha256((store.server_id + ip).encode()).hexdigest()
    budgets = [("email-minute:" + email_key, 60, 1), ("email-hour:" + email_key, 3600, 6),
               ("email-day:" + email_key, 86400, 15), ("ip-hour:" + ip_key, 3600, 30),
               ("ip-day:" + ip_key, 86400, 100), ("known-day" if known else "global-day", 86400, 200)]
    # One sliding cooldown for every address: an account's own cooldown would
    # otherwise reveal which addresses have one.
    last = store.conn.execute("SELECT count FROM portal_rate WHERE bucket=? AND window=0", ("email-last:" + email_key,)).fetchone()
    if last and second - last[0] < mail.VERIFY_COOLDOWN_SECONDS:
        raise PortalError("RATE_LIMITED", "Please wait before requesting another email")
    for key, duration, limit in budgets:
        window = second // duration
        row = store.conn.execute("SELECT count FROM portal_rate WHERE bucket=? AND window=?", (key, window)).fetchone()
        if row and row[0] >= limit:
            raise PortalError("RATE_LIMITED", "Please wait before requesting another email")
    if store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE status IN ('queued','retry','sending')").fetchone()[0] >= 200:
        raise PortalError("RATE_LIMITED", "Mail queue is temporarily full")
    for key, duration, _ in budgets:
        store.conn.execute("INSERT INTO portal_rate VALUES(?,?,1) ON CONFLICT(bucket,window) DO UPDATE SET count=count+1", (key, second // duration))
    store.conn.execute("INSERT INTO portal_rate VALUES(?,0,?) ON CONFLICT(bucket,window) DO UPDATE SET count=excluded.count",
                       ("email-last:" + email_key, second))
    _prune_rate(store, second)


def _prune_rate(store, second):
    # No plaintext network addresses; expired buckets need not accumulate forever.
    store.conn.execute("DELETE FROM portal_rate WHERE (bucket LIKE '%-minute:%' AND window<?) OR (bucket LIKE '%-hour:%' AND window<?) "
                       "OR ((bucket LIKE '%-day:%' OR bucket IN ('global-day','known-day')) AND window<?) "
                       "OR ((bucket LIKE 'email-last:%' OR bucket LIKE 'resend-last:%') AND count<?)",
                       (second // 60 - 2, second // 3600 - 2, second // 86400 - 2, second - 86400))


def _resend_rate(store, account_id, now):
    """A signed-in resend reaches only the verified mailbox, at a bounded rate."""
    second = int(now.timestamp())
    key = hashlib.sha256(("resend:" + account_id).encode()).hexdigest()
    last = store.conn.execute("SELECT count FROM portal_rate WHERE bucket=? AND window=0", ("resend-last:" + key,)).fetchone()
    day = store.conn.execute("SELECT count FROM portal_rate WHERE bucket=? AND window=?", ("resend-day:" + key, second // 86400)).fetchone()
    if (last and second - last[0] < RESEND_COOLDOWN_SECONDS) or (day and day[0] >= RESEND_DAILY_LIMIT):
        raise PortalError("RESEND_COOLDOWN", "Please wait before requesting another resend")
    store.conn.execute("INSERT INTO portal_rate VALUES(?,0,?) ON CONFLICT(bucket,window) DO UPDATE SET count=excluded.count",
                       ("resend-last:" + key, second))
    store.conn.execute("INSERT INTO portal_rate VALUES(?,?,1) ON CONFLICT(bucket,window) DO UPDATE SET count=count+1",
                       ("resend-day:" + key, second // 86400))
    _prune_rate(store, second)


def resend_subscription(store, params, now):
    account = _session(store, params["session_token"], now)
    if not account["proxy_user_id"] or _status(store, account, now) != "active":
        raise PortalError("NOT_ACTIVE", "Subscription is not active")
    _resend_rate(store, account["id"], now)
    try:
        result = queue_subscription_email(store, {"user_id": account["proxy_user_id"]}, now, requested_by="user")
    except domain.DomainError as exc:
        known = {"RATE_LIMITED", "NOT_ACTIVE", "MAIL_NOT_CONFIGURED", "EMAIL_NOT_VERIFIED"}
        raise PortalError(exc.code if exc.code in known else "UNAVAILABLE", exc.message) from None
    if not result["mail"].get("queued"):
        # The administrator resent within the last minute; nothing new was queued.
        raise PortalError("RESEND_COOLDOWN", "A subscription email was sent moments ago")
    return {"queued": True, "email": account["email"]}


def request_code(store, params, peer_ip, now):
    email = _email(params.get("email"))
    # The page names its challenge before sending, so a reply lost to a mobile
    # network or a backgrounded tab still lets the user type the mailed code.
    supplied = params.get("challenge_id")
    if supplied is not None:
        try:
            if str(uuid.UUID(supplied)) != supplied:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise PortalError("VALIDATION", "Invalid challenge identifier") from None
        if store.conn.execute("SELECT 1 FROM portal_challenges WHERE id=?", (supplied,)).fetchone():
            raise PortalError("VALIDATION", "Challenge identifier was already used")
    nickname = params.get("nickname", "")
    if nickname:
        nickname = domain.text(nickname, "nickname", 40)
    else:
        nickname = "共享用户"
    configured, _, config, prefs = mail._config(store)
    if not configured or not prefs["enabled"]:
        raise PortalError("UNAVAILABLE", "Email login is not configured")
    row = store.conn.execute("SELECT * FROM portal_accounts WHERE email=?", (email,)).fetchone()
    account = dict(row) if row else None
    verified, existing = bool(account and account["email_verified_at"]), _existing_identity(store, email)
    if account and _status(store, account, now) == "revoked":
        allowed = False
    elif verified:
        allowed = True  # Verified applicants and linked users may always sign in.
    elif not store.get_setting("registration_enabled", False):
        # Closed means closed, including an application whose code was
        # requested but never verified before registration closed.
        allowed = _binding_candidate(store, email)[0] is not None
    else:
        # Existing users never need a seat; a new application does.
        allowed = existing or not capacity(store)["full"]
    _rate(store, email, peer_ip, now, known=verified or existing)
    identifier, salt = supplied or str(uuid.uuid4()), secrets.token_hex(16)
    code = f"{secrets.randbelow(1000000):06d}"
    digest = hashlib.pbkdf2_hmac("sha256", code.encode(), salt.encode(), 100000).hex()
    if not allowed:
        # Same reply, counting and cost as a real request: whether an address
        # may sign in or apply is not public. The decoy can never verify and no
        # mail is sent; the page itself shows when registration is closed or full.
        store.conn.execute("INSERT INTO portal_challenges(id,account_id,salt,code_hash,sent_at,expires_at) VALUES(?,?,?,?,?,?)",
                           (identifier, DECOY, salt, digest, timestamp(now), timestamp(now + dt.timedelta(seconds=600))))
        return {"challenge_id": identifier}
    if account is None:
        account_id = str(uuid.uuid4())
        store.conn.execute("INSERT INTO portal_accounts(id,email,nickname,created_at,updated_at) VALUES(?,?,?,?,?)", (account_id, email, nickname, timestamp(now), timestamp(now)))
        account = _account(store, account_id)
    store.conn.execute("INSERT INTO portal_challenges(id,account_id,salt,code_hash,sent_at,expires_at) VALUES(?,?,?,?,?,?)",
                       (identifier, account["id"], salt, digest, timestamp(now), timestamp(now + dt.timedelta(seconds=600))))
    template = render_mail("portal_verification", code=code)
    _queue(store, account, kind="portal_verification", event_key="portal-verify:" + identifier,
           subject=template.subject, public_body=template.public_body,
           private_body=template.body, now=now, challenge_id=identifier)
    return {"challenge_id": identifier}


def verify(store, params, now):
    identifier = params.get("challenge_id")
    row = store.conn.execute("SELECT * FROM portal_challenges WHERE id=?", (identifier,)).fetchone()
    if not row:
        raise PortalError("INVALID_CODE", "The code is invalid or expired")
    decoy = row["account_id"] == DECOY
    if not decoy:
        account = _account(store, row["account_id"])
        latest = store.conn.execute("SELECT id FROM portal_challenges WHERE account_id=? ORDER BY sent_at DESC,id DESC LIMIT 1", (account["id"],)).fetchone()
    if (row["used_at"] or row["attempts"] >= 5 or parse_time(row["expires_at"]) <= now or
            (not decoy and (not latest or latest[0] != identifier or account["status"] == "revoked"))):
        raise PortalError("INVALID_CODE", "The code is invalid or expired")
    code = params.get("code")
    valid = isinstance(code, str) and re.fullmatch(r"[0-9]{6}", code)
    # A decoy costs and counts exactly like a real code, and never verifies.
    digest = hashlib.pbkdf2_hmac("sha256", (code if valid else "invalid").encode(), row["salt"].encode(), 100000).hex()
    store.conn.execute("UPDATE portal_challenges SET attempts=attempts+1 WHERE id=?", (identifier,))
    if decoy or not valid or not hmac.compare_digest(digest, row["code_hash"]):
        raise PortalError("INVALID_CODE", "The code is invalid or expired", commit=True)
    if account["email_verified_at"] is None:
        if (not store.get_setting("registration_enabled", False) and
                _binding_candidate(store, account["email"], account_id=account["id"])[0] is None):
            # Registration closed after this code was sent. Roll back, so the
            # still valid code works if registration reopens in time.
            raise PortalError("REGISTRATION_CLOSED", "New registrations are paused")
        if not _existing_identity(store, account["email"]) and capacity(store)["full"]:
            # Seats were taken after the code was sent. Roll back, so the still
            # valid code can be used once a seat is free again.
            raise PortalError("REGISTRATION_FULL", FULL_MESSAGE)
    store.conn.execute("UPDATE portal_challenges SET used_at=? WHERE id=?", (timestamp(now), identifier))
    first = account["email_verified_at"] is None
    if first:
        store.conn.execute("UPDATE portal_accounts SET status='pending',email_verified_at=?,subscription_token=?,updated_at=? WHERE id=?",
                           (timestamp(now), secrets.token_urlsafe(36), timestamp(now), account["id"]))
        account = _account(store, account["id"])
    linked = not account["proxy_user_id"] and _link_existing(store, account, now)
    account = _account(store, account["id"])
    if first and not linked:
        template = render_mail("portal_welcome", name=account["nickname"])
        _queue(store, account, kind="portal_welcome", event_key="portal-welcome:" + account["id"],
               subject=template.subject, public_body=template.public_body, private_body=template.body, now=now)
        store.conn.execute("UPDATE portal_accounts SET welcome_queued_at=? WHERE id=?", (timestamp(now), account["id"]))
        template = render_mail("portal_application_notice")
        mail.enqueue_notification(store, event_key="portal-new:" + account["id"], kind="portal_application_notice",
                                  subject=template.subject, body=template.body, now=now, cooldown_seconds=0)
    session = secrets.token_urlsafe(32)
    expires = now + SESSION_TTL
    store.conn.execute("INSERT INTO portal_sessions VALUES(?,?,?,?,NULL)", (hashlib.sha256(session.encode()).hexdigest(), account["id"], timestamp(now), timestamp(expires)))
    store.conn.execute("DELETE FROM portal_sessions WHERE expires_at<=?", (timestamp(now),))
    return {"session_token": session, "expires_at": timestamp(expires)}


def _session(store, token, now):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", token):
        raise PortalError("UNAUTHENTICATED", "Please sign in again")
    digest = hashlib.sha256(token.encode()).hexdigest()
    row = store.conn.execute("SELECT * FROM portal_sessions WHERE token_hash=?", (digest,)).fetchone()
    if not row or row["revoked_at"] or parse_time(row["expires_at"]) <= now:
        raise PortalError("UNAUTHENTICATED", "Please sign in again")
    account = _account(store, row["account_id"])
    if account["status"] == "revoked":
        raise PortalError("UNAUTHENTICATED", "Please sign in again")
    if account["proxy_user_id"]:
        user = store.get_user(account["proxy_user_id"])
        try:
            valid_email = bool(user["email_verified"] and _email(user["email"]) == account["email"])
        except (ValueError, TypeError):
            valid_email = False
        if not valid_email or user.get("revoked_at") or user.get("deleted_at"):
            raise PortalError("UNAUTHENTICATED", "Please sign in again")
    return account


def handle_public(store, operation, params, peer_ip, now=None):
    now = parse_time(now) if now else utcnow()
    if operation not in PUBLIC_PARAMETERS or not isinstance(params, dict):
        raise PortalError("VALIDATION", "Unsupported operation")
    required, optional = PUBLIC_PARAMETERS[operation]
    if not required <= set(params) or set(params) - required - optional:
        raise PortalError("VALIDATION", "Unexpected request fields")
    if any(not isinstance(value, str) or len(value) > 512 for value in params.values()):
        raise PortalError("VALIDATION", "Request values must be bounded text")
    if operation == "registration.status":
        # Public: whether a new application can start; never counts or identities.
        enabled = bool(store.get_setting("registration_enabled", False)) if _exists(store) else False
        full = enabled and capacity(store)["full"]
        return {"enabled": enabled, "full": full, "accepting": enabled and not full,
                "message": FULL_MESSAGE if full else "" if enabled else "暂不接受新注册，已有用户仍可登录。"}
    if operation == "auth.request_code":
        return request_code(store, params, peer_ip, now)
    if operation == "auth.verify":
        return verify(store, params, now)
    if operation == "session.me":
        account = _session(store, params["session_token"], now)
        details = _public(store, account, now)
        # Personal web pages contain status only. Usage and reusable access
        # settings stay in the administrator interface and verified email.
        visible = {key: details[key] for key in ("id", "email", "nickname", "status", "created_at", "expires_at")}
        return {"account": visible, "delivery": {"method": "email"}}
    if operation == "session.subscription":
        account = _session(store, params["session_token"], now)
        if params["format"] not in {"clash", "shadowrocket"}:
            raise PortalError("VALIDATION", "Unsupported subscription format")
        if _status(store, account, now) != "active":
            raise PortalError("NOT_ACTIVE", "Subscription is not active")
        raise PortalError("EMAIL_DELIVERY_ONLY", "Access information is delivered by verified email")
    if operation == "session.resend_subscription":
        return resend_subscription(store, params, now)
    if operation == "session.logout":
        digest = hashlib.sha256(str(params["session_token"]).encode()).hexdigest()
        store.conn.execute("UPDATE portal_sessions SET revoked_at=? WHERE token_hash=?", (timestamp(now), digest))
        return {"logged_out": True}
    from .production import subscription_response
    response = subscription_response(store, params["token"], params["route"], now)
    return {"status": response["status"], "headers": response["headers"], "body_b64": base64.b64encode(response["body"]).decode()}


def pending_token(store, token):
    if not _exists(store):
        return False
    row = store.conn.execute("SELECT status,proxy_user_id FROM portal_accounts WHERE subscription_token=?", (token,)).fetchone()
    return bool(row and row["status"] != "revoked" and not row["proxy_user_id"])


def handle_admin(store, action, params, now):
    if action == "registration.list":
        return {"registration": snapshot(store, now)}
    try:
        account = _account(store, params.get("account_id"))
    except PortalError as exc:
        raise domain.DomainError(exc.code, str(exc)) from None
    if not account["email_verified_at"] or account["status"] == "revoked":
        raise domain.DomainError("VALIDATION", "Only a verified live account can be reviewed")
    if action == "registration.bind":
        if not isinstance(params.get("user_id"), str) or not params["user_id"]:
            raise domain.DomainError("VALIDATION", "An existing user identity is required")
        if account["proxy_user_id"]:
            if account["proxy_user_id"] != params.get("user_id"):
                raise domain.DomainError("VALIDATION", "Account is already linked")
        else:
            _link_existing(store, account, now, selected_user_id=params.get("user_id"))
        return {"account": _public(store, _account(store, account["id"]), now)}
    if action == "registration.reject":
        if account["proxy_user_id"]:
            raise domain.DomainError("VALIDATION", "Use user.disable for an already allocated user")
        if account["status"] == "rejected":
            return {"account": _public(store, account, now)}
        reason = params.get("reason", "")
        if reason:
            reason = domain.text(reason, "reason", 200)
        store.conn.execute("UPDATE portal_accounts SET status='rejected',rejection_reason=?,updated_at=? WHERE id=?", (reason, timestamp(now), account["id"]))
        template = render_mail("portal_rejected", name=account["nickname"], reason=reason)
        _queue(store, account, kind="portal_review", event_key="portal-reject:" + account["id"], subject=template.subject,
               public_body=template.public_body, private_body=template.body, now=now)
        return {"account": _public(store, _account(store, account["id"]), now)}
    if action != "registration.approve":
        raise domain.DomainError("VALIDATION", "Unknown admission action")
    if account.get("binding_issue"):
        raise domain.DomainError("VALIDATION", "Resolve the existing email identity before creating another user")
    quota = domain.integer(params.get("quota_bytes", store.get_setting("default_quota_bytes")), "quota_bytes", 1)
    if not account["proxy_user_id"]:
        from .budget import validate_allowance
        validate_allowance(store, quota)
        # The same approved registration seats _add_user allocates from; a freed
        # historical slot outside them is not a seat and must not fail approval.
        if not any(slot["user_id"] is None and not slot["tombstoned"] for slot in member_slots(store)):
            store.conn.execute("UPDATE portal_accounts SET status='waiting_resources',updated_at=? WHERE id=?", (timestamp(now), account["id"]))
            return {"account": _public(store, _account(store, account["id"]), now), "waiting_resources": True}
        from .production import _add_user
        result = _add_user(store, {"role": "member", "name": account["nickname"] + " · " + account["id"][:6], "quota_bytes": quota}, now,
                           reserved_account_id=account["id"])
        user_id = result["user"]["id"]
        store.conn.execute("UPDATE credentials SET subscription_token=? WHERE user_id=?", (account["subscription_token"], user_id))
        store.conn.execute("UPDATE users SET email=?,email_verified=1,manual_disabled=0 WHERE id=?", (account["email"], user_id))
        store.conn.execute("UPDATE portal_accounts SET proxy_user_id=?,status='approved',updated_at=? WHERE id=?", (user_id, timestamp(now), account["id"]))
        template = render_mail("portal_approved", name=account["nickname"])
        _queue(store, account, kind="portal_review", event_key="portal-approved:" + account["id"], subject=template.subject,
               public_body=template.public_body, private_body=template.body, now=now)
    return {"account": _public(store, _account(store, account["id"]), now)}


def sync_user(store, user_id, now):
    if not _exists(store):
        return
    row = store.conn.execute("SELECT id FROM portal_accounts WHERE proxy_user_id=?", (user_id,)).fetchone()
    if not row:
        return
    user = store.get_user(user_id)
    if user.get("revoked_at") or user.get("deleted_at"):
        store.conn.execute("UPDATE portal_accounts SET status='revoked',subscription_token=NULL,updated_at=? WHERE id=?", (timestamp(now), row[0]))
        store.conn.execute("UPDATE portal_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE account_id=?", (timestamp(now), row[0]))
        store.conn.execute("UPDATE mail_outbox SET status='cancelled',completed_at=?,error_code='RECIPIENT_NO_LONGER_AUTHORIZED' WHERE id IN (SELECT outbox_id FROM portal_mail WHERE account_id=?) AND status IN ('queued','retry')", (timestamp(now), row[0]))
        store.conn.execute("DELETE FROM mail_private_payload WHERE outbox_id IN (SELECT id FROM mail_outbox WHERE status='cancelled')")
    else:
        token = store.get_credentials(user_id)["subscription_token"]
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        store.conn.execute("UPDATE mail_outbox SET status='cancelled',completed_at=?,error_code='RECIPIENT_NO_LONGER_AUTHORIZED' WHERE id IN (SELECT outbox_id FROM portal_mail WHERE account_id=? AND kind='portal_activated' AND token_hash!=?) AND status IN ('queued','retry')", (timestamp(now), row[0], token_hash))
        store.conn.execute("DELETE FROM mail_private_payload WHERE outbox_id IN (SELECT id FROM mail_outbox WHERE status='cancelled')")
        store.conn.execute("UPDATE portal_accounts SET subscription_token=?,updated_at=? WHERE id=?", (token, timestamp(now), row[0]))
