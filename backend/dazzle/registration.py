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
from .store import parse_time, timestamp, utcnow

SESSION_TTL = dt.timedelta(days=7)
PUBLIC_PARAMETERS = {
    "auth.request_code": ({"email"}, {"nickname"}),
    "auth.verify": ({"challenge_id", "code"}, set()),
    "session.me": ({"session_token"}, set()),
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
    if store.get_setting("registration_enabled") is None:
        store.set_setting("registration_enabled", False)


def _exists(store):
    return bool(store.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='portal_accounts'").fetchone())


def _email(value):
    value = mail._address(value)
    local, host = value.rsplit("@", 1)
    return local.lower() + "@" + host.lower()


def _account(store, identifier):
    row = store.conn.execute("SELECT * FROM portal_accounts WHERE id=?", (identifier,)).fetchone()
    if row is None:
        raise PortalError("NOT_FOUND", "Account not found")
    return dict(row)


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
    if worker["observed_state"] == "running" and domain.eligible(user, now):
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
            "last_error": worker.get("last_error") if worker else None}


def snapshot(store, now=None):
    now = parse_time(now) if now else utcnow()
    if not _exists(store):
        return {"enabled": False, "pending_count": 0, "accounts": [], "pool": {"available": 0, "total": 0}}
    accounts = [_public(store, dict(row), now) for row in store.conn.execute(
        "SELECT * FROM portal_accounts WHERE email_verified_at IS NOT NULL ORDER BY created_at,id")]
    slots = store.conn.execute("SELECT user_id,tombstoned FROM production_workers WHERE role='member'").fetchall()
    return {"enabled": bool(store.get_setting("registration_enabled", False)),
            "portal_url": f"https://{store.policy['server_endpoint']}:9443/portal/",
            "pending_count": sum(a["status"] in {"pending", "waiting_resources"} for a in accounts),
            "accounts": accounts,
            "pool": {"available": sum(r["user_id"] is None and not r["tombstoned"] for r in slots), "total": len(slots)}}


def _links(store, account):
    token = account["subscription_token"]
    if not token or account["status"] == "revoked":
        return {"clash": None, "shadowrocket": None}
    base = f"https://{store.policy['server_endpoint']}:9443/{token}/"
    return {"clash": base + "config.yaml", "shadowrocket": base + "nodes.txt"}


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
        result = _queue(store, account, kind="portal_activated", event_key="portal-activated:" + account["id"] + ":" + str(attempt),
               subject="Dazzle VPS 已开通 · 个人订阅链接", public_body="代理已实际开通，个人订阅通知已生成，实际送达以邮箱为准。",
               private_body=("您的代理已实际开通，流量计量已确认可靠。\nClash / mihomo：" + links["clash"] + "\nShadowrocket：" + links["shadowrocket"] +
                             "\n请使用对应地址导入或更新。转发本邮件可能使他人取得您的代理凭据。"), now=now)
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


def _rate(store, account_email, peer_ip, now):
    try:
        ip = str(ipaddress.ip_address(peer_ip))
    except (ValueError, TypeError):
        raise PortalError("VALIDATION", "Invalid connection source") from None
    second = int(now.timestamp())
    email_key = hashlib.sha256(account_email.encode()).hexdigest()
    ip_key = hashlib.sha256((store.server_id + ip).encode()).hexdigest()
    budgets = [("email-minute:" + email_key, 60, 1), ("email-hour:" + email_key, 3600, 6),
               ("email-day:" + email_key, 86400, 15), ("ip-hour:" + ip_key, 3600, 30),
               ("ip-day:" + ip_key, 86400, 100), ("global-day", 86400, 200)]
    for key, duration, limit in budgets:
        window = second // duration
        row = store.conn.execute("SELECT count FROM portal_rate WHERE bucket=? AND window=?", (key, window)).fetchone()
        if row and row[0] >= limit:
            raise PortalError("RATE_LIMITED", "Please wait before requesting another email")
    if store.conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE status IN ('queued','retry','sending')").fetchone()[0] >= 200:
        raise PortalError("RATE_LIMITED", "Mail queue is temporarily full")
    for key, duration, _ in budgets:
        store.conn.execute("INSERT INTO portal_rate VALUES(?,?,1) ON CONFLICT(bucket,window) DO UPDATE SET count=count+1", (key, second // duration))
    # No plaintext network addresses; expired buckets need not accumulate forever.
    store.conn.execute("DELETE FROM portal_rate WHERE (bucket LIKE '%-minute:%' AND window<?) OR (bucket LIKE '%-hour:%' AND window<?) OR ((bucket LIKE '%-day:%' OR bucket='global-day') AND window<?)", (second // 60 - 2, second // 3600 - 2, second // 86400 - 2))


def request_code(store, params, peer_ip, now):
    email = _email(params.get("email"))
    nickname = params.get("nickname", "")
    if nickname:
        nickname = domain.text(nickname, "nickname", 40)
    else:
        nickname = "共享用户"
    configured, _, config, prefs = mail._config(store)
    if not configured or not prefs["enabled"]:
        raise PortalError("UNAVAILABLE", "Email login is not configured")
    row = store.conn.execute("SELECT * FROM portal_accounts WHERE email=?", (email,)).fetchone()
    if not row and not store.get_setting("registration_enabled", False):
        raise PortalError("REGISTRATION_CLOSED", "New registrations are paused")
    _rate(store, email, peer_ip, now)
    if row:
        account = dict(row)
        if _status(store, account, now) == "revoked":
            raise PortalError("UNAVAILABLE", "This account is unavailable")
        latest = store.conn.execute("SELECT sent_at FROM portal_challenges WHERE account_id=? ORDER BY sent_at DESC LIMIT 1", (account["id"],)).fetchone()
        if latest and (now - parse_time(latest[0])).total_seconds() < mail.VERIFY_COOLDOWN_SECONDS:
            raise PortalError("RATE_LIMITED", "Please wait before requesting another email")
    else:
        identifier = str(uuid.uuid4())
        store.conn.execute("INSERT INTO portal_accounts(id,email,nickname,created_at,updated_at) VALUES(?,?,?,?,?)", (identifier, email, nickname, timestamp(now), timestamp(now)))
        account = _account(store, identifier)
    identifier, salt = str(uuid.uuid4()), secrets.token_hex(16)
    code = f"{secrets.randbelow(1000000):06d}"
    digest = hashlib.pbkdf2_hmac("sha256", code.encode(), salt.encode(), 100000).hex()
    store.conn.execute("INSERT INTO portal_challenges(id,account_id,salt,code_hash,sent_at,expires_at) VALUES(?,?,?,?,?,?)",
                       (identifier, account["id"], salt, digest, timestamp(now), timestamp(now + dt.timedelta(seconds=600))))
    _queue(store, account, kind="portal_verification", event_key="portal-verify:" + identifier,
           subject="Dazzle VPS 邮箱验证码", public_body="网页邮箱验证通知，验证码仅在私密邮件正文中。",
           private_body=f"您的邮箱验证码：{code}\n10分钟内有效，最多尝试5次。注册及登录不会自动开通代理，须由管理员在Mac端启用。", now=now, challenge_id=identifier)
    return {"challenge_id": identifier}


def verify(store, params, now):
    identifier = params.get("challenge_id")
    row = store.conn.execute("SELECT * FROM portal_challenges WHERE id=?", (identifier,)).fetchone()
    if not row:
        raise PortalError("INVALID_CODE", "The code is invalid or expired")
    account = _account(store, row["account_id"])
    latest = store.conn.execute("SELECT id FROM portal_challenges WHERE account_id=? ORDER BY sent_at DESC,id DESC LIMIT 1", (account["id"],)).fetchone()
    if (row["used_at"] or row["attempts"] >= 5 or parse_time(row["expires_at"]) <= now or
            not latest or latest[0] != identifier or account["status"] == "revoked"):
        raise PortalError("INVALID_CODE", "The code is invalid or expired")
    code = params.get("code")
    valid = isinstance(code, str) and re.fullmatch(r"[0-9]{6}", code)
    digest = hashlib.pbkdf2_hmac("sha256", (code if valid else "invalid").encode(), row["salt"].encode(), 100000).hex()
    store.conn.execute("UPDATE portal_challenges SET attempts=attempts+1 WHERE id=?", (identifier,))
    if not valid or not hmac.compare_digest(digest, row["code_hash"]):
        raise PortalError("INVALID_CODE", "The code is invalid or expired", commit=True)
    store.conn.execute("UPDATE portal_challenges SET used_at=? WHERE id=?", (timestamp(now), identifier))
    first = account["email_verified_at"] is None
    if first:
        store.conn.execute("UPDATE portal_accounts SET status='pending',email_verified_at=?,subscription_token=?,updated_at=? WHERE id=?",
                           (timestamp(now), secrets.token_urlsafe(36), timestamp(now), account["id"]))
        account = _account(store, account["id"])
        _queue(store, account, kind="portal_welcome", event_key="portal-welcome:" + account["id"],
               subject="Dazzle VPS 邮箱已绑定 · 等待管理员启用", public_body="邮箱已绑定，正在等待管理员审核与启用。",
               private_body="您的邮箱已绑定，正在等待管理员审核与启用。服务器实际开通并确认计量可靠后，会另发一封包含Clash与Shadowrocket订阅的邮件。", now=now)
        store.conn.execute("UPDATE portal_accounts SET welcome_queued_at=? WHERE id=?", (timestamp(now), account["id"]))
        mail.enqueue_notification(store, event_key="portal-new:" + account["id"], kind="portal_application_notice",
                                  subject="Dazzle VPS 有新的注册申请", body="有已验证邮箱的用户等待审核，请在Mac管理App查看。", now=now, cooldown_seconds=0)
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
    return _account(store, row["account_id"])


def handle_public(store, operation, params, peer_ip, now=None):
    now = parse_time(now) if now else utcnow()
    if operation not in PUBLIC_PARAMETERS or not isinstance(params, dict):
        raise PortalError("VALIDATION", "Unsupported operation")
    required, optional = PUBLIC_PARAMETERS[operation]
    if not required <= set(params) or set(params) - required - optional:
        raise PortalError("VALIDATION", "Unexpected request fields")
    if any(not isinstance(value, str) or len(value) > 512 for value in params.values()):
        raise PortalError("VALIDATION", "Request values must be bounded text")
    if operation == "auth.request_code":
        return request_code(store, params, peer_ip, now)
    if operation == "auth.verify":
        return verify(store, params, now)
    if operation == "session.me":
        account = _session(store, params["session_token"], now)
        links = _links(store, account)
        if _status(store, account, now) == "revoked":
            links = {"clash": None, "shadowrocket": None}
        return {"account": _public(store, account, now), "subscriptions": links}
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
    account = _account(store, params.get("account_id"))
    if not account["email_verified_at"] or account["status"] == "revoked":
        raise domain.DomainError("VALIDATION", "Only a verified live account can be reviewed")
    if action == "registration.reject":
        if account["proxy_user_id"]:
            raise domain.DomainError("VALIDATION", "Use user.disable for an already allocated user")
        reason = params.get("reason", "")
        if reason:
            reason = domain.text(reason, "reason", 200)
        store.conn.execute("UPDATE portal_accounts SET status='rejected',rejection_reason=?,updated_at=? WHERE id=?", (reason, timestamp(now), account["id"]))
        _queue(store, account, kind="portal_review", event_key="portal-reject:" + account["id"], subject="Dazzle VPS 申请审核结果",
               public_body="申请未获批准，请联系管理员。", private_body="您的申请尚未获准使用代理。如有疑问请联系管理员。", now=now)
        return {"account": _public(store, _account(store, account["id"]), now)}
    if action != "registration.approve":
        raise domain.DomainError("VALIDATION", "Unknown admission action")
    quota = domain.integer(params.get("quota_bytes", store.get_setting("default_quota_bytes")), "quota_bytes", 1)
    if not account["proxy_user_id"]:
        row = store.conn.execute("SELECT worker_id FROM production_workers WHERE role='member' AND user_id IS NULL AND tombstoned=0 ORDER BY public_port LIMIT 1").fetchone()
        if not row:
            store.conn.execute("UPDATE portal_accounts SET status='waiting_resources',updated_at=? WHERE id=?", (timestamp(now), account["id"]))
            return {"account": _public(store, _account(store, account["id"]), now), "waiting_resources": True}
        from .production import _add_user
        result = _add_user(store, {"role": "member", "name": account["nickname"] + " · " + account["id"][:6], "quota_bytes": quota}, now)
        user_id = result["user"]["id"]
        store.conn.execute("UPDATE credentials SET subscription_token=? WHERE user_id=?", (account["subscription_token"], user_id))
        store.conn.execute("UPDATE users SET email=?,email_verified=1,manual_disabled=0 WHERE id=?", (account["email"], user_id))
        store.conn.execute("UPDATE portal_accounts SET proxy_user_id=?,status='approved',updated_at=? WHERE id=?", (user_id, timestamp(now), account["id"]))
        _queue(store, account, kind="portal_review", event_key="portal-approved:" + account["id"], subject="Dazzle VPS 申请已获批准",
               public_body="管理员已批准申请，服务器正在开通，请等待网页显示已启用后更新订阅。",
               private_body="管理员已批准申请。服务器正在开通；请等待网页状态变为已启用，再更新原来的订阅链接。", now=now)
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
