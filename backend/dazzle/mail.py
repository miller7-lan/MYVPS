"""Durable notifications with isolated simulation and explicit production SMTP.

RPC only persists settings and intent. The production worker claims a lease,
commits, performs TLS SMTP outside SQLite, then records the accepted/error state.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import smtplib
import ssl
import threading
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime


DEFAULT_PREFERENCES = {"enabled": True, "cooldown_seconds": 3600, "max_attempts": 5}
VERIFY_TTL_SECONDS = 600
VERIFY_COOLDOWN_SECONDS = 60
VERIFY_MAX_ATTEMPTS = 5
RETRY_BASE_SECONDS = 60
RETRY_MAX_SECONDS = 3600


def _production(store):
    return hasattr(store, "get_meta") and store.get_meta("mode") == "production"


def _instant(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("Mail time must include a timezone")
    return value.astimezone(timezone.utc)


def _iso(value):
    return _instant(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def ensure_schema(store):
    # executescript() would implicitly commit the caller's transaction.
    statements = [
        """CREATE TABLE IF NOT EXISTS mail_config (
            id INTEGER PRIMARY KEY CHECK(id=1), configured INTEGER NOT NULL DEFAULT 0,
            transport TEXT NOT NULL DEFAULT 'simulated', settings_json TEXT NOT NULL DEFAULT '{}',
            preferences_json TEXT NOT NULL DEFAULT '{}')""",
        """CREATE TABLE IF NOT EXISTS mail_verifications (
            identity TEXT PRIMARY KEY, email TEXT NOT NULL, salt TEXT NOT NULL,
            code_hash TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            sent_at TEXT NOT NULL, verified_at TEXT)""",
        """CREATE TABLE IF NOT EXISTS mail_outbox (
            id TEXT PRIMARY KEY, dedup_key TEXT NOT NULL UNIQUE, event_key TEXT NOT NULL,
            user_id TEXT, cycle_id TEXT, recipient TEXT NOT NULL, kind TEXT NOT NULL,
            subject TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
            transport TEXT NOT NULL DEFAULT 'simulated', attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL, next_attempt_at TEXT NOT NULL, last_attempt_at TEXT,
            lease_owner TEXT, lease_until TEXT, completed_at TEXT, error_code TEXT)""",
        """CREATE TABLE IF NOT EXISTS mail_simulated_mailbox (
            outbox_id TEXT PRIMARY KEY, recipient TEXT NOT NULL, subject TEXT NOT NULL,
            body TEXT NOT NULL, prepared_at TEXT NOT NULL, delivered_at TEXT)""",
        "CREATE INDEX IF NOT EXISTS mail_due ON mail_outbox(status,next_attempt_at)",
        "CREATE INDEX IF NOT EXISTS mail_cooldown ON mail_outbox(user_id,kind,created_at)",
        "CREATE TABLE IF NOT EXISTS mail_secrets(id INTEGER PRIMARY KEY CHECK(id=1),secret TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS mail_private_payload(outbox_id TEXT PRIMARY KEY,body TEXT NOT NULL)",
    ]
    for statement in statements:
        store.conn.execute(statement)
    store.conn.execute("INSERT OR IGNORE INTO mail_config(id) VALUES(1)")


def _config(store):
    row = store.conn.execute("SELECT * FROM mail_config WHERE id=1").fetchone()
    preferences = dict(DEFAULT_PREFERENCES)
    preferences.update(json.loads(row["preferences_json"]))
    return bool(row["configured"]), row["transport"], json.loads(row["settings_json"]), preferences


def _address(value):
    if not isinstance(value, str) or len(value) > 254:
        raise ValueError("A valid email address is required")
    value = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}", value):
        raise ValueError("A valid email address is required")
    return value


def _safe_text(value, *, limit=10000):
    text = str(value or "")[:limit]
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[redacted]", text, flags=re.S)
    text = re.sub(r"(?i)\b(?:ss|ssr|vmess|vless|tuic|trojan|hysteria2?|hy2|socks5?|http[s]?)://[^\s<>\"']+", "[redacted link]", text)
    text = re.sub(r"(?i)\bBearer\s+[^\s,;]+", "Bearer [redacted]", text)
    text = re.sub(r"(?i)([\"']?(?:password|passwd|secret|token|api[_-]?key|authorization|subscription[_-]?url|private[_-]?key)[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)", r"\1[redacted]", text)
    return text


def _user(store, user_id):
    row = store.conn.execute("SELECT * FROM users WHERE id=?", (str(user_id),)).fetchone()
    if row is None:
        raise KeyError("User not found")
    user = dict(row)
    if user.get("revoked_at"):
        raise ValueError("Revoked users cannot receive mail")
    return user


def _identity(store, params):
    user_id = params.get("user_id")
    if user_id is not None:
        user = _user(store, user_id)
        email = params.get("email", user.get("email"))
        return "user:" + str(user_id), _address(email), str(user_id)
    _, _, config, _ = _config(store)
    email = params.get("email", config.get("admin_email"))
    email = _address(email)
    if email != config.get("admin_email"):
        raise ValueError("Configure the administrator email before verifying it")
    return "admin", email, None


def _verified_recipient(store, user_id=None, recipient=None):
    if user_id is not None:
        user = _user(store, user_id)
        email = user.get("email")
        if not user.get("email_verified") or not email:
            return None
        return email if recipient is None or recipient == email else None
    _, _, config, _ = _config(store)
    email = config.get("admin_email")
    row = store.conn.execute("SELECT email,verified_at FROM mail_verifications WHERE identity='admin'").fetchone()
    if not row or not row["verified_at"] or row["email"] != email:
        return None
    return email if recipient is None or recipient == email else None


def _enqueue(store, *, event_key, user_id, cycle_id, recipient, kind, subject, body, now, cooldown_seconds=0, private_body=None):
    key_parts = [str(user_id) if user_id is not None else "admin", str(cycle_id or ""), str(event_key)]
    dedup_key = hashlib.sha256(json.dumps(key_parts, ensure_ascii=True).encode()).hexdigest()
    previous = store.conn.execute("SELECT id,status FROM mail_outbox WHERE dedup_key=?", (dedup_key,)).fetchone()
    if previous:
        return {"queued": False, "id": previous["id"], "status": previous["status"], "reason": "duplicate"}
    if cooldown_seconds:
        cutoff = _iso(_instant(now) - timedelta(seconds=cooldown_seconds))
        recent = store.conn.execute(
            """SELECT id FROM mail_outbox WHERE user_id IS ? AND cycle_id IS ? AND kind=?
               AND recipient=? AND created_at>? AND status!='cancelled' LIMIT 1""",
            (str(user_id) if user_id is not None else None, cycle_id, kind, recipient, cutoff),
        ).fetchone()
        if recent:
            return {"queued": False, "id": recent["id"], "reason": "cooldown"}
    message_id = uuid.uuid4().hex
    subject = _safe_text(subject, limit=200).replace("\r", " ").replace("\n", " ")
    body = _safe_text(body)
    now_iso = _iso(now)
    store.conn.execute(
        """INSERT INTO mail_outbox(id,dedup_key,event_key,user_id,cycle_id,recipient,kind,subject,body,created_at,next_attempt_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (message_id, dedup_key, _safe_text(event_key, limit=200), str(user_id) if user_id is not None else None,
         cycle_id, recipient, kind, subject, body, now_iso, now_iso),
    )
    # The simulated email is deliberately isolated from the public queue/snapshot.
    transport = "smtp" if _production(store) else "simulated"
    if transport == "smtp":
        store.conn.execute("UPDATE mail_outbox SET transport='smtp' WHERE id=?", (message_id,))
        if private_body is not None:
            store.conn.execute("INSERT INTO mail_private_payload VALUES(?,?)", (message_id, private_body))
    else:
        store.conn.execute(
            "INSERT INTO mail_simulated_mailbox(outbox_id,recipient,subject,body,prepared_at) VALUES(?,?,?,?,?)",
            (message_id, recipient, subject, private_body if private_body is not None else body, now_iso),
        )
    return {"queued": True, "id": message_id, "status": "queued", "transport": transport}


def enqueue_notification(store, *, event_key, user_id=None, kind="notification", subject, body, now, cycle_id=None, recipient=None, cooldown_seconds=None):
    """Queue only a verified recipient. Key identity includes user and quota cycle."""
    ensure_schema(store)
    if _production(store) and not _config(store)[0]:
        return {"queued": False, "reason": "smtp_not_configured"}
    _, _, _, preferences = _config(store)
    if not preferences["enabled"]:
        return {"queued": False, "reason": "notifications_disabled"}
    try:
        email = _verified_recipient(store, user_id, recipient)
    except (KeyError, ValueError):
        return {"queued": False, "reason": "recipient_unavailable"}
    if not email:
        return {"queued": False, "reason": "email_unverified"}
    return _enqueue(store, event_key=event_key, user_id=user_id, cycle_id=cycle_id, recipient=email,
                    kind=_safe_text(kind, limit=80), subject=subject, body=body, now=now,
                    cooldown_seconds=preferences["cooldown_seconds"] if cooldown_seconds is None else cooldown_seconds)


def snapshot_mail(store):
    ensure_schema(store)
    configured, transport, config, preferences = _config(store)
    verification = store.conn.execute("SELECT email,verified_at FROM mail_verifications WHERE identity='admin'").fetchone()
    admin_verified = bool(verification and verification["verified_at"] and verification["email"] == config.get("admin_email"))
    # Neither message bodies nor verification hashes/salts/codes leave this module.
    columns = "id,user_id,cycle_id,recipient,kind,subject,status,transport,attempts,created_at,next_attempt_at,last_attempt_at,lease_until,completed_at,error_code"
    queue = [dict(row) for row in store.conn.execute(f"SELECT {columns} FROM mail_outbox WHERE status IN ('queued','retry','sending') ORDER BY created_at,id LIMIT 100")]
    history = [dict(row) for row in store.conn.execute(f"SELECT {columns} FROM mail_outbox WHERE status NOT IN ('queued','retry','sending') ORDER BY completed_at DESC,id LIMIT 100")]
    for item in history:
        if item["status"] == "sent":
            item["submitted_at"] = item["completed_at"]
    live = _production(store)
    secret_configured = bool(store.conn.execute("SELECT 1 FROM mail_secrets WHERE id=1").fetchone())
    return {"configured": configured, "transport": transport if configured or config else "not_enabled" if live else transport,
            "settings_configured": bool(config), "secret_configured": secret_configured if live else False,
            "credential_required": live and bool(config) and not secret_configured,
            "worker_status": store.get_meta("mail_worker_status", "not_observed") if live else "simulated",
            "admin_email": config.get("admin_email"),
            "admin_email_verified": admin_verified, "queue": queue, "history": history, "preferences": preferences,
            "configuration": {key: config.get(key) for key in ("host", "port", "security", "username", "sender")}}


def mail_snapshot(store, now=None):
    return snapshot_mail(store)


class MailDeliveryError(Exception):
    def __init__(self, code, *, retryable=True):
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def claim_messages(store, now, *, worker_id, limit=20, lease_seconds=60):
    """Claim due work; caller commits before handing claims to a live worker."""
    ensure_schema(store)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("Mail batch limit must be between 1 and 100")
    if not isinstance(lease_seconds, int) or isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 3600:
        raise ValueError("Mail lease must be between 1 and 3600 seconds")
    now_iso = _iso(now)
    _, _, _, preferences = _config(store)
    # Crashes also consume attempts: abandoned leases cannot retry forever.
    store.conn.execute(
        """UPDATE mail_outbox SET status='dead',lease_owner=NULL,lease_until=NULL,
           completed_at=?,error_code='LEASE_EXPIRED' WHERE status='sending' AND lease_until<=? AND attempts>=?""",
        (now_iso, now_iso, preferences["max_attempts"]),
    )
    store.conn.execute(
        """UPDATE mail_outbox SET status='retry',lease_owner=NULL,lease_until=NULL,
           next_attempt_at=?,error_code='LEASE_EXPIRED' WHERE status='sending' AND lease_until<=?""",
        (now_iso, now_iso),
    )
    rows = store.conn.execute(
        "SELECT id FROM mail_outbox WHERE status IN ('queued','retry') AND next_attempt_at<=? ORDER BY created_at,id LIMIT ?",
        (now_iso, limit),
    ).fetchall()
    claimed = []
    for row in rows:
        changed = store.conn.execute(
            """UPDATE mail_outbox SET status='sending',lease_owner=?,lease_until=?,attempts=attempts+1,last_attempt_at=?
               WHERE id=? AND status IN ('queued','retry') AND next_attempt_at<=?""",
            (str(worker_id), _iso(_instant(now) + timedelta(seconds=lease_seconds)), now_iso, row["id"], now_iso),
        ).rowcount
        if changed:
            claimed.append(dict(store.conn.execute("SELECT * FROM mail_outbox WHERE id=?", (row["id"],)).fetchone()))
    return claimed


def _still_authorized(store, message, now):
    if message["kind"] == "verification":
        identity = "user:" + message["user_id"] if message["user_id"] else "admin"
        verification = store.conn.execute("SELECT * FROM mail_verifications WHERE identity=?", (identity,)).fetchone()
        if not verification or verification["email"] != message["recipient"] or verification["verified_at"] or _parse(verification["expires_at"]) <= _instant(now):
            return False
        # The latest code supersedes all prior verification emails.
        if message["created_at"] != verification["sent_at"]:
            return False
        if message["user_id"]:
            try:
                return _user(store, message["user_id"]).get("email") == message["recipient"]
            except (KeyError, ValueError):
                return False
        return _config(store)[2].get("admin_email") == message["recipient"]
    try:
        return _config(store)[3]["enabled"] and bool(_verified_recipient(store, message["user_id"], message["recipient"]))
    except (KeyError, ValueError):
        return False


def finish_message(store, message_id, worker_id, now, *, error=None, transport="simulated"):
    row = store.conn.execute("SELECT * FROM mail_outbox WHERE id=?", (message_id,)).fetchone()
    if not row or row["status"] != "sending" or row["lease_owner"] != str(worker_id) or _parse(row["lease_until"]) <= _instant(now):
        return False
    now_iso = _iso(now)
    if error is None:
        if transport == "smtp" and _production(store):
            status = "sent"  # SMTP accepted; final inbox delivery is not proven.
        elif transport == "simulated":
            store.conn.execute("UPDATE mail_simulated_mailbox SET delivered_at=COALESCE(delivered_at,?) WHERE outbox_id=?", (now_iso, message_id))
            status = "simulated"
        else:
            raise ValueError("Live mail delivery is disabled in phase 1")
        completed_at, next_attempt, error_code = now_iso, now_iso, None
    else:
        _, _, _, preferences = _config(store)
        retry = error.retryable and row["attempts"] < preferences["max_attempts"]
        status = "retry" if retry else "dead"
        completed_at = None if retry else now_iso
        delay = min(RETRY_MAX_SECONDS, RETRY_BASE_SECONDS * (2 ** min(row["attempts"] - 1, 16)))
        next_attempt = _iso(_instant(now) + timedelta(seconds=delay)) if retry else now_iso
        # Never preserve exception messages, SMTP replies, credentials, or payloads.
        allowed = {"TLS_ERROR", "AUTHENTICATION_FAILED", "RECIPIENT_REJECTED", "TRANSIENT_DELIVERY_FAILURE", "DELIVERY_FAILED", "LIVE_TRANSPORT_DISABLED"}
        error_code = error.code if error.code in allowed else "DELIVERY_FAILED"
    store.conn.execute(
        "UPDATE mail_outbox SET status=?,transport=?,completed_at=?,next_attempt_at=?,error_code=?,lease_owner=NULL,lease_until=NULL WHERE id=?",
        (status, transport, completed_at, next_attempt, error_code, message_id),
    )
    if status in {"sent", "simulated", "dead"}:
        store.conn.execute("DELETE FROM mail_private_payload WHERE outbox_id=?", (message_id,))
    return True


def process_outbox(store, now, *, limit=20, worker_id=None, delivery=None):
    ensure_schema(store)
    configured, transport, _, _ = _config(store)
    if not configured:
        return {"processed": 0, "simulated": 0, "retry": 0, "dead": 0, "cancelled": 0, "state": "not_configured"}
    if transport != "simulated":
        raise ValueError("Live mail delivery is disabled in phase 1")
    worker_id = worker_id or uuid.uuid4().hex
    claimed = claim_messages(store, now, worker_id=worker_id, limit=limit)
    result = {"processed": len(claimed), "simulated": 0, "retry": 0, "dead": 0, "cancelled": 0, "state": "simulated"}
    for message in claimed:
        if not _still_authorized(store, message, now):
            store.conn.execute("UPDATE mail_outbox SET status='cancelled',completed_at=?,error_code='RECIPIENT_NO_LONGER_AUTHORIZED',lease_owner=NULL,lease_until=NULL WHERE id=? AND lease_owner=?", (_iso(now), message["id"], worker_id))
            result["cancelled"] += 1
            continue
        failure = None
        try:
            if delivery is not None:
                delivery(message)
        except MailDeliveryError as exc:
            failure = exc
        except Exception:
            failure = MailDeliveryError("DELIVERY_FAILED")
        finish_message(store, message["id"], worker_id, now, error=failure)
        status = store.conn.execute("SELECT status FROM mail_outbox WHERE id=?", (message["id"],)).fetchone()["status"]
        result[status] += 1
    return result


def _smtp_send(config, message, *, password=None, allow_live=False, smtp_factory=None, smtp_ssl_factory=None):
    """TLS submission; callers must explicitly enable and provide the secret."""
    if not allow_live:
        raise MailDeliveryError("LIVE_TRANSPORT_DISABLED", retryable=False)
    if config.get("security") not in ("ssl", "starttls"):
        raise MailDeliveryError("TLS_ERROR", retryable=False)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        factory = (smtp_ssl_factory or smtplib.SMTP_SSL) if config["security"] == "ssl" else (smtp_factory or smtplib.SMTP)
        kwargs = {"timeout": 15}
        if config["security"] == "ssl":
            kwargs["context"] = context
        with factory(config["host"], config["port"], **kwargs) as client:
            if config["security"] == "starttls":
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
            if config.get("username"):
                if not password:
                    raise MailDeliveryError("AUTHENTICATION_FAILED", retryable=False)
                client.login(config["username"], password)
            email = EmailMessage()
            email["From"] = _address(config["sender"])
            email["To"] = _address(message["recipient"])
            email["Subject"] = _safe_text(message["subject"], limit=200).replace("\r", " ").replace("\n", " ")
            if message.get("id"):
                email["Message-ID"] = "<dazzle-" + message["id"] + "@" + config["sender"].rsplit("@", 1)[-1] + ">"
            if message.get("created_at"):
                email["Date"] = format_datetime(_parse(message["created_at"]))
            email.set_content(_safe_text(message["body"]))
            rejected = client.send_message(email)
            if isinstance(rejected, dict) and rejected:
                raise MailDeliveryError("RECIPIENT_REJECTED", retryable=False)
    except MailDeliveryError:
        raise
    except (ssl.SSLError, smtplib.SMTPNotSupportedError):
        raise MailDeliveryError("TLS_ERROR", retryable=False) from None
    except smtplib.SMTPAuthenticationError:
        raise MailDeliveryError("AUTHENTICATION_FAILED", retryable=False) from None
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused):
        raise MailDeliveryError("RECIPIENT_REJECTED", retryable=False) from None
    except smtplib.SMTPResponseException as exc:
        raise MailDeliveryError("TRANSIENT_DELIVERY_FAILURE" if 400 <= exc.smtp_code < 500 else "DELIVERY_FAILED", retryable=400 <= exc.smtp_code < 500) from None
    except (OSError, smtplib.SMTPException):
        raise MailDeliveryError("TRANSIENT_DELIVERY_FAILURE") from None


def simulated_mailbox_for_tests(store, *, recipient=None, delivered_only=False):
    """Test-only local fixture inspection. Never exposed as an RPC action."""
    ensure_schema(store)
    rows = store.conn.execute("SELECT * FROM mail_simulated_mailbox ORDER BY prepared_at,outbox_id").fetchall()
    return [dict(row) for row in rows if (recipient is None or row["recipient"] == recipient) and (not delivered_only or row["delivered_at"])]


def _confirm_live_verification(store, params, now):
    identity, email, user_id = _identity(store, params)
    verification = store.conn.execute("SELECT * FROM mail_verifications WHERE identity=?", (identity,)).fetchone()
    if not verification or verification["email"] != email:
        return {"verified": False, "reason": "verification_missing"}
    if verification["verified_at"]:
        return {"verified": True, "email": email}
    if verification["attempts"] >= VERIFY_MAX_ATTEMPTS:
        return {"verified": False, "reason": "attempt_limit"}
    if _parse(verification["expires_at"]) <= now:
        return {"verified": False, "reason": "expired"}
    code = params.get("code")
    valid = isinstance(code, str) and re.fullmatch(r"[0-9]{6}", code)
    candidate = hashlib.pbkdf2_hmac("sha256", (code if valid else "invalid").encode(), verification["salt"].encode(), 100000).hex()
    store.conn.execute("UPDATE mail_verifications SET attempts=attempts+1 WHERE identity=?", (identity,))
    if not valid or not hmac.compare_digest(candidate, verification["code_hash"]):
        return {"verified": False, "reason": "invalid_code"}
    store.conn.execute("UPDATE mail_verifications SET verified_at=? WHERE identity=?", (_iso(now), identity))
    if user_id:
        store.conn.execute("UPDATE users SET email_verified=1,updated_at=? WHERE id=? AND email=?", (_iso(now), user_id, email))
    return {"verified": True, "email": email}


def handle_live_mail(store, action, params, now):
    """Production request handlers only persist intent; SMTP runs in a worker."""
    if not _production(store):
        raise ValueError("Production mail requires production state")
    if action == "mail.status":
        return snapshot_mail(store)
    if action == "mail.configure":
        if set(params) - {"host", "port", "security", "username", "sender", "admin_email", "secret"}:
            raise ValueError("Unknown SMTP setting")
        host, port, security = params.get("host"), params.get("port"), params.get("security")
        if not isinstance(host, str) or not 1 <= len(host) <= 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise ValueError("Invalid SMTP host")
        if type(port) is not int or not 1 <= port <= 65535 or security not in {"ssl", "starttls"}:
            raise ValueError("SMTP requires a valid port and TLS mode")
        username = params.get("username")
        if not isinstance(username, str) or not 1 <= len(username) <= 254 or any(ord(c) < 32 or ord(c) == 127 for c in username):
            raise ValueError("SMTP authentication username is required")
        config = {"host": host, "port": port, "security": security, "username": username,
                  "sender": _address(params.get("sender")), "admin_email": _address(params.get("admin_email"))}
        old = _config(store)[2]
        # Never send an old authorization code to a newly selected SMTP server.
        if any(old.get(key) != config[key] for key in ("host", "port", "security", "username")):
            store.conn.execute("DELETE FROM mail_secrets WHERE id=1")
        if "secret" in params:
            secret = params["secret"]
            if not isinstance(secret, str) or not 1 <= len(secret) <= 512 or any(ord(c) < 32 or ord(c) == 127 for c in secret):
                raise ValueError("Invalid SMTP authorization code")
            store.conn.execute("INSERT INTO mail_secrets VALUES(1,?) ON CONFLICT(id) DO UPDATE SET secret=excluded.secret", (secret,))
        ready = bool(store.conn.execute("SELECT 1 FROM mail_secrets WHERE id=1").fetchone())
        store.conn.execute("UPDATE mail_config SET configured=?,transport='smtp',settings_json=? WHERE id=1", (int(ready), json.dumps(config)))
        if old.get("admin_email") != config["admin_email"]:
            store.conn.execute("DELETE FROM mail_verifications WHERE identity='admin'")
        value = snapshot_mail(store)
        return {"configured": ready, "secret_configured": ready, "credential_required": not ready,
                "mail": value, "connected": False, "state": "ready" if ready else "smtp_secret_required"}
    if action == "mail.preferences":
        _, _, _, preferences = _config(store)
        for key, value in params.items():
            if key == "enabled" and type(value) is bool:
                pass
            elif key == "cooldown_seconds" and type(value) is int and 0 <= value <= 86400:
                pass
            elif key == "max_attempts" and type(value) is int and 1 <= value <= 10:
                pass
            else:
                raise ValueError("Invalid mail preference")
            preferences[key] = value
        store.conn.execute("UPDATE mail_config SET preferences_json=? WHERE id=1", (json.dumps(preferences),))
        return {"mail": snapshot_mail(store)}
    if action == "mail.verify.confirm":
        return _confirm_live_verification(store, params, now)
    if action in {"mail.verify.send", "mail.test"}:
        if not _config(store)[0]:
            return {"queued": False, "reason": "smtp_secret_required" if _config(store)[2] else "smtp_not_configured"}
        if action == "mail.test":
            return enqueue_notification(store, event_key="test:" + uuid.uuid4().hex, user_id=params.get("user_id"),
                                        kind="test", subject="Dazzle VPS 测试通知",
                                        body="这是一封服务器邮件配置测试通知。SMTP 接受不等于最终进入收件箱；本邮件不含代理凭据或订阅链接。", now=now)
        identity, email, user_id = _identity(store, params)
        existing = store.conn.execute("SELECT sent_at FROM mail_verifications WHERE identity=?", (identity,)).fetchone()
        if existing and (now - _parse(existing["sent_at"])).total_seconds() < VERIFY_COOLDOWN_SECONDS:
            return {"queued": False, "reason": "verification_cooldown", "retry_after_seconds": VERIFY_COOLDOWN_SECONDS}
        code, salt = f"{secrets.randbelow(1000000):06d}", secrets.token_hex(16)
        code_hash = hashlib.pbkdf2_hmac("sha256", code.encode(), salt.encode(), 100000).hex()
        store.conn.execute("INSERT INTO mail_verifications VALUES(?,?,?,?,?,0,?,NULL) ON CONFLICT(identity) DO UPDATE SET email=excluded.email,salt=excluded.salt,code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,sent_at=excluded.sent_at,verified_at=NULL",
                           (identity, email, salt, code_hash, _iso(now + timedelta(seconds=VERIFY_TTL_SECONDS)), _iso(now)))
        if user_id:
            store.conn.execute("UPDATE users SET email=?,email_verified=0,updated_at=? WHERE id=?", (email, _iso(now), user_id))
        result = _enqueue(store, event_key="verify:" + uuid.uuid4().hex, user_id=user_id, cycle_id=None,
                          recipient=email, kind="verification", subject="Dazzle VPS 邮箱验证码",
                          body="邮箱验证通知；验证码仅用于发往已配置收件人的私密邮件。", now=now,
                          private_body=f"您的邮箱验证码：{code}\n10分钟内有效，最多尝试5次。如非本人操作请忽略。")
        return {**result, "expires_at": _iso(now + timedelta(seconds=VERIFY_TTL_SECONDS)), "state": "queued"}
    raise ValueError("This mail action is unavailable in production")


def process_live_outbox(store, now=None, *, delivery=None):
    """Claim and authorize durably, send outside SQLite, finish with the lease."""
    if store.conn.in_transaction:
        raise RuntimeError("SMTP worker cannot run inside a SQLite transaction")
    if not _production(store):
        raise ValueError("SMTP worker requires production state")
    explicit_clock = now is not None
    now = _instant(now) if explicit_clock else datetime.now(timezone.utc)
    worker_id = uuid.uuid4().hex
    store.conn.execute("BEGIN IMMEDIATE")
    try:
        configured, transport, config, _ = _config(store)
        secret_row = store.conn.execute("SELECT secret FROM mail_secrets WHERE id=1").fetchone()
        if not configured or transport != "smtp" or secret_row is None:
            store.conn.rollback()
            return {"processed": 0, "state": "not_configured"}
        claimed = claim_messages(store, now, worker_id=worker_id, limit=1, lease_seconds=120)
        if not claimed:
            store.conn.commit()
            return {"processed": 0, "state": "idle"}
        message = claimed[0]
        if not _still_authorized(store, message, now):
            store.conn.execute("UPDATE mail_outbox SET status='cancelled',completed_at=?,error_code='RECIPIENT_NO_LONGER_AUTHORIZED',lease_owner=NULL,lease_until=NULL WHERE id=?", (_iso(now), message["id"]))
            store.conn.execute("DELETE FROM mail_private_payload WHERE outbox_id=?", (message["id"],))
            store.conn.commit()
            return {"processed": 1, "state": "cancelled"}
        payload = store.conn.execute("SELECT body FROM mail_private_payload WHERE outbox_id=?", (message["id"],)).fetchone()
        if message["kind"] == "verification" and payload is None:
            raise ValueError("Private verification payload is unavailable")
        if payload is not None:
            message["body"] = payload["body"]
        secret = secret_row["secret"]
        store.conn.commit()
    except BaseException:
        store.conn.rollback()
        raise
    failure = None
    try:
        if delivery is None:
            _smtp_send(config, message, password=secret, allow_live=True)
        else:
            delivery(config, message, secret)
    except MailDeliveryError as exc:
        failure = exc
    except Exception:
        failure = MailDeliveryError("DELIVERY_FAILED")
    completed = now if explicit_clock else datetime.now(timezone.utc)
    store.conn.execute("BEGIN IMMEDIATE")
    try:
        finish_message(store, message["id"], worker_id, completed, error=failure, transport="smtp")
        status = store.conn.execute("SELECT status FROM mail_outbox WHERE id=?", (message["id"],)).fetchone()["status"]
        store.conn.commit()
    except BaseException:
        store.conn.rollback()
        raise
    return {"processed": 1, "state": status}


class MailExecutor:
    """Independent SMTP worker: no network waits in proxy sampling/watchdog loop."""
    def __init__(self, store):
        self.state_dir, self.policy = store.state_dir, store.policy
        self.stopped = threading.Event()
        self.failed = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name="dazzle-smtp-worker")

    def _run(self):
        from .production_state import ProductionStore
        while not self.stopped.is_set():
            try:
                with ProductionStore(self.state_dir, policy=self.policy) as store:
                    self.failed.clear()
                    while not self.stopped.is_set():
                        process_live_outbox(store)
                        self.stopped.wait(1)
            except Exception:
                self.failed.set()  # Never propagate SMTP diagnostics or stop proxies.
                self.stopped.wait(5)

    def start(self):
        self.thread.start()

    def close(self):
        self.stopped.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=0.2)


def handle_mail(store, action, params, now):
    ensure_schema(store)
    now = _instant(now)
    if not isinstance(params, dict):
        raise ValueError("Mail parameters must be an object")
    if _production(store):
        return handle_live_mail(store, action, params, now)
    if action == "mail.simulated_inbox":
        if not hasattr(store, "get_meta") or store.get_meta("mode") != "simulation":
            raise ValueError("The simulated inbox is only available in simulation mode")
        limit = params.get("limit", 50)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("Inbox limit must be between 1 and 100")
        rows = store.conn.execute(
            "SELECT * FROM mail_simulated_mailbox ORDER BY prepared_at DESC,outbox_id DESC LIMIT ?", (limit,)
        ).fetchall()
        messages = [{"id": row["outbox_id"], "recipient": row["recipient"], "subject": row["subject"],
                     "body": row["body"], "prepared_at": row["prepared_at"], "delivered_at": row["delivered_at"]}
                    for row in rows]
        return {"sensitive": True, "transport": "simulated", "messages": messages,
                "notice": "Local simulation only; no email was sent to an external mailbox."}
    if action == "mail.configure":
        if "password" in params or "secret" in params:
            raise ValueError("SMTP passwords are not accepted in phase 1")
        host = params.get("host")
        if not isinstance(host, str) or not host or len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise ValueError("A valid SMTP host is required")
        port = params.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("SMTP port must be between 1 and 65535")
        security = params.get("security")
        if security not in ("ssl", "starttls"):
            raise ValueError("SMTP requires ssl or starttls")
        username = params.get("username", "")
        if not isinstance(username, str) or len(username) > 254 or any(ord(char) < 32 for char in username):
            raise ValueError("Invalid SMTP username")
        if params.get("transport", "simulated") != "simulated":
            raise ValueError("Live mail delivery is disabled in phase 1")
        config = {"host": host, "port": port, "security": security, "username": username,
                  "sender": _address(params.get("sender")), "admin_email": _address(params.get("admin_email"))}
        old_email = _config(store)[2].get("admin_email")
        store.conn.execute("UPDATE mail_config SET configured=1,transport='simulated',settings_json=? WHERE id=1", (json.dumps(config),))
        if old_email != config["admin_email"]:
            store.conn.execute("DELETE FROM mail_verifications WHERE identity='admin'")
        return {"mail": snapshot_mail(store), "state": "simulated", "connected": False}
    if action == "mail.preferences":
        _, _, _, preferences = _config(store)
        for key, value in params.items():
            if key == "enabled":
                if not isinstance(value, bool):
                    raise ValueError("enabled must be a boolean")
            elif key == "cooldown_seconds":
                if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 86400:
                    raise ValueError("Mail cooldown must be between 0 and 86400 seconds")
            elif key == "max_attempts":
                if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 10:
                    raise ValueError("Mail attempts must be between 1 and 10")
            else:
                raise ValueError("Unknown mail preference")
            preferences[key] = value
        store.conn.execute("UPDATE mail_config SET preferences_json=? WHERE id=1", (json.dumps(preferences),))
        return {"mail": snapshot_mail(store)}
    if action == "mail.verify.send":
        if not _config(store)[0]:
            raise ValueError("Configure mail simulation before verification")
        identity, email, user_id = _identity(store, params)
        existing = store.conn.execute("SELECT sent_at FROM mail_verifications WHERE identity=?", (identity,)).fetchone()
        if existing and (_instant(now) - _parse(existing["sent_at"])).total_seconds() < VERIFY_COOLDOWN_SECONDS:
            return {"queued": False, "reason": "verification_cooldown", "retry_after_seconds": VERIFY_COOLDOWN_SECONDS - int((_instant(now) - _parse(existing["sent_at"])).total_seconds())}
        code, salt = f"{secrets.randbelow(1000000):06d}", secrets.token_hex(16)
        code_hash = hashlib.pbkdf2_hmac("sha256", code.encode(), salt.encode(), 100000).hex()
        store.conn.execute(
            """INSERT INTO mail_verifications(identity,email,salt,code_hash,expires_at,attempts,sent_at,verified_at)
               VALUES(?,?,?,?,?,0,?,NULL) ON CONFLICT(identity) DO UPDATE SET email=excluded.email,salt=excluded.salt,
               code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,sent_at=excluded.sent_at,verified_at=NULL""",
            (identity, email, salt, code_hash, _iso(now + timedelta(seconds=VERIFY_TTL_SECONDS)), _iso(now)),
        )
        if user_id:
            store.conn.execute("UPDATE users SET email=?,email_verified=0,updated_at=? WHERE id=?", (email, _iso(now), user_id))
        result = _enqueue(store, event_key="verify:" + uuid.uuid4().hex, user_id=user_id, cycle_id=None,
                          recipient=email, kind="verification", subject="DAZZLE 邮箱验证（本地模拟）",
                          body="验证码内容仅保存在隔离的本地模拟邮箱，普通界面不可读取。", now=now,
                          private_body=f"您的邮箱验证码：{code}\n10分钟内有效，最多尝试5次。本邮件来自本地模拟，不会实际发送。")
        return {**result, "expires_at": _iso(now + timedelta(seconds=VERIFY_TTL_SECONDS)), "state": "simulated"}
    if action == "mail.verify.confirm":
        identity, email, user_id = _identity(store, params)
        verification = store.conn.execute("SELECT * FROM mail_verifications WHERE identity=?", (identity,)).fetchone()
        if not verification or verification["email"] != email:
            return {"verified": False, "reason": "verification_missing"}
        if verification["verified_at"]:
            return {"verified": True, "email": email}
        if verification["attempts"] >= VERIFY_MAX_ATTEMPTS:
            return {"verified": False, "reason": "attempt_limit"}
        if _parse(verification["expires_at"]) <= now:
            return {"verified": False, "reason": "expired"}
        code = params.get("code")
        valid_shape = isinstance(code, str) and re.fullmatch(r"[0-9]{6}", code)
        candidate = hashlib.pbkdf2_hmac("sha256", (code if valid_shape else "invalid").encode(), verification["salt"].encode(), 100000).hex()
        store.conn.execute("UPDATE mail_verifications SET attempts=attempts+1 WHERE identity=?", (identity,))
        if not valid_shape or not hmac.compare_digest(candidate, verification["code_hash"]):
            return {"verified": False, "reason": "invalid_code"}
        store.conn.execute("UPDATE mail_verifications SET verified_at=? WHERE identity=?", (_iso(now), identity))
        if user_id:
            store.conn.execute("UPDATE users SET email_verified=1,updated_at=? WHERE id=? AND email=?", (_iso(now), user_id, email))
        return {"verified": True, "email": email}
    if action == "mail.test":
        if not _config(store)[0]:
            raise ValueError("Configure mail simulation before testing")
        return enqueue_notification(store, event_key="test:" + uuid.uuid4().hex, user_id=params.get("user_id"),
                                    kind="test", subject="DAZZLE 测试通知（本地模拟）",
                                    body="邮件通知配置测试。不包含代理凭据、订阅地址或服务器密码。此邮件仅进入本地模拟队列，未实际发送。", now=now)
    if action == "mail.process":
        return process_outbox(store, now, limit=params.get("limit", 20))
    raise ValueError("Unsupported mail action")
