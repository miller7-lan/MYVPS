"""Local simulation domain. It never executes SSH, systemctl, SMTP or firewall commands."""
from __future__ import annotations

import calendar
import datetime as dt
import hashlib
import json
import re
import secrets
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .store import Store, parse_time, timestamp

MAX_INT = 2**63 - 1
REASONS = ("manual_disabled", "quota_exceeded", "metering_failure", "pool_protection", "revoked")


class DomainError(Exception):
    def __init__(self, code: str, message: str):
        self.code, self.message = code, message
        super().__init__(message)


def integer(value, name: str, minimum: int = 0, maximum: int = MAX_INT) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DomainError("VALIDATION", f"{name} must be an integer in the permitted range")
    return value


def boolean(value, name: str) -> bool:
    if type(value) is not bool:
        raise DomainError("VALIDATION", f"{name} must be true or false")
    return value


def text(value, name: str, maximum: int = 120) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise DomainError("VALIDATION", f"{name} must be nonempty text")
    value = value.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise DomainError("VALIDATION", f"{name} contains unsupported control characters")
    return value


def _user(store: Store, params: dict, *, live: bool = True) -> dict:
    user_id = text(params.get("user_id"), "user_id", 80)
    try:
        user = store.get_user(user_id)
    except KeyError:
        raise DomainError("NOT_FOUND", "User not found") from None
    if live and user["revoked_at"] is not None:
        raise DomainError("REVOKED", "Permanently revoked users cannot be restored")
    return user


def disabled_reasons(user: dict, now: dt.datetime | None = None) -> list[str]:
    reasons = set(json.loads(user.get("reasons_json", "[]")))
    if user.get("manual_disabled"):
        reasons.add("manual_disabled")
    if user.get("revoked_at"):
        reasons.add("revoked")
    if user.get("role") == "admin":
        reasons -= {"quota_exceeded", "metering_failure", "pool_protection"}
    elif not user.get("unlimited"):
        allowance = (user.get("quota_bytes") or 0) + user.get("topup_bytes", 0)
        if user.get("used_upload", 0) + user.get("used_download", 0) >= allowance:
            reasons.add("quota_exceeded")
    if now is not None and user.get("role") != "admin" and not user.get("manual_disabled"):
        last = user.get("last_sample_at")
        if not user.get("trusted_sample") or last is None or (now - parse_time(last)).total_seconds() > 5:
            reasons.add("metering_failure")
    return [reason for reason in REASONS if reason in reasons]


def eligible(user: dict, now: dt.datetime | None = None) -> bool:
    return not disabled_reasons(user, now)


def _set_reasons(store: Store, user_id: str, reasons: set[str], now: dt.datetime) -> None:
    reasons -= {"manual_disabled", "revoked"}
    store.conn.execute("UPDATE users SET reasons_json=?,updated_at=? WHERE id=?",
                       (json.dumps(sorted(reasons)), timestamp(now), user_id))


def _incident(store: Store, user: dict, kind: str, now: dt.datetime, *, epoch: str | None = None,
              at: dt.datetime | None = None, upload: int | None = None, download: int | None = None,
              known_delta: tuple[int, int] | None = None, context: str | None = None) -> str:
    identity = [user["id"], kind, user["meter_epoch"], epoch, user["last_sample_at"],
                timestamp(at) if at is not None else None, upload, download, context]
    identifier = "incident-" + hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
    store.conn.execute("INSERT OR IGNORE INTO metering_incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)",
                       (identifier, user["id"], kind, user["meter_epoch"], epoch, user["last_sample_at"],
                        timestamp(at) if at is not None else None, user["last_uplink"], user["last_downlink"],
                        upload, download, known_delta[0] if known_delta is not None else None,
                        known_delta[1] if known_delta is not None else None, int(known_delta is None), timestamp(now)))
    return identifier


def _queue(store: Store, user_id: str, verb: str, reason: str, now: dt.datetime) -> None:
    latest = store.conn.execute(
        "SELECT verb,status FROM runtime_queue WHERE user_id=? ORDER BY rowid DESC LIMIT 1", (user_id,)).fetchone()
    if latest is not None and latest["verb"] == verb and latest["status"] == "pending":
        return
    store.conn.execute("INSERT INTO runtime_queue VALUES (?,?,?,?,?,?,NULL,NULL)",
                       (str(uuid.uuid4()), user_id, verb, "pending", reason, timestamp(now)))


def provider_freshness(provider: dict, now: dt.datetime, max_age_seconds: int = 3600) -> dict:
    observed = provider.get("observed_at")
    try:
        age = (now - parse_time(observed)).total_seconds() if observed else None
    except (ValueError, TypeError):
        age = None
    fresh = age is not None and 0 <= age <= max_age_seconds
    return {"state": "fresh" if fresh else "stale", "observed_at": observed,
            "age_seconds": age, "max_age_seconds": max_age_seconds}


def _sync_runtime(store: Store, now: dt.datetime, user_id: str | None = None) -> None:
    rows = store.conn.execute("SELECT * FROM users" + (" WHERE id=?" if user_id else ""),
                              (user_id,) if user_id else ()).fetchall()
    for row in rows:
        user = dict(row)
        provider = store.get_meta("provider", {})
        reserve, safety = store.get_setting("admin_reserve_bytes"), store.get_setting("safety_margin_bytes")
        if (user["role"] != "admin" and provider.get("unit_verified") and
                type(provider.get("remaining_bytes")) is int and (reserve is not None or safety is not None)):
            inherited = set(json.loads(user["reasons_json"]))
            if provider["remaining_bytes"] <= (reserve or 0) + (safety or 0):
                inherited.add("pool_protection")
            elif provider_freshness(provider, now)["state"] == "fresh":
                inherited.discard("pool_protection")
            user["reasons_json"] = json.dumps(sorted(inherited))
        reasons = disabled_reasons(user, now)
        _set_reasons(store, user["id"], set(reasons), now)
        state = store.conn.execute("SELECT status,runtime_version FROM runtime_state WHERE user_id=?",
                                   (user["id"],)).fetchone()
        target = "start" if not reasons else "stop"
        if state is None or (target == "start" and state["status"] != "running") or (
                target == "stop" and state["status"] == "running"):
            _queue(store, user["id"], target, ",".join(reasons) or "authorized", now)
    _notify_health(store, now)


def _public_user(store: Store, user: dict, now: dt.datetime) -> dict:
    reasons = disabled_reasons(user, now)
    runtime = store.conn.execute("SELECT status FROM runtime_state WHERE user_id=?", (user["id"],)).fetchone()
    if user["revoked_at"]:
        status = "revoked"
    elif reasons:
        status = "disabled"
    else:
        status = "running" if runtime is not None and runtime["status"] == "running" else "ready"
    return {
        **{key: user[key] for key in ("id", "name", "role", "port", "quota_bytes", "topup_bytes",
                                      "used_upload", "used_download", "credential_version", "threshold_percent",
                                      "email", "meter_state", "updated_at")},
        "status": status, "disabled_reasons": reasons, "unlimited": bool(user["unlimited"]),
        "auto_restore": bool(user["auto_restore"]), "email_verified": bool(user["email_verified"]),
        "deleted_at": user.get("deleted_at"),
    }


def _settings(store: Store) -> dict:
    return {row["key"]: json.loads(row["value"]) for row in store.conn.execute("SELECT * FROM settings")}


def _month_shift(year: int, month: int, offset: int) -> tuple[int, int]:
    index = year * 12 + month - 1 + offset
    return index // 12, index % 12 + 1


def _boundary(year: int, month: int, settings: dict) -> dt.datetime:
    hour, minute = map(int, settings["time"].split(":"))
    day = min(settings["day"], calendar.monthrange(year, month)[1])
    return dt.datetime(year, month, day, hour, minute, tzinfo=ZoneInfo(settings["timezone"])).astimezone(dt.timezone.utc)


def _period(now: dt.datetime, settings: dict) -> tuple[dt.datetime, dt.datetime]:
    local = now.astimezone(ZoneInfo(settings["timezone"]))
    current = _boundary(local.year, local.month, settings)
    if current > now:
        before = _month_shift(local.year, local.month, -1)
        return _boundary(*before, settings), current
    after = _month_shift(local.year, local.month, 1)
    return current, _boundary(*after, settings)


def _next_boundary(after: dt.datetime, settings: dict) -> dt.datetime:
    local = after.astimezone(ZoneInfo(settings["timezone"]))
    boundary = _boundary(local.year, local.month, settings)
    if boundary <= after:
        boundary = _boundary(*_month_shift(local.year, local.month, 1), settings)
    return boundary


def _create_cycle(store: Store, start: dt.datetime, end: dt.datetime) -> dict:
    cycle_id = "quota-" + start.strftime("%Y%m%dT%H%M%SZ")
    store.conn.execute("INSERT OR IGNORE INTO cycles VALUES (?,?,?,?,?,?)",
                       (cycle_id, timestamp(start), timestamp(end), "administrator_schedule", "active", "{}"))
    store.set_meta("current_cycle_id", cycle_id)
    return dict(store.conn.execute("SELECT * FROM cycles WHERE id=?", (cycle_id,)).fetchone())


def ensure_cycle(store: Store, now: dt.datetime) -> dict:
    cycle_id = store.get_meta("current_cycle_id")
    row = store.conn.execute("SELECT * FROM cycles WHERE id=?", (cycle_id,)).fetchone() if cycle_id else None
    return dict(row) if row else _create_cycle(store, *_period(now, _settings(store)))


def _mail_event(store: Store, user: dict, kind: str, now: dt.datetime, *, cycle_id: str, detail: str) -> None:
    try:
        from .mail import enqueue_notification
    except ImportError:
        return
    enqueue_notification(store, event_key=f"{cycle_id}:{user['id']}:{kind}", user_id=user["id"],
                         kind=kind, subject=f"Dazzle'VPS {kind}", body=detail, now=now, cycle_id=cycle_id)


def _notify_health(store: Store, now: dt.datetime) -> None:
    """Verified-recipient alerts with persistent event-key deduplication."""
    production = store.get_meta("mode") == "production"
    try:
        from .mail import enqueue_notification
    except ImportError:
        return
    cycle = ensure_cycle(store, now)
    def admin(kind: str, key: str, body: str, *, scope: str | None = None) -> None:
        enqueue_notification(store, event_key=key, user_id=None, kind=kind,
                             subject="Dazzle'VPS " + kind, body=body, now=now,
                             cycle_id=scope or cycle["id"])
    protected = []
    for row in store.conn.execute("SELECT * FROM users WHERE revoked_at IS NULL"):
        user = dict(row)
        reasons = disabled_reasons(user, now)
        # Awaiting the first zero baseline is a bootstrap gate, not an incident.
        failed_meter = user["meter_state"] in {"failure", "reconciliation_required"}
        if failed_meter:
            incident = store.conn.execute(
                "SELECT id FROM metering_incidents WHERE user_id=? AND resolved_at IS NULL "
                "ORDER BY detected_at DESC,rowid DESC LIMIT 1", (user["id"],)).fetchone()
            episode = incident["id"] if incident is not None else user["meter_epoch"] or "unavailable"
            detail = ("管理员计量异常已记录；管理员访问继续保留。" if user["role"] == "admin" else
                      "计量异常已记录，已请求暂停该普通用户；请核对实例实际状态确认停用。" if production else
                      "计量异常已记录，已请求暂停该普通用户。本地模拟尚未部署，不能视为线上停用完成。")
            admin("metering_failure", f"{cycle['id']}:{user['id']}:metering_failure:{episode}", detail)
        if "pool_protection" in reasons:
            protected.append(user["id"])
    if protected:
        admin("pool_protection", f"{cycle['id']}:pool_protection",
              f"总池保护已限制 {len(protected)} 个普通用户并请求暂停；管理员不受此保护暂停。"
              "请核对实例实际运行状态。" if production else
              f"总池保护已限制 {len(protected)} 个普通用户并请求暂停；管理员不受此保护暂停。当前仅为本地模拟，未部署到线上。")
    for task in store.conn.execute("SELECT id FROM runtime_queue WHERE status='failed' AND verb='stop'"):
        admin("runtime_pause_failed", "runtime_pause_failed:" + task["id"],
              "新用户实例暂停任务失败，尚未确认停止，请核对实际运行状态。" if production else
              "本地模拟的暂停任务失败，不能确认用户已停用。请检查任务状态；未执行任何线上服务操作。",
              scope="runtime-task:" + task["id"])
    if production:
        for task in store.conn.execute("SELECT p.id,w.user_id FROM production_jobs p JOIN production_workers w ON w.worker_id=p.worker_id WHERE p.status='failed' AND p.action IN ('stage','stop','revoke')"):
            if disabled_reasons(store.get_user(task["user_id"]), now):
                admin("runtime_pause_failed", "runtime_pause_failed:" + task["id"],
                      "新用户实例的暂停任务失败，尚未确认停止；请检查服务器实例状态。旧代理不在本次任务范围内。",
                      scope="runtime-task:" + task["id"])
    quota_end = parse_time(cycle["end_at"])
    if dt.timedelta(0) < quota_end - now <= dt.timedelta(hours=24):
        admin("quota_cycle_upcoming", f"{cycle['id']}:quota_cycle_upcoming",
              "管理员制定的用户额度周期将在24小时内切换。这不是商家流量重置确认。")
    provider = store.get_meta("provider", {})
    expected = provider.get("expected_reset_at")
    verified_expectation = (expected and provider.get("observed_at") and provider.get("evidence") and
                            provider.get("source") and provider.get("source") != "historical_manual_snapshot" and
                            provider.get("sync_state") in {"verified", "manual_confirmed"})
    if verified_expectation:
        try:
            expected_at = parse_time(expected)
            if parse_time(provider["observed_at"]) > now:
                return
            actual = parse_time(provider["last_actual_reset_at"]) if provider.get("last_actual_reset_at") else None
        except (ValueError, TypeError):
            return
        provider_scope = "provider-expected-" + hashlib.sha256(
            f"{provider.get('instance_id')}:{timestamp(expected_at)}".encode()).hexdigest()[:24]
        if actual is not None and actual >= expected_at:
            return
        if dt.timedelta(0) < expected_at - now <= dt.timedelta(hours=24):
            admin("provider_cycle_upcoming", provider_scope + ":upcoming",
                  "已核实的商家预计重置时间将在24小时内到达；仍需实际重置证据，用户额度不会因此重置。",
                  scope=provider_scope)
        elif now >= expected_at:
            admin("provider_reset_waiting", provider_scope + ":waiting",
                  "商家预计重置时间已到，但尚未确认实际重置。等待商家证据，保留原账本及用户限制，不重置额度。",
                  scope=provider_scope)


def _quota(store: Store, user_id: str, now: dt.datetime) -> None:
    user = store.get_user(user_id)
    reasons = set(json.loads(user["reasons_json"]))
    if user["role"] == "admin" or user["unlimited"]:
        reasons.discard("quota_exceeded")
    else:
        allowance = user["quota_bytes"] + user["topup_bytes"]
        used = user["used_upload"] + user["used_download"]
        if used >= allowance:
            reasons.add("quota_exceeded")
        else:
            reasons.discard("quota_exceeded")
        cycle = ensure_cycle(store, now)
        if allowance > 0 and used * 100 >= allowance * user["threshold_percent"]:
            _mail_event(store, user, "quota_threshold", now, cycle_id=cycle["id"],
                        detail="The current administrator-scheduled allowance is approaching its threshold.")
        if "quota_exceeded" in reasons:
            _mail_event(store, user, "quota_exceeded", now, cycle_id=cycle["id"],
                        detail="当前管理员规则下的个人载荷额度已用尽，已请求暂停该用户；以实例实际状态确认停用。" if store.get_meta("mode") == "production" else
                        "The current administrator-scheduled allowance has been used. A pause has been requested in the local simulation; no production suspension has been performed.")
    _set_reasons(store, user_id, reasons, now)


def _guard(store: Store, now: dt.datetime) -> None:
    for row in store.conn.execute("SELECT * FROM users WHERE revoked_at IS NULL AND role='member' AND manual_disabled=0"):
        user = dict(row)
        if store.get_meta("mode") == "production":
            worker = store.worker(user["id"])
            # A newly approved slot has no proxy listener before its first
            # staged origin. Do not invent a metering gap before any process
            # could carry traffic; staged/running workers retain the 5s guard.
            if (worker["observed_state"] in {"unprovisioned", "provisioned"} and worker["process_id"] in (None, 0) and
                    not user["meter_epoch"] and not user["last_sample_at"]):
                continue
            if (worker["origin_pending"] and worker["verified_at"] and
                    0 <= (now - parse_time(worker["verified_at"])).total_seconds() <= 5):
                continue
        last = user["last_sample_at"]
        if not user["trusted_sample"] or last is None or (now - parse_time(last)).total_seconds() > 5:
            _incident(store, user, "meter_unavailable", now)
            reasons = set(json.loads(user["reasons_json"])) | {"metering_failure"}
            _set_reasons(store, user["id"], reasons, now)
            store.conn.execute("UPDATE users SET meter_state='failure',trusted_sample=0 WHERE id=?", (user["id"],))


def _cycle_tick(store: Store, now: dt.datetime) -> dict:
    cycle = ensure_cycle(store, now)
    transitioned = []
    boundary = parse_time(cycle["end_at"])
    if now >= boundary:
        users = [dict(row) for row in store.conn.execute("SELECT * FROM users")]
        def covered(user):
            if not user["trusted_sample"] or user["last_sample_at"] is None:
                return False
            cutoff = parse_time(user["last_sample_at"])
            return boundary <= cutoff <= boundary + dt.timedelta(seconds=5)
        # Collector order is final fresh sample, then tick. That sample belongs
        # to the closing cycle; following deltas belong to the next cycle.
        # This explicitly bounds boundary allocation uncertainty to five seconds.
        report = {"users": [_public_user(store, user, now) for user in users],
                  "used_upload": sum(user["used_upload"] for user in users),
                  "used_download": sum(user["used_download"] for user in users),
                  "provider_cycle_id": store.get_meta("provider", {}).get("cycle_id"),
                  "accounting_basis": "proxy_payload", "allocation_uncertainty_seconds": 5,
                  "processed_at": timestamp(now),
                  "sample_cutoffs": {user["id"]: user["last_sample_at"] for user in users},
                  "complete": all(covered(user) for user in users if not user["revoked_at"])}
        store.conn.execute("UPDATE cycles SET status='closed',report_json=? WHERE id=?",
                           (json.dumps(report, ensure_ascii=False), cycle["id"]))
        try:
            from .mail import enqueue_notification
        except ImportError:
            enqueue_notification = None
        if enqueue_notification is not None:
            enqueue_notification(store, event_key="quota-cycle-closed:" + cycle["id"], user_id=None,
                                 kind="cycle_summary", subject="Dazzle'VPS quota cycle summary",
                                 body=f"Recorded upload: {report['used_upload']} bytes; download: {report['used_download']} bytes. "
                                      "This is the administrator schedule, not a confirmed provider reset.",
                                 now=now, cycle_id=cycle["id"])
        for user in users:
            reasons = set(json.loads(user["reasons_json"]))
            had_quota = "quota_exceeded" in reasons
            reasons.discard("quota_exceeded")
            manual = user["manual_disabled"] or (had_quota and not user["auto_restore"])
            if user["role"] != "admin" and user["meter_epoch"] is not None and not covered(user):
                _incident(store, user, "cycle_boundary_unknown", now, context=cycle["id"])
                reasons.add("metering_failure")
                store.conn.execute("UPDATE users SET trusted_sample=0,meter_state='reconciliation_required' WHERE id=?", (user["id"],))
            store.conn.execute("UPDATE users SET used_upload=0,used_download=0,topup_bytes=0,manual_disabled=?,updated_at=? WHERE id=?",
                               (int(manual), timestamp(now), user["id"]))
            _set_reasons(store, user["id"], reasons, now)
        transitioned.append(cycle["id"])
        settings = _settings(store)
        following = _next_boundary(boundary, settings)
        skipped = now >= following
        # A missed scheduler run does not manufacture intermediate allowances,
        # archives or notification emails. Only the actual old ledger closes.
        if skipped:
            start, end = _period(now, settings)
        else:
            start, end = boundary, following
        cycle = _create_cycle(store, start, end)
        for user in users:
            if user["role"] == "member" and not user["revoked_at"]:
                _mail_event(store, user, "cycle_started", now, cycle_id=cycle["id"],
                            detail="A new administrator-scheduled quota cycle began. Manual, metering and provider-protection restrictions remain in force.")
    _guard(store, now)
    _sync_runtime(store, now)
    return {"transitioned": transitioned, "cycle_id": cycle["id"]}


def snapshot(store: Store, now: dt.datetime | None = None) -> dict:
    now = parse_time(now) if now is not None else store.now
    current = ensure_cycle(store, now)
    all_users = [_public_user(store, dict(row), now) for row in store.conn.execute("SELECT * FROM users ORDER BY created_at,id")]
    users = [user for user in all_users if not user["deleted_at"]]
    deleted_users = [user for user in all_users if user["deleted_at"]]
    provider = store.get_meta("provider")
    freshness = provider_freshness(provider, now)
    members_allocated = sum((user["quota_bytes"] or 0) + user["topup_bytes"] for user in users
                            if user["role"] == "member" and not user["unlimited"] and user["status"] != "revoked")
    settings = _settings(store)
    verified_total = provider.get("total_bytes") if provider.get("unit_verified") else None
    overallocated = verified_total is not None and members_allocated > verified_total - (settings["admin_reserve_bytes"] or 0) - (settings["safety_margin_bytes"] or 0)
    try:
        from .mail import snapshot_mail
        mail = snapshot_mail(store)
    except ImportError:
        mail = {"configured": False, "transport": "simulated", "admin_email": None,
                "queue": [], "history": [], "preferences": {}}
    cycles = []
    for row in store.conn.execute("SELECT * FROM cycles ORDER BY start_at DESC LIMIT 100"):
        cycle = dict(row)
        cycle["report"] = json.loads(cycle.pop("report_json"))
        cycles.append(cycle)
    current = dict(current)
    current.pop("report_json", None)
    warnings = ["Provider allowance and reset time have not been verified."] if not provider.get("unit_verified") else []
    if freshness["state"] != "fresh":
        warnings.append("Provider observation is missing or older than one hour; protection is insufficiently verified.")
    if settings["admin_reserve_bytes"] is None or settings["safety_margin_bytes"] is None:
        warnings.append("Administrator reserve and safety margin are not configured.")
    return {"schema_version": 1, "mode": store.get_meta("mode"), "revision": store.revision,
            "settings": settings, "quota_cycle": current, "provider": provider,
            "provider_freshness": freshness, "users": users, "deleted_users": deleted_users,
            "totals": {"users_count": sum(user["status"] != "revoked" for user in users),
                       "members_allocated_bytes": members_allocated,
                       "used_upload": sum(user["used_upload"] for user in all_users),
                       "used_download": sum(user["used_download"] for user in all_users),
                       "overallocated": bool(overallocated),
                       "protection_state": "unverified" if not provider.get("unit_verified") else "stale" if freshness["state"] != "fresh" else (
                           "active" if any("pool_protection" in user["disabled_reasons"] for user in users) else "ready")},
            "mail": mail,
            "operations": [dict(row) for row in store.conn.execute("SELECT * FROM operations ORDER BY rowid DESC LIMIT 100")],
            "cycles": cycles,
            "metering_incidents": [dict(row) for row in store.conn.execute(
                "SELECT * FROM metering_incidents ORDER BY detected_at DESC,id LIMIT 200")],
            "health": {"proxy": "not_deployed", "metering": "simulated", "provider": provider.get("sync_state", "unverified"),
                       "mail": "simulated" if mail["configured"] else "not_configured", "ssh": "not_checked", "warnings": warnings}}


def _new_credentials(store: Store, user_id: str, version: int, now: dt.datetime) -> None:
    store.conn.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET "
                       "version=excluded.version,vless_uuid=excluded.vless_uuid,tuic_uuid=excluded.tuic_uuid,"
                       "tuic_password=excluded.tuic_password,subscription_token=excluded.subscription_token,"
                       "reality_public_key=excluded.reality_public_key,short_id=excluded.short_id,created_at=excluded.created_at",
                       (user_id, version, str(uuid.uuid4()), str(uuid.uuid4()), secrets.token_urlsafe(32),
                        secrets.token_urlsafe(36), "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", secrets.token_hex(8), timestamp(now)))


def _add_user(store: Store, params: dict, now: dt.datetime) -> dict:
    name, role = text(params.get("name"), "name"), params.get("role", "member")
    if role not in {"member", "admin"}:
        raise DomainError("VALIDATION", "role must be member or admin")
    if role == "admin" and store.conn.execute("SELECT 1 FROM users WHERE role='admin' AND revoked_at IS NULL").fetchone():
        raise DomainError("VALIDATION", "Only one live administrator identity is permitted")
    quota = None if role == "admin" else integer(params.get("quota_bytes", store.get_setting("default_quota_bytes")), "quota_bytes", 1)
    occupied = {row[0] for row in store.conn.execute("SELECT port FROM users")}
    port = next((value for value in range(24430, 65536) if value not in occupied), None)
    if port is None:
        raise DomainError("VALIDATION", "No simulation ports remain available")
    user_id, at = str(uuid.uuid4()), timestamp(now)
    store.conn.execute("INSERT INTO users (id,name,role,port,quota_bytes,unlimited,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                       (user_id, name, role, port, quota, int(role == "admin"), at, at))
    _new_credentials(store, user_id, 1, now)
    _sync_runtime(store, now, user_id)
    return store.get_user(user_id)


def _sample(store: Store, params: dict, now: dt.datetime, *, allow_revoked: bool = False) -> dict:
    user = _user(store, params, live=not allow_revoked)
    epoch = text(params.get("epoch"), "epoch", 200)
    upload = integer(params.get("uplink"), "uplink")
    download = integer(params.get("downlink"), "downlink")
    try:
        at = parse_time(params.get("at"))
    except (ValueError, TypeError):
        raise DomainError("VALIDATION", "Sample at must be a timezone-aware ISO timestamp") from None
    if at > now + dt.timedelta(seconds=5):
        raise DomainError("VALIDATION", "Sample timestamp is too far in the future")
    cycle = ensure_cycle(store, now)
    previous_at = parse_time(user["last_sample_at"]) if user["last_sample_at"] else None
    if previous_at and at < previous_at:
        raise DomainError("VALIDATION", "Out-of-order samples are not accepted")
    if previous_at == at and epoch == user["meter_epoch"] and upload == user["last_uplink"] and download == user["last_downlink"]:
        return {"duplicate": True, "trusted": bool(user["trusted_sample"])}
    initial = user["meter_epoch"] is None
    changed = not initial and epoch != user["meter_epoch"]
    regression = not initial and not changed and (upload < user["last_uplink"] or download < user["last_downlink"])
    stale = (now - at).total_seconds() > 5 or (previous_at is not None and (at - previous_at).total_seconds() > 5)
    crossing = previous_at is not None and previous_at < parse_time(cycle["start_at"]) <= at
    safe_initial = initial and upload == 0 and download == 0 and not stale
    trusted = safe_initial or not (initial or changed or regression or stale or crossing)
    reasons = set(json.loads(user["reasons_json"]))
    if not trusted:
        kind = ("initial_nonzero_baseline" if initial else "worker_epoch_changed" if changed else
                "counter_regression" if regression else "cycle_boundary_gap" if crossing else
                "sample_gap" if previous_at is not None and (at - previous_at).total_seconds() > 5 else "stale_sample")
        known_delta = None
        if (not initial and not changed and not regression and previous_at is not None and
                previous_at >= parse_time(cycle["start_at"]) and at <= parse_time(cycle["end_at"]) + dt.timedelta(seconds=5)):
            known_delta = upload - user["last_uplink"], download - user["last_downlink"]
        _incident(store, user, kind, now, epoch=epoch, at=at, upload=upload, download=download, known_delta=known_delta)
        reasons.add("metering_failure")
    elif safe_initial:
        reasons.discard("metering_failure")
    delta_up = delta_down = 0
    if trusted and not initial:
        delta_up, delta_down = upload - user["last_uplink"], download - user["last_downlink"]
        if user["used_upload"] + user["used_download"] + delta_up + delta_down > MAX_INT:
            raise DomainError("VALIDATION", "Accumulated usage exceeds the supported range")
        if delta_up or delta_down:
            minute = at.replace(second=0, microsecond=0)
            bucket = "minute-" + hashlib.sha256(json.dumps(
                [user["id"], cycle["id"], epoch, timestamp(minute)], separators=(",", ":")).encode()).hexdigest()
            store.conn.execute("INSERT INTO ledger VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                               "upload=ledger.upload+excluded.upload,download=ledger.download+excluded.download,sample_at=excluded.sample_at",
                               (bucket, user["id"], cycle["id"], epoch, delta_up, delta_down, timestamp(at), timestamp(now)))
    meter_state = "trusted" if trusted and "metering_failure" not in reasons else "reconciliation_required"
    store.conn.execute("UPDATE users SET meter_epoch=?,last_uplink=?,last_downlink=?,last_sample_at=?,trusted_sample=?,"
                       "meter_state=?,used_upload=used_upload+?,used_download=used_download+?,updated_at=? WHERE id=?",
                       (epoch, upload, download, timestamp(at), int(trusted), meter_state, delta_up, delta_down, timestamp(now), user["id"]))
    _set_reasons(store, user["id"], reasons, now)
    _quota(store, user["id"], now)
    _sync_runtime(store, now, user["id"])
    return {"duplicate": False, "trusted": trusted, "upload_delta": delta_up, "download_delta": delta_down}


def deploy_preview(store: Store, now: dt.datetime) -> dict:
    from .runtime import deployment_preview
    result = deployment_preview()
    result["planned_ports"] = [{"user_id": row["id"], "port": row["port"], "protocols": ["TCP/VLESS", "UDP/TUIC"],
                                "listening_checked": False, "firewall_approved": False}
                               for row in store.conn.execute("SELECT id,port FROM users WHERE revoked_at IS NULL")]
    return result


def ledger_retention_preview(store: Store, now: dt.datetime, keep_days: int = 90) -> dict:
    """Plan-only compaction metadata; this function never deletes ledger rows."""
    keep_days = integer(keep_days, "keep_days", 30, 3650)
    cutoff = timestamp(now - dt.timedelta(days=keep_days))
    old = store.conn.execute("SELECT COUNT(*),COALESCE(SUM(upload),0),COALESCE(SUM(download),0) FROM ledger WHERE sample_at<?", (cutoff,)).fetchone()
    return {"mode": "preview_only", "applied": False, "delete_available": False,
            "retention_days": keep_days, "cutoff_at": cutoff, "older_minute_rows": old[0],
            "older_upload_bytes": old[1], "older_download_bytes": old[2],
            "proposed": "Compact old minute rows into per-user/per-cycle/per-epoch totals after separate validation.",
            "preserves": ["all byte totals", "closed cycle reports", "current counters", "revoked tombstones", "manual mutation idempotency"]}


def _provider_observe(store: Store, params: dict, now: dt.datetime) -> dict:
    from .provider import handle_observation
    result = handle_observation(store, params, now)
    provider = result["provider"]
    if not result.get("duplicate"):
        try:
            from .mail import enqueue_notification
        except ImportError:
            enqueue_notification = None
        if enqueue_notification is not None:
            cycle = ensure_cycle(store, now)
            warning = not provider.get("unit_verified") or result.get("event_kind") != "reset_confirmed"
            kind = "provider_warning" if warning else "provider_cycle_confirmed"
            enqueue_notification(store, event_key=f"{kind}:{provider.get('observed_at')}", user_id=None,
                                 kind=kind, subject="Dazzle'VPS provider observation",
                                 body="Provider evidence was recorded separately. Administrator-scheduled user quotas were not reset.",
                                 now=now, cycle_id=cycle["id"])
    return result


def handle_action(store: Store, action: str, params: dict, now: dt.datetime) -> dict:
    if action in {"snapshot", "status"}:
        return snapshot(store, now)
    if action == "deploy.preview":
        return deploy_preview(store, now)
    if action == "history.preview":
        return ledger_retention_preview(store, now, params.get("keep_days", 90))
    if action == "rollback.preview":
        if params.get("target", "last_good") not in {"last_good", "baseline"}:
            raise DomainError("VALIDATION", "Unknown rollback target")
        return {"mode": "simulation", "target": params.get("target", "last_good"),
                "preserves": ["usage", "quota_cycles", "provider_observations", "revoked_tombstones"],
                "production_mutations": False}
    if action == "user.export":
        user = _user(store, params)
        format_name = params.get("format", "shadowrocket")
        if format_name not in {"shadowrocket", "mihomo", "uris"}:
            raise DomainError("VALIDATION", "Unsupported export format")
        from .rendering import render_export
        return render_export(store, user, format_name)
    result: dict = {}
    user_id = None
    if action == "user.add":
        user_id = _add_user(store, params, now)["id"]
    elif action in {"user.enable", "user.disable", "user.revoke", "user.rotate", "user.update", "user.topup", "user.delete"}:
        user = _user(store, params, live=action != "user.delete")
        user_id = user["id"]
        if action == "user.delete":
            if user["role"] == "admin" and not store.conn.execute(
                    "SELECT 1 FROM users WHERE role='admin' AND id!=? AND revoked_at IS NULL AND deleted_at IS NULL", (user_id,)).fetchone():
                raise DomainError("LAST_ADMIN", "The last administrator cannot be deleted")
            store.conn.execute("UPDATE users SET deleted_at=COALESCE(deleted_at,?),revoked_at=COALESCE(revoked_at,?),manual_disabled=1,email_verified=0,updated_at=? WHERE id=?",
                               (timestamp(now), timestamp(now), timestamp(now), user_id))
            store.conn.execute("DELETE FROM credentials WHERE user_id=?", (user_id,))
            store.conn.execute("UPDATE mail_outbox SET status='cancelled',completed_at=?,error_code='RECIPIENT_NO_LONGER_AUTHORIZED',lease_owner=NULL,lease_until=NULL WHERE user_id=? AND status IN ('queued','retry')",
                               (timestamp(now), user_id))
            store.conn.execute("DELETE FROM mail_private_payload WHERE outbox_id IN (SELECT id FROM mail_outbox WHERE user_id=? AND status='cancelled')", (user_id,))
            _queue(store, user_id, "stop", "permanently_deleted", now)
        elif action == "user.enable":
            store.conn.execute("UPDATE users SET manual_disabled=0,updated_at=? WHERE id=?", (timestamp(now), user_id))
            if user["role"] != "admin" and not user["trusted_sample"]:
                _set_reasons(store, user_id, set(json.loads(user["reasons_json"])) | {"metering_failure"}, now)
        elif action == "user.disable":
            store.conn.execute("UPDATE users SET manual_disabled=1,updated_at=? WHERE id=?", (timestamp(now), user_id))
        elif action == "user.revoke":
            store.conn.execute("UPDATE users SET revoked_at=?,manual_disabled=1,updated_at=? WHERE id=?",
                               (timestamp(now), timestamp(now), user_id))
            store.conn.execute("DELETE FROM credentials WHERE user_id=?", (user_id,))
            _queue(store, user_id, "stop", "revoked", now)
        elif action == "user.rotate":
            version = user["credential_version"] + 1
            _new_credentials(store, user_id, version, now)
            store.conn.execute("UPDATE users SET credential_version=?,updated_at=? WHERE id=?", (version, timestamp(now), user_id))
            _queue(store, user_id, "rotate", "credentials_rotated", now)
            result["requires_reimport"] = True
        elif action == "user.topup":
            if user["role"] == "admin" or user["unlimited"]:
                raise DomainError("VALIDATION", "Unlimited accounts do not need a top-up")
            amount = integer(params.get("bytes"), "bytes", 1)
            if amount + user["topup_bytes"] + user["quota_bytes"] > MAX_INT:
                raise DomainError("VALIDATION", "Allowance exceeds supported range")
            store.conn.execute("UPDATE users SET topup_bytes=topup_bytes+?,updated_at=? WHERE id=?", (amount, timestamp(now), user_id))
        else:
            changes = {}
            if "name" in params:
                changes["name"] = text(params["name"], "name")
            if "quota_bytes" in params:
                if user["role"] == "admin":
                    raise DomainError("VALIDATION", "Administrator allowance is unlimited")
                changes["quota_bytes"] = integer(params["quota_bytes"], "quota_bytes", 1)
            for key in ("auto_restore", "unlimited"):
                if key in params:
                    value = boolean(params[key], key)
                    if key == "unlimited" and user["role"] == "admin" and not value:
                        raise DomainError("VALIDATION", "Administrator allowance must remain unlimited")
                    changes[key] = int(value)
            if "threshold_percent" in params:
                changes["threshold_percent"] = integer(params["threshold_percent"], "threshold_percent", 1, 100)
            if "email" in params:
                address = params["email"]
                if address is not None:
                    address = text(address, "email", 254)
                    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", address):
                        raise DomainError("VALIDATION", "Invalid email address")
                changes["email"] = address
                if address != user["email"]:
                    changes["email_verified"] = 0
            if not changes:
                raise DomainError("VALIDATION", "No supported user fields were supplied")
            if changes.get("quota_bytes", user["quota_bytes"]) is not None and changes.get("quota_bytes", user["quota_bytes"]) + user["topup_bytes"] > MAX_INT:
                raise DomainError("VALIDATION", "Combined allowance exceeds the supported range")
            changes["updated_at"] = timestamp(now)
            store.conn.execute("UPDATE users SET " + ",".join(key + "=?" for key in changes) + " WHERE id=?",
                               (*changes.values(), user_id))
        if action not in {"user.revoke", "user.delete"}:
            _quota(store, user_id, now)
        _sync_runtime(store, now, user_id)
    elif action == "settings.update":
        permitted = {"default_quota_bytes", "admin_reserve_bytes", "safety_margin_bytes", "day", "time", "timezone"}
        if not params or set(params) - permitted:
            raise DomainError("VALIDATION", "Unsupported settings fields")
        ensure_cycle(store, now)
        for key, value in params.items():
            if key == "day":
                value = integer(value, "day", 1, 28)
            elif key == "time":
                if not isinstance(value, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
                    raise DomainError("VALIDATION", "Time must use HH:MM")
            elif key == "timezone":
                try:
                    ZoneInfo(text(value, "timezone", 100))
                except ZoneInfoNotFoundError:
                    raise DomainError("VALIDATION", "Unknown timezone") from None
            elif value is not None or key == "default_quota_bytes":
                value = integer(value, key, 1 if key == "default_quota_bytes" else 0)
            store.set_setting(key, value)
        _sync_runtime(store, now)
        result["schedule_effective"] = "next_boundary"
    elif action == "provider.observe":
        result = _provider_observe(store, params, now)
    elif action == "cycle.tick":
        at = parse_time(params["at"]) if params.get("at") is not None else now
        result = _cycle_tick(store, at)
        now = at
        store.now = at
    elif action == "meter.sample":
        result = _sample(store, params, now)
        user_id = params["user_id"]
    elif action in {"meter.failure", "meter.reconcile"}:
        user = _user(store, params)
        user_id = user["id"]
        reasons = set(json.loads(user["reasons_json"]))
        if action == "meter.failure":
            at = parse_time(params["at"]) if params.get("at") is not None else now
            if user["last_sample_at"] is None or (at - parse_time(user["last_sample_at"])).total_seconds() > 5:
                _incident(store, user, "meter_unavailable", now)
                reasons.add("metering_failure")
                store.conn.execute("UPDATE users SET meter_state='failure',trusted_sample=0 WHERE id=?", (user_id,))
            _set_reasons(store, user_id, reasons, now)
        else:
            evidence = text(params.get("evidence"), "evidence", 2000)
            evidence = re.sub(r"(?i)\b(?:vless|tuic|hysteria2?|hy2|trojan|ss|vmess)://\S+", "[redacted credential link]", evidence)
            evidence = re.sub(r"(?i)\b(?:password|secret|token|private_key)\s*[:=]\s*\S+", "[redacted credential]", evidence)
            for credentials in store.conn.execute("SELECT vless_uuid,tuic_uuid,tuic_password,subscription_token FROM credentials"):
                for secret in credentials:
                    evidence = evidence.replace(secret, "[redacted credential]")
            if not user["trusted_sample"] or not user["last_sample_at"] or (now - parse_time(user["last_sample_at"])).total_seconds() > 5:
                raise DomainError("VALIDATION", "A fresh trusted sample is required before reconciliation")
            reasons.discard("metering_failure")
            _set_reasons(store, user_id, reasons, now)
            store.conn.execute("UPDATE users SET meter_state='trusted' WHERE id=?", (user_id,))
            store.conn.execute("UPDATE metering_incidents SET resolved_at=?,evidence=?,operator=?,resolution=? "
                               "WHERE user_id=? AND resolved_at IS NULL",
                               (timestamp(now), evidence, "ssh_authenticated_administrator" if store.get_meta("mode") == "production" else "local_simulation_administrator", "acknowledged_unallocated_gap",
                                user_id))
        _sync_runtime(store, now, user_id)
    elif action.startswith("mail."):
        from .mail import handle_mail
        result = handle_mail(store, action, params, now)
    elif action == "runtime.process":
        from .runtime import process
        result = process(store, now)
        _notify_health(store, now)
    elif action == "rollback.apply":
        target = params.get("target", "last_good")
        if target not in {"last_good", "baseline"}:
            raise DomainError("VALIDATION", "Unknown rollback target")
        row = store.conn.execute("SELECT state_json FROM runtime_snapshots WHERE name=?", (target,)).fetchone()
        if row is None:
            raise DomainError("NOT_FOUND", "Simulation runtime snapshot not found")
        state = json.loads(row[0])
        for entry in state:
            try:
                user = store.get_user(entry["user_id"])
            except KeyError:
                continue
            allowed = eligible(user, now)
            status = "running" if entry["status"] == "running" and allowed else "stopped"
            store.conn.execute("INSERT INTO runtime_state VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET "
                               "status=excluded.status,runtime_version=excluded.runtime_version,updated_at=excluded.updated_at",
                               (user["id"], status, user["credential_version"], timestamp(now)))
        _sync_runtime(store, now)
        result = {"target": target, "mode": "simulation", "preserved_authorization_and_ledger": True}
    elif action == "demo.initialize":
        if store.conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise DomainError("VALIDATION", "Demo initialization requires an empty state")
        _add_user(store, {"name": "Administrator", "role": "admin"}, now)
        _add_user(store, {"name": "Example member", "role": "member"}, now)
        result["initialized"] = True
    else:
        raise DomainError("UNSUPPORTED", "Unsupported action")
    if user_id is not None:
        result["user"] = _public_user(store, store.get_user(user_id), now)
    return result
