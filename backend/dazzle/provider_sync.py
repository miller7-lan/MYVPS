"""Automatic QQG traffic sync: key storage, observation intake and alerts.

The QQG key is stored like the SMTP authorization code: in its own table, set
by one private administrator action, never returned, logged or replayed. The
writer's ProviderExecutor reads QQG outside every SQLite transaction and then
applies one short write. A failed read records the failure and nothing else.

QQG's number only ever tightens the local budget (budget.snapshot): it never
stops a proxy by itself, re-grants an allowance or resets a user cycle.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import threading
from urllib.parse import urlsplit
import uuid

from . import qqg
from .store import parse_time, timestamp, utcnow

SOURCE = "qqg_api"
EVIDENCE = "QQG 控制台流量接口自动读取（魔方云 flow；GB 按 1024³ 字节换算，精度 0.01GB）"
DEFAULT_INTERVAL = 600
MIN_INTERVAL, MAX_INTERVAL = 300, 3600
RETRY_SECONDS = (60, 120, 300, 600)
AUTH_RETRY_SECONDS = 3600  # Repeated failed logins could trip QQG's account protection.
AUTH_CODES = {"AUTH_FAILED", "UNAUTHORIZED", "CONFIG_INVALID", "CONFIG_INCOMPLETE"}
FAILURE_NOTICE_AFTER = dt.timedelta(hours=1)
ESTIMATE_MAX_AGE = dt.timedelta(hours=6)
LOW_PERCENTS = (20, 10, 5)
RESET_TOLERANCE = 2 * qqg.PRECISION_BYTES
SAMPLE_RETENTION = dt.timedelta(days=62)
CALIBRATION_MINIMUM = 1_000_000_000
POLL_CHECK_SECONDS = 15
TABLES = ("provider_api_config", "provider_api_secret", "provider_samples")


def ensure_schema(store) -> None:
    store.conn.execute("CREATE TABLE IF NOT EXISTS provider_api_config(id INTEGER PRIMARY KEY CHECK(id=1),"
                       "settings_json TEXT NOT NULL,updated_at TEXT NOT NULL)")
    store.conn.execute("CREATE TABLE IF NOT EXISTS provider_api_secret(id INTEGER PRIMARY KEY CHECK(id=1),"
                       "username TEXT NOT NULL,token TEXT NOT NULL)")
    store.conn.execute("CREATE TABLE IF NOT EXISTS provider_samples(id INTEGER PRIMARY KEY AUTOINCREMENT,"
                       "observed_at TEXT NOT NULL,total_bytes INTEGER,used_bytes INTEGER NOT NULL,remaining_bytes INTEGER,"
                       "reset_date TEXT,local_cycle_id TEXT NOT NULL,local_cycle_used INTEGER NOT NULL)")


def _ready(store) -> bool:
    """Read paths on a read-only or not yet migrated database see no sync at all."""
    count = store.conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN (?,?,?)",
                               TABLES).fetchone()[0]
    return count == len(TABLES)


def _settings(store) -> dict | None:
    row = store.conn.execute("SELECT settings_json FROM provider_api_config WHERE id=1").fetchone()
    return json.loads(row[0]) if row else None


def _state(store) -> dict:
    state = store.get_meta("provider_sync", None)
    return dict(state) if isinstance(state, dict) else {}


def _mask(username: str) -> str:
    if "@" in username:
        name, domain = username.split("@", 1)
        return (name[:2] if len(name) > 2 else "") + "***@" + domain
    return username[:3] + "****" + username[-2:] if len(username) > 6 else "****"


def _safe(message, limit=120) -> str:
    text = message if isinstance(message, str) else ""
    text = re.sub(r"[A-Za-z0-9+/=_.-]{24,}", "[已隐藏]", text)
    return "".join(char for char in text if char.isprintable()).strip()[:limit]


def _gb(value) -> str:
    return f"{value / qqg.GIB:.2f}GB" if type(value) is int else "未知"


def _local_usage(store, now) -> tuple[str, int]:
    """Current quota cycle and its summed per-user counters: a tiny table, no ledger scan."""
    from .domain import ensure_cycle
    cycle = ensure_cycle(store, now)
    used = store.conn.execute("SELECT COALESCE(SUM(used_upload+used_download),0) FROM users").fetchone()[0]
    return cycle["id"], used


def _payload_between(store, from_cycle, from_used, to_cycle, to_used) -> int | None:
    """Local payload between two counter readings, across at most one closed cycle."""
    if not (isinstance(from_cycle, str) and isinstance(to_cycle, str) and
            type(from_used) is int and type(to_used) is int):
        return None
    if from_cycle == to_cycle:
        return max(0, to_used - from_used)
    closed = store.conn.execute("SELECT end_at,report_json FROM cycles WHERE id=?", (from_cycle,)).fetchone()
    following = store.conn.execute("SELECT start_at FROM cycles WHERE id=?", (to_cycle,)).fetchone()
    if closed is None or following is None or closed["end_at"] != following["start_at"]:
        return None
    try:
        report = json.loads(closed["report_json"])
        total = int(report["used_upload"]) + int(report["used_download"])
    except (KeyError, TypeError, ValueError):
        return None
    return max(0, total - from_used) + to_used


def status(store, now=None) -> dict:
    """Public view: never the token, never the full username."""
    empty = {"configured": False, "enabled": False, "credential_configured": False, "api_host": None,
             "host_id": None, "username_hint": None, "interval_seconds": None, "state": "not_configured",
             "last_attempt_at": None, "last_success_at": None, "last_error": None, "consecutive_failures": 0,
             "failing_since": None, "next_attempt_at": None, "calibration": None}
    if not _ready(store):
        return empty
    settings = _settings(store)
    credential = store.conn.execute("SELECT 1 FROM provider_api_secret WHERE id=1").fetchone() is not None
    state = _state(store)
    if not settings or not credential:
        label = "not_configured"
    elif not settings["enabled"]:
        label = "disabled"
    elif state.get("consecutive_failures"):
        label = "error"
    elif state.get("last_success_at"):
        label = "ok"
    else:
        label = "waiting"
    result = dict(empty)
    if settings:
        result.update({"api_host": urlsplit(settings["api_url"]).hostname, "host_id": settings["host_id"],
                       "username_hint": settings.get("username_hint"), "interval_seconds": settings["interval_seconds"]})
    result.update({"configured": bool(settings) and credential, "enabled": bool(settings and settings["enabled"]),
                   "credential_configured": credential, "state": label,
                   "last_attempt_at": state.get("last_attempt_at"), "last_success_at": state.get("last_success_at"),
                   "last_error": state.get("last_error"), "consecutive_failures": state.get("consecutive_failures", 0),
                   "failing_since": state.get("failing_since"), "next_attempt_at": state.get("next_attempt_at"),
                   "calibration": calibration(store)})
    return result


def configure(store, params, now) -> dict:
    """Private administrator action; a supplied token is stored and never echoed."""
    from .domain import DomainError, boolean
    ensure_schema(store)
    allowed = {"enabled", "api_url", "username", "token", "host_id", "interval_seconds"}
    if not isinstance(params, dict) or not params or set(params) - allowed:
        raise DomainError("VALIDATION", "Unsupported provider sync fields")
    current = _settings(store) or {"enabled": False, "api_url": qqg.DEFAULT_API_URL, "host_id": None,
                                   "interval_seconds": DEFAULT_INTERVAL, "username_hint": None}
    instance = str(store.get_meta("provider", {}).get("instance_id") or "")
    try:
        api_url = qqg.normalize_api_url(params.get("api_url", current["api_url"]))
        host_id = qqg.checked_host_id(params.get("host_id", current["host_id"] if current["host_id"] is not None
                                                 else instance))
    except qqg.QqgError as exc:
        raise DomainError("VALIDATION", exc.message) from None
    if str(host_id) != instance:
        raise DomainError("VALIDATION", "host_id 与已登记的 QQG 实例不一致；更换实例须另行核对")
    interval = params.get("interval_seconds", current["interval_seconds"])
    if type(interval) is not int or not MIN_INTERVAL <= interval <= MAX_INTERVAL:
        raise DomainError("VALIDATION", "interval_seconds 须为 300 到 3600 秒")
    enabled = boolean(params["enabled"], "enabled") if "enabled" in params else current["enabled"]
    if ("username" in params) != ("token" in params):
        raise DomainError("VALIDATION", "username 与 token 须一同提供")
    hint = current.get("username_hint")
    if "token" in params:
        if params["token"] is None and params["username"] is None:
            store.conn.execute("DELETE FROM provider_api_secret WHERE id=1")
            hint = None
        else:
            try:
                username, token = qqg.checked_username(params["username"]), qqg.checked_token(params["token"])
            except qqg.QqgError as exc:
                raise DomainError("VALIDATION", exc.message) from None
            store.conn.execute("INSERT INTO provider_api_secret VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET "
                               "username=excluded.username,token=excluded.token", (username, token))
            hint = _mask(username)
    elif api_url != current["api_url"] or host_id != current["host_id"]:
        # Never send a stored key to a newly selected site or instance.
        store.conn.execute("DELETE FROM provider_api_secret WHERE id=1")
        hint = None
    credential = store.conn.execute("SELECT 1 FROM provider_api_secret WHERE id=1").fetchone() is not None
    if enabled and not credential:
        raise DomainError("VALIDATION", "启用自动同步前须提供 QQG 登录名与 API token")
    settings = {"enabled": enabled, "api_url": api_url, "host_id": host_id, "interval_seconds": interval,
                "username_hint": hint, "config_version": uuid.uuid4().hex}
    store.conn.execute("INSERT INTO provider_api_config VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET "
                       "settings_json=excluded.settings_json,updated_at=excluded.updated_at",
                       (json.dumps(settings), timestamp(now)))
    state = _state(store)
    state.update({"next_attempt_at": timestamp(now), "consecutive_failures": 0, "failing_since": None,
                  "last_error": None})
    store.set_meta("provider_sync", state)
    return {"provider_sync": status(store, now)}


def _notify(store, kind, event_key, now, detail) -> None:
    try:
        from .mail import enqueue_notification
    except ImportError:
        return
    from .mail_templates import render
    template = render(kind, detail=detail)
    enqueue_notification(store, event_key=event_key, user_id=None, kind=kind, subject=template.subject,
                         body=template.body, now=now, cooldown_seconds=0)


def record_success(store, reading, now, *, config_version=None) -> dict:
    """Validate first, then write: a rejected reading leaves every row untouched."""
    from .provider import ProviderObservation
    ensure_schema(store)
    settings = _settings(store)
    if not settings or not settings["enabled"] or (config_version is not None and
                                                   settings["config_version"] != config_version):
        return {"applied": False, "reason": "configuration_changed"}
    provider = dict(store.get_meta("provider", {}) or {})
    instance = str(provider.get("instance_id") or "")
    if str(reading.host_id) != instance or settings["host_id"] != reading.host_id:
        raise ValueError("QQG reading belongs to another instance")
    observed_at = timestamp(now)
    ProviderObservation(instance_id=instance, observed_at=observed_at, source=SOURCE, evidence=EVIDENCE,
                        operator="provider_sync", total_bytes=reading.total_bytes,
                        remaining_bytes=reading.remaining_bytes, unit_verified=True,
                        verified=True).validate(instance, now)
    cycle_id, cycle_used = _local_usage(store, now)
    last = store.conn.execute("SELECT * FROM provider_samples ORDER BY id DESC LIMIT 1").fetchone()
    reset_cycle = None
    if last is not None and reading.used_bytes + RESET_TOLERANCE < last["used_bytes"]:
        if last["reset_date"] and reading.reset_date and reading.reset_date > last["reset_date"]:
            reset_cycle = "qqg:" + last["reset_date"]
        else:
            reset_cycle = "qqg:manual:" + observed_at  # QQG staff or a plan change reset the counter.
    store.conn.execute("INSERT INTO provider_samples(observed_at,total_bytes,used_bytes,remaining_bytes,reset_date,"
                       "local_cycle_id,local_cycle_used) VALUES(?,?,?,?,?,?,?)",
                       (observed_at, reading.total_bytes, reading.used_bytes, reading.remaining_bytes,
                        reading.reset_date, cycle_id, cycle_used))
    store.conn.execute("DELETE FROM provider_samples WHERE observed_at<?", (timestamp(now - SAMPLE_RETENTION),))
    anchor = provider.get("calibration_anchor")
    if reset_cycle or provider.get("source") != SOURCE or not isinstance(anchor, dict):
        anchor = {"observed_at": observed_at, "used_bytes": reading.used_bytes,
                  "local_cycle_id": cycle_id, "local_cycle_used": cycle_used}
    provider.update({"total_bytes": reading.total_bytes, "remaining_bytes": reading.remaining_bytes,
                     "used_bytes": reading.used_bytes, "total_display": reading.total_display,
                     "remaining_display": reading.remaining_display, "used_display": reading.used_display,
                     "expected_reset_date": reading.reset_date or provider.get("expected_reset_date"),
                     "unlimited": reading.unlimited, "unit": reading.unit, "precision_bytes": reading.precision_bytes,
                     "observed_at": observed_at, "source": SOURCE, "evidence": EVIDENCE, "sync_state": "verified",
                     "automatic_available": True, "unit_verified": True, "local_cycle_id": cycle_id,
                     "local_cycle_used": cycle_used, "calibration_anchor": anchor})
    if reset_cycle:
        provider.update({"cycle_id": reset_cycle, "last_actual_reset_at": observed_at,
                         "reset_detected_after": last["observed_at"]})
        store.conn.execute("CREATE TABLE IF NOT EXISTS provider_history (id TEXT PRIMARY KEY,event_key TEXT UNIQUE,"
                           "kind TEXT NOT NULL,observation_json TEXT NOT NULL,created_at TEXT NOT NULL)")
        store.conn.execute("INSERT OR IGNORE INTO provider_history VALUES (?,?,?,?,?)",
                           (str(uuid.uuid4()), "provider_reset:" + instance + ":" + reset_cycle, "reset_detected",
                            json.dumps({"previous_used_bytes": last["used_bytes"], "used_bytes": reading.used_bytes,
                                        "previous_observed_at": last["observed_at"], "observed_at": observed_at,
                                        "reset_date": reading.reset_date, "source": SOURCE}), observed_at))
    store.set_meta("provider", provider)
    state = _state(store)
    state.update({"last_attempt_at": observed_at, "last_success_at": observed_at, "consecutive_failures": 0,
                  "failing_since": None, "last_error": None,
                  "next_attempt_at": timestamp(now + dt.timedelta(seconds=settings["interval_seconds"]))})
    store.set_meta("provider_sync", state)
    if reset_cycle:
        _notify(store, "provider_auto_reset", "provider_auto_reset:" + instance + ":" + reset_cycle, now,
                f"QQG 已用流量从 {_gb(last['used_bytes'])} 降到 {reading.used_display}；"
                f"新的归零日期为 {reading.reset_date or '未提供'}。")
    if reading.total_bytes and reading.remaining_bytes is not None:
        percent = reading.remaining_bytes * 100 / reading.total_bytes
        crossed = [level for level in LOW_PERCENTS if percent <= level]
        if crossed:
            level = min(crossed)
            _notify(store, "provider_auto_low",
                    f"provider_auto_low:{instance}:{reading.reset_date or 'unknown'}:{level}", now,
                    f"QQG 剩余 {reading.remaining_display}（约 {percent:.1f}%），总量 {reading.total_display}，"
                    f"预计 {reading.reset_date or '未提供'} 归零。")
    return {"applied": True, "reset_detected": bool(reset_cycle)}


def record_failure(store, code, message, now, *, config_version=None) -> dict:
    """Only the sync state changes: no provider figure, user or budget row is touched."""
    ensure_schema(store)
    settings = _settings(store)
    if not settings or (config_version is not None and settings["config_version"] != config_version):
        return {"applied": False, "reason": "configuration_changed"}
    code = code if isinstance(code, str) and re.fullmatch(r"[A-Z_]{1,40}", code) else "INTERNAL"
    safe = _safe(message) or code
    state = _state(store)
    failures = int(state.get("consecutive_failures") or 0) + 1
    failing_since = state.get("failing_since") or timestamp(now)
    delay = AUTH_RETRY_SECONDS if code in AUTH_CODES else min(
        RETRY_SECONDS[min(failures, len(RETRY_SECONDS)) - 1], settings["interval_seconds"])
    state.update({"last_attempt_at": timestamp(now), "consecutive_failures": failures,
                  "failing_since": failing_since, "last_error": {"code": code, "message": safe, "at": timestamp(now)},
                  "next_attempt_at": timestamp(now + dt.timedelta(seconds=delay))})
    store.set_meta("provider_sync", state)
    if now - parse_time(failing_since) >= FAILURE_NOTICE_AFTER:
        _notify(store, "provider_sync_failed", "provider_sync_failed:" + failing_since, now,
                f"最近一次错误：{code}。{safe}")
    return {"applied": True, "retry_in_seconds": delay}


def remaining_estimate(store, now) -> dict | None:
    """QQG remaining now: the last automatic reading minus local payload counted since.

    QQG counts at least every payload byte, so this never overstates what is
    left and keeps protecting through a short outage. Disabled, unlimited or
    older than six hours: None, and the local budget alone governs as before.
    """
    if not _ready(store):
        return None
    settings = _settings(store)
    provider = store.get_meta("provider", {}) or {}
    if (not settings or not settings.get("enabled") or provider.get("source") != SOURCE or
            not provider.get("unit_verified") or provider.get("unlimited")):
        return None
    remaining, observed = provider.get("remaining_bytes"), provider.get("observed_at")
    if type(remaining) is not int or not isinstance(observed, str):
        return None
    try:
        age = now - parse_time(observed)
    except (ValueError, TypeError):
        return None
    if not -dt.timedelta(minutes=5) <= age <= ESTIMATE_MAX_AGE:
        return None
    since = _payload_between(store, provider.get("local_cycle_id"), provider.get("local_cycle_used"),
                             *_local_usage(store, now))
    since = since or 0
    return {"observed_at": observed, "age_seconds": max(0, int(age.total_seconds())),
            "observed_remaining_bytes": remaining, "local_payload_since_bytes": since,
            "estimated_remaining_bytes": max(0, remaining - since)}


def calibration(store) -> dict | None:
    """QQG-counted bytes per local payload byte since QQG's last reset (≈2 means both directions)."""
    provider = store.get_meta("provider", {}) or {}
    anchor = provider.get("calibration_anchor")
    if provider.get("source") != SOURCE or not isinstance(anchor, dict) or type(provider.get("used_bytes")) is not int:
        return None
    local = _payload_between(store, anchor.get("local_cycle_id"), anchor.get("local_cycle_used"),
                             provider.get("local_cycle_id"), provider.get("local_cycle_used"))
    counted = provider["used_bytes"] - int(anchor.get("used_bytes") or 0)
    ratio = round(counted / local, 3) if local is not None and local >= CALIBRATION_MINIMUM and counted >= 0 else None
    return {"since": anchor.get("observed_at"), "until": provider.get("observed_at"),
            "provider_used_delta_bytes": counted, "local_payload_delta_bytes": local, "ratio": ratio,
            "minimum_local_bytes": CALIBRATION_MINIMUM}


class SyncCache:
    """The client (and its in-memory JWT) lives only as long as one configuration."""

    def __init__(self, client_factory=None):
        self.client_factory = client_factory or (lambda creds: qqg.QqgClient(creds))
        self.client = None
        self.key = None


def sync_once(store, cache, *, now=None) -> float:
    """One due attempt; returns seconds until the next check. Network stays outside SQLite."""
    if store.conn.in_transaction:
        raise RuntimeError("Provider sync cannot run inside a SQLite transaction")
    clock = (lambda: now) if now is not None else utcnow
    if not _ready(store):
        return POLL_CHECK_SECONDS
    settings = _settings(store)
    if not settings or not settings["enabled"]:
        cache.client = cache.key = None
        return POLL_CHECK_SECONDS
    due = _state(store).get("next_attempt_at")
    if due:
        wait = (parse_time(due) - clock()).total_seconds()
        if wait > 0:
            return min(POLL_CHECK_SECONDS, wait)
    version = settings["config_version"]
    reading = error = None
    try:
        if cache.key != version or cache.client is None:
            secret = store.conn.execute("SELECT username,token FROM provider_api_secret WHERE id=1").fetchone()
            if secret is None:
                cache.client = cache.key = None
                return POLL_CHECK_SECONDS
            cache.client = cache.client_factory(qqg.credentials(settings["api_url"], secret["username"],
                                                                secret["token"], settings["host_id"]))
            cache.key = version
        reading = cache.client.read_flow()
    except qqg.QqgError as exc:
        error = exc
    except Exception:
        error = qqg.QqgError("INTERNAL", "读取 QQG 时发生内部错误")
    finished = clock()
    store.conn.execute("BEGIN IMMEDIATE")
    try:
        if reading is not None:
            try:
                record_success(store, reading, finished, config_version=version)
            except ValueError:
                record_failure(store, "BAD_RESPONSE", "QQG 返回的数据未通过身份、时间或数量核对", finished,
                               config_version=version)
        else:
            record_failure(store, error.code, error.message, finished, config_version=version)
        store.conn.commit()
    except BaseException:
        store.conn.rollback()
        raise
    return POLL_CHECK_SECONDS


class ProviderExecutor:
    """Independent QQG reader: network waits never touch the sampling loop."""

    def __init__(self, store, *, client_factory=None):
        self.state_dir, self.policy = store.state_dir, store.policy
        self.cache = SyncCache(client_factory)
        self.stopped = threading.Event()
        self.failed = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name="dazzle-provider-sync")

    def _run(self):
        from .production_state import ProductionStore
        while not self.stopped.is_set():
            try:
                with ProductionStore(self.state_dir, policy=self.policy) as store:
                    self.failed.clear()
                    while not self.stopped.is_set():
                        self.stopped.wait(sync_once(store, self.cache))
            except Exception:
                self.failed.set()  # Never propagate provider diagnostics or stop proxies.
                self.stopped.wait(30)

    def start(self):
        self.thread.start()

    def close(self):
        self.stopped.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=0.2)
