"""Provider evidence is independent of administrator quota allocation.

No guessed QQG endpoints, browser cookies or live billing operations. The only
automatic source is qqg.py (the IDCSmart V10 API-key login and the 魔方云 traffic
card QQG's own console reads), applied by provider_sync.py; this module keeps
the explicit administrator evidence intake.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

UTC = timezone.utc


def instant(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp requires an explicit timezone")
    return result.astimezone(UTC)


@dataclass(frozen=True)
class ProviderObservation:
    instance_id: str
    observed_at: str
    source: str
    evidence: str
    kind: str = "observation"
    operator: str = "administrator"
    cycle_id: str | None = None
    cycle_start_at: str | None = None
    last_actual_reset_at: str | None = None
    expected_reset_at: str | None = None
    total_bytes: int | None = None
    remaining_bytes: int | None = None
    unit_verified: bool = False
    verified: bool = False

    def validate(self, instance_id: str, now: datetime) -> None:
        if self.instance_id != instance_id:
            raise ValueError("Provider instance identity mismatch")
        if not self.source.strip() or not self.evidence.strip():
            raise ValueError("Provider evidence and source are required")
        observed = instant(self.observed_at)
        if observed > now.astimezone(UTC) + timedelta(minutes=5):
            raise ValueError("Provider observation is in the future")
        for name in ("total_bytes", "remaining_bytes"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or not 0 <= value <= 2**63-1):
                raise ValueError("Invalid provider byte count")
        if self.total_bytes is not None and self.remaining_bytes is not None:
            if self.remaining_bytes > self.total_bytes:
                raise ValueError("Provider remaining exceeds total; reconcile plan or gift first")
        for value in (self.cycle_start_at, self.last_actual_reset_at, self.expected_reset_at):
            if value is not None:
                instant(value)
        if self.kind == "reset_confirmed":
            if not (self.verified and self.cycle_id and self.last_actual_reset_at):
                raise ValueError("Confirmed reset needs verified cycle identity and actual reset timestamp")
            if instant(self.last_actual_reset_at) > observed:
                raise ValueError("Actual reset cannot be later than observation")


class ProviderSource(Protocol):
    automatic_available: bool
    def read(self) -> ProviderObservation: ...


class UnavailableProvider:
    automatic_available = False
    def read(self) -> ProviderObservation:
        raise NotImplementedError("QQG official read-only API documentation and scope not verified")


class FixtureProvider:
    """Explicit, isolated test source; never label its observations as live."""
    automatic_available = False
    def __init__(self, values: list[ProviderObservation | Exception]):
        self.values = iter(values)
    def read(self) -> ProviderObservation:
        item = next(self.values)
        if isinstance(item, Exception):
            raise item
        return item


class ProviderCycleMonitor:
    def __init__(self, instance_id: str, source: ProviderSource | None = None):
        self.instance_id = instance_id
        self.source = source or UnavailableProvider()
        self.last: ProviderObservation | None = None
        self.processed: set[str] = set()

    def check(self, now: datetime) -> dict:
        if isinstance(self.source, UnavailableProvider):
            return {"sync_state": "unverified", "automatic_available": False,
                    "quota_effect": "none", "message": "自动识别不可用：等待官方接口文档与只读权限核验"}
        try:
            item = self.source.read()
            item.validate(self.instance_id, now)
            if self.last and instant(item.observed_at) < instant(self.last.observed_at):
                raise ValueError("Provider observation is older than last accepted observation")
            reset = item.kind == "reset_confirmed" and item.cycle_id not in self.processed
            if reset:
                self.processed.add(item.cycle_id)
            self.last = item
            return {"sync_state": "verified" if item.verified else "unverified",
                    "automatic_available": self.source.automatic_available,
                    "new_provider_reset": reset, "observation": asdict(item),
                    "quota_effect": "none"}
        except (ValueError, OSError, TimeoutError, StopIteration):
            return {"sync_state": "waiting_confirmation", "automatic_available": self.source.automatic_available,
                    "quota_effect": "none", "message": "等待服务商刷新确认；保留原账本及限制"}


def next_poll_seconds(expected_reset_at: str | None, now: datetime,
                      official_minimum_seconds: int = 900) -> int:
    """Future adapter must supply its official minimum. No live poll is enabled."""
    if type(official_minimum_seconds) is not int or official_minimum_seconds < 60:
        raise ValueError("A verified safe API poll minimum is required")
    interval = 3600
    if expected_reset_at:
        distance = abs((instant(expected_reset_at) - now.astimezone(UTC)).total_seconds())
        if distance <= 3600:
            interval = 300
    return max(interval, official_minimum_seconds)


def handle_observation(store, params: dict, now: datetime) -> dict:
    """Explicit administrator evidence intake; this cannot allocate quotas."""
    import json
    import uuid
    from .domain import DomainError, _set_reasons, _sync_runtime
    from .store import timestamp
    current = store.get_meta("provider")
    if params.get("instance_id") != current["instance_id"]:
        raise DomainError("VALIDATION", "Instance identity mismatch; migration needs a separate reviewed action")
    evidence = params.get("evidence")
    if not isinstance(evidence, str) or not 4 <= len(evidence.strip()) <= 2000:
        raise DomainError("VALIDATION", "A short non-secret evidence note is required")
    kind = params.get("kind", "manual")
    if kind not in {"manual", "renewal", "gift", "upgrade", "paid_reset", "reset_confirmed"}:
        raise DomainError("VALIDATION", "Unknown provider event kind")
    observation = ProviderObservation(
        instance_id=current["instance_id"], observed_at=timestamp(now),
        source="administrator_panel_confirmation", evidence=evidence.strip(), kind=kind,
        operator="local_authenticated_administrator",
        cycle_id=params.get("external_cycle_id"), last_actual_reset_at=params.get("last_actual_reset_at"),
        cycle_start_at=params.get("cycle_start_at"), expected_reset_at=params.get("expected_reset_at"),
        total_bytes=params.get("total_bytes"), remaining_bytes=params.get("remaining_bytes"),
        unit_verified=params.get("unit_verified", False), verified=kind == "reset_confirmed",
    )
    if type(observation.unit_verified) is not bool:
        raise DomainError("VALIDATION", "unit_verified must be boolean")
    if (observation.total_bytes is not None or observation.remaining_bytes is not None) and not observation.unit_verified:
        raise DomainError("VALIDATION", "Byte conversion requires explicit confirmed unit evidence")
    try:
        observation.validate(current["instance_id"], now)
    except ValueError:
        raise DomainError("VALIDATION", "Provider observation failed identity, time or amount validation") from None
    store.conn.execute("CREATE TABLE IF NOT EXISTS provider_history (id TEXT PRIMARY KEY,event_key TEXT UNIQUE,kind TEXT NOT NULL,observation_json TEXT NOT NULL,created_at TEXT NOT NULL)")
    if kind == "reset_confirmed":
        event_key = "provider_reset:" + current["instance_id"] + ":" + str(observation.cycle_id)
    else:
        event_key = str(uuid.uuid4())
    if store.conn.execute("SELECT 1 FROM provider_history WHERE event_key=?", (event_key,)).fetchone():
        return {"duplicate": True, "quota_effect": "none", "provider": current}
    for name in ("total_display", "remaining_display", "expected_reset_date", "timezone"):
        if name in params:
            value = params[name]
            if not isinstance(value, str) or not 1 <= len(value) <= 120 or any(ord(c) < 32 for c in value):
                raise DomainError("VALIDATION", "Invalid provider display field")
            if name == "expected_reset_date":
                try:
                    datetime.strptime(value, "%Y-%m-%d")
                except ValueError:
                    raise DomainError("VALIDATION", "Reset date must use YYYY-MM-DD") from None
            current[name] = value
    for name in ("cycle_id", "cycle_start_at", "last_actual_reset_at", "expected_reset_at"):
        value = getattr(observation, name)
        if value is not None:
            current[name] = value
    current.update({"observed_at": observation.observed_at, "source": observation.source,
                    "evidence": observation.evidence, "sync_state": "manual_confirmed",
                    "automatic_available": False})
    # Never retain old normalized amounts as if this newer raw-only observation verified them.
    current.update({"total_bytes": observation.total_bytes, "remaining_bytes": observation.remaining_bytes,
                    "unit_verified": observation.unit_verified})
    store.set_meta("provider", current)
    store.conn.execute("INSERT INTO provider_history VALUES (?,?,?,?,?)",
                       (str(uuid.uuid4()), event_key, kind, json.dumps(asdict(observation)), timestamp(now)))
    reserve, safety = store.get_setting("admin_reserve_bytes"), store.get_setting("safety_margin_bytes")
    protection_configured = reserve is not None or safety is not None
    if observation.unit_verified and observation.remaining_bytes is not None and protection_configured:
        protect = observation.remaining_bytes <= (reserve or 0) + (safety or 0)
        for row in store.conn.execute("SELECT * FROM users WHERE role='member' AND revoked_at IS NULL").fetchall():
            reasons = set(json.loads(row["reasons_json"]))
            if protect:
                reasons.add("pool_protection")
            else:
                reasons.discard("pool_protection")
            _set_reasons(store, row["id"], reasons, now)
        _sync_runtime(store, now)
    return {"provider": current, "quota_effect": "none", "event_kind": kind,
            "notice": "仅记录商家信息；未刷新管理员设定的用户额度"}
