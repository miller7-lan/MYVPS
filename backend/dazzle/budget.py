"""Explicit administrator budget; never impersonates provider billing data.

An unconfigured installation retains its existing authorisations. Adoption is an
explicit administrative transaction. All numbers use integer decimal GB/bytes.
A fresh automatic QQG reading (provider_sync) can only lower the administrators'
shared remainder and refuse growing promises; it never raises either.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import stat
import uuid

from .store import timestamp

GB = 1_000_000_000
CGROUP_ROOT = Path('/sys/fs/cgroup')


def _guard_cgroup_pids(worker_id):
    """Return PIDs in the exact systemd guard cgroup.

    systemd may place a templated service below a dedicated slice instead of
    directly below ``system.slice``.  Looking up the exact unit directory
    keeps the check fail-closed while working with either layout; an absent or
    empty match still means the administrator guard is not ready.
    """
    target = 'dazzle-vps-meter-guard@' + worker_id + '.service'
    matches = []
    try:
        for candidate in CGROUP_ROOT.rglob(target):
            if candidate.is_dir() and (candidate / 'cgroup.procs').is_file():
                matches.append(candidate / 'cgroup.procs')
    except (OSError, ValueError):
        return []
    pids = []
    seen = set()
    for path in matches:
        try:
            values = [int(value) for value in path.read_text().split()]
        except (OSError, ValueError):
            continue
        for pid in values:
            if pid > 0 and pid not in seen:
                seen.add(pid)
                pids.append(pid)
    return pids


def guard_approval(policy):
    """Fixed root evidence, never supplied by a web or SSH RPC parameter."""
    path=Path('/etc/dazzle-vps/admin-budget-guard.json')
    try:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size>4096:
            return None
        value=json.loads(path.read_text())
        if (value.get('server_id') != policy['server_id'] or value.get('approved') is not True or
                policy['workers'].get(value.get('worker_id'),{}).get('role') != 'admin' or
                str(uuid.UUID(value.get('boot_id',''))) != value.get('boot_id')):
            return None
        unit=Path('/etc/systemd/system/dazzle-admin@'+value['worker_id']+'.service')
        current=unit.lstat()
        if (not stat.S_ISREG(current.st_mode) or current.st_uid != 0 or current.st_mode & 0o022 or
                hashlib.sha256(unit.read_bytes()).hexdigest() != value.get('reviewed_unit_sha256')):
            return None
        expected='dazzle-vps-meter-guard@'+value['worker_id']+'.service'
        lines=[line.strip() for line in unit.read_text().splitlines()]
        if not any(line.startswith('BindsTo=') and expected in line.split('=',1)[1].split() for line in lines):
            return None
        return value
    except (OSError, ValueError, TypeError, KeyError):
        return None


def admin_guard_ready(store):
    if store.get_meta('mode') != 'production':
        return True
    approval=guard_approval(store.policy)
    if not approval:
        return False
    pids = _guard_cgroup_pids(approval['worker_id'])
    return bool(pids and all(pid > 0 and Path('/proc/' + str(pid)).is_dir() for pid in pids))


ADMIN_POOL = "administrator"


def configured(store):
    return bool(store.get_setting("budget_confirmed", False))


def ensure_schema(store):
    """Additive: a member may draw on the administrators' remaining pool."""
    if "quota_pool" not in {row[1] for row in store.conn.execute("PRAGMA table_info(users)")}:
        store.conn.execute("ALTER TABLE users ADD COLUMN quota_pool TEXT")


def in_admin_pool(user):
    return user["role"] == "admin" or user.get("quota_pool") == ADMIN_POOL


def pool_users(store):
    """Live users whose allowance is the shared remainder, never a fixed reservation."""
    users = [dict(row) for row in store.conn.execute(
        "SELECT * FROM users WHERE revoked_at IS NULL AND deleted_at IS NULL ORDER BY created_at,id")]
    return [user for user in users if in_admin_pool(user)]


def _used_this_cycle(store, user_id=None):
    from .domain import ensure_cycle
    cycle = ensure_cycle(store, store.now)
    query = "SELECT COALESCE(SUM(upload+download),0) FROM ledger WHERE cycle_id=?"
    values = [cycle["id"]]
    if user_id is not None:
        query += " AND user_id=?"
        values.append(user_id)
    return store.conn.execute(query, values).fetchone()[0]


def _released(store, user):
    if not (user["revoked_at"] or user.get("deleted_at")):
        return False
    if store.get_meta("mode") != "production":
        row = store.conn.execute("SELECT status FROM runtime_state WHERE user_id=?", (user["id"],)).fetchone()
        return row is not None and row[0] == "stopped"
    # A stopped process is not yet a settled assignment. Preserve the remaining
    # reservation throughout tail reconciliation and root release confirmation.
    return bool(store.conn.execute("SELECT 1 FROM resource_leases WHERE user_id=? AND status='released'", (user["id"],)).fetchone())


def reservations(store, *, replace_user=None, replace_allowance=None):
    result = 0
    for row in store.conn.execute("SELECT * FROM users WHERE role='member'"):
        user = dict(row)
        if _released(store, user):
            continue
        if user["id"] == replace_user:
            allowance = replace_allowance  # Also a pool member leaving for a fixed allowance.
        elif user.get("quota_pool") == ADMIN_POOL:
            continue  # Shares the administrators' remainder; it reserves nothing.
        else:
            allowance = ((user["quota_bytes"] or 0) + user["topup_bytes"])
        result += max(0, allowance - user["used_upload"] - user["used_download"])
    return result


def _provider_estimate(store, now):
    from .provider_sync import remaining_estimate
    return remaining_estimate(store, now if now is not None else store.now)


def snapshot(store, now=None):
    active = configured(store)
    total = store.get_setting("budget_total_bytes") if active else None
    margin = store.get_setting("budget_safety_bytes") if active else None
    spent = _used_this_cycle(store)
    reserved = reservations(store) if active else 0
    local = max(0, total - margin - spent - reserved) if active else None
    remaining, limited_by, provider = local, "local" if active else None, None
    estimate = _provider_estimate(store, now) if active else None
    if estimate is not None:
        # QQG's own remainder, after the same margin and member reservations, can
        # only lower the administrators' share; it never raises it above local.
        cap = max(0, estimate["estimated_remaining_bytes"] - margin - reserved)
        provider = {**estimate, "admin_cap_bytes": cap,
                    "overcommitted_bytes": max(0, reserved + margin - estimate["estimated_remaining_bytes"])}
        if cap < local:
            remaining, limited_by = cap, "provider"
    pool = pool_users(store)
    admin = next((user for user in pool if user["role"] == "admin"), None)
    admin_used = admin["used_upload"] + admin["used_download"] if admin else 0  # Same basis as refresh_admin.
    if not active:
        reason = "请先确认套餐预算和安全余量；商家实时余额尚未核验。"
    elif remaining >= GB:
        reason = ""
    else:
        reason = "QQG 实际剩余不足1GB" if limited_by == "provider" else "可分配预算不足1GB"
    notice = ("本地预算与 QQG 实时剩余取较小值；QQG 读数会扣除之后的本地用量。" if estimate is not None else
              "本地预算，不等于QQG实时计费余额。")
    return {"source": "administrator_budget" if active else "not_configured", "configured": active,
            "administrator_pool": {"user_ids": [user["id"] for user in pool],
                                   "used_bytes": sum(user["used_upload"] + user["used_download"] for user in pool)},
            "verified": estimate is not None, "provider_remaining_verified": estimate is not None,
            "can_allocate": bool(active and remaining >= GB), "reason": reason,
            "total_bytes": total, "safety_margin_bytes": margin, "used_bytes": spent,
            "members_reserved_bytes": reserved, "available_bytes": remaining, "local_available_bytes": local,
            "limited_by": limited_by, "provider": provider,
            "admin_allowance_bytes": admin_used + remaining if active else None,
            "admin_remaining_bytes": remaining, "confirmed_at": store.get_setting("budget_confirmed_at"),
            "overcommitted_bytes": max(0, spent + reserved + (margin or 0) - (total or 0)) if active else 0,
            "accounting_basis": "local_proxy_payload", "notice": notice}


def validate_allowance(store, allowance, *, user=None, trial=False):
    from .domain import DomainError, integer
    allowance = integer(allowance, "quota_bytes", 1)
    if user and allowance < user["used_upload"] + user["used_download"]:
        raise DomainError("QUOTA_BELOW_USED", "额度不能低于已经使用的流量")
    if not configured(store):
        # Existing rows remain authorised during adoption, but a production
        # client cannot issue new promises by bypassing the App's disabled UI.
        # Reducing an existing allowance (including making a legacy unlimited
        # member finite) is required to prepare a safe budget adoption.
        increases = user is None or (not user["unlimited"] and
                    allowance > (user["quota_bytes"] or 0) + user["topup_bytes"])
        if trial or (store.get_meta("mode") == "production" and increases):
            raise DomainError("BUDGET_NOT_CONFIGURED", "请先在App确认套餐预算与安全余量")
        return
    allowance = integer(allowance, "quota_bytes", GB if trial else 50 * GB)
    if allowance % GB:
        raise DomainError("VALIDATION", "额度须为整数GB")
    total = store.get_setting("budget_total_bytes")
    margin = store.get_setting("budget_safety_bytes")
    reserved = reservations(store, replace_user=user["id"] if user else None, replace_allowance=allowance)
    if user is None:
        reserved += allowance
    if _used_this_cycle(store) + reserved + margin > total:
        raise DomainError("BUDGET_EXCEEDED", "超过可分配预算，操作未生效；不会挤占其他用户预留额度")
    estimate = _provider_estimate(store, store.now)
    # Only a growing promise is checked against QQG, so a reduction is never refused.
    if (estimate is not None and reserved > reservations(store) and
            reserved + margin > estimate["estimated_remaining_bytes"]):
        raise DomainError("PROVIDER_REMAINING_EXCEEDED", "超过 QQG 实际剩余流量，操作未生效；请先核对 QQG 余量或调整预算")


def configure(store, params, now):
    from .domain import DomainError, integer, text
    if params.get("confirmed") is not True:
        raise DomainError("VALIDATION", "须明确确认本地套餐预算，而非商家实时余额")
    total = integer(params.get("total_bytes"), "total_bytes", GB)
    margin = integer(params.get("safety_margin_bytes"), "safety_margin_bytes", 0, total - 1)
    if total % GB or margin % GB:
        raise DomainError("VALIDATION", "套餐预算和安全余量须为整数GB")
    evidence = text(params.get("evidence"), "evidence", 500)
    if not admin_guard_ready(store):
        raise DomainError('ADMIN_GUARD_REQUIRED', '管理员代理独立计量保护尚未通过部署核验，预算未启用；现有代理不变')
    if store.conn.execute("SELECT 1 FROM users WHERE role='member' AND unlimited=1 AND revoked_at IS NULL AND deleted_at IS NULL").fetchone():
        raise DomainError("UNLIMITED_MEMBER", "请先为不限量普通用户设置有限额度，再启用预算保护")
    if _used_this_cycle(store) + reservations(store) + margin > total:
        raise DomainError("BUDGET_EXCEEDED", "现有用量与用户预留已超过此预算；原配置保持不变")
    for name, value in {"budget_total_bytes": total, "budget_safety_bytes": margin,
                        "budget_confirmed": True, "budget_confirmed_at": timestamp(now),
                        "budget_evidence": evidence}.items():
        store.set_setting(name, value)
    refresh_admin(store, now)
    return {"budget": snapshot(store, now)}


def refresh_admin(store, now):
    if not configured(store):
        return
    info = snapshot(store, now)
    remaining = info["admin_remaining_bytes"]
    for user in pool_users(store):
        reasons = set(json.loads(user["reasons_json"]))
        if remaining <= 0:
            reasons.add("quota_exceeded")
        else:
            reasons.discard("quota_exceeded")
        # Every pool member may use the one shared remainder; on the same counters
        # the quota check compares, the allowance is exhausted exactly when it is.
        allowance = user["used_upload"] + user["used_download"] + remaining
        store.conn.execute("UPDATE users SET unlimited=0,quota_bytes=?,reasons_json=? WHERE id=?",
                           (allowance, json.dumps(sorted(reasons)), user["id"]))
