"""Explicit historical database rows for pre-budget production regressions.

These fixtures model users that already existed before budget adoption. They do
not call, patch, or relax the production admission RPC. New-admission tests must
use ``confirm_test_budget`` and the real RPC instead.
"""
import secrets
import uuid
from unittest.mock import patch

from dazzle import domain, trials
from dazzle.production import handle_request, plan_jobs
from dazzle.store import timestamp


def seed_legacy_user(store, params, now):
    """Load one historical authorisation into a temporary ProductionStore."""
    if store.conn.in_transaction:
        raise AssertionError("Historical fixture must own its transaction")
    role = params.get("role", "member")
    store.now = now
    store.conn.execute("BEGIN IMMEDIATE")
    try:
        row = store.conn.execute("SELECT * FROM production_workers WHERE role=? AND user_id IS NULL AND tombstoned=0 ORDER BY public_port LIMIT 1", (role,)).fetchone()
        if row is None:
            raise AssertionError("Historical fixture needs an unused approved slot")
        identifier = row["worker_id"] if not store.conn.execute("SELECT 1 FROM users WHERE id=?", (row["worker_id"],)).fetchone() else str(uuid.uuid4())
        quota = None if role == "admin" else params.get("quota_bytes", store.get_setting("default_quota_bytes"))
        store.conn.execute("INSERT INTO users(id,name,role,port,quota_bytes,unlimited,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                           (identifier, params.get("name", "Historical member"), role, row["public_port"], quota,
                            int(role == "admin" or params.get("unlimited", False)), timestamp(now), timestamp(now)))
        domain._new_credentials(store, identifier, 1, now)
        store.conn.execute("UPDATE credentials SET reality_public_key='' WHERE user_id=?", (identifier,))
        store.conn.execute("UPDATE production_workers SET user_id=?,api_secret=? WHERE worker_id=?",
                           (identifier, secrets.token_urlsafe(36), row["worker_id"]))
        trials.register_lease(store, row["worker_id"], identifier, now)
        domain.ensure_cycle(store, now)
        plan_jobs(store, now)
        store.set_meta("revision", store.revision + 1)
        store.conn.commit()
    except BaseException:
        store.conn.rollback()
        raise
    return store.get_user(identifier)


def confirm_test_budget(store, now, *, total_gb=500, margin_gb=0):
    """Adopt a real isolated budget; only root evidence is replaced by a fixture."""
    with patch("dazzle.budget.admin_guard_ready", return_value=True):
        response = handle_request(store, {"api_version": 1, "request_id": str(uuid.uuid4()),
            "action": "budget.configure", "server_id": store.server_id, "expected_revision": store.revision,
            "params": {"total_bytes": total_gb * 1_000_000_000, "safety_margin_bytes": margin_gb * 1_000_000_000,
                       "confirmed": True, "evidence": "Isolated test budget; no provider or production guard involved"}}, now)
    if not response["ok"]:
        raise AssertionError(response)
    return response
