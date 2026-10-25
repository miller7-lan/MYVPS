"""Simulation executor for project-owned proxy workers. No systemctl calls.

A future privileged helper must accept fixed registered worker IDs only, recheck
current authorization and generation at execution time, and preserve revocations.
This phase intentionally cannot control production services.
"""
from __future__ import annotations
import json


def process(store, now) -> dict:
    from .store import parse_time, timestamp
    now = parse_time(now)
    stamp = timestamp(now)
    applied = rejected = 0
    for task in store.conn.execute("SELECT * FROM runtime_queue WHERE status='pending' ORDER BY rowid").fetchall():
        user = store.conn.execute("SELECT * FROM users WHERE id=?", (task["user_id"],)).fetchone()
        if user is None:
            store.conn.execute("UPDATE runtime_queue SET status='failed',applied_at=?,detail=? WHERE id=?",
                               (stamp, "Unknown registered user; no action taken", task["id"]))
            rejected += 1
            continue
        from .domain import eligible
        allowed = eligible(dict(user), now)
        # Old queued starts/rotations must never resurrect disabled or revoked users.
        desired = "running" if allowed else "stopped"
        store.conn.execute("INSERT INTO runtime_state(user_id,status,runtime_version,updated_at) VALUES(?,?,?,?) "
                           "ON CONFLICT(user_id) DO UPDATE SET status=excluded.status,runtime_version=excluded.runtime_version,updated_at=excluded.updated_at",
                           (user["id"], desired, user["credential_version"], stamp))
        store.conn.execute("UPDATE runtime_queue SET status='applied',applied_at=?,detail=? WHERE id=?",
                           (stamp, "Simulated only: " + desired, task["id"]))
        applied += 1
    return {"applied": applied, "rejected": rejected, "mode": "simulation", "production_changed": False}


def deployment_preview() -> dict:
    return {"mode": "preview_only", "production_changed": False, "apply_available": False,
            "preserve": ["existing TCP/UDP443", "SSH configuration, keys and port", "global firewall", "other services"],
            "changes_requiring_approval": [
                "Register dedicated low-privilege agent and restricted project worker helper",
                "Install project-only files and SQLite ledger under /opt and /var/lib/dazzle-vps",
                "Enable loopback-only authenticated native API on NEW per-user workers",
                "Validate and separately approve each new public TCP/UDP proxy port and reachability",
                "Install project systemd service/timers after local validation",
                "Configure verified official provider adapter and securely provision credentials",
                "Configure real TLS SMTP and explicitly authorize test email",
            ],
            "rollback": ["Stop NEW project workers and agent only", "Keep legacy443 untouched",
                         "Restore last known-good project runtime after reapplying permanent revocation tombstones",
                         "Never roll back ledger counters, mail idempotency or completed cycles",
                         "Never overwrite current valid TLS certificate with an older backup"],
            "blockers": ["No official QQG API scope/schema verified", "No real SMTP configured",
                         "Native API is not enabled or verified on production", "New ports not approved"]}
