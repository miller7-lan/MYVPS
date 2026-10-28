#!/usr/bin/env python3
"""Exact-plan v2 writer refresh; existing guarded Cores are never restarted.

The lock holder, rather than ``current``, identifies the fallback writer. The
public process and SSH control entry are held while a consistent backup and a
read-only standby are prepared. Existing Coordinator takeover/acceptance gates
remain authoritative; every live guard, including the administrator's guard,
shares the unchanged five-second sample deadline. No policy, registry, worker
definition, firewall, SSH setting or ledger backup is restored by this module.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import pwd
import re
import signal
import subprocess
import sys
import uuid

from .coordinator import (Abort, Coordinator, FRESHNESS_LIMIT, HOLD, LAUNCHER, Layout, RELEASE, READER, LedgerReader,
                          UNIT_PROPERTIES, _issue, fallback_reserve, observe_phase, observe_unit,
                          parse_status, process_record, running_workers, sample_ages,
                          validate_parameters, worker_problems, worker_units)
from .expansion import ExpansionHost, PORTAL_ACCOUNT, PORTAL_PORT, PORTAL_UNIT, TAKEOVER_ALLOWANCE, guard_ready, writer_dropin
from .helper import canonical_uuid, validate_policy
from .installer import canonical, sha256

OPERATION = "v2_writer_refresh"
ACKNOWLEDGEMENTS = frozenset({"abort_rather_than_restart_core", "fallback_is_best_effort_fail_closed",
                              "portal_briefly_unavailable", "registration_and_ledger_preserved"})


class RefreshLedgerReader(LedgerReader):
    """The ordinary agent-owned read-only reader, with only a mail-busy count."""
    def __init__(self, database, *, python=None, user=None, group=None, extra_groups=None):
        marker = "for line in sys.stdin:\n"
        if READER.count(marker) != 1:
            raise ValueError("The reviewed read-only ledger reader changed")
        extra = '''base_facts = facts
def facts():
    result = base_facts()
    result["mail_pending"] = connection.execute("SELECT COUNT(*) FROM mail_outbox WHERE status IN ('queued','retry','sending')").fetchone()[0]
    return result
'''
        script = READER.replace(marker, extra + marker)
        options = {} if user is None else {"user": user, "group": group, "extra_groups": list(extra_groups or [])}
        self.process = subprocess.Popen([python or sys.executable, "-I", "-c", script, str(database)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, cwd="/", umask=0o077, close_fds=True, **options)
        self.buffer, self.sequence = b"", 0


class RefreshHost(ExpansionHost):
    def completed_guard_proof(self, identifier, worker):
        """A sticky startup STATUS needs independent root completion evidence."""
        from dazzle.meter_guard import GuardError, read_proof
        try:
            policy = json.loads(self.read_trusted(self.layout.policy))
            proof = read_proof(policy, identifier, directory=self.layout.guard_proofs)
            config = self.read_trusted(self.layout.etc / "workers" / (identifier + ".json"))
            return bool(proof and proof["phase"] == "complete" and proof["mode"] == "running"
                        and proof["generation"] == worker["root_ack_generation"]
                        and proof["process_id"] == worker["process_id"]
                        and proof["config_sha256"] == sha256(config))
        except (GuardError, OSError, ValueError, KeyError, TypeError):
            return False

    def ledger(self):
        account = pwd.getpwnam(self.layout.agent_account)
        return RefreshLedgerReader(self.layout.database, user=account.pw_uid, group=account.pw_gid,
                                   extra_groups=[self.group(self.layout.project_group)])

    def writer_release(self, pid):
        text = (self.layout.proc / str(int(pid)) / "cgroup").read_text()
        matches = re.findall(r"(?:^|/)dazzle-vps-writer@([a-f0-9]{24})\.service(?:$|/|\n)", text)
        if len(set(matches)) != 1:
            raise ValueError("The exclusive lock holder has no unique immutable writer unit")
        return matches[0]


def _inventory(host, directory):
    inventory = host.release_inventory(directory)
    manifest = json.loads(host.read_trusted(directory / "release.json"))
    if (sha256(canonical(inventory))[:24] != directory.name or manifest.get("release_id") != directory.name
            or manifest.get("files") != inventory):
        raise ValueError("An immutable release no longer matches its recorded inventory")
    return sha256(canonical(inventory))


def _definitions(host, units):
    files = {}
    for observed in units:
        for name in [observed["fragment"], *observed["dropins"].split()]:
            if name:
                files[name] = sha256(host.read_trusted(name))
    return files


def refresh_guard_ready(identifier, observed, worker, user, host=None):
    if guard_ready(identifier, observed):
        return True
    status = parse_status(observed["status"])
    # A guard started by recovery first announces api-only-transition. Older
    # guards never update STATUS after that first READY, even after activation.
    # Accept that exact historical label only for a fully settled, enabled,
    # quota-bound trusted row. The callers still verify the original Core and
    # guard identities, bindings, fresh samples, budget and TCP witness.
    historical = status.get("phase") in {
        "bootstrap-inactive", "api-only", "api-only-origin", "activation-transition", "activation-origin"}
    verifier = getattr(host, "completed_guard_proof", None)
    proven = bool(historical and worker and verifier and verifier(identifier, worker))
    # Other startup labels remain rejected without a root-owned, same-boot
    # completed running proof pinned to this PID, generation and config digest.
    # This proof establishes completion, not sample freshness; all existing
    # stream/identity/age checks in preview, gate and acceptance still apply.
    if status.get("phase") == "api-only-transition" or proven:
        return bool(worker and user and worker["role"] == user["role"] in {"admin", "member"}
                    and observed["active"] == "active" and observed["sub"] == "running"
                    and status["_"] == "member-guard-ready" and status.get("worker") == identifier
                    and worker["observed_state"] == "running" and worker["provisioned"]
                    and not worker["origin_pending"] and not worker["last_error"] and not worker["tombstoned"]
                    and type(worker["process_id"]) is int and worker["process_id"] > 0
                    and worker["generation"] == worker["root_ack_generation"] == worker["observed_generation"]
                    and user["credential_version"] == worker["credential_version"]
                    and not user["manual_disabled"] and not user["deleted_at"] and not user["revoked_at"]
                    and not json.loads(user["reasons_json"] or "[]")
                    and user["unlimited"] == 0 and type(user["quota_bytes"]) is int and user["quota_bytes"] > 0
                    and user["trusted_sample"] and user["meter_state"] == "trusted")
    # Older run_guard sends STATUS only on its first successful evaluation
    # (meter_guard.py:295-297). A continuously running administrator guard may
    # therefore keep its initial admin-preparing text after the budget is
    # enforced. Accept that text only against the current quota-bound trusted
    # administrator row. Process identity and fresh streams are checked by the
    # preview/gate/accept callers; the guard itself is never restarted here.
    return bool(worker and user and worker["role"] == user["role"] == "admin"
                and user["unlimited"] == 0 and type(user["quota_bytes"]) is int and user["quota_bytes"] > 0
                and user["trusted_sample"] and user["meter_state"] == "trusted"
                and observed["active"] == "active" and observed["sub"] == "running"
                and status["_"] == "member-guard-ready" and status.get("worker") == identifier
                and status.get("phase") == "admin-preparing")


def build_plan(host, layout, *, new_release_id, plan_id=None, parameters=None, measurements=None):
    """Read-only preview, also re-derived at apply before any service is held."""
    parameters = validate_parameters(parameters)
    if not RELEASE.fullmatch(new_release_id or ""):
        raise ValueError("An immutable staged release identifier is required")
    plan_id, issues = canonical_uuid(plan_id or str(uuid.uuid4())), []
    policy_bytes = host.read_trusted(layout.policy)
    policy = validate_policy(json.loads(policy_bytes))
    if policy["version"] != 2:
        raise ValueError("Writer refresh requires the existing v2 policy")
    current = host.current_release()
    current_hash = _inventory(host, current)
    holders = host.lock_holders()
    if len(holders) != 1 or holders[0]["mode"] != "WRITE":
        raise ValueError("One exclusive writer lock holder is required")
    previous_id = host.writer_release(holders[0]["pid"])
    if not RELEASE.fullmatch(previous_id or "") or previous_id == new_release_id:
        raise ValueError("A distinct pinned previous writer is required")
    previous = layout.prefix / "releases" / previous_id
    previous_hash = _inventory(host, previous)
    new_dir = layout.prefix / "releases" / new_release_id
    new_hash = _inventory(host, new_dir)
    old_name, new_name = (layout.instance(layout.writer_template, key) for key in (previous_id, new_release_id))
    old, new, portal = (observe_unit(host, name) for name in (old_name, new_name, PORTAL_UNIT))
    if old["pid"] != holders[0]["pid"] or (old["active"], old["sub"]) != ("active", "running"):
        _issue(issues, "OLD_WRITER", "The exclusive writer is not the same running unit")
    if new["pid"] or new["active"] not in {"inactive", ""}:
        _issue(issues, "NEW_WRITER", "The target writer instance is already active")
    template = layout.units / layout.writer_template
    expected_dropin = writer_dropin(layout)
    if (old["fragment"] != str(template) or old["dropins"].split() != [str(expected_dropin)]
            or old["need_reload"] != "no"):
        _issue(issues, "WRITER_DEFINITION", "The writer must use only the existing reviewed template and portal drop-in")
    if (host.read_trusted(template) != host.read_trusted(new_dir / "deployment/portal-systemd/writer@.service")
            or host.read_trusted(expected_dropin) != host.read_trusted(new_dir / "deployment/portal-systemd/agent.conf")):
        raise ValueError("This narrow refresh cannot change the installed writer template or drop-in")
    account = host.account(PORTAL_ACCOUNT)
    if (not account or account["uid"] != policy["portal_uid"] or account["shell"] != "/usr/sbin/nologin"
            or account["home"] != "/nonexistent" or account["groups"]):
        raise ValueError("The existing private portal identity is not valid")
    if (portal["active"], portal["sub"]) != ("active", "running") or not portal["pid"]:
        _issue(issues, "PORTAL", "The existing public portal must be running before refresh")
    all_units = worker_units(layout, policy)
    with host.ledger() as ledger:
        facts = ledger.facts()
        live = set(running_workers(facts))
        phase = observe_phase(host, ledger, live) if measurements is None else None
        facts = ledger.facts()
    if facts["meta"].get("server_id") != policy["server_id"] or facts["meta"].get("mode") != "production":
        raise ValueError("Ledger identity differs from the unchanged root policy")
    if facts["jobs_active"] or facts["meta"].get("agent_recovery_only"):
        _issue(issues, "LEDGER_BUSY", "Managed jobs or recovery mode prevent a writer refresh")
    if facts.get("mail_pending") != 0:
        _issue(issues, "MAIL_BUSY", "Pending or in-flight mail must finish before refreshing the writer")
    if facts.get("registration_state_source") != "settings" or type(facts.get("registration_enabled")) is not bool:
        _issue(issues, "REGISTRATION", "The existing registration setting cannot be preserved reliably")
    workers = {worker["worker_id"]: worker for worker in facts["workers"]}
    if set(workers) != set(all_units) or not live:
        raise ValueError("Policy and ledger worker bindings must match, with at least one live worker")
    users = {user["id"]: user for user in facts["users"]}
    units, dormant, guards, processes, observed_units = {}, {}, {}, {}, [old, portal]
    now = host.wall()
    for identifier, value in all_units.items():
        worker = workers[identifier]
        if (worker["role"], worker["public_port"], worker["api_port"]) != (value["role"], value["public_port"], value["api_port"]):
            raise ValueError("A worker binding differs from its root authorization")
        observed = observe_unit(host, value["unit"])
        if identifier not in live:
            if observed["pid"] or observed["active"] not in {"", "inactive"} or worker["user_id"] or worker["provisioned"]:
                _issue(issues, "DORMANT_WORKER", "Only unprovisioned inactive seats may be omitted from live sampling")
            dormant[identifier] = {"unit": value["unit"], "pid": observed["pid"], "active": observed["active"]}
            continue
        value = {**value, "guard": layout.instance(layout.guard_template, identifier)}
        units[identifier], processes[identifier] = value, process_record(host, observed)
        guard = observe_unit(host, value["guard"])
        guards[identifier] = process_record(host, guard)
        observed_units.extend([observed, guard])
        if (observed["active"], observed["sub"]) != ("active", "running") or observed["pid"] != worker["process_id"]:
            _issue(issues, "CORE", "A live Core process differs from its settled ledger binding")
        if (observed["binds_to"] != [value["guard"]] or observed["need_reload"] != "no"
                or not refresh_guard_ready(identifier, guard, worker, users.get(worker["user_id"]), host)):
            _issue(issues, "GUARD", "Every live worker must remain bound to its existing ready meter guard")
        for problem in worker_problems(worker, users.get(worker["user_id"]), "member", parameters, now, facts["cycle"]):
            _issue(issues, "LEDGER", problem)
    members = {key: value for key, value in units.items() if value["role"] == "member"}
    witness = {}
    for identifier, value in members.items():
        observed = host.witness(processes[identifier]["pid"], value["public_port"])
        witness[identifier] = len(observed["established"])
        if not observed["listening"] or not observed["established"]:
            _issue(issues, "WITNESS", "A real member TCP session must remain connected during refresh", volatile=True)
    ages = sample_ages(facts, now)
    if set(ages) != set(units) or max(ages.values(), default=float("inf")) > 2:
        _issue(issues, "FRESHNESS", "Every live stream needs a fresh trusted sample", volatile=True)
    if measurements is None:
        offset = host.standby_ready_offset(old_name, old["pid"], old["exec_start_us"])
        latency = host.helper_latency(next(iter(units)), 3)
        measurements = {"old_writer_standby_ready_seconds": offset, "takeover_allowance_seconds": TAKEOVER_ALLOWANCE,
                        "old_writer_start_to_ready_seconds": round(offset + TAKEOVER_ALLOWANCE, 3) if offset else None,
                        "helper_status_latency_seconds": latency, "best_guard_sample_age_seconds": round(phase[0], 3)}
    start = measurements["old_writer_start_to_ready_seconds"]
    best = measurements["best_guard_sample_age_seconds"]
    available = round(FRESHNESS_LIMIT - best - parameters["takeover_deadline"] - parameters["safety_margin"], 3)
    reserve = fallback_reserve(start, max(measurements["helper_status_latency_seconds"]), len(units)) if start and 0 < start < 60 else None
    if reserve is None or reserve > available or best > parameters["max_sample_age_at_stop"]:
        _issue(issues, "FALLBACK_BUDGET", "The measured pinned-writer fallback does not fit the unchanged sample deadline")
    measurements = {**measurements, "fallback_reserve_seconds": reserve, "available_for_fallback_seconds": available}
    registry = host.read_trusted(layout.registry)
    if host.read(layout.control) != LAUNCHER:
        raise ValueError("The private control entry is not the fixed installed launcher")
    host.require_replaceable(layout.control)
    reviewed = {"server_id": policy["server_id"], "policy_sha256": sha256(policy_bytes), "registry_sha256": sha256(registry),
                "policy": policy, "previous_release_id": previous_id, "current_release_id": current.name,
                "new_release_id": new_release_id, "previous_inventory_sha256": previous_hash,
                "current_inventory_sha256": current_hash, "new_inventory_sha256": new_hash,
                "units": {"old_writer": old_name, "new_writer": new_name, "workers": units, "portal": PORTAL_UNIT},
                "processes": {"old_writer": process_record(host, old), "workers": processes, "guards": guards,
                              "portal": process_record(host, portal)},
                "definitions": _definitions(host, observed_units), "dormant": dormant, "portal_account": account,
                "lock": host.lock_identity(), "files": {}, "parameters": parameters,
                "ledger": {"revision": facts["meta"].get("revision"), "incidents_total": facts["incidents_total"],
                           "cycle_id": facts["cycle"]["id"] if facts["cycle"] else None,
                           "registration_enabled": facts.get("registration_enabled")},
                "certificate_sync": {"loaded": False},
                "unchanged": ["policy and registry", "all Core and guard processes", "firewall and SSH", "registration setting",
                              "ledger and counters; no automatic database restore"]}
    return {"version": 1, "operation": OPERATION, "plan_id": plan_id, "reviewed": reviewed,
            "measurements": measurements, "observed": {"at": now.isoformat(), "member_witness_connections": witness},
            "issues": issues, "ready_for_approval": not issues,
            "blocking_issues": sum(not value["volatile"] for value in issues)}


def validate_approval(plan, approval):
    fields = {"version", "operation", "approved", "approval_id", "plan_sha256", "acknowledgements"}
    if (not isinstance(approval, dict) or set(approval) != fields or approval["version"] != 1
            or approval["operation"] != OPERATION or approval["approved"] is not True
            or plan.get("version") != 1 or plan.get("operation") != OPERATION or not plan.get("ready_for_approval")
            or approval["plan_sha256"] != sha256(canonical(plan))):
        raise ValueError("Approval must bind this exact ready v2 writer refresh plan")
    canonical_uuid(plan["plan_id"]); canonical_uuid(approval["approval_id"])
    acknowledgements = approval["acknowledgements"]
    if (not isinstance(acknowledgements, dict) or set(acknowledgements) != ACKNOWLEDGEMENTS
            or any(value is not True for value in acknowledgements.values())):
        raise ValueError("Every narrow refresh acknowledgement is required")


class RefreshCoordinator(Coordinator):
    def __init__(self, host, layout, plan, approval):
        validate_approval(plan, approval)
        self.host, self.layout, self.renderer = host, layout, None
        self.plan, self.reviewed, self.parameters = plan, plan["reviewed"], plan["reviewed"]["parameters"]
        self.run_dir, self.units = layout.handoff / plan["plan_id"], self.reviewed["units"]
        self.members = {key: value for key, value in self.units["workers"].items() if value["role"] == "member"}
        self.journal = {"version": 1, "operation": OPERATION, "plan_id": plan["plan_id"], "plan_sha256": approval["plan_sha256"],
                        "approval_id": approval["approval_id"], "status": "started", "steps": []}
        self.interrupted = self.held = self.prepared = self.standby = self.old_stopped = self.portal_held = False
        self.standby_pid, self.ledger = None, None
        self.guards, self.adopted, self.preflight_witness = {}, [], {}

    def verify_plan(self):
        fresh = build_plan(self.host, self.layout, new_release_id=self.reviewed["new_release_id"], plan_id=self.plan["plan_id"],
                           parameters=self.parameters, measurements=self.plan["measurements"])
        self.require(fresh["reviewed"] == self.reviewed, "Reviewed v2 facts changed since approval")
        self.require(not [item for item in fresh["issues"] if not item["volatile"]], "Current refresh checks have blocking issues")
        self.step("plan_reverified")

    def hold_portal(self):
        self.require(self.same_process(self.reviewed["processes"]["portal"], self.unit(PORTAL_UNIT)), "Portal process changed since review")
        self.portal_held = True
        self.require(self.host.systemctl("stop", PORTAL_UNIT, timeout=30) == 0, "Public writes could not be held")
        portal = self.unit(PORTAL_UNIT)
        self.require(portal["pid"] == 0 and portal["active"] == "inactive" and not self.host.listeners(PORTAL_PORT),
                     "The public portal is not fully stopped")
        # Private RPC handlers have a five-second socket timeout; allow any
        # already accepted request to finish before the consistent backup.
        self.host.sleep(5.1)
        self.step("public_writes_held")

    def backup(self):
        facts = self.ledger.facts()
        self.require(facts["meta"].get("revision") == self.reviewed["ledger"]["revision"] and not facts["jobs_active"]
                     and facts.get("mail_pending") == 0,
                     "A management operation happened after review")
        path = self.run_dir / "pre-refresh.sqlite3"
        self.host.write(path, self.ledger.backup(), mode=0o600)
        self.host.normalize_backup(path)
        result = self.host.migration_check(self.layout.prefix / "releases" / self.reviewed["new_release_id"], path, self.reviewed["policy"])
        self.journal["backup"] = {"path": str(path), "sha256": sha256(self.host.read(path)), "automatic_restore": False,
                                  "additive_migration": result}
        self.step("backup_and_migration_verified")

    def gate(self):
        self.check()
        self.require(self.host.read(self.layout.control) == HOLD and not self.host.control_processes(), "Private management is not held")
        self.require(self.unit(PORTAL_UNIT)["pid"] == 0 and not self.host.listeners(PORTAL_PORT), "Public writes are not held")
        self.require(self.host.current_release().name == self.reviewed["current_release_id"], "Current changed during preparation")
        for path, digest in [(self.layout.policy, self.reviewed["policy_sha256"]), (self.layout.registry, self.reviewed["registry_sha256"]),
                             *self.reviewed["definitions"].items()]:
            self.require(sha256(self.host.read_trusted(path)) == digest, "A reviewed policy, registry or service definition changed")
        self.require(self.same_process(self.reviewed["processes"]["old_writer"], self.unit(self.units["old_writer"])), "The old writer changed")
        self.require(self.exclusive(self.reviewed["processes"]["old_writer"]["pid"]), "The old writer does not exclusively hold the lock")
        self.require(self.standby_ready(self.unit(self.units["new_writer"])), "The new standby is not freshly ready")
        facts = self.ledger.facts()
        current_workers = {worker["worker_id"]: worker for worker in facts["workers"]}
        current_users = {user["id"]: user for user in facts["users"]}
        for key, value in self.units["workers"].items():
            core, guard = self.unit(value["unit"]), self.unit(value["guard"])
            worker = current_workers.get(key)
            user = current_users.get(worker["user_id"]) if worker else None
            self.require(self.same_process(self.reviewed["processes"]["workers"][key], core) and core["binds_to"] == [value["guard"]],
                         "An existing Core changed or lost its guard")
            self.require(self.same_process(self.reviewed["processes"]["guards"][key], guard)
                         and refresh_guard_ready(key, guard, worker, user, self.host), "An existing meter guard changed")
            self.guards[key] = {"pid": guard["pid"], "invocation": guard["invocation"]}
        for value in self.reviewed["dormant"].values():
            current = self.unit(value["unit"])
            self.require(current["pid"] == value["pid"] == 0 and current["active"] == value["active"], "A dormant seat became active")
        ledger = self.reviewed["ledger"]
        self.require(facts["meta"].get("revision") == ledger["revision"] and not facts["jobs_active"] and facts.get("mail_pending") == 0
                     and facts["incidents_total"] == ledger["incidents_total"] and not facts["meta"].get("agent_recovery_only")
                     and facts.get("registration_enabled") == ledger["registration_enabled"]
                     and facts.get("registration_state_source") == "settings"
                     and (facts["cycle"] or {}).get("id") == ledger["cycle_id"], "The approved ledger state changed")
        self.require(set(running_workers(facts)) == set(self.units["workers"]), "The live worker set changed")
        users = {user["id"]: user for user in facts["users"]}
        for worker in facts["workers"]:
            if worker["worker_id"] in self.units["workers"]:
                self.require(not worker_problems(worker, users.get(worker["user_id"]), "member", self.parameters, self.host.wall(), facts["cycle"]),
                             "An existing stream is no longer trusted and settled")
        self.require(self.fresh_after(facts, dt.datetime.min.replace(tzinfo=dt.timezone.utc)), "Samples are no longer fresh")
        witness = self.require_witness(min(5.0, self.parameters["witness_wait_seconds"]))
        witness = {key: sorted(set(value) & set(self.preflight_witness[key])) for key, value in witness.items()}
        self.require(all(witness.values()), "No original member TCP witness survived preparation")
        self.step("gate_passed")
        return {"facts": facts, "witness": witness}

    def takeover(self, baseline):
        # The inherited state machine uses `members` only to determine the
        # earliest guarded sample deadline here. v2 administrators are guarded
        # too, so include all live workers for that calculation, then restore
        # the member-only witness/acceptance view in every return path.
        members = self.members
        self.members = self.units["workers"]
        try:
            return super().takeover(baseline)
        finally:
            self.members = members

    def fallback(self, reason, stopped_mono, guard_deadline):
        record = self.journal["fallback"] = {"reason": reason}
        self.host.systemctl("stop", "--no-block", self.units["new_writer"])
        until, killed = self.host.monotonic() + .6, False
        while True:
            observed = self.observe(self.units["new_writer"])
            if observed is not None and observed["pid"] == 0:
                break
            if self.host.monotonic() > until:
                if killed:
                    record["new_writer_stop_unconfirmed"] = True
                    self.journal["status"] = "fallback_failed_manual_review"
                    self.step("fallback_failed")
                    return False
                self.host.systemctl("kill", "--signal=SIGKILL", "--kill-whom=all", self.units["new_writer"])
                until, killed = self.host.monotonic() + .6, True
            self.host.sleep(.02)
        restarted = self.host.wall()
        self.host.systemctl("start", "--no-block", self.units["old_writer"])
        fresh = None
        while self.host.monotonic() < guard_deadline + 10:
            old, facts = self.observe(self.units["old_writer"]), self.facts()
            live = self.live_workers()
            if (old is not None and old["active"] == "active" and old["pid"] and self.exclusive(old["pid"])
                    and live and facts is not None and self.fresh_after(facts, restarted, live)):
                fresh = self.host.monotonic(); break
            self.host.sleep(.05)
        interrupted = sorted(set(self.units["workers"]) - set(self.live_workers()))
        record.update({"fresh_after_seconds": round(fresh - stopped_mono, 3) if fresh else None,
                       "within_sample_deadline": bool(fresh is not None and fresh <= guard_deadline),
                       "policy_restored": False, "workers_interrupted": len(interrupted)})
        self.journal["status"] = ("fallback_complete" if fresh is not None and not interrupted else
                                  "fallback_complete_workers_interrupted" if fresh is not None else "fallback_failed_manual_review")
        self.step("fallback_finished")
        return False

    def settle_old_writer(self):
        """The stopped writer releases its lock before its threads finish unwinding.

        The new writer can own the lock and persist samples within a fraction of a
        second, so acceptance used to see the old PID still exiting and stopped at
        taken_over_writer_review_required. Wait for that exit, applying the
        takeover's own kill rule; never touch a Core, guard or the new writer.
        """
        name, pid = self.units["old_writer"], self.reviewed["processes"]["old_writer"]["pid"]
        started, limit, killed = self.host.monotonic(), self.parameters["old_writer_kill_after"], False
        while True:
            observed = self.observe(name)
            if observed is not None and observed["pid"] != pid:
                return
            elapsed = self.host.monotonic() - started
            if not killed and elapsed >= limit:
                self.host.systemctl("kill", "--signal=SIGKILL", "--kill-whom=all", name)
                killed = True
            elif elapsed >= limit + 2.0:
                return  # Acceptance still records a writer that did not exit.
            self.host.sleep(0.05)

    def accept(self, baseline):
        self.settle_old_writer()
        health, preserved = super().accept(baseline)
        facts = self.facts()
        workers = {worker["worker_id"]: worker for worker in facts["workers"]} if facts else {}
        users = {user["id"]: user for user in facts["users"]} if facts else {}
        for key, value in self.units["workers"].items():
            observed = self.unit(value["guard"])
            worker = workers.get(key)
            user = users.get(worker["user_id"]) if worker else None
            if (not self.same_process(self.reviewed["processes"]["guards"][key], observed)
                    or not refresh_guard_ready(key, observed, worker, user, self.host)):
                preserved = False
                self.journal["guard_preservation"] = "A live administrator or member guard changed"
        return health, preserved

    def guard_ready(self, identifier, observed):
        # Inherited acceptance must use the same settled-recovery evidence as
        # preview and gate; otherwise a member's sticky first STATUS fails only
        # after takeover. The original identity and freshness checks still run.
        facts = self.facts()
        if facts is None:
            return False
        worker = next((w for w in facts["workers"] if w["worker_id"] == identifier), None)
        user = next((u for u in facts["users"] if worker and u["id"] == worker["user_id"]), None)
        return refresh_guard_ready(identifier, observed, worker, user, self.host)

    def resume_portal(self):
        if not self.portal_held:
            return True
        code = self.host.systemctl("start", PORTAL_UNIT, timeout=30)
        until = self.host.monotonic() + 15
        while code == 0 and self.host.monotonic() < until:
            observed = self.observe(PORTAL_UNIT)
            if (observed is not None and observed["active"] == "active" and observed["pid"]
                    and self.host.listeners(PORTAL_PORT) == [(observed["pid"], self.reviewed["portal_account"]["uid"])]
                    and self.host.https_status(PORTAL_PORT, "/portal/") == 200
                    and self.host.https_status(PORTAL_PORT, "/" + "Z" * 32 + "/nodes.txt") == 404):
                self.portal_held = False
                self.journal["portal"] = "running"
                return True
            self.host.sleep(.25)
        self.journal["portal"] = "manual_review_required"
        return False

    def finalize(self):
        self.host.switch_current(self.layout.prefix / "releases" / self.reviewed["new_release_id"],
                                 self.layout.prefix / "releases" / self.reviewed["current_release_id"])
        self.require(self.host.current_release().name == self.reviewed["new_release_id"], "Current switch was not confirmed")
        self.require(self.host.systemctl("disable", self.units["old_writer"]) == 0
                     and self.host.systemctl("enable", self.units["new_writer"]) == 0, "Writer boot enablement failed")
        self.require(self.unit(self.units["old_writer"])["file_state"] == "disabled"
                     and self.unit(self.units["new_writer"])["file_state"] in {"enabled", "indirect"}, "Writer boot state was not confirmed")
        self.require(self.resume_portal(), "The public portal did not return after writer refresh")
        self.step("finalized", current=self.reviewed["new_release_id"])

    def revert(self, reason):
        self.journal["abort_reason"] = reason
        ok = True
        if self.standby:
            self.host.systemctl("stop", self.units["new_writer"])
            observed = self.observe(self.units["new_writer"])
            ok = observed is not None and observed["pid"] == 0
        self.journal["status"] = "aborted_no_core_or_writer_changed" if ok else "aborted_manual_review_required"
        self.step("reverted")

    def run(self):
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, self.interrupt)
        self.host.directory(self.layout.handoff, 0o750, self.host.group(self.layout.project_group))
        if self.host.exists(self.run_dir):
            raise ValueError("This exact plan has already been attempted")
        self.host.directory(self.run_dir, 0o700, 0); self.persist()
        try:
            with self.host.ledger() as self.ledger:
                try:
                    self.verify_plan(); self.hold_control(); self.hold_portal()
                    self.preflight_witness = self.require_witness(self.parameters["witness_wait_seconds"])
                    self.backup(); self.start_standby()
                    baseline = self.gate()
                    if self.takeover(baseline):
                        health, preserved = self.accept(baseline)
                        if health:
                            self.finalize()
                            self.journal["status"] = "refresh_complete" if preserved else "refresh_complete_preservation_not_proven"
                        else:
                            self.journal["status"] = "taken_over_writer_review_required"
                except Exception as exc:
                    if not isinstance(exc, Abort):
                        self.journal["unexpected_error"] = type(exc).__name__
                    if not self.old_stopped:
                        self.revert(str(exc) if isinstance(exc, Abort) else "Preparation failed before stopping the writer")
                    elif self.journal["status"] == "started":
                        self.journal["status"] = "manual_review_required"
        finally:
            try:
                if not self.resume_portal():
                    self.journal["status"] = "portal_manual_review_required"
            finally:
                self.release_control(); self.persist()
        return self.journal


def main(argv=None):
    parser = argparse.ArgumentParser(description="Narrow v2 exclusive writer refresh")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true"); mode.add_argument("--apply", action="store_true")
    parser.add_argument("--new-release-id"); parser.add_argument("--plan", type=Path); parser.add_argument("--approval", type=Path)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0 or platform.system() != "Linux":
            raise ValueError("Target root on Linux is required")
        layout = Layout(); host = RefreshHost(layout)
        if args.preview:
            plan = build_plan(host, layout, new_release_id=args.new_release_id)
            result = {"mode": "preview", "production_modified": False, "plan_sha256": sha256(canonical(plan)), "plan": plan}
        else:
            if not args.plan or not args.approval:
                raise ValueError("The exact preview plan and its bound approval are required")
            plan = json.loads(args.plan.read_text())
            if (layout.prefix / "releases" / plan["reviewed"]["new_release_id"]).resolve() not in Path(__file__).resolve().parents:
                raise ValueError("Apply must run from the immutable staged target release")
            result = RefreshCoordinator(host, layout, plan, json.loads(args.approval.read_text())).run()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if args.preview or result.get("status") == "refresh_complete" else 1
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc) if isinstance(exc, (ValueError, Abort)) else "Refresh checks failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
