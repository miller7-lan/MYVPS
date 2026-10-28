#!/usr/bin/env python3
"""One-shot, separately approved: bind the administrator proxy to its own meter
guard and adopt the confirmed local budget inside the guard's preparation window.

Order matters. The guard starts first (it reads the root marker and the reviewed
instance unit from disk), and only then does daemon-reload make the running
administrator Core BindsTo that live guard, so the Core is never restarted and
never bound to an inactive unit. budget.configure must then succeed well inside
the guard's 60 s preparation window; otherwise the dependency is removed again
while the guard is still alive. Afterwards the reviewed members join the
administrators' remaining pool. Members, the writer and the portal are untouched.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import uuid

from .access_preview import administrator_preview
from .coordinator import Abort, HOLD, Host, LAUNCHER, Layout, observe_unit, parse_instant, parse_status
from .helper import canonical_uuid, validate_policy
from .installer import canonical, sha256

OPERATION = "administrator_budget_guard"
MARKER = Path("/etc/dazzle-vps/admin-budget-guard.json")
PREPARATION_SECONDS = 60.0
CONFIGURE_BY_SECONDS = 35.0  # Leave most of the guard's window as margin.
RECOVER_BY_SECONDS = 50.0  # Leave ten seconds before an unlimited guard expires.
GB = 1_000_000_000
ACKNOWLEDGEMENTS = frozenset({"administrator_proxy_becomes_fail_closed_metered", "budget_is_local_not_provider_billing",
                              "never_restart_administrator_core"})


class AdminHost(Host):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.operation_deadline = None
        # Host.show/systemctl also issue blocking commands. Bound those through
        # the same absolute deadline as the RPC, not just a pre-call clock check.
        runner, host = self.runner, self
        class DeadlineRunner:
            def run(self, arguments, *, input=None, timeout=30):
                return runner.run(arguments, input=input, timeout=host.command_timeout(timeout))
        self.runner = DeadlineRunner()

    def command_timeout(self, timeout):
        if self.operation_deadline is None:
            return timeout
        remaining = self.operation_deadline - self.monotonic()
        if remaining <= 0:
            raise Abort("The administrator operation deadline has expired")
        return min(timeout, remaining)

    def boot_id(self):
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()

    def rpc(self, release_dir, request, *, timeout=60):
        """Our own reviewed management call, run by the release's fixed control
        module (it drops to the agent account); the held launcher stays held."""
        result = subprocess.run([str(Path(release_dir) / "venv/bin/python"), "-I", "-m", "deployment.control"],
                                input=json.dumps(request).encode() + b"\n", capture_output=True, timeout=self.command_timeout(timeout),
                                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, cwd="/")
        try:
            return json.loads(result.stdout)
        except ValueError:
            return {"ok": False, "error": {"code": "UNPARSEABLE"}}


def request(server_id, action, params, revision=None):
    value = {"api_version": 1, "request_id": str(uuid.uuid4()), "action": action, "server_id": server_id, "params": params}
    if revision is not None:
        value["expected_revision"] = revision
    return value


def snapshot(host, release_dir, server_id, *, timeout=60):
    reply = host.rpc(release_dir, request(server_id, "snapshot", {}), timeout=timeout)
    if not reply.get("ok"):
        raise ValueError("A read-only management snapshot is unavailable")
    return reply["data"], reply["revision"]


def guard_status(identifier, observed):
    status = parse_status(observed["status"])
    return observed["active"] == "active" and status["_"] == "member-guard-ready" and status.get("worker") == identifier, status.get("phase")


def administrator_ledger_preflight(host, layout, identifier, observed, identity, data, issues, *, expected_server_id):
    """Use raw read-only facts: unlimited snapshots hide meter restrictions.

    This does not acknowledge historical gaps or replace the independent Native
    validation performed by the real guard before it can be bound to the Core.
    """
    result = {"raw_meter_verified": False, "sample_age_seconds": None, "history_complete": False,
              "open_historical_incidents": None, "unknown_historical_incidents": None}
    try:
        with host.ledger() as reader:
            facts = reader.facts()
        if (facts["meta"].get("server_id") != expected_server_id or facts["meta"].get("mode") != "production"
                or data.get("server_id", expected_server_id) != expected_server_id):
            raise ValueError("Ledger identity mismatch")
        user = next(row for row in facts["users"] if row["id"] == identifier)
        worker = next(row for row in facts["workers"] if row["worker_id"] == identifier)
        repeated = observe_unit(host, layout.instance(layout.admin_template, identifier))
        if (identity is None or (repeated["active"], repeated["sub"]) != ("active", "running")
                or repeated["pid"] != observed["pid"] or repeated["invocation"] != observed["invocation"]
                or repeated["restarts"] != observed["restarts"] or host.identity(repeated["pid"]) != identity):
            _issue(issues, "ADMIN_PROCESS_CHANGED", "The administrator Core identity changed during the read-only check")
        age = (host.wall() - parse_instant(user["last_sample_at"])).total_seconds()
        result["sample_age_seconds"] = round(age, 3)
        reasons = json.loads(user["reasons_json"])
        raw_ok = (user["role"] == "admin" and user["unlimited"] and user["trusted_sample"] == 1 and user["meter_state"] == "trusted"
                  and not user["manual_disabled"] and not user["revoked_at"] and not user["deleted_at"]
                  and isinstance(reasons, list) and not reasons and 0 <= age <= 5
                  and isinstance(user.get("epoch_sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", user["epoch_sha256"])
                  and worker["role"] == "admin" and worker["user_id"] == identifier and worker["process_id"] == observed["pid"]
                  and worker["observed_state"] == "running" and not worker["origin_pending"] and not worker["tombstoned"]
                  and not worker["last_error"] and worker["generation"] == worker["root_ack_generation"] == worker["observed_generation"]
                  and worker["credential_version"] == user["credential_version"])
        result["raw_meter_verified"] = bool(raw_ok)
        if not raw_ok:
            _issue(issues, "ADMIN_RAW_METER", "Raw administrator authorization, epoch, sample freshness or worker identity is not trusted")
        records = data.get("metering_incidents", [])
        complete = facts["incidents_total"] <= len(records)
        history = [row for row in records if row.get("user_id") == identifier and not row.get("resolved_at")]
        result.update(history_complete=complete, open_historical_incidents=len(history),
                      unknown_historical_incidents=sum(bool(row.get("unknown_delta")) for row in history),
                      unknown_history_is_not_zero=bool(not complete or any(row.get("unknown_delta") for row in history)))
        if not complete:
            _issue(issues, "ADMIN_HISTORY_UNVERIFIED", "The bounded snapshot cannot enumerate all historical meter incidents; review is required")
    except (OSError, ValueError, TypeError, KeyError, StopIteration, subprocess.SubprocessError):
        _issue(issues, "ADMIN_RAW_LEDGER", "Raw read-only administrator metering evidence is unavailable")
    return result


def build_admin_plan(host, layout, *, total_bytes, safety_margin_bytes, pool_user_ids, evidence, plan_id=None):
    """Read-only preview bound to exact unit text, marker, Core identity and budget numbers."""
    plan_id = canonical_uuid(plan_id or str(uuid.uuid4()))
    if (type(total_bytes) is not int or type(safety_margin_bytes) is not int or total_bytes < GB or total_bytes % GB
            or safety_margin_bytes < 0 or safety_margin_bytes % GB or safety_margin_bytes >= total_bytes):
        raise ValueError("Budget numbers must be whole decimal GB with a margin below the total")
    if not isinstance(evidence, str) or not 1 <= len(evidence) <= 500:
        raise ValueError("Budget evidence text is required")
    issues = []
    policy = validate_policy(json.loads(host.read_trusted(layout.policy)))
    admins = [key for key, worker in policy["workers"].items() if worker["role"] == "admin"]
    if len(admins) != 1:
        raise ValueError("Exactly one administrator worker is expected")
    admin = admins[0]
    release_dir = host.current_release()
    unit = layout.instance(layout.admin_template, admin)
    template_path, instance_path = layout.units / layout.admin_template, layout.units / unit
    template = host.read(template_path)
    if template is None or host.read(instance_path) is not None or host.read(MARKER) is not None:
        raise ValueError("The administrator unit has no reviewed template-only baseline")
    boot = host.boot_id()
    preview = administrator_preview(policy, template.decode("utf-8"), boot)
    if not preview["service_execution_unchanged"]:
        raise ValueError("The administrator service execution would change")
    rendered = preview["unit"].encode()
    marker = canonical(preview["root_marker"]) + b"\n"
    observed = observe_unit(host, unit)
    if (observed["active"], observed["sub"]) != ("active", "running") or observed["pid"] <= 0:
        _issue(issues, "ADMIN_STATE", "The administrator Core is not running")
    if observed["fragment"] != str(template_path) or observed["dropins"] or observed["binds_to"]:
        _issue(issues, "ADMIN_UNIT", "The administrator unit is not the reviewed independent template")
    try:
        identity = host.identity(observed["pid"]) if observed["pid"] else None
    except (OSError, ValueError):
        identity = None
    guard = observe_unit(host, preview["guard"])
    if guard["active"] not in {"inactive", ""} or guard["pid"]:
        _issue(issues, "GUARD_ACTIVE", "The administrator guard is already present or active")
    data, revision = snapshot(host, release_dir, policy["server_id"])
    budget = data["budget"]
    if budget.get("configured"):
        raise ValueError("A budget is already configured")
    users = {user["id"]: user for user in data["users"]}
    user = users.get(admin)
    if user is None or user["role"] != "admin" or not user["unlimited"] or user["disabled_reasons"] or user["meter_state"] != "trusted":
        _issue(issues, "ADMIN_LEDGER", "The administrator is not a trusted, unrestricted pre-budget user")
    raw_meter = administrator_ledger_preflight(host, layout, admin, observed, identity, data, issues,
                                               expected_server_id=policy["server_id"])
    pool = []
    for identifier in pool_user_ids:
        member = users.get(identifier)
        if (member is None or member["role"] != "member" or member["unlimited"] or member["topup_bytes"] or member.get("trial")
                or member.get("quota_pool")):
            raise ValueError("A pool user is not a finite non-trial member without a top-up")
        pool.append({"user_id": identifier, "port": member["port"], "quota_bytes": member["quota_bytes"]})
    used = budget["used_bytes"]
    # budget.configure commits before selected members join the shared pool.
    # Its real intermediate reservation still includes their fixed allowance;
    # approving only the final pool shape could exhaust and stop the admin in
    # between the two RPCs. Released leases reserve nothing, unsettled tails do.
    reservation_users = {member["id"]: member for member in [*data["users"], *data.get("deleted_users", [])]}
    def reservation(member):
        if (member["role"] != "member" or member.get("quota_pool") == "administrator"
                or (member.get("cleanup") or {}).get("state") == "released"):
            return 0
        return max(0, (member["quota_bytes"] or 0) + member["topup_bytes"] - member["used_upload"] - member["used_download"])
    before_pool = sum(reservation(member) for member in reservation_users.values())
    fixed = sum(reservation(member) for member in reservation_users.values() if member["id"] not in pool_user_ids)
    intermediate_remaining = total_bytes - safety_margin_bytes - used - before_pool
    if used + fixed + safety_margin_bytes > total_bytes:
        _issue(issues, "BUDGET_EXCEEDED", "Recorded usage and fixed member reservations already exceed this budget")
    if intermediate_remaining < GB:
        _issue(issues, "BUDGET_TRANSITION_HEADROOM", "budget.configure needs at least 1 GB of headroom before the selected members join the pool")
    if data["health"].get("controller_mode") != "normal":
        _issue(issues, "CONTROLLER", "The writer is not in its normal mode")
    if host.read(layout.control) != LAUNCHER:
        raise ValueError("Management entry differs from the reviewed fixed launcher")
    host.require_replaceable(layout.control)
    reviewed = {
        "server_id": policy["server_id"], "release": release_dir.name, "administrator": admin, "unit": unit,
        "guard": preview["guard"], "boot_id": boot,
        "process": {"pid": observed["pid"], "invocation": observed["invocation"], "restarts": observed["restarts"], "identity": identity},
        "files": {str(instance_path): {"before_sha256": None, "after_sha256": sha256(rendered), "mode": "0644", "content": rendered.decode()},
                  str(MARKER): {"before_sha256": None, "after_sha256": sha256(marker), "mode": "0644", "content": marker.decode()}},
        "budget": {"total_bytes": total_bytes, "safety_margin_bytes": safety_margin_bytes, "evidence": evidence},
        "configure_minimum_remaining_bytes": GB,
        "pool": pool, "revision": revision,
        "expected_remaining_bytes": total_bytes - safety_margin_bytes - used - fixed,
        "control": {"original_sha256": sha256(LAUNCHER), "hold_sha256": sha256(HOLD)},
        "unchanged": ["no Core restart", "member units, guards and writer untouched", "no firewall, SSH, account or provider change",
                      "registration unchanged", "ledger never restored or reset"],
    }
    return {"version": 1, "operation": OPERATION, "plan_id": plan_id, "reviewed": reviewed, "issues": issues,
            "measurements": {"before_pool_reserved_bytes": before_pool, "before_pool_remaining_bytes": intermediate_remaining,
                             "administrator": raw_meter},
            "ready_for_approval": not issues,
            "notice": "After this change the administrator proxy, like members, is stopped by its own guard whenever its metering is "
                      "older than five seconds or the shared remaining budget is exhausted."}


def _issue(issues, code, message):
    issues.append({"code": code, "message": message})


def validate_admin_approval(plan, approval):
    fields = {"version", "operation", "approved", "approval_id", "plan_sha256", "acknowledgements"}
    if (not isinstance(approval, dict) or set(approval) != fields or approval["version"] != 1
            or approval["operation"] != OPERATION or approval["approved"] is not True):
        raise ValueError("A separate explicit administrator budget approval is required")
    canonical_uuid(approval["approval_id"])
    if approval["plan_sha256"] != sha256(canonical(plan)) or not plan.get("ready_for_approval"):
        raise ValueError("Approval must bind the exact ready administrator plan")
    if (not isinstance(approval["acknowledgements"], dict) or set(approval["acknowledgements"]) != ACKNOWLEDGEMENTS
            or not all(value is True for value in approval["acknowledgements"].values())):
        raise ValueError("Every reviewed administrator acknowledgement is required")


class AdminBudgetExecutor:
    def __init__(self, host, layout, plan, approval, *, plan_builder=build_admin_plan):
        validate_admin_approval(plan, approval)
        self.host, self.layout, self.plan, self.reviewed = host, layout, plan, plan["reviewed"]
        self.plan_builder = plan_builder
        self.run_dir = layout.handoff / plan["plan_id"]
        self.release_dir = layout.prefix / "releases" / self.reviewed["release"]
        self.instance = layout.units / self.reviewed["unit"]
        self.journal = {"version": 1, "operation": OPERATION, "plan_id": plan["plan_id"], "plan_sha256": approval["plan_sha256"],
                        "approval_id": approval["approval_id"], "status": "started", "steps": []}
        self.held = self.written = self.guard_started = self.bound = False
        self.interrupted = False
        self.preparation_started = None
        self.budget_attempted = False
        self.budget_outcome = "not_attempted"

    def step(self, name, **detail):
        self.journal["steps"].append({"step": name, "at": self.host.wall().isoformat(), **detail})
        self.persist()

    def persist(self):
        self.host.write(self.run_dir / "receipt.json", json.dumps(self.journal, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n", mode=0o600)

    def require(self, condition, message):
        if not condition:
            raise Abort(message)

    def interrupt(self, *_):
        self.interrupted = True

    def check(self):
        if self.interrupted and not self.bound:
            raise Abort("Operator interrupt before the administrator dependency was bound")

    def same_admin(self):
        observed = observe_unit(self.host, self.reviewed["unit"])
        record = self.reviewed["process"]
        try:
            identity = self.host.identity(observed["pid"])
        except (OSError, ValueError):
            return False, observed
        return (observed["active"] == "active" and observed["pid"] == record["pid"] and observed["invocation"] == record["invocation"]
                and observed["restarts"] == record["restarts"] and identity == record["identity"]), observed

    def rpc(self, action, params, *, write):
        revision = None
        if write:
            _, revision = snapshot(self.host, self.release_dir, self.reviewed["server_id"])
        payload = request(self.reviewed["server_id"], action, params, revision)
        if action == "budget.configure":
            # Persist the idempotency key before submission. A lost reply does
            # not prove that the SQLite transaction was rolled back.
            self.step("budget_request_prepared", request_id=payload["request_id"])
            self.budget_attempted = True
            self.budget_outcome = "unknown"
        reply = self.host.rpc(self.release_dir, payload)
        if action == "budget.configure" and reply.get("ok") is True:
            self.budget_outcome = "applied"
        return reply

    def resolve_budget(self):
        """Read back an ambiguous submission after its bounded child has exited.

        Never retry with a new request id or unbind a possibly committed budget.
        If the read itself fails, retain the guard and report the uncertainty.
        """
        if not self.budget_attempted or self.budget_outcome == "applied":
            return self.budget_outcome
        try:
            data, _ = snapshot(self.host, self.release_dir, self.reviewed["server_id"], timeout=3)
            admin = next(user for user in data["users"] if user["id"] == self.reviewed["administrator"])
            if data["budget"].get("configured") and not admin["unlimited"]:
                self.budget_outcome = "applied"
            elif not data["budget"].get("configured") and admin["unlimited"]:
                self.budget_outcome = "not_applied"
        except (OSError, ValueError, StopIteration, subprocess.SubprocessError, Abort):
            self.budget_outcome = "unknown"
        return self.budget_outcome

    def hold(self):
        self.require(self.host.read(self.layout.control) == LAUNCHER, "Management entry differs from the reviewed launcher")
        self.host.write(self.layout.control, HOLD, mode=0o755)
        self.held = True
        deadline, quiet = self.host.monotonic() + 20, 0
        while quiet < 3:
            quiet = quiet + 1 if not self.host.control_processes() else 0
            self.require(quiet >= 3 or self.host.monotonic() <= deadline, "In-flight management calls did not finish")
            self.host.sleep(0.1)
        self.step("management_held")

    def release(self):
        if self.held and self.host.read(self.layout.control) == HOLD:
            self.host.write(self.layout.control, LAUNCHER, mode=0o755)
        self.held = False

    def unbind(self):
        """Remove the reviewed dependency while the guard still lives; never touch the Core."""
        ok = True
        if self.bound and observe_unit(self.host, self.reviewed["guard"])["active"] != "active":
            return False
        if self.host.read(self.instance) is not None:
            if sha256(self.host.read(self.instance)) != self.reviewed["files"][str(self.instance)]["after_sha256"]:
                return False
            self.host.remove(self.instance)
        ok = self.host.systemctl("daemon-reload", timeout=10) == 0 and ok
        same, observed = self.same_admin()
        ok = ok and same and not observed["binds_to"]
        if ok and self.guard_started:
            self.host.systemctl("stop", self.reviewed["guard"])
        if ok and self.host.read(MARKER) is not None:
            self.host.remove(MARKER)
        self.bound = not ok and self.bound
        return ok

    def run(self):
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, self.interrupt)
        self.host.directory(self.layout.handoff, 0o750, self.host.group(self.layout.project_group))
        if self.host.exists(self.run_dir):
            raise ValueError("This plan was already attempted; review its receipt")
        self.host.directory(self.run_dir, 0o700, 0)
        self.persist()
        try:
            fresh = self.plan_builder(self.host, self.layout, total_bytes=self.reviewed["budget"]["total_bytes"],
                                      safety_margin_bytes=self.reviewed["budget"]["safety_margin_bytes"],
                                      pool_user_ids=[entry["user_id"] for entry in self.reviewed["pool"]],
                                      evidence=self.reviewed["budget"]["evidence"], plan_id=self.plan["plan_id"])
            for volatile in ("revision", "expected_remaining_bytes"):
                fresh["reviewed"][volatile] = self.reviewed[volatile]
            self.require(fresh["reviewed"] == self.reviewed and fresh["ready_for_approval"], "Reviewed facts changed since the approved plan")
            self.step("plan_reverified")
            self.hold()
            self.written = True  # Also clean up an interrupted partial file write.
            for path, spec in self.reviewed["files"].items():
                self.require(self.host.read(path) is None, "A planned path appeared since review")
                self.host.write(path, spec["content"].encode(), mode=int(spec["mode"], 8), gid=0)
            self.step("marker_and_unit_written")
            self.check()
            began = self.host.monotonic()
            self.preparation_started = began
            self.host.operation_deadline = began + CONFIGURE_BY_SECONDS
            self.guard_started = True
            self.host.systemctl("start", self.reviewed["guard"], timeout=15)
            ready, phase = guard_status(self.reviewed["administrator"], observe_unit(self.host, self.reviewed["guard"]))
            self.require(ready and phase == "admin-preparing", "The administrator guard did not prove a trusted running administrator")
            self.step("guard_ready", phase=phase)
            self.check()
            self.bound = True  # Reload may apply even if its caller times out.
            self.require(self.host.systemctl("daemon-reload", timeout=10) == 0, "systemd daemon-reload failed")
            same, observed = self.same_admin()
            self.require(same and observed["binds_to"] == [self.reviewed["guard"]] and observed["fragment"] == str(self.instance)
                         and observed["need_reload"] == "no", "The administrator dependency transfer was not proven")
            self.step("administrator_bound", seconds_since_guard=round(self.host.monotonic() - began, 3))
            self.require(self.host.monotonic() - began < CONFIGURE_BY_SECONDS, "Too little of the preparation window remains")
            budget = self.reviewed["budget"]
            reply = self.rpc("budget.configure", {"total_bytes": budget["total_bytes"], "safety_margin_bytes": budget["safety_margin_bytes"],
                                                  "confirmed": True, "evidence": budget["evidence"]}, write=True)
            self.require(reply.get("ok") is True, "budget.configure was refused: " + str((reply.get("error") or {}).get("code")))
            data, _ = snapshot(self.host, self.release_dir, self.reviewed["server_id"])
            admin = next(user for user in data["users"] if user["id"] == self.reviewed["administrator"])
            self.require(data["budget"]["configured"] and not admin["unlimited"], "The administrator did not become budget-limited")
            self.step("budget_configured", seconds_since_guard=round(self.host.monotonic() - began, 3),
                      remaining_bytes=data["budget"]["admin_remaining_bytes"])
        except Exception as exc:
            if not isinstance(exc, Abort):
                self.journal["unexpected_error"] = f"{type(exc).__name__}: {exc}"
            self.journal["abort_reason"] = str(exc) if isinstance(exc, Abort) else "Unexpected failure"
            if self.preparation_started is not None:
                self.host.operation_deadline = self.preparation_started + RECOVER_BY_SECONDS
            outcome = self.resolve_budget()
            self.journal["budget_outcome"] = outcome
            if outcome in {"not_attempted", "not_applied"}:
                try:
                    undone = (not self.written) or self.unbind()
                except (OSError, ValueError, subprocess.SubprocessError, Abort):
                    undone = False
                self.journal["status"] = "aborted_administrator_unchanged" if undone else "aborted_manual_review_required"
                self.step("reverted" if undone else "revert_incomplete")
            else:
                # Committed or unresolvable state must retain metering. Undoing
                # BindsTo here could leave a configured administrator unguarded.
                self.journal["status"] = ("budget_applied_manual_review_required" if outcome == "applied"
                                          else "budget_outcome_unknown_manual_review_required")
                self.step("guard_retained_budget_requires_review")
            self.release()
            self.host.operation_deadline = None
            self.persist()
            return self.journal
        try:
            self.host.operation_deadline = began + RECOVER_BY_SECONDS
            joined = []
            for entry in self.reviewed["pool"]:
                reply = self.rpc("user.update", {"user_id": entry["user_id"], "quota_pool": "administrator"}, write=True)
                joined.append({"user_id": entry["user_id"], "ok": reply.get("ok") is True,
                               "error": (reply.get("error") or {}).get("code")})
            self.journal["pool"] = joined
            self.step("pool_joined", joined=sum(item["ok"] for item in joined))
            # The budget is proven committed, so the unlimited preparation
            # timeout no longer applies. Still bound subsequent commands.
            self.host.operation_deadline = began + PREPARATION_SECONDS + 15
            # The guard's preparation deadline must pass while the administrator stays bound and running.
            while self.host.monotonic() - began < PREPARATION_SECONDS + 5:
                self.host.sleep(1.0)
            same, observed = self.same_admin()
            guard = observe_unit(self.host, self.reviewed["guard"])
            healthy = same and observed["binds_to"] == [self.reviewed["guard"]] and guard["active"] == "active"
            self.journal["acceptance"] = {"administrator_core_preserved": same, "guard_active_after_window": guard["active"] == "active"}
            self.journal["status"] = ("budget_guard_complete" if healthy and all(item["ok"] for item in joined) else
                                      "budget_guard_complete_pool_review_required" if healthy else "administrator_review_required")
            self.step("accepted")
        except Exception as exc:
            self.journal["unexpected_error"] = type(exc).__name__
            self.journal["budget_outcome"] = "applied"
            self.journal["status"] = "budget_applied_manual_review_required"
            self.step("guard_retained_post_configuration_review")
        finally:
            self.release()
            self.host.operation_deadline = None
            self.persist()
        return self.journal


def main(argv=None):
    parser = argparse.ArgumentParser(description="Target-local exact-approved administrator budget guard")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--total-gb", type=int)
    parser.add_argument("--margin-gb", type=int, default=0)
    parser.add_argument("--pool-user", action="append", default=[])
    parser.add_argument("--evidence")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--approval", type=Path)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0 or platform.system() != "Linux":
            raise ValueError("Target root on Linux is required")
        layout = Layout()
        host = AdminHost(layout)
        if args.preview:
            if args.total_gb is None:
                raise ValueError("The confirmed total budget is required")
            plan = build_admin_plan(host, layout, total_bytes=args.total_gb * GB, safety_margin_bytes=args.margin_gb * GB,
                                    pool_user_ids=[canonical_uuid(value) for value in args.pool_user], evidence=args.evidence)
            result = {"mode": "preview", "production_modified": False, "plan_sha256": sha256(canonical(plan)), "plan": plan}
        else:
            if not args.plan or not args.approval:
                raise ValueError("Apply requires the exact saved plan and a separate approval")
            plan = json.loads(args.plan.read_text())
            if host.current_release().name != plan["reviewed"]["release"]:
                raise ValueError("The current release changed since review")
            result = AdminBudgetExecutor(host, layout, plan, json.loads(args.approval.read_text())).run()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if args.preview or result.get("status") == "budget_guard_complete" else 1
    except Exception as exc:
        message = str(exc) if isinstance(exc, (ValueError, Abort)) and len(str(exc)) < 300 else "Checks failed"
        print(json.dumps({"ok": False, "error": message, "production_note": "No step beyond the recorded receipt was attempted"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
