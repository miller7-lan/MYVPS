"""Administrator budget guard executor against a simulated systemd and RPC. No root."""
import copy
import datetime as dt
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

from deployment import admin_budget
from deployment.admin_budget import MARKER, AdminBudgetExecutor, build_admin_plan
from deployment.coordinator import HOLD, LAUNCHER, Layout
from deployment.helper import CORE_SHA256
from deployment.installer import canonical, sha256

ROOT = Path(__file__).resolve().parents[1]
GB = admin_budget.GB
UTC = dt.timezone.utc


class AdminWorld:
    def __init__(self):
        self.layout = Layout()
        self.time = 100.0
        self.server, self.admin, self.member = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        self.policy = {"version": 2, "server_id": self.server, "server_endpoint": "8.8.8.8", "agent_uid": 991, "portal_uid": 992,
                       "core_sha256": CORE_SHA256, "workers": {self.admin: {"role": "admin", "public_port": 24430, "api_port": 34430},
                                                               self.member: {"role": "member", "public_port": 24431, "api_port": 34431}}}
        self.template = (ROOT / "systemd/dazzle-admin@.service").read_bytes()
        self.files = {"/etc/dazzle-vps/policy.json": canonical(self.policy) + b"\n", "/usr/local/bin/dazzle-vps-control": LAUNCHER,
                      "/etc/systemd/system/dazzle-admin@.service": self.template}
        self.dirs = {"/etc/dazzle-vps", "/etc/dazzle-vps/handoff", "/etc/systemd/system", "/usr/local/bin"}
        self.admin_unit = "dazzle-admin@" + self.admin + ".service"
        self.guard = "dazzle-vps-meter-guard@" + self.admin + ".service"
        self.units = {self.admin_unit: {"active": "active", "sub": "running", "pid": 4200, "invocation": "inv-4200", "restarts": 0,
                                        "fragment": "/etc/systemd/system/dazzle-admin@.service", "binds_to": [], "status": ""},
                      self.guard: {"active": "inactive", "sub": "dead", "pid": 0, "invocation": "", "restarts": 0, "fragment": "",
                                   "binds_to": [], "status": ""}}
        self.calls, self.revision = [], 40
        self.budget = {"configured": False, "used_bytes": 14 * GB, "admin_remaining_bytes": None}
        self.users = {self.admin: {"id": self.admin, "role": "admin", "port": 24430, "unlimited": True, "quota_bytes": None, "topup_bytes": 0,
                                   "used_upload": 5 * GB, "used_download": 7 * GB, "disabled_reasons": [], "meter_state": "trusted",
                                   "trial": None, "quota_pool": None},
                      self.member: {"id": self.member, "role": "member", "port": 24431, "unlimited": False, "quota_bytes": 100 * GB,
                                    "topup_bytes": 0, "used_upload": GB, "used_download": GB, "disabled_reasons": [], "meter_state": "trusted",
                                    "trial": None, "quota_pool": None}}
        self.guard_started_at, self.guard_ready = None, True
        self.configure_error, self.configure_delay = None, 0.5
        self.incidents = []

    def tick(self):
        guard = self.units[self.guard]
        if guard["active"] == "active" and self.users[self.admin]["unlimited"] and self.time - self.guard_started_at >= 60:
            guard.update(active="inactive", sub="dead", pid=0)  # ADMIN_PREPARATION_EXPIRED
        admin = self.units[self.admin_unit]
        if admin["active"] == "active" and any(self.units[name]["active"] != "active" for name in admin["binds_to"]):
            admin.update(active="inactive", sub="dead", pid=0)  # systemd BindsTo= on an inactive unit stops it.

    def advance(self, seconds):
        end = self.time + seconds
        while self.time < end:
            self.time = min(end, self.time + 0.5)
            self.tick()

    def instance_path(self):
        return "/etc/systemd/system/" + self.admin_unit

    def systemctl(self, *arguments):
        self.calls.append(arguments)
        verb, name = arguments[0], (arguments[1] if len(arguments) > 1 else None)
        if verb == "daemon-reload":
            admin = self.units[self.admin_unit]
            source = self.files.get(self.instance_path())
            admin["fragment"] = self.instance_path() if source else "/etc/systemd/system/dazzle-admin@.service"
            admin["binds_to"] = [self.guard] if source and ("BindsTo=" + self.guard).encode() in source else []
        elif verb == "start" and name == self.guard:
            marker, unit = self.files.get(str(MARKER)), self.files.get(self.instance_path())
            ok = (self.guard_ready and marker is not None and unit is not None and self.units[self.admin_unit]["active"] == "active")
            self.guard_started_at = self.time
            self.units[self.guard].update(active="active" if ok else "failed", sub="running" if ok else "failed", pid=7000 if ok else 0,
                                          invocation="inv-guard" if ok else "",
                                          status="member-guard-ready; worker=%s; phase=admin-preparing" % self.admin if ok else "")
            return 0 if ok else 1
        elif verb == "stop" and name == self.guard:
            self.units[self.guard].update(active="inactive", sub="dead", pid=0)
        self.tick()
        return 0

    def show(self, name, properties):
        unit = self.units.get(name, {"active": "inactive", "sub": "dead", "pid": 0, "invocation": "", "restarts": 0, "fragment": "",
                                     "binds_to": [], "status": ""})
        values = {"LoadState": "loaded", "ActiveState": unit["active"], "SubState": unit["sub"], "MainPID": str(unit["pid"]),
                  "NRestarts": str(unit["restarts"]), "InvocationID": unit["invocation"], "FragmentPath": unit["fragment"],
                  "DropInPaths": "", "BindsTo": " ".join(unit["binds_to"]), "After": "", "StatusText": unit["status"],
                  "UnitFileState": "static", "NeedDaemonReload": "no", "ExecMainStartTimestampMonotonic": "0",
                  "ActiveEnterTimestampMonotonic": "0"}
        return {key: values.get(key, "") for key in properties}

    def rpc(self, request):
        action = request["action"]
        if action == "snapshot":
            return {"ok": True, "revision": self.revision,
                    "data": {"budget": dict(self.budget), "users": copy.deepcopy(list(self.users.values())),
                             "server_id": self.server, "metering_incidents": copy.deepcopy(self.incidents),
                             "health": {"controller_mode": "normal"}}}
        if request.get("expected_revision") != self.revision:
            return {"ok": False, "error": {"code": "REVISION_CONFLICT"}}
        if action == "budget.configure":
            self.advance(self.configure_delay)
            if self.configure_error:
                return {"ok": False, "error": {"code": self.configure_error}}
            ready = (self.files.get(str(MARKER)) and self.units[self.admin_unit]["binds_to"] == [self.guard]
                     and self.units[self.guard]["active"] == "active")
            if not ready:
                return {"ok": False, "error": {"code": "ADMIN_GUARD_REQUIRED"}}
            self.budget.update(configured=True, admin_remaining_bytes=500 * GB - 14 * GB - 98 * GB)
            self.users[self.admin]["unlimited"] = False
        elif action == "user.update":
            self.users[request["params"]["user_id"]]["quota_pool"] = request["params"]["quota_pool"]
        self.revision += 1
        return {"ok": True, "revision": self.revision, "data": {}}


class FakeAdminHost:
    def __init__(self, world):
        self.world, self.layout = world, world.layout
        self.operation_deadline = None
        self.rpc_timeouts = []
        self.snapshot_delay = 0
        self.lose_configure_reply = False
        self.fail_snapshot_after_configure = False
        self.raw_admin = {"trusted_sample": 1, "epoch_sha256": "a" * 64, "manual_disabled": 0,
                          "revoked_at": None, "deleted_at": None, "reasons_json": "[]"}
        self.raw_worker = {"worker_id": world.admin, "user_id": world.admin, "role": "admin", "process_id": 4200,
                           "observed_state": "running", "generation": 3, "root_ack_generation": 3, "observed_generation": 3,
                           "origin_pending": 0, "tombstoned": 0, "last_error": None, "credential_version": 1}

    command_timeout = admin_budget.AdminHost.command_timeout

    def ledger(self):
        host = self
        class ReadOnlyFacts:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def facts(self):
                user = {**host.world.users[host.world.admin], "credential_version": 1,
                        "last_sample_at": host.wall().isoformat(), **host.raw_admin}
                return {"meta": {"server_id": host.world.server, "mode": "production"},
                        "users": [user], "workers": [copy.deepcopy(host.raw_worker)],
                        "incidents_total": len(host.world.incidents)}
        return ReadOnlyFacts()

    def read(self, path): return self.world.files.get(str(path))

    def read_trusted(self, path): return self.world.files[str(path)]

    def write(self, path, payload, *, mode, gid=None):
        if str(Path(path).parent) not in self.world.dirs:
            raise ValueError("parent missing")
        self.world.files[str(path)] = bytes(payload)

    def remove(self, path): del self.world.files[str(path)]
    def exists(self, path): return str(path) in self.world.files or str(path) in self.world.dirs
    def directory(self, path, mode, gid): self.world.dirs.add(str(path))
    def group(self, name): return 1234
    def require_replaceable(self, path): pass
    def control_processes(self): return []
    def systemctl(self, *arguments, timeout=30):
        self.command_timeout(timeout)
        return self.world.systemctl(*arguments)
    def show(self, unit, properties=()):
        self.command_timeout(10)
        return self.world.show(unit, properties)

    def identity(self, pid):
        if not any(unit["pid"] == pid for unit in self.world.units.values()) or not pid:
            raise ValueError("no such process")
        return str(pid) + ":1"

    def current_release(self): return Path("/opt/dazzle-vps/releases/" + "b" * 24)
    def boot_id(self): return "11111111-2222-3333-4444-555555555555"
    def rpc(self, release_dir, request, *, timeout=60):
        timeout = self.command_timeout(timeout)
        action = request["action"]
        self.rpc_timeouts.append((action, timeout))
        if action == "snapshot":
            if self.fail_snapshot_after_configure and self.world.budget["configured"]:
                raise subprocess.TimeoutExpired(["fixture-snapshot"], timeout)
            if self.snapshot_delay >= timeout:
                self.world.advance(timeout)
                raise subprocess.TimeoutExpired(["fixture-snapshot"], timeout)
            self.world.advance(self.snapshot_delay)
        if action == "budget.configure":
            delay = self.world.configure_delay
            if delay >= timeout:
                self.world.advance(timeout)
                raise subprocess.TimeoutExpired(["fixture-configure"], timeout)
            result = self.world.rpc(request)
            if self.lose_configure_reply:
                self.world.advance(timeout - delay)
                raise subprocess.TimeoutExpired(["fixture-configure-reply"], timeout)
            return result
        return self.world.rpc(request)
    def monotonic(self): return self.world.time
    def wall(self): return dt.datetime(2026, 10, 27, tzinfo=UTC) + dt.timedelta(seconds=self.world.time)
    def sleep(self, seconds): self.world.advance(seconds)


def approval(plan, **overrides):
    value = {"version": 1, "operation": admin_budget.OPERATION, "approved": True, "approval_id": str(uuid.uuid4()),
             "plan_sha256": sha256(canonical(plan)),
             "acknowledgements": {name: True for name in admin_budget.ACKNOWLEDGEMENTS}}
    value.update(overrides)
    return value


class AdminBudgetTests(unittest.TestCase):
    def setUp(self):
        self.world = AdminWorld()
        self.host = FakeAdminHost(self.world)

    def plan(self):
        return build_admin_plan(self.host, self.world.layout, total_bytes=500 * GB, safety_margin_bytes=0,
                                pool_user_ids=[self.world.member], evidence="User-confirmed 500 GB local plan budget; no margin")

    def test_preview_binds_exact_unit_marker_process_budget_and_pool(self):
        plan = self.plan()
        self.assertTrue(plan["ready_for_approval"], plan["issues"])
        reviewed = plan["reviewed"]
        unit = reviewed["files"][self.world.instance_path()]["content"]
        self.assertIn("BindsTo=" + self.world.guard, unit)
        self.assertEqual(unit.split("[Service]", 1)[1], self.world.template.decode().split("[Service]", 1)[1])
        marker = reviewed["files"][str(MARKER)]["content"]
        self.assertIn(sha256(unit.encode()), marker)
        self.assertEqual(reviewed["process"]["pid"], 4200)
        self.assertEqual(reviewed["pool"], [{"user_id": self.world.member, "port": 24431, "quota_bytes": 100 * GB}])
        self.assertEqual(reviewed["expected_remaining_bytes"], 486 * GB)

    def test_preview_checks_the_real_budget_configuration_before_pool_membership(self):
        def plan(total):
            return build_admin_plan(self.host, self.world.layout, total_bytes=total * GB, safety_margin_bytes=0,
                                    pool_user_ids=[self.world.member], evidence="Isolated intermediate-state review")
        exhausted = plan(112)  # 14 GB spent + the member's 98 GB remaining reservation.
        self.assertFalse(exhausted["ready_for_approval"])
        self.assertEqual(exhausted["measurements"]["before_pool_remaining_bytes"], 0)
        self.assertEqual(exhausted["reviewed"]["expected_remaining_bytes"], 98 * GB)
        self.assertIn("BUDGET_TRANSITION_HEADROOM", {item["code"] for item in exhausted["issues"]})
        boundary = plan(113)
        self.assertTrue(boundary["ready_for_approval"], boundary)
        self.assertEqual(boundary["measurements"]["before_pool_remaining_bytes"], GB)
        self.assertEqual(boundary["reviewed"]["budget"]["safety_margin_bytes"], 0)
        self.world.budget["used_bytes"] += 1
        self.assertFalse(plan(113)["ready_for_approval"])  # One byte below the conservative transition minimum.

    def test_intermediate_reservation_excludes_existing_pool_users(self):
        self.world.users[self.world.member]["quota_pool"] = "administrator"
        plan = build_admin_plan(self.host, self.world.layout, total_bytes=15 * GB, safety_margin_bytes=0,
                                pool_user_ids=[], evidence="Isolated existing-pool review")
        self.assertTrue(plan["ready_for_approval"], plan)
        self.assertEqual(plan["measurements"]["before_pool_reserved_bytes"], 0)
        self.assertEqual(plan["measurements"]["before_pool_remaining_bytes"], GB)

    def test_hidden_unlimited_admin_restrictions_are_rejected_from_raw_ledger(self):
        # Public disabled_reasons remains [], as it does for an unlimited
        # administrator, even though the raw restriction would stop its guard.
        self.host.raw_admin["reasons_json"] = '["metering_failure"]'
        plan = self.plan()
        self.assertFalse(plan["ready_for_approval"])
        self.assertIn("ADMIN_RAW_METER", {item["code"] for item in plan["issues"]})
        self.assertEqual(self.world.users[self.world.admin]["disabled_reasons"], [])

    def test_raw_trust_epoch_freshness_and_same_core_are_all_required(self):
        valid = copy.deepcopy(self.host.raw_admin)
        valid_worker = copy.deepcopy(self.host.raw_worker)
        cases = [
            ({"trusted_sample": 0}, {}),
            ({"epoch_sha256": None}, {}),
            ({"last_sample_at": (self.host.wall() - dt.timedelta(seconds=5.01)).isoformat()}, {}),
            ({"last_sample_at": (self.host.wall() + dt.timedelta(seconds=.01)).isoformat()}, {}),
            ({}, {"process_id": 4201}),
            ({}, {"observed_generation": 2}),
            ({}, {"origin_pending": 1}),
        ]
        for user, worker in cases:
            with self.subTest(user=user, worker=worker):
                self.host.raw_admin = {**valid, **user}
                self.host.raw_worker = {**valid_worker, **worker}
                plan = self.plan()
                self.assertFalse(plan["ready_for_approval"], plan)
                self.assertIn("ADMIN_RAW_METER", {item["code"] for item in plan["issues"]})
        self.host.raw_admin = valid
        self.host.raw_worker = valid_worker
        self.assertTrue(self.plan()["ready_for_approval"])

    def test_historical_incidents_are_reported_and_preserved_without_immediate_restrictions(self):
        self.world.incidents = [{"id": str(uuid.uuid4()), "user_id": self.world.admin, "resolved_at": None,
                                 "unknown_delta": 1} for _ in range(19)]
        original = copy.deepcopy(self.world.incidents)
        plan = self.plan()
        self.assertTrue(plan["ready_for_approval"], plan)
        measured = plan["measurements"]["administrator"]
        self.assertEqual(measured["open_historical_incidents"], 19)
        self.assertEqual(measured["unknown_historical_incidents"], 19)
        self.assertTrue(measured["unknown_history_is_not_zero"])
        self.assertTrue(measured["raw_meter_verified"])
        self.assertEqual(self.world.incidents, original)

    def test_core_changing_during_ledger_read_is_not_an_approvable_preview(self):
        original = self.host.ledger
        def changed():
            reader = original()
            facts = reader.facts
            def facts_then_change():
                result = facts()
                self.world.units[self.world.admin_unit]["pid"] = 4201
                return result
            reader.facts = facts_then_change
            return reader
        self.host.ledger = changed
        plan = self.plan()
        self.assertFalse(plan["ready_for_approval"])
        self.assertIn("ADMIN_PROCESS_CHANGED", {item["code"] for item in plan["issues"]})

    def test_success_binds_without_restart_configures_budget_then_joins_pool(self):
        plan = self.plan()
        receipt = AdminBudgetExecutor(self.host, self.world.layout, plan, approval(plan)).run()
        self.assertEqual(receipt["status"], "budget_guard_complete", receipt)
        admin = self.world.units[self.world.admin_unit]
        self.assertEqual((admin["active"], admin["pid"], admin["binds_to"]), ("active", 4200, [self.world.guard]))
        self.assertTrue(self.world.budget["configured"])
        self.assertEqual(self.world.users[self.world.member]["quota_pool"], "administrator")
        self.assertEqual(self.world.files["/usr/local/bin/dazzle-vps-control"], LAUNCHER)
        order = [call[0] for call in self.world.calls if call[0] in {"start", "daemon-reload"}]
        self.assertEqual(order[:2], ["start", "daemon-reload"])  # The guard lives before the Core is bound to it.
        self.assertGreaterEqual(self.world.time - self.world.guard_started_at, 60)
        self.assertEqual(self.world.units[self.world.guard]["active"], "active")

    def test_guard_that_cannot_prove_the_administrator_leaves_everything_unbound(self):
        self.world.guard_ready = False
        plan = self.plan()
        receipt = AdminBudgetExecutor(self.host, self.world.layout, plan, approval(plan)).run()
        self.assertEqual(receipt["status"], "aborted_administrator_unchanged", receipt)
        self.assertNotIn(self.world.instance_path(), self.world.files)
        self.assertNotIn(str(MARKER), self.world.files)
        admin = self.world.units[self.world.admin_unit]
        self.assertEqual((admin["active"], admin["pid"], admin["binds_to"]), ("active", 4200, []))
        self.assertFalse(self.world.budget["configured"])
        self.assertEqual(self.world.files["/usr/local/bin/dazzle-vps-control"], LAUNCHER)

    def test_refused_budget_unbinds_while_the_guard_still_lives(self):
        self.world.configure_error = "BUDGET_EXCEEDED"
        plan = self.plan()
        receipt = AdminBudgetExecutor(self.host, self.world.layout, plan, approval(plan)).run()
        self.assertEqual(receipt["status"], "aborted_administrator_unchanged", receipt)
        admin = self.world.units[self.world.admin_unit]
        self.assertEqual((admin["active"], admin["pid"], admin["binds_to"]), ("active", 4200, []))
        self.assertEqual(self.world.units[self.world.guard]["active"], "inactive")
        self.assertNotIn(str(MARKER), self.world.files)
        self.assertFalse(self.world.budget["configured"])
        stop = next(index for index, call in enumerate(self.world.calls) if call[0] == "stop")
        reloads = [index for index, call in enumerate(self.world.calls) if call[0] == "daemon-reload"]
        self.assertLess(reloads[-1], stop)  # Dependency removed before the guard stops.

    def test_slow_configuration_is_abandoned_before_the_preparation_window_closes(self):
        self.world.configure_delay = 0.5
        plan = self.plan()
        executor = AdminBudgetExecutor(self.host, self.world.layout, plan, approval(plan))
        original = self.host.systemctl
        delayed = False
        def slow_reload(*arguments, timeout=30):
            nonlocal delayed
            if arguments[0] == "daemon-reload" and self.world.units[self.world.guard]["active"] == "active" and not delayed:
                delayed = True
                self.world.advance(admin_budget.CONFIGURE_BY_SECONDS)
            return original(*arguments, timeout=timeout)
        self.host.systemctl = slow_reload
        receipt = executor.run()
        self.assertEqual(receipt["status"], "aborted_administrator_unchanged", receipt)
        self.assertEqual(self.world.units[self.world.admin_unit]["pid"], 4200)
        self.assertFalse(self.world.budget["configured"])

    def test_slow_budget_rpc_is_cut_off_by_absolute_deadline_and_unbinds_live_guard(self):
        plan = self.plan()
        self.world.configure_delay = 45  # Below the previous per-RPC 60 second timeout.
        executor = AdminBudgetExecutor(self.host, self.world.layout, plan, approval(plan))
        original = self.host.systemctl
        delayed = False
        def reload_delay(*arguments, timeout=30):
            nonlocal delayed
            if arguments[0] == "daemon-reload" and not delayed:
                delayed = True
                self.world.advance(20)  # Still inside the preparation budget.
            return original(*arguments, timeout=timeout)
        self.host.systemctl = reload_delay
        receipt = executor.run()
        self.assertEqual(receipt["status"], "aborted_administrator_unchanged", receipt)
        self.assertEqual(receipt["budget_outcome"], "not_applied")
        self.assertEqual(self.world.units[self.world.admin_unit]["pid"], 4200)
        self.assertEqual(self.world.units[self.world.admin_unit]["binds_to"], [])
        configure_timeout = next(value for action, value in self.host.rpc_timeouts if action == "budget.configure")
        self.assertLessEqual(configure_timeout, 15)
        self.assertLess(self.world.time - self.world.guard_started_at, 60)

    def test_slow_preconfiguration_snapshot_cannot_run_out_the_guard_window(self):
        plan = self.plan()
        executor = AdminBudgetExecutor(self.host, self.world.layout, plan, approval(plan))
        original = executor.hold
        def hold_then_slow_snapshot():
            original()
            self.host.snapshot_delay = 45
        executor.hold = hold_then_slow_snapshot
        receipt = executor.run()
        self.assertEqual(receipt["status"], "aborted_administrator_unchanged", receipt)
        self.assertEqual(receipt["budget_outcome"], "not_attempted")
        self.assertEqual(self.world.units[self.world.admin_unit]["pid"], 4200)
        self.assertFalse(self.world.budget["configured"])
        self.assertLess(self.world.time - self.world.guard_started_at, 60)

    def test_committed_budget_with_lost_reply_is_detected_and_never_unbound(self):
        plan = self.plan()
        self.host.lose_configure_reply = True
        receipt = AdminBudgetExecutor(self.host, self.world.layout, plan, approval(plan)).run()
        self.assertEqual(receipt["status"], "budget_applied_manual_review_required", receipt)
        self.assertEqual(receipt["budget_outcome"], "applied")
        self.assertTrue(self.world.budget["configured"])
        self.assertEqual(self.world.units[self.world.admin_unit]["pid"], 4200)
        self.assertEqual(self.world.units[self.world.admin_unit]["binds_to"], [self.world.guard])
        self.assertEqual(self.world.units[self.world.guard]["active"], "active")
        self.assertFalse(any(call[0] == "stop" for call in self.world.calls))
        self.assertTrue(any(step["step"] == "budget_request_prepared" and step.get("request_id") for step in receipt["steps"]))

    def test_unresolvable_budget_submission_keeps_guard_and_reports_unknown(self):
        plan = self.plan()
        self.host.lose_configure_reply = True
        self.host.fail_snapshot_after_configure = True
        receipt = AdminBudgetExecutor(self.host, self.world.layout, plan, approval(plan)).run()
        self.assertEqual(receipt["status"], "budget_outcome_unknown_manual_review_required", receipt)
        self.assertEqual(receipt["budget_outcome"], "unknown")
        self.assertEqual(self.world.units[self.world.admin_unit]["pid"], 4200)
        self.assertEqual(self.world.units[self.world.guard]["active"], "active")
        self.assertFalse(any(call[0] == "stop" for call in self.world.calls))

    def test_real_host_bounds_rpc_and_inherited_systemctl_to_the_same_deadline(self):
        captured = []
        class RecordingRunner:
            def run(self, arguments, *, input=None, timeout=30):
                captured.append((arguments, timeout))
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        host = admin_budget.AdminHost(runner=RecordingRunner())
        host.monotonic = lambda: 100.0
        host.operation_deadline = 102.5
        self.assertEqual(host.systemctl("daemon-reload", timeout=60), 0)
        self.assertEqual(captured[-1][1], 2.5)
        # Host.show goes through this runner as well, rather than getting a
        # fresh unbounded ten-second allowance on every status observation.
        host.runner.run(["/usr/bin/systemctl", "show", self.world.guard], timeout=10)
        self.assertEqual(captured[-1][1], 2.5)
        with patch("deployment.admin_budget.subprocess.run", return_value=SimpleNamespace(stdout=b'{"ok":true}')) as child:
            self.assertTrue(host.rpc(Path("/isolated"), {"action": "snapshot"}, timeout=60)["ok"])
            self.assertEqual(child.call_args.kwargs["timeout"], 2.5)
        host.operation_deadline = 100.0
        with self.assertRaises(admin_budget.Abort):
            host.rpc(Path("/isolated"), {"action": "snapshot"})

    def test_postcommit_snapshot_failure_does_not_remove_a_confirmed_guard(self):
        plan = self.plan()
        self.host.fail_snapshot_after_configure = True
        receipt = AdminBudgetExecutor(self.host, self.world.layout, plan, approval(plan)).run()
        self.assertEqual(receipt["status"], "budget_applied_manual_review_required", receipt)
        self.assertEqual(receipt["budget_outcome"], "applied")
        self.assertEqual(self.world.units[self.world.admin_unit]["binds_to"], [self.world.guard])
        self.assertEqual(self.world.units[self.world.admin_unit]["pid"], 4200)
        self.assertFalse(any(call[0] == "stop" for call in self.world.calls))

    def test_previously_bound_or_configured_baselines_and_bad_numbers_are_refused(self):
        with self.assertRaises(ValueError):
            build_admin_plan(self.host, self.world.layout, total_bytes=500 * GB + 1, safety_margin_bytes=0, pool_user_ids=[], evidence="x")
        self.world.files[str(MARKER)] = b"{}"
        with self.assertRaises(ValueError):
            self.plan()
        del self.world.files[str(MARKER)]
        self.world.budget["configured"] = True
        with self.assertRaises(ValueError):
            self.plan()
        self.world.budget["configured"] = False
        self.world.users[self.world.member]["topup_bytes"] = GB
        with self.assertRaises(ValueError):
            self.plan()

    def test_approval_must_bind_the_exact_plan_and_every_acknowledgement(self):
        plan = self.plan()
        for bad in (approval(plan, plan_sha256="0" * 64), approval(plan, acknowledgements={}), approval(plan, operation="other")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                AdminBudgetExecutor(self.host, self.world.layout, plan, bad)

    def test_changed_administrator_process_before_apply_aborts_without_writing(self):
        plan = self.plan()
        self.world.units[self.world.admin_unit].update(pid=4201, invocation="inv-4201")
        receipt = AdminBudgetExecutor(self.host, self.world.layout, plan, approval(plan)).run()
        self.assertEqual(receipt["status"], "aborted_administrator_unchanged")
        self.assertNotIn(str(MARKER), self.world.files)
        self.assertNotIn(self.world.instance_path(), self.world.files)


if __name__ == "__main__":
    unittest.main()
