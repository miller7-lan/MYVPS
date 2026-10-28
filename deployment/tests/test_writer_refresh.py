"""v2 refresh rehearsal using the deterministic existing handoff simulator."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from deployment import writer_refresh as refresh
from deployment.coordinator import HOLD, LAUNCHER
from deployment.expansion import PORTAL_UNIT, expanded_policy, writer_dropin
from deployment.installer import canonical, sha256
from deployment.tests.test_expansion import PhaseBHost, PhaseBWorld, WEB_UID

ROOT = Path(__file__).resolve().parents[1]


class RefreshWorld(PhaseBWorld):
    def __init__(self):
        super().__init__()
        self.live_policy = expanded_policy(self.policy, WEB_UID)
        self.files[str(self.layout.policy)] = canonical(self.live_policy) + b"\n"
        self.files[str(writer_dropin(self.layout))] = (ROOT / "portal-systemd/agent.conf").read_bytes()
        self.units[self.w1]["dropins"] = str(writer_dropin(self.layout))
        self.admin_guard = self.layout.instance(self.layout.guard_template, self.admin)
        self.units[self.admin_guard] = dict(self.unit("admin_guard", 4501),
            status="member-guard-ready; worker=%s; phase=running" % self.admin)
        self.identities[4501] = "4501:16"
        self.units[self.admin_unit]["binds_to"] = [self.admin_guard]
        self.files["/etc/systemd/system/dazzle-admin@.service"] = (ROOT / "systemd/dazzle-admin@.service").read_bytes()
        self.files["/etc/systemd/system/" + PORTAL_UNIT] = (ROOT / "portal-systemd/subscription.service").read_bytes().replace(b"@ORIGIN@", b"https://8.8.8.8:9443")
        self.portal_uid[4600] = WEB_UID
        self.registration_enabled = True
        self.mail_pending = 0
        self.users[self.admin].update(unlimited=0, quota_bytes=500_000_000_000)
        # current can be ahead of the actual lock-holding writer.
        self.current_inventory = {"backend/current_marker.py": "f" * 64}
        self.current = sha256(canonical(self.current_inventory))[:24]
        for key, inventory in ((self.old_release, self.old_inventory), (self.current, self.current_inventory)):
            self.files["/opt/dazzle-vps/releases/" + key + "/release.json"] = canonical({"release_id": key, "files": inventory})
        self.inventory_map = {self.old_release: self.old_inventory, self.current: self.current_inventory, self.new_release: self.new_inventory}

    def facts(self):
        facts = super().facts()
        facts["mail_pending"] = self.mail_pending
        for identifier, worker in self.live_policy["workers"].items():
            if identifier not in self.policy["workers"]:
                facts["workers"].append({"worker_id": identifier, "role": "member", "user_id": None,
                    "public_port": worker["public_port"], "api_port": worker["api_port"], "generation": 0,
                    "root_ack_generation": 0, "observed_generation": 0, "observed_state": "unprovisioned",
                    "process_id": None, "origin_pending": 0, "last_error": None, "tombstoned": 0,
                    "credential_version": 0, "provisioned": 0})
        return facts

    def portal_socket(self):
        return any(unit["pid"] == self.lock_holder and unit["active"] == "active" for name, unit in self.units.items()
                   if name in {self.w1, self.w2})

    def systemctl(self, *arguments, timeout=30):
        if arguments[:2] == ("start", PORTAL_UNIT):
            return super().systemctl("restart", PORTAL_UNIT, timeout=timeout)
        return super().systemctl(*arguments, timeout=timeout)


class RefreshFakeHost(PhaseBHost):
    def writer_release(self, pid):
        for name, value in self.world.units.items():
            if name.startswith("dazzle-vps-writer@") and value["pid"] == pid:
                return name.split("@", 1)[1].removesuffix(".service")
        raise ValueError("No lock-holding writer")

    def release_inventory(self, directory):
        return self.world.inventory_map[Path(directory).name]


def approve(plan):
    return {"version": 1, "operation": refresh.OPERATION, "approved": True, "approval_id": str(uuid.uuid4()),
            "plan_sha256": sha256(canonical(plan)), "acknowledgements": {key: True for key in refresh.ACKNOWLEDGEMENTS}}


class WriterRefreshTests(unittest.TestCase):
    def setUp(self):
        self.world = RefreshWorld()
        self.host = RefreshFakeHost(self.world)

    def plan(self):
        return refresh.build_plan(self.host, self.world.layout, new_release_id=self.world.new_release)

    def run_plan(self, plan=None):
        plan = plan or self.plan()
        return refresh.RefreshCoordinator(self.host, self.world.layout, plan, approve(plan)).run()

    def test_preview_is_readonly_and_resolves_old_writer_from_lock_not_current(self):
        files, calls = dict(self.world.files), list(self.world.calls)
        plan = self.plan()
        self.assertTrue(plan["ready_for_approval"], plan["issues"])
        self.assertEqual(plan["reviewed"]["previous_release_id"], self.world.old_release)
        self.assertNotEqual(plan["reviewed"]["current_release_id"], self.world.old_release)
        self.assertEqual(len(plan["reviewed"]["units"]["workers"]), 2)
        self.assertEqual(len(plan["reviewed"]["dormant"]), 3)
        self.assertEqual(self.world.files, files)
        self.assertEqual(self.world.calls, calls)

    def test_success_preserves_policy_registry_cores_guards_and_registration(self):
        policy, registry = self.world.files[str(self.world.layout.policy)], self.world.files[str(self.world.layout.registry)]
        units = [self.world.admin_unit, self.world.member_unit, self.world.guard, self.world.admin_guard]
        pids = {key: self.world.units[key]["pid"] for key in units}
        result = self.run_plan()
        self.assertEqual(result["status"], "refresh_complete", result)
        self.assertEqual(self.world.current, self.world.new_release)
        self.assertEqual(self.world.files[str(self.world.layout.policy)], policy)
        self.assertEqual(self.world.files[str(self.world.layout.registry)], registry)
        self.assertTrue(self.world.registration_enabled)
        self.assertEqual({key: self.world.units[key]["pid"] for key in units}, pids)
        self.assertEqual(self.world.files[str(self.world.layout.control)], LAUNCHER)
        self.assertEqual(result["portal"], "running")
        self.assertEqual(result["acceptance"]["writer_health"], "passed")
        self.assertEqual(result["acceptance"]["connection_preservation"], "passed")
        self.assertEqual(self.world.connections[4300], [9001, 9002])

    def test_old_writer_still_unwinding_after_releasing_the_lock_does_not_fail_acceptance(self):
        # The live 413da refresh stopped at taken_over_writer_review_required: the
        # new writer owned the lock and persisted samples within 0.3s while the
        # stopped writer's threads were still unwinding.
        world, original = self.world, self.world.systemctl
        def systemctl(*arguments, timeout=30):
            rest = [value for value in arguments[1:] if not value.startswith("--")]
            if arguments[0] == "stop" and rest == [world.w1]:
                world.calls.append(arguments)
                unit = world.units[world.w1]; pid = unit["pid"]
                unit["active"] = "deactivating"; world.persisting.discard(pid)
                def release():
                    if world.lock_holder == pid:
                        world.lock_holder = None
                world.at(world.old_stop_delay, release)
                world.at(5.0, lambda: unit["pid"] == pid and world.exit(world.w1))
                return 0
            return original(*arguments, timeout=timeout)
        world.systemctl = systemctl
        pids = {key: world.units[key]["pid"] for key in (world.admin_unit, world.member_unit, world.guard, world.admin_guard)}
        result = self.run_plan()
        self.assertEqual(result["status"], "refresh_complete", result)
        self.assertEqual(result["acceptance"]["writer_health"], "passed")
        self.assertIn(("kill", "--signal=SIGKILL", "--kill-whom=all", world.w1), world.calls)
        self.assertEqual({key: world.units[key]["pid"] for key in pids}, pids)

    def test_public_portal_is_stopped_before_backup_and_restarted_after_takeover(self):
        observed = []
        original = self.host.migration_check
        def migration(*args):
            observed.append((self.world.units[PORTAL_UNIT]["pid"], self.world.files[str(self.world.layout.control)]))
            return original(*args)
        self.host.migration_check = migration
        self.assertEqual(self.run_plan()["status"], "refresh_complete")
        self.assertEqual(observed, [(0, HOLD)])

    def test_registry_drift_aborts_before_old_writer_stop(self):
        plan = self.plan()
        self.world.files[str(self.world.layout.registry)] += b" "
        result = self.run_plan(plan)
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed")
        self.assertFalse(any(call[:3] == ("stop", "--no-block", self.world.w1) for call in self.world.calls))
        self.assertEqual(self.world.units[self.world.w1]["pid"], 4100)

    def test_guard_failure_blocks_even_for_administrator(self):
        self.world.units[self.world.admin_guard]["status"] = "untrusted"
        plan = self.plan()
        self.assertFalse(plan["ready_for_approval"])
        self.assertIn("GUARD", [value["code"] for value in plan["issues"]])

    def test_stale_admin_preparing_status_with_current_enforced_quota_preserves_guard(self):
        self.world.units[self.world.admin_guard]["status"] = "member-guard-ready; worker=%s; phase=admin-preparing" % self.world.admin
        result = self.run_plan()
        self.assertEqual(result["status"], "refresh_complete", result)
        self.assertEqual(self.world.units[self.world.admin_guard]["pid"], 4501)

    def test_completed_recovery_retains_first_ready_status_without_restarting_any_guard(self):
        for identifier, unit in ((self.world.admin, self.world.admin_guard), (self.world.member, self.world.guard)):
            self.world.units[unit]["status"] = "member-guard-ready; worker=%s; phase=api-only-transition" % identifier
        units = (self.world.admin_unit, self.world.member_unit, self.world.admin_guard, self.world.guard)
        before = {u: self.world.units[u]["pid"] for u in units}
        result = self.run_plan()
        self.assertEqual(result["status"], "refresh_complete", result)
        self.assertEqual({u: self.world.units[u]["pid"] for u in units}, before)
        self.assertEqual(self.world.connections[4300], [9001, 9002])

    def test_recovery_first_ready_status_cannot_hide_an_unsettled_or_untrusted_stream(self):
        cases = (("worker", "origin_pending", 1), ("worker", "root_ack_generation", 999),
                 ("user", "trusted_sample", 0), ("user", "manual_disabled", 1),
                 ("user", "meter_state", "unknown"), ("user", "reasons_json", '["metering_failure"]'))
        for target, key, value in cases:
            with self.subTest(target=target, field=key):
                world = RefreshWorld(); host = RefreshFakeHost(world)
                world.units[world.admin_guard]["status"] = "member-guard-ready; worker=%s; phase=api-only-transition" % world.admin
                original = world.facts
                def facts():
                    result = original()
                    row = next(r for r in result["workers" if target == "worker" else "users"]
                               if r["worker_id" if target == "worker" else "id"] == world.admin)
                    row[key] = value
                    return result
                world.facts = facts
                plan = refresh.build_plan(host, world.layout, new_release_id=world.new_release)
                self.assertFalse(plan["ready_for_approval"], plan["issues"])
                self.assertIn("GUARD", [v["code"] for v in plan["issues"]])

    def test_other_startup_phases_are_not_accepted_as_completed_recovery(self):
        for phase in ("api-only", "activation-transition", "bootstrap-inactive"):
            with self.subTest(phase=phase):
                self.world.units[self.world.admin_guard]["status"] = "member-guard-ready; worker=%s; phase=%s" % (self.world.admin, phase)
                plan = self.plan()
                self.assertFalse(plan["ready_for_approval"])
                self.assertIn("GUARD", [v["code"] for v in plan["issues"]])

    def test_true_unlimited_administrator_preparation_is_not_ready(self):
        self.world.users[self.world.admin].update(unlimited=1, quota_bytes=None)
        self.world.units[self.world.admin_guard]["status"] = "member-guard-ready; worker=%s; phase=admin-preparing" % self.world.admin
        plan = self.plan()
        self.assertFalse(plan["ready_for_approval"])
        self.assertIn("GUARD", [value["code"] for value in plan["issues"]])

    def test_member_cannot_use_administrator_preparing_exception(self):
        self.world.units[self.world.guard]["status"] = "member-guard-ready; worker=%s; phase=admin-preparing" % self.world.member
        plan = self.plan()
        self.assertFalse(plan["ready_for_approval"])
        self.assertIn("GUARD", [value["code"] for value in plan["issues"]])

    def test_untrusted_administrator_stream_blocks(self):
        self.world.users[self.world.admin]["trusted_sample"] = 0
        plan = self.plan()
        self.assertFalse(plan["ready_for_approval"])
        self.assertIn("LEDGER", [value["code"] for value in plan["issues"]])

    def test_slow_measured_fallback_never_reaches_writer_stop(self):
        self.world.standby_offset = 10
        plan = self.plan()
        self.assertFalse(plan["ready_for_approval"])
        with self.assertRaises(ValueError):
            refresh.RefreshCoordinator(self.host, self.world.layout, plan, approve(plan))
        self.assertEqual(self.world.calls, [])

    def test_pending_or_inflight_mail_blocks_preview(self):
        self.world.mail_pending = 1
        plan = self.plan()
        self.assertFalse(plan["ready_for_approval"])
        self.assertIn("MAIL_BUSY", [value["code"] for value in plan["issues"]])

    def test_mail_queued_while_standby_warms_aborts_before_old_writer_stop(self):
        plan = self.plan()
        self.world.at(5.7, lambda: setattr(self.world, "mail_pending", 1))
        result = self.run_plan(plan)
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed", result)
        self.assertEqual(self.world.units[self.world.w1]["pid"], 4100)
        self.assertFalse(any(call[:3] == ("stop", "--no-block", self.world.w1) for call in self.world.calls))

    def test_failed_takeover_restarts_exact_pinned_writer_without_restoring_policy(self):
        self.world.takeover_mode = "fail"
        self.world.old_cold_start = .4
        policy = self.world.files[str(self.world.layout.policy)]
        result = self.run_plan()
        self.assertEqual(result["status"], "fallback_complete", result)
        self.assertEqual(self.world.files[str(self.world.layout.policy)], policy)
        self.assertFalse(result["fallback"]["policy_restored"])
        self.assertTrue(result["fallback"]["within_sample_deadline"])
        self.assertEqual(self.world.units[self.world.member_unit]["pid"], 4300)
        self.assertEqual(result["portal"], "running")

    def test_standby_never_ready_aborts_without_stopping_existing_writer_or_cores(self):
        self.world.standby_warming = True
        result = self.run_plan()
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed", result)
        self.assertEqual(self.world.units[self.world.w1]["pid"], 4100)
        self.assertEqual(self.world.units[self.world.member_unit]["pid"], 4300)
        self.assertEqual(result["portal"], "running")

    def test_additive_migration_failure_aborts_without_stopping_writer(self):
        self.host.migration_check = lambda *args: (_ for _ in ()).throw(ValueError("fixture migration rejected"))
        result = self.run_plan()
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed")
        self.assertEqual(self.world.units[self.world.w1]["pid"], 4100)
        self.assertEqual(result["portal"], "running")

    def test_approval_binds_exact_plan_and_operation(self):
        plan = self.plan(); approval = approve(plan)
        changed = copy.deepcopy(plan); changed["reviewed"]["current_release_id"] = "a" * 24
        with self.assertRaises(ValueError):
            refresh.validate_approval(changed, approval)
        approval["operation"] = "portal_expansion_handoff"
        with self.assertRaises(ValueError):
            refresh.validate_approval(plan, approval)

    def test_cgroup_resolver_accepts_nested_slice_and_rejects_ambiguity(self):
        host = refresh.RefreshHost()
        name = "a" * 24
        with patch.object(Path, "read_text", return_value="0::/system.slice/nested.slice/dazzle-vps-writer@" + name + ".service\n"):
            self.assertEqual(host.writer_release(123), name)
        with patch.object(Path, "read_text", return_value="0::/system.slice/unrelated.service\n"):
            with self.assertRaises(ValueError):
                host.writer_release(123)

    def test_real_readonly_reader_reports_mail_busy_count_without_payloads(self):
        from dazzle.production_state import ProductionStore
        with tempfile.TemporaryDirectory() as folder:
            policy = {**self.world.policy, "agent_uid": max(os.getuid(), 1)}
            with ProductionStore(Path(folder) / "state", policy=policy, initialize=True) as store:
                for index, status in enumerate(("queued", "retry", "sending", "sent")):
                    store.conn.execute("INSERT INTO mail_outbox(id,dedup_key,event_key,recipient,kind,subject,body,status,created_at,next_attempt_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (str(index), str(index), str(index), "private@example.test", "test", "private subject", "private body", status,
                         "2026-10-27T00:00:00Z", "2026-10-27T00:00:00Z"))
                with refresh.RefreshLedgerReader(store.path) as reader:
                    facts = reader.facts()
                self.assertEqual(facts["mail_pending"], 3)
                for private in ("private@example.test", "private subject", "private body"):
                    self.assertNotIn(private, json.dumps(facts))


if __name__ == "__main__":
    unittest.main()
