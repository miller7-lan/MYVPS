"""Phase B portal handoff against the deterministic simulated host. No systemctl, no root."""
import json
from pathlib import Path
import unittest
import uuid

from deployment import expansion
from deployment.coordinator import HOLD, LAUNCHER
from deployment.expansion import (PORTAL_TLS, PORTAL_UNIT, TMPFILES, ExpansionCoordinator, build_expansion_plan, certsync_dropin,
                                  policy_snapshot, writer_dropin)
from deployment.installer import canonical, sha256
from deployment.portal_upgrade import expanded_policy
from deployment.tests.test_coordinator import FakeHost, World

ROOT = Path(__file__).resolve().parents[1]
WEB_UID, AGENT_UID = 992, 991
TEMPLATES = ("subscription.service", "agent.conf", "certsync.conf", "tmpfiles.conf", "writer@.service", "meter-guard@.service",
             "guarded-member.service")


class PhaseBWorld(World):
    """After Phase A: writer@A writes, the member is bound to its live guard, 9443 serves subscriptions."""
    def __init__(self):
        super().__init__()
        self.old_inventory = {"backend/dazzle/production.py": "a" * 64, "deployment/portal-systemd/writer@.service": "b" * 64}
        self.old_release = sha256(canonical(self.old_inventory))[:24]
        templates = {name: (ROOT / "portal-systemd" / name).read_bytes() for name in TEMPLATES}
        self.new_inventory = {"deployment/portal-systemd/" + name: sha256(body) for name, body in templates.items()}
        self.new_release = sha256(canonical(self.new_inventory))[:24]
        new_dir = "/opt/dazzle-vps/releases/" + self.new_release
        for name, body in templates.items():
            self.files[new_dir + "/deployment/portal-systemd/" + name] = body
        self.files[new_dir + "/release.json"] = json.dumps({"release_id": self.new_release, "files": self.new_inventory}).encode()
        self.current = self.old_release
        old_writer = self.units.pop(self.w1)
        self.w1 = "dazzle-vps-writer@" + self.old_release + ".service"
        self.w2 = "dazzle-vps-writer@" + self.new_release + ".service"
        old_writer.update(fragment="/etc/systemd/system/dazzle-vps-writer@.service", exec_start_us=5_000_000, active_enter_us=7_900_000)
        self.units[self.w1] = old_writer
        self.files["/etc/systemd/system/dazzle-vps-writer@.service"] = templates["writer@.service"]
        member_file = "/etc/systemd/system/" + self.member_unit
        self.files[member_file] = templates["guarded-member.service"].replace(b"%i", self.member.encode())
        self.units[self.member_unit].update(fragment=member_file, binds_to=[self.guard], after=["network-online.target", self.guard])
        self.units[self.guard] = dict(self.unit("guard", 4500), status="member-guard-ready; worker=%s; phase=running" % self.member)
        self.identities[4500] = "4500:14"
        self.subscription_unit = (ROOT / "systemd/dazzle-vps-subscription.service").read_bytes()
        self.files["/etc/systemd/system/" + PORTAL_UNIT] = self.subscription_unit
        self.units[PORTAL_UNIT] = dict(self.unit("portal", 4600), fragment="/etc/systemd/system/" + PORTAL_UNIT, file_state="enabled")
        self.identities[4600] = "4600:15"
        self.portal_uid = {4600: AGENT_UID}
        self.dirs.update({"/etc/dazzle-vps/handoff", "/etc/tmpfiles.d", "/etc/systemd/system/dazzle-vps-certsync.service.d"})
        self.accounts = {"dazzle-agent": {"uid": AGENT_UID, "gid": AGENT_UID, "shell": "/usr/sbin/nologin", "home": "/nonexistent", "groups": []},
                         "dazzle-web": {"uid": WEB_UID, "gid": WEB_UID, "shell": "/usr/sbin/nologin", "home": "/nonexistent", "groups": []}}
        self.standby_offset, self.portal_starts, self.tmpfiles_runs = 0.282, True, []
        self.conflicting_ports = set()
        self.registration_enabled, self.registration_state_source = False, "settings"
        self.install_certsync("success")

    def facts(self):
        return {**super().facts(), "registration_enabled": self.registration_enabled,
                "registration_state_source": self.registration_state_source}

    def reload(self):
        self.reloads += 1
        self.hooks.pop(self.reloads, lambda: None)()
        member_file = "/etc/systemd/system/" + self.member_unit
        lines = self.files[member_file].decode().splitlines()
        self.units[self.member_unit]["binds_to"] = next(line for line in lines if line.startswith("BindsTo=")).split("=", 1)[1].split()

    def portal_socket(self):
        writer = self.units.get(self.w2, {})
        policy = json.loads(self.files["/etc/dazzle-vps/policy.json"])
        return writer.get("active") == "active" and self.lock_holder == writer.get("pid") and policy["version"] == 2

    def systemctl(self, *arguments, timeout=30):
        verb = arguments[0]
        name = next((value for value in arguments[1:] if not value.startswith("--")), None)
        if verb == "restart" and name == PORTAL_UNIT:
            self.calls.append(arguments)
            body = self.files["/etc/systemd/system/" + PORTAL_UNIT]
            unit = self.units[PORTAL_UNIT]
            self.portal_uid.pop(unit["pid"], None)
            portal = b"User=dazzle-web\n" in body
            if portal and not self.portal_starts:
                unit.update(active="failed", sub="failed", pid=0)
                return 1
            pid = self.pid()
            unit.update(active="active", sub="running", pid=pid, invocation="inv-" + str(pid))
            self.portal_uid[pid] = WEB_UID if portal else AGENT_UID
            return 0
        if verb == "start" and name == "dazzle-vps-certsync.service":
            result = super().systemctl(*arguments, timeout=timeout)
            policy = json.loads(self.files["/etc/dazzle-vps/policy.json"])
            if self.certsync_outcome == "success" and policy["version"] == 2 and PORTAL_TLS in self.dirs:
                self.files[PORTAL_TLS + "/cert.pem"] = self.files[PORTAL_TLS + "/key.pem"] = b"pem"
            return result
        return super().systemctl(*arguments, timeout=timeout)


class PhaseBHost(FakeHost):
    def port_is_bound(self, port, protocol):
        return (port, protocol) in self.world.conflicting_ports

    def account(self, name):
        value = self.world.accounts.get(name)
        return dict(value) if value else None

    def group(self, name):
        return self.world.accounts[name]["gid"] if name in self.world.accounts else 1234

    def standby_ready_offset(self, unit, pid, exec_start_us):
        return self.world.standby_offset

    def tmpfiles(self, path):
        self.world.tmpfiles_runs.append(str(path))
        self.world.dirs.add(str(expansion.PORTAL_RUNTIME))
        return str(path) in self.world.files

    def directory_info(self, path):
        return {"mode": "0750", "uid": 0, "gid": WEB_UID, "directory": True} if str(path) in self.world.dirs else None

    def directory(self, path, mode, gid):
        if str(Path(path).parent) not in self.world.dirs:
            self.world.dirs.add(str(Path(path).parent))  # /etc/systemd/system and /etc/dazzle-vps exist on the target.
        self.world.dirs.add(str(path))

    def listeners(self, port):
        unit = self.world.units[PORTAL_UNIT]
        return [(unit["pid"], self.world.portal_uid[unit["pid"]])] if unit["active"] == "active" and unit["pid"] else []

    def https_status(self, port, path):
        unit = self.world.units[PORTAL_UNIT]
        if unit["active"] != "active":
            return None
        portal = b"User=dazzle-web\n" in self.world.files["/etc/systemd/system/" + PORTAL_UNIT]
        if path == "/portal/":
            return 200 if portal else 404
        return 404 if (not portal or self.world.portal_socket()) else 503


def approve(plan):
    return {"version": 1, "operation": expansion.OPERATION, "approved": True, "approval_id": str(uuid.uuid4()),
            "plan_sha256": sha256(canonical(plan)), "acknowledgements": {name: True for name in expansion.ACKNOWLEDGEMENTS}}


class ExpansionTests(unittest.TestCase):
    def setUp(self):
        self.world = PhaseBWorld()
        self.host = PhaseBHost(self.world)
        self.v1 = self.world.files["/etc/dazzle-vps/policy.json"]

    def plan(self, **kwargs):
        return build_expansion_plan(self.host, self.world.layout, new_release_id=self.world.new_release, **kwargs)

    def test_public_or_statistics_port_conflict_blocks_before_handoff(self):
        for port, protocol in ((24432, "tcp"), (24433, "udp"), (34434, "tcp")):
            with self.subTest(port=port, protocol=protocol):
                self.world.conflicting_ports = {(port, protocol)}
                plan = self.plan()
                self.assertFalse(plan["ready_for_approval"])
                self.assertIn("PORT_CONFLICT", {issue["code"] for issue in plan["issues"]})
                self.assertEqual(self.world.calls, [])

    def test_new_listener_after_approval_aborts_without_stopping_writer(self):
        plan = self.plan()
        self.assertTrue(plan["ready_for_approval"])
        self.world.conflicting_ports.add((24432, "udp"))
        result = ExpansionCoordinator(self.host, self.world.layout, plan, approve(plan)).run()
        self.assertTrue(result["status"].startswith("aborted"), result)
        self.assertNotIn(("stop", self.world.w1), self.world.calls)

    def run_plan(self):
        plan = self.plan()
        self.assertTrue(plan["ready_for_approval"], plan["issues"])
        return plan, ExpansionCoordinator(self.host, self.world.layout, plan, approve(plan)).run()

    def test_preview_plans_exact_files_three_seats_and_a_measured_standby_fallback(self):
        plan = self.plan()
        self.assertTrue(plan["ready_for_approval"], plan["issues"])
        files = plan["reviewed"]["files"]
        self.assertEqual({path: spec["phase"] for path, spec in files.items()}, {
            str(policy_snapshot(self.world.layout)): "prepare", str(TMPFILES): "prepare", str(writer_dropin(self.world.layout)): "prepare",
            str(certsync_dropin(self.world.layout)): "prepare", "/etc/dazzle-vps/policy.json": "policy",
            "/etc/systemd/system/" + PORTAL_UNIT: "portal"})
        expanded = json.loads(files["/etc/dazzle-vps/policy.json"]["content"])
        self.assertEqual(expanded, expanded_policy(json.loads(self.v1), WEB_UID))
        self.assertEqual(sorted(worker["public_port"] for worker in expanded["workers"].values()), [24430, 24431, 24432, 24433, 24434])
        self.assertIn("User=dazzle-web", files["/etc/systemd/system/" + PORTAL_UNIT]["content"])
        self.assertIn("--origin https://8.8.8.8:9443", files["/etc/systemd/system/" + PORTAL_UNIT]["content"])
        measured = plan["measurements"]
        self.assertEqual(measured["old_writer_start_to_ready_seconds"], 0.782)
        self.assertEqual(measured["fallback_reserve_seconds"], round(0.6 + 0.782 + 2 * 0.25 + 0.7, 3))

    def test_success_hands_over_without_core_or_guard_change_and_starts_the_portal(self):
        plan, receipt = self.run_plan()
        self.assertEqual(receipt["status"], "handoff_complete", receipt)
        self.assertEqual(receipt["portal"], "portal_running")
        self.assertEqual(self.world.current, self.world.new_release)
        self.assertEqual(self.world.files["/etc/dazzle-vps/policy.json"], canonical(expanded_policy(json.loads(self.v1), WEB_UID)) + b"\n")
        self.assertEqual((self.world.units[self.world.member_unit]["pid"], self.world.units[self.world.admin_unit]["pid"]), (4300, 4200))
        self.assertEqual(self.world.units[self.world.guard]["pid"], 4500)
        self.assertEqual(self.world.lock_holder, self.world.units[self.world.w2]["pid"])
        self.assertEqual((self.world.units[self.world.w1]["file_state"], self.world.units[self.world.w2]["file_state"]), ("disabled", "enabled"))
        self.assertEqual(self.world.files["/usr/local/bin/dazzle-vps-control"], LAUNCHER)
        self.assertIn(str(TMPFILES), self.world.tmpfiles_runs)
        self.assertTrue(self.world.files[PORTAL_TLS + "/cert.pem"])
        portal = self.world.units[PORTAL_UNIT]
        self.assertEqual(self.world.portal_uid[portal["pid"]], WEB_UID)
        self.assertNotIn("fallback", receipt)

    def test_failed_takeover_restores_v1_and_the_pinned_writer_and_keeps_guards(self):
        self.world.takeover_mode = "fail"
        self.world.old_cold_start = 0.6
        plan, receipt = self.run_plan()
        self.assertEqual(receipt["status"], "fallback_complete_members_preserved", receipt)
        self.assertTrue(receipt["fallback"]["v1_policy_restored"])
        self.assertTrue(receipt["fallback"]["within_sample_deadline"])
        self.assertEqual(self.world.files["/etc/dazzle-vps/policy.json"], self.v1)
        self.assertEqual(self.world.current, self.world.old_release)
        self.assertEqual(self.world.units[self.world.guard]["active"], "active")
        self.assertEqual(self.world.units[self.world.member_unit]["pid"], 4300)
        self.assertEqual(self.world.units[self.world.member_unit]["binds_to"], [self.world.guard])
        self.assertNotIn(str(writer_dropin(self.world.layout)), self.world.files)
        self.assertEqual(self.world.files["/etc/systemd/system/" + PORTAL_UNIT], self.world.subscription_unit)
        self.assertEqual(self.world.units[PORTAL_UNIT]["pid"], 4600)

    def test_hung_takeover_falls_back_at_the_deadline(self):
        self.world.takeover_mode = "hang"
        self.world.old_cold_start = 0.6
        plan, receipt = self.run_plan()
        self.assertEqual(receipt["fallback"]["reason"], "takeover deadline passed")
        self.assertEqual(receipt["status"], "fallback_complete_members_preserved", receipt)
        self.assertEqual(self.world.files["/etc/dazzle-vps/policy.json"], self.v1)

    def test_standby_that_never_warms_reverts_v2_policy_and_prepared_files_without_touching_processes(self):
        plan = self.plan()
        self.world.standby_warming = True
        receipt = ExpansionCoordinator(self.host, self.world.layout, plan, approve(plan)).run()
        self.assertEqual(receipt["status"], "aborted_no_core_or_writer_changed", receipt)
        steps = [step["step"] for step in receipt["steps"]]
        self.assertIn("policy_expanded", steps)
        self.assertEqual(self.world.files["/etc/dazzle-vps/policy.json"], self.v1)
        for path in (writer_dropin(self.world.layout), certsync_dropin(self.world.layout), TMPFILES, policy_snapshot(self.world.layout)):
            self.assertNotIn(str(path), self.world.files)
        self.assertEqual(self.world.lock_holder, 4100)
        self.assertEqual(self.world.units[self.world.w2]["pid"], 0)
        self.assertEqual((self.world.units[self.world.member_unit]["pid"], self.world.units[self.world.guard]["pid"]), (4300, 4500))
        self.assertEqual(self.world.files["/usr/local/bin/dazzle-vps-control"], LAUNCHER)

    def test_witness_that_leaves_before_preparation_aborts_with_nothing_written(self):
        plan = self.plan()
        self.world.connections[4300] = []
        receipt = ExpansionCoordinator(self.host, self.world.layout, plan, approve(plan)).run()
        self.assertEqual(receipt["status"], "aborted_no_core_or_writer_changed", receipt)
        self.assertEqual(self.world.files["/etc/dazzle-vps/policy.json"], self.v1)
        self.assertNotIn(str(TMPFILES), self.world.files)

    def test_portal_that_cannot_start_restores_the_subscription_service(self):
        self.world.portal_starts = False
        plan, receipt = self.run_plan()
        self.assertEqual(receipt["portal"], "portal_failed_subscription_restored")
        self.assertEqual(receipt["status"], "handoff_complete_portal_not_running")
        self.assertEqual(self.world.files["/etc/systemd/system/" + PORTAL_UNIT], self.world.subscription_unit)
        portal = self.world.units[PORTAL_UNIT]
        self.assertEqual((portal["active"], self.world.portal_uid[portal["pid"]]), ("active", AGENT_UID))
        self.assertEqual(self.world.current, self.world.new_release)  # The writer handoff itself stays complete.

    def test_missing_account_unknown_cold_start_or_unguarded_member_are_not_ready(self):
        del self.world.accounts["dazzle-web"]
        self.assertIn("PORTAL_ACCOUNT", {issue["code"] for issue in self.plan()["issues"]})
        self.world.accounts["dazzle-web"] = {"uid": WEB_UID, "gid": WEB_UID, "shell": "/usr/sbin/nologin", "home": "/nonexistent", "groups": []}
        self.world.standby_offset = None
        self.assertIn("FALLBACK_TIMING", {issue["code"] for issue in self.plan()["issues"]})
        self.world.standby_offset = 0.282
        self.world.units[self.world.member_unit]["binds_to"] = [self.world.w1]
        self.assertIn("MEMBER_UNIT", {issue["code"] for issue in self.plan()["issues"]})

    def test_privileged_or_grouped_portal_account_and_slow_writer_are_refused(self):
        self.world.accounts["dazzle-web"]["groups"] = ["dazzle-vps"]
        with self.assertRaises(ValueError):
            self.plan()
        self.world.accounts["dazzle-web"]["groups"] = []
        self.world.standby_offset = 2.5
        self.assertIn("FALLBACK_BUDGET", {issue["code"] for issue in self.plan()["issues"]})

    def test_approval_requires_the_portal_restart_acknowledgement(self):
        plan = self.plan()
        approval = approve(plan)
        approval["acknowledgements"].pop("portal_restart_briefly_interrupts_subscription_fetch")
        with self.assertRaises(ValueError):
            ExpansionCoordinator(self.host, self.world.layout, plan, approval)

    def test_registration_enabled_unknown_or_invalid_cannot_be_part_of_a_ready_plan(self):
        for value, source in ((True, "settings"), (None, "missing_setting"), (None, "missing_table"),
                              (None, "invalid_setting"), (0, "settings"), ("false", "settings"), (False, "missing_setting")):
            with self.subTest(value=value, source=source):
                self.world.registration_enabled, self.world.registration_state_source = value, source
                plan = self.plan()
                self.assertFalse(plan["ready_for_approval"])
                self.assertIn("REGISTRATION", {issue["code"] for issue in plan["issues"]})

    def test_registration_becoming_enabled_during_preparation_aborts_before_stopping_writer(self):
        plan = self.plan()
        self.world.hooks[1] = lambda: setattr(self.world, "registration_enabled", True)
        result = ExpansionCoordinator(self.host, self.world.layout, plan, approve(plan)).run()
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed", result)
        self.assertIn("Registration is enabled", result["abort_reason"])
        self.assertNotIn(("stop", "--no-block", self.world.w1), self.world.calls)
        self.assertEqual(self.world.current, self.world.old_release)
        self.assertEqual(self.world.files["/usr/local/bin/dazzle-vps-control"], LAUNCHER)

    def test_account_creation_is_separately_approved_and_unprivileged(self):
        del self.world.accounts["dazzle-web"]
        created = []
        def create(name):
            created.append(name)
            self.world.accounts[name] = {"uid": WEB_UID, "gid": WEB_UID, "shell": "/usr/sbin/nologin", "home": "/nonexistent", "groups": []}
        self.host.create_account = create
        with self.assertRaises(ValueError):
            expansion.create_portal_account(self.host, {"version": 1, "operation": "other", "approved": True,
                                                        "approval_id": str(uuid.uuid4()), "account": "dazzle-web"})
        result = expansion.create_portal_account(self.host, {"version": 1, "operation": expansion.ACCOUNT_OPERATION, "approved": True,
                                                             "approval_id": str(uuid.uuid4()), "account": "dazzle-web"})
        self.assertEqual((created, result["uid"], result["supplementary_groups"]), (["dazzle-web"], WEB_UID, []))


if __name__ == "__main__":
    unittest.main()
