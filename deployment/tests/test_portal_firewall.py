"""Registration seat firewall plan against recorded ufw output. No ufw is run."""
import copy
import json
import unittest
import uuid

from deployment import portal_firewall
from deployment.coordinator import Layout
from deployment.helper import CORE_SHA256
from deployment.installer import canonical, sha256
from deployment.portal_upgrade import expanded_policy

SERVER = str(uuid.uuid4())
STATUS = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere                   # SSH administration
80/tcp                     ALLOW IN    Anywhere                   # IP certificate validation
443/tcp                    ALLOW IN    Anywhere                   # VLESS REALITY
443/udp                    ALLOW IN    Anywhere                   # TUIC v5
8443/tcp                   ALLOW IN    Anywhere                   # Private HTTPS subscription
24430/tcp                  ALLOW IN    Anywhere                   # dazzle-vps:{server}:24430:tcp
24430/udp                  ALLOW IN    Anywhere                   # dazzle-vps:{server}:24430:udp
24431/tcp                  ALLOW IN    Anywhere                   # dazzle-vps:{server}:24431:tcp
24431/udp                  ALLOW IN    Anywhere                   # dazzle-vps:{server}:24431:udp
9443/tcp                   ALLOW IN    Anywhere                   # dazzle-vps:{server}:9443:tcp
22/tcp (v6)                ALLOW IN    Anywhere (v6)              # SSH administration
80/tcp (v6)                ALLOW IN    Anywhere (v6)              # IP certificate validation
443/tcp (v6)               ALLOW IN    Anywhere (v6)              # VLESS REALITY
443/udp (v6)               ALLOW IN    Anywhere (v6)              # TUIC v5
8443/tcp (v6)              ALLOW IN    Anywhere (v6)              # Private HTTPS subscription
""".format(server=SERVER)


class FakeFirewallHost:
    def __init__(self, policy):
        self.status, self.policy, self.calls, self.listeners = STATUS, policy, [], set()
        self.fail_on = None

    def read_trusted(self, path):
        return canonical(self.policy) + b"\n"

    def ufw_status(self):
        return self.status

    def listening(self, port, protocol):
        return (port, protocol) in self.listeners

    def ufw(self, *arguments):
        self.calls.append(arguments)
        if arguments == self.fail_on:
            return False
        lines = self.status.splitlines()
        if arguments[0] == "allow":
            port_protocol, comment = arguments[1], arguments[3]
            lines.insert(lines.index("22/tcp (v6)                ALLOW IN    Anywhere (v6)              # SSH administration"),
                         f"{port_protocol:<27}ALLOW IN    Anywhere                   # {comment}")
        elif arguments[:3] == ("--force", "delete", "allow"):
            lines = [line for line in lines if not line.startswith(arguments[3] + " ")]
        self.status = "\n".join(lines) + "\n"
        return True


def policy():
    v1 = {"version": 1, "server_id": SERVER, "server_endpoint": "8.8.8.8", "agent_uid": 991, "core_sha256": CORE_SHA256,
          "workers": {str(uuid.uuid4()): {"role": "admin", "public_port": 24430, "api_port": 34430},
                      str(uuid.uuid4()): {"role": "member", "public_port": 24431, "api_port": 34431}}}
    return v1, expanded_policy(v1, 1201)


class FirewallPlanTests(unittest.TestCase):
    def setUp(self):
        self.v1, self.v2 = policy()
        self.host, self.layout = FakeFirewallHost(self.v2), Layout()

    def approve(self, plan):
        return {"version": 1, "operation": portal_firewall.OPERATION, "approved": True, "approval_id": str(uuid.uuid4()),
                "plan_sha256": sha256(canonical(plan))}

    def test_occupied_new_tcp_or_udp_port_cannot_be_exposed(self):
        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol):
                self.host.listeners = {("24432", protocol)}
                plan = portal_firewall.build_firewall_plan(self.host, self.layout)
                self.assertFalse(plan["ready_for_approval"])
                self.assertIn("PORT_CONFLICT", {issue["code"] for issue in plan["issues"]})
                self.assertEqual(self.host.calls, [])

    def test_new_listener_after_preview_prevents_any_ufw_command(self):
        plan = portal_firewall.build_firewall_plan(self.host, self.layout)
        self.host.listeners.add(("24433", "udp"))
        with self.assertRaises(ValueError):
            portal_firewall.apply_firewall(self.host, self.layout, plan, self.approve(plan))
        self.assertEqual(self.host.calls, [])

    def test_listener_appearing_during_changes_stops_before_exposure_or_deletion(self):
        original = self.host.ufw
        def with_listener(*arguments):
            result = original(*arguments)
            self.host.listeners.update({("24433", "tcp"), ("443", "tcp")})
            return result
        self.host.ufw = with_listener
        plan = portal_firewall.build_firewall_plan(self.host, self.layout)
        result = portal_firewall.apply_firewall(self.host, self.layout, plan, self.approve(plan))
        self.assertEqual(result["reason"], "port_became_bound")
        self.assertNotIn(("allow", "24433/tcp", "comment", "dazzle-vps:%s:24433:tcp" % SERVER), self.host.calls)
        self.assertFalse(any(call[0] == "--force" for call in self.host.calls))

    def test_recorded_status_parses_both_families_and_comments(self):
        active, default, rules = portal_firewall.parse_status(STATUS)
        self.assertTrue(active)
        self.assertIn("deny (incoming)", default)
        self.assertEqual(len(rules), 15)
        self.assertTrue(portal_firewall.has(rules, "8443", "tcp", v6=True))
        self.assertEqual(rules[0]["comment"], "SSH administration")

    def test_plan_adds_exactly_six_seat_rules_and_removes_three_unused_legacy_allows(self):
        plan = portal_firewall.build_firewall_plan(self.host, self.layout)
        self.assertTrue(plan["ready_for_approval"], plan["issues"])
        self.assertEqual([(rule["port"], rule["protocol"]) for rule in plan["reviewed"]["adds"]],
                         [(str(port), protocol) for port in (24432, 24433, 24434) for protocol in ("tcp", "udp")])
        self.assertTrue(all(rule["comment"] == "dazzle-vps:%s:%s:%s" % (SERVER, rule["port"], rule["protocol"]) for rule in plan["reviewed"]["adds"]))
        self.assertEqual(plan["reviewed"]["removes"], [{"port": "443", "protocol": "tcp"}, {"port": "443", "protocol": "udp"},
                                                       {"port": "8443", "protocol": "tcp"}])

    def test_apply_changes_only_reviewed_rules_and_keeps_ssh_and_certificate_validation(self):
        plan = portal_firewall.build_firewall_plan(self.host, self.layout)
        result = portal_firewall.apply_firewall(self.host, self.layout, plan, self.approve(plan))
        self.assertEqual(result["status"], "firewall_complete")
        _, _, rules = portal_firewall.parse_status(self.host.status)
        for port, protocol in (("22", "tcp"), ("80", "tcp")):
            self.assertTrue(portal_firewall.has(rules, port, protocol) and portal_firewall.has(rules, port, protocol, v6=True))
        self.assertFalse(any(rule["to"] in {"443/tcp", "443/udp", "8443/tcp"} for rule in rules))
        self.assertEqual(sum(rule["to"].startswith("2443") and rule["to"][:5] in {"24432", "24433", "24434"} for rule in rules), 6)
        self.assertTrue(all(call[0] == "allow" or call[:3] == ("--force", "delete", "allow") for call in self.host.calls))

    def test_used_legacy_port_or_v1_policy_or_changed_status_blocks(self):
        self.host.listeners.add(("8443", "tcp"))
        self.assertIn("LEGACY_LISTENER", {issue["code"] for issue in portal_firewall.build_firewall_plan(self.host, self.layout)["issues"]})
        self.host.listeners.clear()
        plan = portal_firewall.build_firewall_plan(self.host, self.layout)
        self.host.status = self.host.status.replace("# SSH administration", "# changed", 1)
        with self.assertRaises(ValueError):
            portal_firewall.apply_firewall(self.host, self.layout, plan, self.approve(plan))
        self.assertEqual(self.host.calls, [])
        with self.assertRaises(ValueError):
            portal_firewall.build_firewall_plan(FakeFirewallHost(self.v1), self.layout)

    def test_missing_protected_rule_and_inactive_firewall_are_not_ready(self):
        self.host.status = STATUS.replace("Status: active", "Status: inactive")
        self.assertIn("UFW", {issue["code"] for issue in portal_firewall.build_firewall_plan(self.host, self.layout)["issues"]})
        self.host.status = "\n".join(line for line in STATUS.splitlines() if not line.startswith("80/tcp ")) + "\n"
        self.assertIn("PROTECTED_RULE", {issue["code"] for issue in portal_firewall.build_firewall_plan(self.host, self.layout)["issues"]})

    def test_failed_ufw_command_reports_partial_without_continuing(self):
        plan = portal_firewall.build_firewall_plan(self.host, self.layout)
        self.host.fail_on = ("allow", "24433/tcp", "comment", "dazzle-vps:%s:24433:tcp" % SERVER)
        result = portal_firewall.apply_firewall(self.host, self.layout, plan, self.approve(plan))
        self.assertEqual(result["status"], "partial_manual_review_required")
        self.assertEqual([call[1] for call in self.host.calls], ["24432/tcp", "24432/udp", "24433/tcp"])
        self.assertFalse(any(call[0] == "--force" for call in self.host.calls))


if __name__ == "__main__":
    unittest.main()
