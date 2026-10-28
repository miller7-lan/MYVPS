#!/usr/bin/env python3
"""Separately approved ufw change for the reviewed registration seats.

Adds exactly the public TCP/UDP allows for the v2 policy's new member ports and
removes the allows left behind by the administrator-removed legacy services
(443/tcp, 443/udp, 8443/tcp) only while nothing listens on them. SSH (22/tcp)
and certificate validation (80/tcp) are never touched; the default policy,
logging and every other rule stay as they are.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import uuid

from .coordinator import Host, Layout
from .helper import canonical_uuid, validate_policy
from .installer import canonical, sha256
from .portal_upgrade import NEW_PUBLIC_PORTS

OPERATION = "portal_firewall_ports"
LEGACY = (("443", "tcp"), ("443", "udp"), ("8443", "tcp"))
PROTECTED = (("22", "tcp"), ("80", "tcp"))
RULE = re.compile(r"^(?P<to>\S+(?: \(v6\))?)\s+(?P<action>ALLOW|DENY|REJECT|LIMIT)(?: IN)?\s+(?P<source>Anywhere(?: \(v6\))?|\S+)(?:\s+#\s*(?P<comment>.*))?$")


class FirewallHost(Host):
    def ufw_status(self):
        result = self.runner.run(["/usr/sbin/ufw", "status", "verbose"], timeout=30)
        if result.returncode:
            raise ValueError("ufw status is unavailable")
        return result.stdout.decode("utf-8", "replace")

    def ufw(self, *arguments):
        return self.runner.run(["/usr/sbin/ufw", *arguments], timeout=60).returncode == 0

    def listening(self, port, protocol):
        flag = "-Htln" if protocol == "tcp" else "-Huln"
        result = self.runner.run(["/usr/bin/ss", flag, "sport = :" + str(int(port))], timeout=10)
        if result.returncode:
            raise ValueError("The firewall target listeners could not be checked")
        return bool(result.stdout.strip())


def parse_status(text):
    """Active state, default policy line and (port/proto, v6, action, source, comment) rows."""
    active = bool(re.search(r"^Status: active$", text, re.M))
    default = next((line.strip() for line in text.splitlines() if line.startswith("Default:")), "")
    rules = []
    for line in text.splitlines():
        match = RULE.match(line.strip())
        if not match or match.group("to") in {"To", "--"}:
            continue
        to = match.group("to")
        rules.append({"to": to.replace(" (v6)", ""), "v6": to.endswith("(v6)"), "action": match.group("action"),
                      "source": match.group("source").replace(" (v6)", ""), "comment": (match.group("comment") or "").strip()})
    return active, default, rules


def has(rules, port, protocol, *, v6=False):
    return any(rule["to"] == port + "/" + protocol and rule["action"] == "ALLOW" and rule["source"] == "Anywhere" and rule["v6"] == v6
               for rule in rules)


def build_firewall_plan(host, layout, *, plan_id=None):
    plan_id = canonical_uuid(plan_id or str(uuid.uuid4()))
    policy = validate_policy(json.loads(host.read_trusted(layout.policy)))
    if policy["version"] != 2:
        raise ValueError("Seat ports are opened only after the reviewed v2 policy is live")
    seats = sorted(worker["public_port"] for worker in policy["workers"].values()
                   if worker["role"] == "member" and worker["public_port"] in NEW_PUBLIC_PORTS)
    if seats != list(NEW_PUBLIC_PORTS):
        raise ValueError("The live policy does not contain exactly the reviewed registration seats")
    text = host.ufw_status()
    active, default, rules = parse_status(text)
    issues = []
    if not active or "deny (incoming)" not in default:
        issues.append({"code": "UFW", "message": "ufw must be active with a default incoming deny"})
    for port, protocol in PROTECTED:
        if not has(rules, port, protocol):
            issues.append({"code": "PROTECTED_RULE", "message": "A protected allow is missing: " + port + "/" + protocol})
    adds = [{"port": str(port), "protocol": protocol, "comment": "dazzle-vps:%s:%d:%s" % (policy["server_id"], port, protocol)}
            for port in NEW_PUBLIC_PORTS for protocol in ("tcp", "udp") if not has(rules, str(port), protocol)]
    for rule in adds:
        if host.listening(rule["port"], rule["protocol"]):
            issues.append({"code": "PORT_CONFLICT", "message": "A port proposed for public access is already bound: " + rule["port"] + "/" + rule["protocol"]})
    removes = []
    for port, protocol in LEGACY:
        if has(rules, port, protocol) or has(rules, port, protocol, v6=True):
            if host.listening(port, protocol):
                issues.append({"code": "LEGACY_LISTENER", "message": "A legacy port is still in use: " + port + "/" + protocol})
            removes.append({"port": port, "protocol": protocol})
    reviewed = {"server_id": policy["server_id"], "status_sha256": sha256(text.encode()), "adds": adds, "removes": removes,
                "protected": [port + "/" + protocol for port, protocol in PROTECTED], "default": default,
                "unchanged": ["SSH 22/tcp and certificate validation 80/tcp", "default policies and logging", "all other rules"]}
    return {"version": 1, "operation": OPERATION, "plan_id": plan_id, "reviewed": reviewed, "issues": issues,
            "ready_for_approval": not issues and bool(adds or removes)}


def apply_firewall(host, layout, plan, approval):
    fields = {"version", "operation", "approved", "approval_id", "plan_sha256"}
    if (not isinstance(approval, dict) or set(approval) != fields or approval["version"] != 1 or approval["approved"] is not True
            or approval["operation"] != OPERATION or approval["plan_sha256"] != sha256(canonical(plan)) or not plan.get("ready_for_approval")):
        raise ValueError("A separate explicit firewall approval bound to the exact plan is required")
    canonical_uuid(approval["approval_id"])
    fresh = build_firewall_plan(host, layout, plan_id=plan["plan_id"])
    if fresh["reviewed"] != plan["reviewed"] or fresh["issues"]:
        raise ValueError("The firewall changed since review")
    done = []
    for rule in plan["reviewed"]["adds"]:
        if host.listening(rule["port"], rule["protocol"]):
            return {"status": "partial_manual_review_required", "applied": done, "failed": rule, "reason": "port_became_bound"}
        if not host.ufw("allow", rule["port"] + "/" + rule["protocol"], "comment", rule["comment"]):
            return {"status": "partial_manual_review_required", "applied": done, "failed": rule}
        done.append({"added": rule["port"] + "/" + rule["protocol"]})
    for rule in plan["reviewed"]["removes"]:
        if host.listening(rule["port"], rule["protocol"]):
            return {"status": "partial_manual_review_required", "applied": done, "failed": rule, "reason": "legacy_port_became_bound"}
        if not host.ufw("--force", "delete", "allow", rule["port"] + "/" + rule["protocol"]):
            return {"status": "partial_manual_review_required", "applied": done, "failed": rule}
        done.append({"removed": rule["port"] + "/" + rule["protocol"]})
    _, _, rules = parse_status(host.ufw_status())
    verified = (all(has(rules, rule["port"], rule["protocol"]) for rule in plan["reviewed"]["adds"])
                and not any(has(rules, rule["port"], rule["protocol"]) or has(rules, rule["port"], rule["protocol"], v6=True)
                            for rule in plan["reviewed"]["removes"])
                and all(has(rules, port, protocol) for port, protocol in PROTECTED))
    return {"status": "firewall_complete" if verified else "firewall_review_required", "applied": done}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Target-local exact-approved registration seat firewall change")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--approval", type=Path)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0 or platform.system() != "Linux":
            raise ValueError("Target root on Linux is required")
        layout = Layout()
        host = FirewallHost(layout)
        if args.preview:
            plan = build_firewall_plan(host, layout)
            result = {"mode": "preview", "production_modified": False, "plan_sha256": sha256(canonical(plan)), "plan": plan}
        else:
            if not args.plan or not args.approval:
                raise ValueError("Apply requires the exact saved plan and a separate approval")
            result = apply_firewall(host, layout, json.loads(args.plan.read_text()), json.loads(args.approval.read_text()))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if args.preview or result.get("status") == "firewall_complete" else 1
    except Exception as exc:
        message = str(exc) if isinstance(exc, ValueError) and len(str(exc)) < 300 else "Checks failed"
        print(json.dumps({"ok": False, "error": message}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
