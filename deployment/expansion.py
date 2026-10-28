#!/usr/bin/env python3
"""One-shot target executor for Phase B: hand the single writer to a release
that also serves the registration portal, under the reviewed three-seat v2 policy.

The discipline is the Phase A coordinator's: a read-only preview, an exact plan
bound to a separate approval, management held, a real member TCP witness, a
consistent backup with an additive migration check, a warmed read-only standby,
and a stop only at the writer's best sample phase inside the unchanged
five-second deadline. Members already belong to their own meter guards, so no
Core dependency changes here. The fallback cold-starts the pinned previous
release after restoring the v1 policy; its budget uses that writer's measured
start-to-standby-ready time. After acceptance the 9443 service becomes the
portal; if it cannot start, the previous subscription-only unit is restored.
Registration stays closed, and the firewall, the budget and the administrator
guard are separate approvals.
"""
from __future__ import annotations

import argparse
import datetime as dt
import grp
import json
import os
from pathlib import Path
import platform
import pwd
import re
import signal
import socket
import ssl
import uuid

from .coordinator import (Abort, Coordinator, FRESHNESS_LIMIT, HOLD, Host, LAUNCHER, Layout, RELEASE, _issue,
                          fallback_reserve, observe_phase, observe_unit, parse_status, process_record, sample_ages,
                          units_members, validate_parameters, worker_problems, worker_units)
from .helper import canonical_uuid, validate_policy
from .installer import canonical, sha256
from .portal_upgrade import NEW_API_PORTS, NEW_PUBLIC_PORTS, PORTAL_TLS, expanded_policy

OPERATION = "portal_expansion_handoff"
ACCOUNT_OPERATION = "create_portal_account"
PORTAL_ACCOUNT = "dazzle-web"
PORTAL_UNIT = "dazzle-vps-subscription.service"
PORTAL_PORT = 9443
TMPFILES = Path("/etc/tmpfiles.d/dazzle-vps-portal.conf")
PORTAL_RUNTIME = Path("/run/dazzle-vps-portal")
TAKEOVER_ALLOWANCE = 0.5  # Lock acquisition to writer-ready after standby-ready (Phase A observed 0.184 s).
ACKNOWLEDGEMENTS = frozenset({"abort_rather_than_restart_core", "fallback_is_best_effort_fail_closed",
                              "registration_stays_closed", "portal_restart_briefly_interrupts_subscription_fetch"})


def writer_dropin(layout):
    return layout.units / "dazzle-vps-writer@.service.d" / "portal.conf"


def certsync_dropin(layout):
    return layout.units / "dazzle-vps-certsync.service.d" / "portal.conf"


def policy_snapshot(layout):
    return layout.handoff / "policy-v1-before-portal.json"


class ExpansionHost(Host):
    """Production access for Phase B; tests substitute a simulated host."""

    def account(self, name):
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            return None
        groups = sorted(group.gr_name for group in grp.getgrall() if name in group.gr_mem)
        return {"uid": entry.pw_uid, "gid": entry.pw_gid, "shell": entry.pw_shell, "home": entry.pw_dir, "groups": groups}

    def standby_ready_offset(self, unit, pid, exec_start_us):
        """Seconds from this invocation's ExecMainStart to its first standby-ready line."""
        try:
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            result = self.runner.run(["/usr/bin/journalctl", "-u", unit, "_PID=" + str(int(pid)), "-o", "json", "--no-pager"], timeout=30)
        except (OSError, ValueError):
            return None
        if result.returncode:
            return None
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            try:
                entry = json.loads(line)
                message = entry.get("MESSAGE")
                if entry.get("_BOOT_ID", "").replace("-", "") != boot.replace("-", "") or not isinstance(message, str):
                    continue
                status = json.loads(message) if message.startswith("{") else None
            except ValueError:
                continue
            if isinstance(status, dict) and status.get("phase") == "standby-ready" and status.get("pid") == pid:
                offset = (int(entry["__MONOTONIC_TIMESTAMP"]) - int(exec_start_us)) / 1e6
                return round(offset, 3) if offset > 0 else None
        return None

    def tmpfiles(self, path):
        return self.runner.run(["/usr/bin/systemd-tmpfiles", "--create", str(path)], timeout=30).returncode == 0

    def directory_info(self, path):
        try:
            info = Path(path).lstat()
        except FileNotFoundError:
            return None
        return {"mode": "%04o" % (info.st_mode & 0o7777), "uid": info.st_uid, "gid": info.st_gid,
                "directory": Path(path).is_dir() and not Path(path).is_symlink()}

    def file_mode(self, path):
        info = Path(path).lstat()
        return {"mode": info.st_mode & 0o7777, "gid": info.st_gid}

    def listeners(self, port):
        """(pid, uid) of processes listening on the TCP port."""
        result = self.runner.run(["/usr/bin/ss", "-Htlnp", "sport = :" + str(int(port))], timeout=10)
        found = []
        for pid in sorted({int(value) for value in re.findall(r"pid=(\d+)", result.stdout.decode("utf-8", "replace"))}):
            try:
                status = (self.layout.proc / str(pid) / "status").read_text()
                found.append((pid, int(re.search(r"^Uid:\s+(\d+)", status, re.M).group(1))))
            except (OSError, AttributeError):
                continue
        return found

    def port_is_bound(self, port, protocol):
        if protocol not in {"tcp", "udp"}:
            raise ValueError("An explicit transport is required")
        flag = "-Htln" if protocol == "tcp" else "-Huln"
        result = self.runner.run(["/usr/bin/ss", flag, "sport = :" + str(int(port))], timeout=10)
        if result.returncode:
            raise ValueError("The new registration port listeners could not be checked")
        return bool(result.stdout.strip())

    def https_status(self, port, path):
        """Local loopback probe of our own service; certificates are verified by certsync."""
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        try:
            endpoint = json.loads(self.read_trusted(self.layout.policy)).get("server_endpoint")
        except (OSError, ValueError, TypeError, AttributeError):
            endpoint = None
        if not isinstance(endpoint, str) or not endpoint:
            raise ValueError("The reviewed server endpoint is unavailable for the portal health probe")
        host_header = ("[" + endpoint + "]" if ":" in endpoint and not endpoint.startswith("[") else endpoint) + ":" + str(int(port))
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=5) as raw:
                with context.wrap_socket(raw) as stream:
                    stream.settimeout(5)
                    stream.sendall(("GET " + path + " HTTP/1.1\r\nHost: " + host_header + "\r\nConnection: close\r\n\r\n").encode())
                    head = stream.recv(64)
        except OSError:
            return None
        match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return int(match.group(1)) if match else None

    def create_account(self, name):
        if self.runner.run(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
                            "--shell", "/usr/sbin/nologin", name], timeout=30).returncode:
            raise ValueError("The portal service account could not be created")


def validate_expansion_approval(plan, approval):
    fields = {"version", "operation", "approved", "approval_id", "plan_sha256", "acknowledgements"}
    if (not isinstance(approval, dict) or set(approval) != fields or approval["version"] != 1
            or approval["operation"] != OPERATION or approval["approved"] is not True):
        raise ValueError("A separate explicit Phase B approval is required")
    canonical_uuid(approval["approval_id"])
    if approval["plan_sha256"] != sha256(canonical(plan)) or not plan.get("ready_for_approval") or plan.get("operation") != OPERATION:
        raise ValueError("Approval must bind the exact ready Phase B plan")
    acknowledgements = approval["acknowledgements"]
    if (not isinstance(acknowledgements, dict) or set(acknowledgements) != ACKNOWLEDGEMENTS
            or not all(value is True for value in acknowledgements.values())):
        raise ValueError("Every reviewed Phase B acknowledgement is required")


def guard_ready(identifier, observed):
    status = parse_status(observed["status"])
    return (observed["active"] == "active" and observed["sub"] == "running" and status["_"] == "member-guard-ready"
            and status.get("worker") == identifier and status.get("phase") == "running")


def build_expansion_plan(host, layout, *, new_release_id, plan_id=None, parameters=None, measurements=None):
    """Read-only. The same function re-derives the plan at apply time."""
    parameters = validate_parameters(parameters)
    if not RELEASE.fullmatch(new_release_id or ""):
        raise ValueError("An immutable 24-hex release identifier is required")
    plan_id = canonical_uuid(plan_id or str(uuid.uuid4()))
    issues = []
    policy_bytes = host.read_trusted(layout.policy)
    policy = validate_policy(json.loads(policy_bytes))
    if policy["version"] != 1 or sorted(worker["role"] for worker in policy["workers"].values()) != ["admin", "member"]:
        raise ValueError("Phase B starts from the reviewed two-worker v1 policy")
    previous = host.current_release()
    if previous.name == new_release_id:
        raise ValueError("The new release is already current")
    old_inventory = host.release_inventory(previous)
    if sha256(canonical(old_inventory))[:24] != previous.name:
        raise ValueError("The pinned fallback release no longer matches its identifier")
    new_dir = layout.prefix / "releases" / new_release_id
    new_inventory = host.release_inventory(new_dir)
    manifest = json.loads(host.read_trusted(new_dir / "release.json"))
    if (sha256(canonical(new_inventory))[:24] != new_release_id or manifest.get("release_id") != new_release_id
            or manifest.get("files") != new_inventory):
        raise ValueError("The staged new release does not match its immutable inventory")
    account = host.account(PORTAL_ACCOUNT)
    if account is None:
        _issue(issues, "PORTAL_ACCOUNT", "The separately approved portal service account does not exist yet")
    elif (account["uid"] in {0, policy["agent_uid"]} or account["shell"] != "/usr/sbin/nologin"
          or account["home"] != "/nonexistent" or account["groups"]):
        raise ValueError("The portal service account is not the reviewed unprivileged identity")
    expanded = expanded_policy(policy, account["uid"]) if account else None
    if expanded and sorted(worker["public_port"] for key, worker in expanded["workers"].items() if key not in policy["workers"]) != list(NEW_PUBLIC_PORTS):
        raise ValueError("The expansion must add exactly the reviewed registration seats")

    new_ports = [{"port": port, "protocol": protocol, "bound": host.port_is_bound(port, protocol)}
                 for ports, protocols in ((NEW_PUBLIC_PORTS, ("tcp", "udp")), (NEW_API_PORTS, ("tcp",)))
                 for port in ports for protocol in protocols]
    for probe in new_ports:
        if probe["bound"]:
            _issue(issues, "PORT_CONFLICT", "A proposed registration port is already bound: %s/%s" % (probe["port"], probe["protocol"]))

    units = worker_units(layout, policy)
    members = {key: value for key, value in units.items() if value["role"] == "member"}
    old_writer = layout.instance(layout.writer_template, previous.name)
    new_writer = layout.instance(layout.writer_template, new_release_id)

    files = {}
    def plan_file(path, content, *, phase, mode, group="root", before=None):
        current = host.read(path)
        if (sha256(current) if current is not None else None) != before:
            raise ValueError("A planned path has unreviewed existing content: " + str(path))
        files[str(path)] = {"phase": phase, "before_sha256": before, "after_sha256": sha256(content),
                            "mode": "%04o" % mode, "group": group, "content": content.decode("utf-8")}

    def template(name):
        return host.read_trusted(new_dir / "deployment/portal-systemd" / name)

    portal_source = host.read(layout.units / PORTAL_UNIT)
    if portal_source is None:
        raise ValueError("The existing subscription service unit is missing")
    origin = "https://" + policy["server_endpoint"] + ":" + str(PORTAL_PORT)
    portal_unit = template("subscription.service").replace(b"@ORIGIN@", origin.encode())
    if re.search(rb"@[A-Z_]+@", portal_unit) or b"User=" + PORTAL_ACCOUNT.encode() + b"\n" not in portal_unit:
        raise ValueError("The portal unit template is not the reviewed unprivileged service")
    plan_file(policy_snapshot(layout), policy_bytes, phase="prepare", mode=0o640, group=layout.project_group)
    plan_file(TMPFILES, template("tmpfiles.conf"), phase="prepare", mode=0o644)
    plan_file(writer_dropin(layout), template("agent.conf"), phase="prepare", mode=0o644)
    plan_file(certsync_dropin(layout), template("certsync.conf"), phase="prepare", mode=0o644)
    if expanded:
        plan_file(layout.policy, canonical(expanded) + b"\n", phase="policy", mode=0o640, group=layout.project_group,
                  before=sha256(policy_bytes))
    plan_file(layout.units / PORTAL_UNIT, portal_unit, phase="portal", mode=0o644, before=sha256(portal_source))

    old = observe_unit(host, old_writer)
    if (old["active"], old["sub"]) != ("active", "running") or old["pid"] <= 0:
        _issue(issues, "OLD_WRITER", "The current writer must be running throughout preparation")
    if old["fragment"] != str(layout.units / layout.writer_template) or old["dropins"]:
        _issue(issues, "OLD_WRITER_UNIT", "The current writer has an unreviewed unit source or drop-in")
    processes = {"old_writer": process_record(host, old), "workers": {}, "guards": {}}
    for identifier, value in units.items():
        observed = observe_unit(host, value["unit"])
        processes["workers"][identifier] = process_record(host, observed)
        if (observed["active"], observed["sub"]) != ("active", "running") or observed["pid"] <= 0:
            _issue(issues, "WORKER_STATE", "A registered worker is not running: " + value["role"])
        if value["role"] == "member":
            if (observed["fragment"] != str(layout.units / value["unit"]) or observed["dropins"]
                    or observed["binds_to"] != [value["guard"]]):
                _issue(issues, "MEMBER_UNIT", "A member is not bound only to its own reviewed guard")
            guard = observe_unit(host, value["guard"])
            processes["guards"][identifier] = {"pid": guard["pid"], "invocation": guard["invocation"]}
            if not guard_ready(identifier, guard):
                _issue(issues, "GUARD", "A member guard is not ready on a running trusted member")
        elif observed["binds_to"] or observed["dropins"]:
            _issue(issues, "ADMIN_UNIT", "The administrator must stay independent of the writer during Phase B")
    new = observe_unit(host, new_writer)
    if new["active"] not in {"inactive", ""} or new["pid"]:
        _issue(issues, "NEW_UNIT_ACTIVE", "The new writer instance is already active")
    portal = observe_unit(host, PORTAL_UNIT)
    if (portal["active"], portal["sub"]) != ("active", "running"):
        _issue(issues, "PORTAL_SERVICE", "The existing subscription service must be running before it is replaced")
    certsync = observe_unit(host, layout.certsync_unit)
    web_tls = host.directory_info(PORTAL_TLS)
    if web_tls is not None and (not web_tls["directory"] or web_tls["uid"] != layout.trusted_uid or web_tls["mode"] != "0750"):
        raise ValueError("An unreviewed portal certificate path already exists")

    try:
        lock = host.lock_identity()
        if host.lock_holders() != [{"pid": old["pid"], "mode": "WRITE"}]:
            _issue(issues, "LOCK_HOLDER", "The writer lock is not held exclusively by the current writer")
    except (OSError, ValueError):
        raise ValueError("The writer lock cannot be observed") from None

    now = host.wall()
    with host.ledger() as ledger:
        facts = ledger.facts()
        phase = observe_phase(host, ledger, units_members(units)) if measurements is None else None
    if facts["meta"].get("server_id") != policy["server_id"] or facts["meta"].get("mode") != "production":
        raise ValueError("Ledger identity does not match the root policy")
    if facts.get("registration_enabled") is not False or facts.get("registration_state_source") != "settings":
        _issue(issues, "REGISTRATION", "Registration must be explicitly disabled in the live settings until its separate approval")
    if facts["jobs_active"]:
        _issue(issues, "JOBS", "Managed worker operations are pending")
    if facts["meta"].get("agent_recovery_only"):
        _issue(issues, "RECOVERY", "The writer is in explicit recovery-only mode")
    by_worker = {worker["worker_id"]: worker for worker in facts["workers"]}
    users = {user["id"]: user for user in facts["users"]}
    for identifier, value in units.items():
        worker = by_worker.get(identifier)
        if worker is None or (worker["role"], worker["public_port"], worker["api_port"]) != (value["role"], value["public_port"], value["api_port"]):
            raise ValueError("Ledger worker bindings do not match the root policy")
        for problem in worker_problems(worker, users.get(worker["user_id"]), value["role"], parameters, now, facts["cycle"]):
            _issue(issues, "LEDGER", value["role"] + ": " + problem)
        if worker["process_id"] != processes["workers"][identifier]["pid"]:
            _issue(issues, "PID", "Ledger and systemd disagree on a worker process")
    if set(by_worker) - set(units):
        raise ValueError("The ledger already registers workers outside the v1 policy")
    ages = sample_ages(facts, now)
    if set(ages) != set(units) or max(ages.values(), default=float("inf")) > 2.0:
        _issue(issues, "FRESHNESS", "Every registered worker needs a fresh trusted ledger sample", volatile=True)
    witness = {}
    for identifier, value in members.items():
        pid = processes["workers"][identifier]["pid"]
        observed = host.witness(pid, value["public_port"]) if pid else {"listening": False, "established": []}
        witness[identifier] = len(observed["established"])
        if not observed["listening"]:
            _issue(issues, "LISTENER", "A member Core is not listening on its public TCP port")
        if not observed["established"]:
            _issue(issues, "WITNESS", "Keep one real VLESS TCP client connected for every member during the switch", volatile=True)

    if measurements is None:
        offset = host.standby_ready_offset(old_writer, old["pid"], old["exec_start_us"]) if old["pid"] else None
        latencies = host.helper_latency(next(iter(members)), 3) if members else [0.0]
        measurements = {"old_writer_standby_ready_seconds": offset, "takeover_allowance_seconds": TAKEOVER_ALLOWANCE,
                        "old_writer_start_to_ready_seconds": round(offset + TAKEOVER_ALLOWANCE, 3) if offset else None,
                        "helper_status_latency_seconds": latencies,
                        "best_member_sample_age_seconds": round(phase[0], 3), "other_sample_age_at_best_seconds": round(phase[1], 3)}
    start_to_ready = measurements["old_writer_start_to_ready_seconds"]
    best_age, other_age = measurements["best_member_sample_age_seconds"], measurements["other_sample_age_at_best_seconds"]
    window = parameters["takeover_deadline"] + parameters["safety_margin"]
    available = round(FRESHNESS_LIMIT - best_age - window, 3)
    if not start_to_ready or not 0 < start_to_ready < 60:
        reserve = None
        _issue(issues, "FALLBACK_TIMING", "The current writer's start-to-standby-ready time is not in this boot's journal")
    else:
        reserve = fallback_reserve(start_to_ready, max(measurements["helper_status_latency_seconds"]), len(units))
        if best_age > parameters["max_sample_age_at_stop"] or reserve > available or other_age + window > FRESHNESS_LIMIT:
            _issue(issues, "FALLBACK_BUDGET", "At the writer's best observed sample phase a fallback to the pinned writer would not fit the remaining sample deadline; the writer will not be stopped")
    measurements = {**measurements, "fallback_reserve_seconds": reserve, "available_for_fallback_seconds": available}

    registry_bytes = host.read(layout.registry)
    reviewed = {
        "server_id": policy["server_id"], "policy_sha256": sha256(policy_bytes),
        "expanded_policy": expanded, "expanded_policy_sha256": sha256(canonical(expanded) + b"\n") if expanded else None,
        "portal_account": account, "registry_sha256": sha256(registry_bytes) if registry_bytes is not None else None,
        "new_port_checks": new_ports,
        "previous_release_id": previous.name, "new_release_id": new_release_id,
        "previous_inventory_sha256": sha256(canonical(old_inventory)), "new_inventory_sha256": sha256(canonical(new_inventory)),
        "units": {"old_writer": old_writer, "new_writer": new_writer, "workers": units, "portal": PORTAL_UNIT},
        "processes": processes, "old_writer_start": {"exec_start_us": old["exec_start_us"], "active_enter_us": old["active_enter_us"]},
        "portal_service": {"pid": portal["pid"], "invocation": portal["invocation"], "fragment": portal["fragment"], "port": PORTAL_PORT,
                           "origin": origin},
        "lock": lock, "files": files,
        "directories": {str(PORTAL_TLS): {"mode": "0750", "group": PORTAL_ACCOUNT, "exists": web_tls is not None},
                        str(writer_dropin(layout).parent): {"mode": "0755", "group": "root"},
                        str(certsync_dropin(layout).parent): {"mode": "0755", "group": "root"},
                        str(PORTAL_RUNTIME): {"mode": "2750", "owner": layout.agent_account, "group": PORTAL_ACCOUNT, "via": str(TMPFILES)}},
        "ledger": {"revision": facts["meta"].get("revision"), "jobs_active": facts["jobs_active"],
                   "incidents_unresolved": facts["incidents_unresolved"], "incidents_total": facts["incidents_total"],
                   "registration_enabled": facts.get("registration_enabled"), "registration_state_source": facts.get("registration_state_source"),
                   "cycle_id": facts["cycle"]["id"] if facts["cycle"] else None},
        "control": {"path": str(layout.control), "original_sha256": sha256(LAUNCHER), "hold_sha256": sha256(HOLD)},
        "parameters": parameters,
        "certificate_sync": {"unit": layout.certsync_unit, "loaded": certsync["load"] == "loaded", "dropins": certsync["dropins"]},
        "unchanged": ["no Core restart and no member or administrator dependency change", "no firewall, SSH, account-other-than-portal or provider change",
                      "registration stays closed", "budget and administrator guard unchanged", "ledger is never restored or reset",
                      "certificate sources unchanged; the portal receives a separate read-only copy"],
    }
    if host.read(layout.control) != LAUNCHER:
        raise ValueError("Management entry differs from the reviewed fixed launcher")
    host.require_replaceable(layout.control)
    blocking = [issue for issue in issues if not issue["volatile"]]
    return {"version": 1, "operation": OPERATION, "plan_id": plan_id, "reviewed": reviewed, "measurements": measurements,
            "observed": {"at": now.isoformat(), "ledger_age_seconds": {key: round(value, 3) for key, value in ages.items()},
                         "member_witness_connections": witness},
            "issues": issues, "ready_for_approval": not issues, "blocking_issues": len(blocking),
            "notice": "Apply holds management, proves every check again and stops the current writer only inside the measured budget. "
                      "A failed takeover restores the v1 policy and cold-starts the pinned writer on a best-effort basis; guards stay fail-closed. "
                      "The 9443 service restarts once to become the portal."}


class ExpansionCoordinator(Coordinator):
    """Phase A's gates and takeover; Phase B preparation, fallback and finalize."""

    def __init__(self, host, layout, plan, approval):
        validate_expansion_approval(plan, approval)
        self.host, self.layout, self.renderer = host, layout, None
        self.plan, self.reviewed, self.parameters = plan, plan["reviewed"], plan["reviewed"]["parameters"]
        self.run_dir = layout.handoff / plan["plan_id"]
        self.units = self.reviewed["units"]
        self.members = {key: value for key, value in self.units["workers"].items() if value["role"] == "member"}
        self.journal = {"version": 1, "operation": OPERATION, "plan_id": plan["plan_id"], "plan_sha256": approval["plan_sha256"],
                        "approval_id": approval["approval_id"], "status": "started", "steps": []}
        self.interrupted = False
        self.held = self.prepared = self.standby = self.old_stopped = self.policy_written = False
        self.standby_pid = None
        self.guards, self.adopted, self.preflight_witness = {}, [], {}
        self.ledger = None

    def verify_plan(self):
        fresh = build_expansion_plan(self.host, self.layout, new_release_id=self.reviewed["new_release_id"], plan_id=self.plan["plan_id"],
                                     parameters=self.parameters, measurements=self.plan["measurements"])
        self.require(fresh["reviewed"] == self.reviewed, "Reviewed facts changed since the approved plan")
        blocking = [issue["message"] for issue in fresh["issues"] if not issue["volatile"]]
        self.require(not blocking, "Current state has unresolved blocking issues: " + "; ".join(blocking))
        self.step("plan_reverified")

    def backup(self):
        facts = self.ledger.facts()
        self.require(facts["meta"].get("revision") == self.reviewed["ledger"]["revision"] and not facts["jobs_active"],
                     "A management change happened after review")
        path = self.run_dir / "pre-handoff.sqlite3"
        self.host.write(path, self.ledger.backup(), mode=0o600)
        self.host.normalize_backup(path)
        payload = self.host.read(path)
        # The new release must migrate this exact ledger additively under the v2 policy it will run with.
        result = self.host.migration_check(self.layout.prefix / "releases" / self.reviewed["new_release_id"], path,
                                           self.reviewed["expanded_policy"])
        self.journal["backup"] = {"path": str(path), "sha256": sha256(payload), "bytes": len(payload),
                                  "automatic_restore": False, "additive_migration": result}
        self.step("backup_and_migration_verified")

    def prepare(self):
        self.check()
        for path, spec in self.reviewed["files"].items():
            if spec["before_sha256"] is not None:
                current = self.host.read(path)
                self.require(current is not None and sha256(current) == spec["before_sha256"], "A replaced file changed since review")
                self.host.write(self.run_dir / ("original-" + Path(path).name), current, mode=0o600)
        self.prepared = True
        self.host.directory(writer_dropin(self.layout).parent, 0o755, 0)
        self.host.directory(certsync_dropin(self.layout).parent, 0o755, 0)
        self.host.directory(PORTAL_TLS, 0o750, self.host.group(PORTAL_ACCOUNT))
        for path, spec in self.reviewed["files"].items():
            if spec["phase"] == "prepare":
                self.write_planned(path)
        self.require(self.host.tmpfiles(TMPFILES), "The portal runtime directory could not be created")
        self.require(self.reload(), "systemd daemon-reload failed")
        old = self.unit(self.units["old_writer"])
        self.require(self.same_process(self.reviewed["processes"]["old_writer"], old) and old["need_reload"] == "no",
                     "The current writer changed while unit definitions were prepared")
        self.step("units_prepared")

    def verify_guards(self):
        for identifier, value in self.members.items():
            self.check()
            observed, record = self.unit(value["guard"]), self.reviewed["processes"]["guards"][identifier]
            self.require(guard_ready(identifier, observed) and observed["pid"] == record["pid"] and observed["invocation"] == record["invocation"],
                         "A member guard is not the same ready process")
            self.guards[identifier] = {"pid": observed["pid"], "invocation": observed["invocation"]}
        self.step("guards_verified", guards=len(self.guards))

    def write_policy(self):
        self.check()
        self.policy_written = True
        self.write_planned(self.layout.policy)
        self.step("policy_expanded", seats=len(NEW_PUBLIC_PORTS))

    def gate(self):
        """Every switch precondition, proven again immediately before the stop."""
        self.check()
        self.require(self.host.read(self.layout.control) == HOLD and not self.host.control_processes(), "Management is not held and quiescent")
        policy = self.host.read(self.layout.policy)
        self.require(policy is not None and sha256(policy) == self.reviewed["expanded_policy_sha256"], "Root policy is not the reviewed v2 policy")
        registry = self.host.read(self.layout.registry)
        self.require((sha256(registry) if registry is not None else None) == self.reviewed["registry_sha256"],
                     "A root worker operation happened during preparation")
        old = self.reviewed["processes"]["old_writer"]
        self.require(self.same_process(old, self.unit(self.units["old_writer"])), "The current writer is not the same live process")
        self.require(self.exclusive(old["pid"]), "The single writer lock is not held by the current writer")
        self.require(self.standby_ready(self.unit(self.units["new_writer"])), "The standby is not freshly ready")
        for identifier, value in self.members.items():
            observed, record = self.unit(value["guard"]), self.guards[identifier]
            self.require(guard_ready(identifier, observed) and observed["pid"] == record["pid"]
                         and observed["invocation"] == record["invocation"], "A member guard is not the same ready process")
        for identifier, value in self.units["workers"].items():
            observed = self.unit(value["unit"])
            self.require(self.same_process(self.reviewed["processes"]["workers"][identifier], observed),
                         "A registered Core is not the same live process")
            self.require(value["role"] != "member" or observed["binds_to"] == [value["guard"]], "A member is not bound to its own guard")
        facts, now, ledger = self.ledger.facts(), self.host.wall(), self.reviewed["ledger"]
        self.require(facts["meta"].get("revision") == ledger["revision"] and not facts["jobs_active"]
                     and facts["incidents_total"] == ledger["incidents_total"] and not facts["meta"].get("agent_recovery_only")
                     and (facts["cycle"] or {}).get("id") == ledger["cycle_id"], "Ledger state changed since review")
        self.require(facts.get("registration_enabled") is False and facts.get("registration_state_source") == "settings",
                     "Registration is enabled or its disabled setting cannot be verified")
        users = {user["id"]: user for user in facts["users"]}
        for worker in facts["workers"]:
            value = self.units["workers"].get(worker["worker_id"])
            if value is not None:
                self.require(not worker_problems(worker, users.get(worker["user_id"]), value["role"], self.parameters, now, facts["cycle"]),
                             "A worker is no longer settled, trusted and authorized")
        self.require(self.fresh_after(facts, dt.datetime.min.replace(tzinfo=dt.timezone.utc)), "Ledger samples are not fresh")
        current = self.require_witness(min(5.0, self.parameters["witness_wait_seconds"]))
        witness = {key: sorted(set(value) & set(self.preflight_witness[key])) for key, value in current.items()}
        self.require(all(witness.values()), "No member TCP session lasted through preparation; keep one real client connected")
        self.step("gate_passed", witness={key: len(value) for key, value in witness.items()})
        return {"facts": facts, "witness": witness}

    def restore_v1_policy(self):
        if not self.policy_written:
            return True
        restored = self.restore_planned(self.layout.policy)
        self.policy_written = not restored
        return restored

    def restore_prepared(self):
        restored = all([self.restore_planned(path) for path, spec in self.reviewed["files"].items() if spec["phase"] == "prepare"])
        return self.reload() and restored

    def fallback(self, reason, stopped_mono, guard_deadline):
        """Best effort inside the remaining deadline; members stay bound to their guards."""
        record = self.journal["fallback"] = {"reason": reason, "started_after": round(self.host.monotonic() - stopped_mono, 3)}
        self.host.systemctl("stop", "--no-block", self.units["new_writer"])
        limit, killed = self.host.monotonic() + 0.6, False
        while True:
            observed = self.observe(self.units["new_writer"])
            if observed is not None and observed["pid"] == 0:
                break
            if self.host.monotonic() > limit:
                if killed:
                    break
                self.host.systemctl("kill", "--signal=SIGKILL", "--kill-whom=all", self.units["new_writer"])
                limit, killed = self.host.monotonic() + 0.6, True
            self.host.sleep(0.02)
        try:
            record["v1_policy_restored"] = self.restore_v1_policy()
        except (OSError, ValueError):
            record["v1_policy_restored"] = False
        restart_wall = self.host.wall()
        self.host.systemctl("start", "--no-block", self.units["old_writer"])
        fresh_at, watch_until = None, guard_deadline + 10.0
        while self.host.monotonic() < watch_until:
            old = self.observe(self.units["old_writer"])
            if old is not None and old["active"] in {"active", "activating"} and old["pid"] and self.exclusive(old["pid"]):
                facts = self.facts()
                if facts is not None and self.fresh_after(facts, restart_wall, self.live_workers()):
                    fresh_at = self.host.monotonic()
                    break
            self.host.sleep(0.05)
        interrupted = [key for key in self.members if key not in self.live_workers()]
        record.update({"old_writer_fresh_after": round(fresh_at - stopped_mono, 3) if fresh_at else None,
                       "within_sample_deadline": bool(fresh_at and fresh_at <= guard_deadline),
                       "members_interrupted": len(interrupted)})
        if fresh_at is None:
            self.journal["status"] = "fallback_failed_manual_review"
            self.step("fallback_failed")
            return False
        restored = record["v1_policy_restored"] and self.restore_prepared()
        self.journal["status"] = ("fallback_complete_members_preserved" if restored and not interrupted else
                                  "fallback_complete_members_interrupted" if restored else "fallback_definition_review_required")
        self.step("fallback_finished")
        return False

    def finalize(self):
        new_dir = self.layout.prefix / "releases" / self.reviewed["new_release_id"]
        self.host.switch_current(new_dir, self.layout.prefix / "releases" / self.reviewed["previous_release_id"])
        if self.host.current_release().name != self.reviewed["new_release_id"]:
            raise ValueError("Current release switch was not confirmed")
        self.host.systemctl("disable", self.units["old_writer"])
        self.host.systemctl("enable", self.units["new_writer"])
        if (self.unit(self.units["old_writer"])["file_state"], self.unit(self.units["new_writer"])["file_state"]) not in {
                ("disabled", "enabled"), ("disabled", "indirect")}:
            raise ValueError("Boot enablement was not confirmed")
        self.step("writer_finalized", current=self.reviewed["new_release_id"])
        self.journal["certificate_sync_after_switch"] = self.certificate_sync()
        portal_ready = (self.journal["certificate_sync_after_switch"] in {"passed", "not_installed"}
                        and self.host.exists(PORTAL_TLS + "/cert.pem") and self.host.exists(PORTAL_TLS + "/key.pem"))
        self.journal["portal"] = self.switch_portal() if portal_ready else "not_switched_certificate_copy_missing"
        self.step("portal_finalized", portal=self.journal["portal"])

    def portal_healthy(self, uid, *, portal):
        """The one 9443 listener is this unit's process under the expected account.

        An unknown token must reach the writer through the private socket and
        come back 404 (an unavailable socket answers 503); the portal page is 200.
        """
        deadline = self.host.monotonic() + 15
        while self.host.monotonic() < deadline:
            observed = self.observe(PORTAL_UNIT)
            listeners = self.host.listeners(PORTAL_PORT)
            if (observed is not None and observed["active"] == "active" and observed["pid"]
                    and listeners == [(observed["pid"], uid)]):
                if self.host.https_status(PORTAL_PORT, "/" + "Z" * 32 + "/nodes.txt") == 404 and (
                        not portal or self.host.https_status(PORTAL_PORT, "/portal/") == 200):
                    return True
            self.host.sleep(0.25)
        return False

    def switch_portal(self):
        """One restart turns the subscription-only service into the portal; failure restores it."""
        path = self.layout.units / PORTAL_UNIT
        self.write_planned(path)
        if (self.reload() and self.host.systemctl("restart", PORTAL_UNIT, timeout=30) == 0
                and self.portal_healthy(self.reviewed["portal_account"]["uid"], portal=True)):
            return "portal_running"
        restored = self.restore_planned(path) and self.reload()
        if restored and self.host.systemctl("restart", PORTAL_UNIT, timeout=30) == 0 and self.portal_healthy(
                self.host.account(self.layout.agent_account)["uid"], portal=False):
            return "portal_failed_subscription_restored"
        return "portal_failed_manual_review_required"

    def revert(self, reason):
        """Undo preparation in reverse. Never stops a Core, a guard or the current writer."""
        self.journal["abort_reason"] = reason
        ok = True
        try:
            if self.standby:
                self.host.systemctl("stop", self.units["new_writer"])
                observed = self.observe(self.units["new_writer"])
                ok = observed is not None and observed["pid"] == 0
            if ok:
                ok = self.restore_v1_policy()
            if ok and self.prepared:
                ok = self.restore_prepared()
        except (OSError, ValueError):
            ok = False
        self.journal["status"] = "aborted_no_core_or_writer_changed" if ok else "aborted_manual_review_required"
        self.step("reverted" if ok else "revert_incomplete")

    def run(self):
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, self.interrupt)
        self.host.directory(self.layout.handoff, 0o750, self.host.group(self.layout.project_group))
        if self.host.exists(self.run_dir):
            raise ValueError("This plan was already attempted; review its receipt")
        self.host.directory(self.run_dir, 0o700, 0)
        self.persist()
        try:
            with self.host.ledger() as self.ledger:
                try:
                    self.verify_plan()
                    self.hold_control()
                    self.preflight_witness = self.require_witness(self.parameters["witness_wait_seconds"])
                    self.backup()
                    self.prepare()
                    self.verify_guards()
                    self.write_policy()
                    self.start_standby()
                    baseline = self.gate()
                    if self.takeover(baseline):
                        health, preserved = self.accept(baseline)
                        if health:
                            self.finalize()
                            portal = self.journal.get("portal")
                            self.journal["status"] = ("handoff_complete" if preserved and portal == "portal_running" else
                                                      "handoff_complete_portal_not_running" if preserved else
                                                      "handoff_complete_preservation_not_proven")
                        else:
                            self.journal["status"] = "taken_over_writer_review_required"
                except Exception as exc:
                    if not isinstance(exc, Abort):
                        self.journal["unexpected_error"] = f"{type(exc).__name__}: {exc}"
                    if not self.old_stopped:
                        self.revert(str(exc) if isinstance(exc, Abort) else "Unexpected failure before the writer was stopped")
                    elif self.journal["status"] == "started":
                        self.journal["status"] = "manual_review_required"
        finally:
            self.release_control()
            self.persist()
        return self.journal


def create_portal_account(host, approval):
    """Separately approved: one unprivileged nologin system account, nothing else."""
    fields = {"version", "operation", "approved", "approval_id", "account"}
    if (not isinstance(approval, dict) or set(approval) != fields or approval["version"] != 1 or approval["approved"] is not True
            or approval["operation"] != ACCOUNT_OPERATION or approval["account"] != PORTAL_ACCOUNT):
        raise ValueError("A separate explicit portal account approval is required")
    canonical_uuid(approval["approval_id"])
    if host.account(PORTAL_ACCOUNT) is None:
        host.create_account(PORTAL_ACCOUNT)
    account = host.account(PORTAL_ACCOUNT)
    if account is None or account["shell"] != "/usr/sbin/nologin" or account["home"] != "/nonexistent" or account["groups"]:
        raise ValueError("The portal account is not the reviewed unprivileged identity")
    return {"operation": ACCOUNT_OPERATION, "approval_id": approval["approval_id"], "account": PORTAL_ACCOUNT,
            "uid": account["uid"], "gid": account["gid"], "supplementary_groups": account["groups"], "services_changed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Target-local exact-approved Phase B portal handoff")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--create-account", action="store_true")
    parser.add_argument("--new-release-id")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--approval", type=Path)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0 or platform.system() != "Linux":
            raise ValueError("Target root on Linux is required")
        layout = Layout()
        host = ExpansionHost(layout)
        if args.create_account:
            if not args.approval:
                raise ValueError("Account creation requires its approval")
            result = create_portal_account(host, json.loads(args.approval.read_text()))
        elif args.preview:
            plan = build_expansion_plan(host, layout, new_release_id=args.new_release_id)
            result = {"mode": "preview", "production_modified": False, "plan_sha256": sha256(canonical(plan)), "plan": plan}
        else:
            if not args.plan or not args.approval:
                raise ValueError("Apply requires the exact saved plan and a separate approval")
            plan = json.loads(args.plan.read_text())
            here = Path(__file__).resolve()
            if (layout.prefix / "releases" / plan["reviewed"]["new_release_id"]).resolve() not in here.parents:
                raise ValueError("Apply must run from the staged new release")
            result = ExpansionCoordinator(host, layout, plan, json.loads(args.approval.read_text())).run()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("status", "ok") in {"ok", "handoff_complete"} or args.preview or args.create_account else 1
    except Exception as exc:
        message = str(exc) if isinstance(exc, (ValueError, Abort)) and len(str(exc)) < 300 else "Checks failed"
        print(json.dumps({"ok": False, "error": message, "production_note": "No step beyond the recorded receipt was attempted"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
