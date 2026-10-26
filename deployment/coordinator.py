#!/usr/bin/env python3
"""One-shot target coordinator for the live writer handoff (phase A).

Preview is read-only. Apply runs exactly once as root on the target, from the
staged immutable new release, bound to an exact reviewed plan and a separate
approval, so the switch window never depends on SSH round trips. It holds the
management entry, starts per-member guards and a read-only standby pinned to
the new release, adopts complete member units without restarting any Core and
hands the single ledger lock over inside the existing five-second sample
deadline. The old writer is stopped only after every precondition is proven
again and only when the remaining budget also covers a fallback to the pinned
old release. Policy v2, the portal, new ports, accounts and certificate sources
are a separate later approval; nothing here relaxes the fail-closed guards.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import datetime as dt
import grp
import json
import os
from pathlib import Path
import platform
import pwd
import re
import select
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

from .handoff import OLD_POLICY_SNAPSHOT, OLD_WRITER, guard_name, render_existing_member, render_old_writer_fallback
from .helper import HelperError, Runner, atomic_bytes, canonical_uuid, checked_path, validate_policy
from .member_gate import DROP_IN as GATE_DROP_IN, GATE_SETTINGS, OPENED as GATE_OPENED
from .installer import canonical, sha256

OPERATION = "live_writer_handoff"
STAGE_OPERATION = "stage_release"
FRESHNESS_LIMIT = 5.0  # The existing guard/ledger limit. It is never extended here.
RELEASE = re.compile(r"[a-f0-9]{24}")
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9@_.:-]{0,200}\.service")
LAUNCHER = (b'#!/bin/sh\n[ "$#" -eq 1 ] && [ "$1" = rpc ] || exit 1\n'
            b'exec /opt/dazzle-vps/current/venv/bin/python -I -m deployment.control\n')
HOLD = (b"#!/bin/sh\n# Reviewed live writer handoff: management is held; proxies and metering continue.\n"
        b"printf '%s\\n' '{\"ok\":false,\"request_id\":null,\"revision\":0,\"data\":null,\"error\":"
        b"{\"code\":\"CONTROL_UNAVAILABLE\",\"message\":\"Private production control is held for a reviewed writer handoff\"}}'\n"
        b"exit 1\n")
PARAMETERS = {
    "max_sample_age_at_stop": (1.0, 0.05, 1.5),   # ceiling; the stop waits for the writer's best phase
    "takeover_deadline": (1.2, 0.5, 2.5),         # new writer READY with post-stop samples
    "safety_margin": (0.25, 0.1, 1.0),
    "old_writer_kill_after": (0.8, 0.3, 2.0),     # a writer that has not exited by then is killed
    "fresh_moment_timeout": (8.0, 2.0, 30.0),
    "guard_ready_timeout": (15.0, 5.0, 60.0),
    "standby_ready_timeout": (45.0, 5.0, 120.0),
    "control_drain_timeout": (20.0, 2.0, 120.0),
    "acceptance_seconds": (3.0, 2.0, 30.0),
    "witness_wait_seconds": (30.0, 0.0, 300.0),
    "quota_margin_bytes": (1 << 30, 0, 1 << 40),
    "cycle_margin_seconds": (900, 60, 86400),
    "host_stall_lookback_seconds": (86400, 3600, 7 * 86400),  # any kernel report of a VM pause in it blocks approval
    "max_steal_before_stop": (0.2, 0.0, 2.0),     # hypervisor steal tolerated from verification to the stop
}
# Kernel lines that mean this VM (or a CPU) did not run. Pauses outlast the 5 s guards.
STALL_KINDS = (("clocksource_skip", "Long readout interval"), ("rt_throttling", "RT throttling activated"),
               ("soft_lockup", "soft lockup"), ("rcu_stall", "self-detected stall"), ("hung_task", "blocked for more than"))
UNIT_PROPERTIES = ("LoadState", "ActiveState", "SubState", "MainPID", "NRestarts", "InvocationID", "FragmentPath",
                   "DropInPaths", "BindsTo", "After", "StatusText", "UnitFileState", "NeedDaemonReload",
                   "ExecMainStartTimestampMonotonic", "ActiveEnterTimestampMonotonic", "Wants", "IPAddressDeny", "ControlGroup")
FAST_PROPERTIES = ("ActiveState", "SubState", "MainPID", "StatusText")


class Abort(Exception):
    """A controlled stop before the old writer was stopped."""


@dataclass(frozen=True)
class Layout:
    prefix: Path = Path("/opt/dazzle-vps")
    etc: Path = Path("/etc/dazzle-vps")
    state: Path = Path("/var/lib/dazzle-vps")
    units: Path = Path("/etc/systemd/system")
    control: Path = Path("/usr/local/bin/dazzle-vps-control")
    proc: Path = Path("/proc")
    helper_socket: str = "/run/dazzle-vps/helper.sock"
    old_writer: str = OLD_WRITER
    writer_template: str = "dazzle-vps-writer@.service"
    guard_template: str = "dazzle-vps-meter-guard@.service"
    member_template: str = "dazzle-proxy@.service"
    admin_template: str = "dazzle-admin@.service"
    certsync_unit: str = "dazzle-vps-certsync.service"
    agent_account: str = "dazzle-agent"
    project_group: str = "dazzle-vps"
    trusted_uid: int = 0

    def instance(self, template, name):
        return template.replace("@.service", "@" + name + ".service")

    @property
    def handoff(self): return self.etc / "handoff"
    @property
    def snapshot(self): return self.handoff / "previous-policy-v1.json"
    @property
    def guard_proofs(self): return self.etc / "guard-proofs"
    @property
    def policy(self): return self.etc / "policy.json"
    @property
    def registry(self): return self.etc / "registry.json"
    @property
    def database(self): return self.state / "state.sqlite3"
    @property
    def lock(self): return self.state / "agent.lock"


def parse_show(text):
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key] = value
    return fields


def parse_status(text):
    """Our own sd_notify STATUS lines: `leading-word; key=value; ...`."""
    parts = [part.strip() for part in (text or "").split(";")]
    result = {"_": parts[0]}
    for part in parts[1:]:
        key, separator, value = part.partition("=")
        if separator:
            result[key] = value
    return result


def parse_locks(text, device, inode):
    target = "%02x:%02x:%d" % (os.major(device), os.minor(device), inode)
    holders = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[1] == "FLOCK" and parts[5] == target:
            holders.append({"pid": int(parts[4]), "mode": parts[3]})
        elif len(parts) >= 9 and parts[1] == "->" and parts[2] == "FLOCK" and parts[6] == target:
            holders.append({"pid": int(parts[5]), "mode": "WAITING"})
    return holders


def parse_tcp(text):
    rows = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            rows.append((int(fields[1].rsplit(":", 1)[1], 16), fields[3], int(fields[9])))
        except (IndexError, ValueError):
            continue
    return rows


def process_identity(text, pid):
    if int(text.split("(", 1)[0]) != pid:
        raise ValueError("Process identity mismatch")
    fields = text[text.rfind(")") + 2:].split()
    if fields[0] in {"Z", "X", "x"}:
        raise ValueError("Process is exiting")
    return str(pid) + ":" + fields[19]


def parse_instant(value):
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp requires a timezone")
    return result.astimezone(dt.timezone.utc)


def parse_stalls(text):
    """`journalctl -k -o short-unix` lines → stall records; cs_nsec is the length of the clocksource skip."""
    stalls = []
    for line in text.splitlines():
        match = re.match(r"(\d+(?:\.\d+)?) \S+ kernel: (.*)", line)
        kind = match and next((name for name, needle in STALL_KINDS if needle in match.group(2)), None)
        if kind:
            length = re.search(r"cs_nsec: (\d+)", match.group(2))
            stalls.append({"at": float(match.group(1)), "kind": kind,
                           "seconds": round(int(length.group(1)) / 1e9, 3) if length else None})
    return stalls


def validate_parameters(values=None):
    values = dict(values or {name: spec[0] for name, spec in PARAMETERS.items()})
    if set(values) != set(PARAMETERS):
        raise ValueError("Exactly the reviewed timing parameters are required")
    for name, (_, low, high) in PARAMETERS.items():
        value = values[name]
        if type(value) not in {int, float} or not low <= value <= high:
            raise ValueError("Timing parameter is outside the reviewed range: " + name)
    if values["takeover_deadline"] + values["max_sample_age_at_stop"] + values["safety_margin"] >= FRESHNESS_LIMIT:
        raise ValueError("Timing parameters leave no fallback budget")
    return values


def running_workers(facts):
    users = {user["id"]: user for user in facts["users"]}
    return {worker["worker_id"]: (worker, users[worker["user_id"]]) for worker in facts["workers"]
            if worker["user_id"] and not worker["tombstoned"] and worker["observed_state"] in {"running", "staged"}}


def sample_ages(facts, now):
    ages = {}
    for identifier, (_, user) in running_workers(facts).items():
        try:
            age = (now - parse_instant(user["last_sample_at"])).total_seconds()
        except (TypeError, ValueError, AttributeError):
            age = float("inf")
        ages[identifier] = age if age >= -0.5 else float("inf")
    return ages


def split_ages(ages, members):
    """Member ages bound the guard deadline; other workers only need sample continuity."""
    member = max((ages.get(key, float("inf")) for key in members), default=0.0)
    other = max((value for key, value in ages.items() if key not in members), default=0.0)
    return member, other


def observe_phase(host, ledger, members, seconds=3.0):
    """Best member age the old writer's own cadence offers, and the other ages then.

    The writer persists each worker's frame on that worker's 1 s stream phase and
    only on its 0.5 s drain tick, so persisted ages never all reach zero together.
    """
    best, end = None, host.monotonic() + seconds
    while host.monotonic() < end:
        member, other = split_ages(sample_ages(ledger.facts(), host.wall()), members)
        if best is None or member < best[0]:
            best = (member, other)
        host.sleep(0.02)
    return best


def fallback_reserve(start_to_ready, helper_latency, running):
    """Stop an unready standby, cold-start the pinned old writer, then one sample cycle."""
    return round(0.6 + start_to_ready + running * helper_latency + 0.5 + 0.2, 3)


def worker_problems(worker, user, role, parameters, now, cycle):
    problems = []
    if worker["observed_state"] != "running" or worker["origin_pending"] or worker["last_error"] or worker["tombstoned"]:
        problems.append("registered worker is not in a settled running state")
    if not worker["observed_generation"] == worker["root_ack_generation"] == worker["generation"]:
        problems.append("a managed transition is planned or unacknowledged")
    if user is None or user["revoked_at"] or user["deleted_at"] or user["manual_disabled"]:
        problems.append("registered worker is not an enabled live user")
        return problems
    if user["credential_version"] != worker["credential_version"]:
        problems.append("credential version is not applied")
    if role == "member":
        if json.loads(user["reasons_json"] or "[]") or not user["trusted_sample"] or user["meter_state"] != "trusted":
            problems.append("member authorization or metering is not trusted")
        if not user["unlimited"]:
            remaining = (user["quota_bytes"] or 0) + user["topup_bytes"] - user["used_upload"] - user["used_download"]
            if remaining < parameters["quota_margin_bytes"]:
                problems.append("member is too close to its allowance for an automatic transition to be excluded")
    if cycle is None or (parse_instant(cycle["end_at"]) - now).total_seconds() < parameters["cycle_margin_seconds"]:
        problems.append("the administrator cycle boundary is too close")
    return problems


READER = r'''
import base64, hashlib, json, pathlib, sqlite3, sys
connection = sqlite3.connect(pathlib.Path(sys.argv[1]).resolve().as_uri() + "?mode=ro", uri=True, timeout=2, isolation_level=None)
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA busy_timeout=2000")
USER = ("id", "role", "manual_disabled", "revoked_at", "deleted_at", "reasons_json", "trusted_sample", "meter_state",
        "last_sample_at", "last_uplink", "last_downlink", "used_upload", "used_download", "quota_bytes", "topup_bytes",
        "unlimited", "credential_version")
WORKER = ("worker_id", "role", "user_id", "public_port", "api_port", "generation", "root_ack_generation",
          "observed_generation", "observed_state", "process_id", "origin_pending", "last_error", "tombstoned",
          "credential_version", "provisioned")
def facts():
    connection.execute("BEGIN")
    try:
        meta = {row[0]: json.loads(row[1]) for row in connection.execute(
            "SELECT key,value FROM meta WHERE key IN ('revision','mode','server_id','agent_recovery_only')")}
        users = []
        for row in connection.execute("SELECT * FROM users"):
            value = {key: row[key] for key in USER}
            value["epoch_sha256"] = hashlib.sha256(row["meter_epoch"].encode()).hexdigest() if row["meter_epoch"] else None
            users.append(value)
        workers = [{key: row[key] for key in WORKER} for row in connection.execute("SELECT * FROM production_workers")]
        jobs = connection.execute("SELECT COUNT(*) FROM production_jobs WHERE status IN ('pending','executing')").fetchone()[0]
        open_incidents = connection.execute("SELECT COUNT(*) FROM metering_incidents WHERE resolved_at IS NULL").fetchone()[0]
        total = connection.execute("SELECT COUNT(*) FROM metering_incidents").fetchone()[0]
        cycle = connection.execute("SELECT id,start_at,end_at FROM cycles WHERE status='active' ORDER BY start_at DESC LIMIT 1").fetchone()
        return {"meta": meta, "users": users, "workers": workers, "jobs_active": jobs, "incidents_unresolved": open_incidents,
                "incidents_total": total, "cycle": dict(cycle) if cycle else None}
    finally:
        connection.execute("ROLLBACK")
def backup():
    target = sqlite3.connect(":memory:")
    try:
        connection.backup(target)
        payload = target.serialize()
    finally:
        target.close()
    if len(payload) > 64 * 1024 * 1024:
        raise ValueError()
    return {"sqlite_b64": base64.b64encode(payload).decode(), "bytes": len(payload)}
for line in sys.stdin:
    request = None
    try:
        request = json.loads(line)
        reply = {"ok": True, "id": request["id"], "data": {"facts": facts, "backup": backup}[request["query"]]()}
    except Exception:
        reply = {"ok": False, "id": request.get("id") if isinstance(request, dict) else None}
    sys.stdout.write(json.dumps(reply, separators=(",", ":")) + "\n")
    sys.stdout.flush()
'''


class LedgerReader:
    """Read-only SQLite facts in a child that runs as the agent account.

    Root never opens the live WAL database: a root connection could create a
    root-owned -wal/-shm that the agent or a guard can no longer open.
    """
    def __init__(self, database, *, python=None, user=None, group=None, extra_groups=None):
        options = {} if user is None else {"user": user, "group": group, "extra_groups": list(extra_groups or [])}
        self.process = subprocess.Popen([python or sys.executable, "-I", "-c", READER, str(database)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, cwd="/", umask=0o077,
                                        close_fds=True, **options)
        self.buffer, self.sequence = b"", 0

    def query(self, name, timeout=10.0):
        # Each request carries an identifier: a reply that arrives after its own
        # timeout must never be mistaken for the answer to a newer query.
        self.sequence += 1
        self.process.stdin.write(json.dumps({"query": name, "id": self.sequence}).encode() + b"\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" not in self.buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("Ledger facts timed out")
                ready, _, _ = select.select([self.process.stdout], [], [], remaining)
                if not ready:
                    continue
                chunk = os.read(self.process.stdout.fileno(), 1 << 20)
                if not chunk:
                    raise ValueError("Ledger reader stopped")
                self.buffer += chunk
                if len(self.buffer) > 96 * 1024 * 1024:
                    raise ValueError("Ledger reply exceeds its limit")
            line, _, self.buffer = self.buffer.partition(b"\n")
            reply = json.loads(line)
            if reply.get("id") == self.sequence:
                break
        if reply.get("ok") is not True:
            raise ValueError("Ledger facts are unavailable")
        return reply["data"]

    def facts(self):
        return self.query("facts")

    def backup(self):
        return base64.b64decode(self.query("backup", timeout=60.0)["sqlite_b64"], validate=True)

    def close(self):
        try:
            self.process.stdin.close()
            self.process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()
            self.process.wait()
        finally:
            self.process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Host:
    """The only production access path; tests substitute a simulated host."""
    def __init__(self, layout=None, runner=None):
        self.layout, self.runner = layout or Layout(), runner or Runner()

    def systemctl(self, *arguments, timeout=30):
        if any(value.endswith(".service") and not UNIT.fullmatch(value) for value in arguments):
            raise ValueError("Untrusted unit name")
        try:
            return self.runner.run(["/usr/bin/systemctl", *arguments], timeout=timeout).returncode
        except (OSError, subprocess.SubprocessError):
            return 255

    def show(self, unit, properties=UNIT_PROPERTIES):
        if not UNIT.fullmatch(unit):
            raise ValueError("Untrusted unit name")
        try:
            result = self.runner.run(["/usr/bin/systemctl", "show", unit, "--property=" + ",".join(properties)], timeout=10)
        except (OSError, subprocess.SubprocessError):
            raise ValueError("Unit state could not be observed") from None
        if result.returncode:
            raise ValueError("Unit state could not be observed")
        return parse_show(result.stdout.decode("utf-8", "replace"))

    def read(self, path):
        path = Path(path)
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Unexpected project path type")
        return path.read_bytes()

    def read_trusted(self, path):
        checked_path(path, self.layout.trusted_uid)
        return Path(path).read_bytes()

    def require_replaceable(self, path):
        """An atomic swap needs a root-only file in a root-only directory, as the installer left them."""
        try:
            checked_path(Path(path).parent, self.layout.trusted_uid, directory=True)
            checked_path(path, self.layout.trusted_uid)
        except HelperError as exc:
            raise ValueError("Management entry cannot be swapped safely: " + exc.message) from None

    def exists(self, path):
        return Path(path).exists() or Path(path).is_symlink()

    def write(self, path, payload, *, mode, gid=None):
        atomic_bytes(path, payload, mode=mode, trusted_uid=self.layout.trusted_uid, gid=gid)

    def remove(self, path):
        path = Path(path)
        checked_path(path, self.layout.trusted_uid)
        path.unlink()
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def directory(self, path, mode, gid):
        path = Path(path)
        checked_path(path.parent, self.layout.trusted_uid, directory=True)
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=mode)
            os.chown(path, self.layout.trusted_uid, gid)
            os.chmod(path, mode)
        info = checked_path(path, self.layout.trusted_uid, directory=True)
        if stat.S_IMODE(info.st_mode) != mode or info.st_gid != gid:
            raise ValueError("Existing project directory has unreviewed ownership or mode")

    def group(self, name):
        return grp.getgrnam(name).gr_gid

    def identity(self, pid):
        return process_identity((self.layout.proc / str(pid) / "stat").read_text(), pid)

    def lock_identity(self):
        info = self.layout.lock.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Writer lock is not a regular single-link file")
        return {"device": info.st_dev, "inode": info.st_ino}

    def lock_holders(self):
        lock = self.lock_identity()
        return parse_locks((self.layout.proc / "locks").read_text(), lock["device"], lock["inode"])

    def witness(self, pid, port):
        """Inbound established TCP on the public port held by this exact Core.

        Stats API sessions use the loopback API port and outbound sessions use
        ephemeral local ports, so neither can be mistaken for a user session.
        """
        inodes = set()
        for entry in (self.layout.proc / str(pid) / "fd").iterdir():
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(int(target[8:-1]))
        established, listening = set(), False
        for name in ("tcp", "tcp6"):
            try:
                text = (self.layout.proc / str(pid) / "net" / name).read_text()
            except FileNotFoundError:
                continue
            for local_port, state, inode in parse_tcp(text):
                if local_port == port and inode in inodes:
                    if state == "01":
                        established.add(inode)
                    elif state == "0A":
                        listening = True
        return {"listening": listening, "established": sorted(established)}

    def control_processes(self):
        busy = []
        for entry in self.layout.proc.iterdir():
            if not entry.name.isdigit() or int(entry.name) == os.getpid():
                continue
            try:
                argv = [part.decode("utf-8", "replace") for part in (entry / "cmdline").read_bytes().split(b"\0") if part]
            except OSError:
                continue
            control = str(self.layout.control)
            if ("deployment.control" in argv or any(part == control or part.startswith(control + " ") for part in argv) or
                    ("dazzle.production" in argv and "rpc" in argv)):
                busy.append(int(entry.name))
        return busy

    def normalize_backup(self, path):
        """Root opens only its private copy: rollback journal, no sidecars, intact."""
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            check = connection.execute("PRAGMA quick_check").fetchone()[0]
        finally:
            connection.close()
        if mode != "delete" or check != "ok" or any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
            raise ValueError("The private backup is not a self-contained intact snapshot")

    def monotonic(self):
        return time.monotonic()

    def monotonic_ns(self):
        return time.monotonic_ns()

    def wall(self):
        return dt.datetime.now(dt.timezone.utc)

    def sleep(self, seconds):
        time.sleep(seconds)

    def steal_seconds(self):
        """Cumulative time the hypervisor did not run this VM (/proc/stat steal)."""
        fields = (self.layout.proc / "stat").read_text().split("\n", 1)[0].split()
        if len(fields) < 9 or fields[0] != "cpu":
            raise ValueError("Unexpected /proc/stat layout")
        return int(fields[8]) / os.sysconf("SC_CLK_TCK")

    def host_stalls(self, lookback_seconds):
        result = self.runner.run(["/usr/bin/journalctl", "--dmesg", "--boot", "--since", "-%ds" % int(lookback_seconds),
                                  "--output", "short-unix", "--no-pager", "--quiet",
                                  "--grep", "|".join(needle for _, needle in STALL_KINDS)], timeout=30)
        if result.returncode not in (0, 1):  # 1: nothing matched
            raise ValueError("The kernel log cannot be read")
        return parse_stalls(result.stdout.decode("utf-8", "replace"))

    def ledger(self):
        account = pwd.getpwnam(self.layout.agent_account)
        return LedgerReader(self.layout.database, user=account.pw_uid, group=account.pw_gid,
                            extra_groups=[self.group(self.layout.project_group)])

    def helper_latency(self, worker_id, count=3):
        values = []
        for _ in range(count):
            began, identifier = time.monotonic(), str(uuid.uuid4())
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(10)
                connection.connect(self.layout.helper_socket)
                connection.sendall(json.dumps({"version": 1, "request_id": identifier, "action": "status",
                                               "worker_id": worker_id, "generation": 0, "params": {}}).encode() + b"\n")
                connection.shutdown(socket.SHUT_WR)
                reply = b""
                while chunk := connection.recv(65536):
                    reply += chunk
                    if len(reply) > 1 << 20:
                        raise ValueError("Helper reply exceeds its limit")
            if json.loads(reply).get("ok") is not True:
                raise ValueError("Helper status probe failed")
            values.append(round(time.monotonic() - began, 4))
        return values

    def current_release(self):
        from .repair import current_release
        return current_release(self.layout.prefix, self.layout.trusted_uid)

    def release_inventory(self, directory):
        from .repair import installed_inventory
        return installed_inventory(directory, self.layout.trusted_uid)

    def switch_current(self, destination, previous):
        from .repair import atomic_current
        atomic_current(self.layout.prefix, destination, expected_previous=previous, trusted_uid=self.layout.trusted_uid)

    def migration_check(self, release_dir, backup, policy):
        from .update import check_additive_migration
        return check_additive_migration(release_dir, backup, policy, self.runner)


class ReleaseRenderer:
    """Pure text rendering from the staged release and observed live sources."""
    def guard_template(self, text, release_id):
        if text.count("@RELEASE_ID@") != 3:
            raise ValueError("Guard template must pin its guard and gate commands to one release")
        body = text.replace("@RELEASE_ID@", release_id)
        python = "/opt/dazzle-vps/releases/" + release_id + "/venv/bin/python -I -m "
        expected = ("ExecStart=" + python + "dazzle.meter_guard ", "ExecStartPost=+" + python + "deployment.member_gate open %i\n",
                    "ExecStopPost=+/bin/sh -c '" + python + "deployment.member_gate close %i ", "\nRestartPreventExitStatus=3\n")
        if (any(body.count(line) != 1 for line in expected) or "/current/" in body or re.search(r"@[A-Z_]+@", body)
                or "BindsTo=" in body or "Requires=" in body or "ReadWritePaths=/var/lib/dazzle-vps" in body):
            raise ValueError("Guard template is not the reviewed independent read-only guard")
        return body.encode()

    def writer_template(self, text):
        command = ("ExecStart=/opt/dazzle-vps/releases/%i/venv/bin/python -I -m dazzle.production --policy "
                   "/etc/dazzle-vps/policy.json --state-dir /var/lib/dazzle-vps agent --standby --allow-no-core-recovery\n")
        if text.count("ExecStart=") != 1 or command not in text or "/current/" in text:
            raise ValueError("Writer template is not pinned to its release instance")
        return text.encode()

    def member_override(self, template, member_id, guard_unit, old_writer):
        if guard_unit != guard_name(member_id) or old_writer != OLD_WRITER:
            raise ValueError("Unexpected guarded unit names")
        return render_existing_member(template, member_id).encode()

    def old_writer_fallback(self, unit, previous_release_id, snapshot):
        if str(snapshot) != OLD_POLICY_SNAPSHOT:
            raise ValueError("Unexpected policy snapshot path")
        return render_old_writer_fallback(unit, previous_release_id).encode()

    def guarded_member_template(self, text):
        required = ("\nWants=network-online.target dazzle-vps-meter-guard@%i.service\n", "\nAfter=network-online.target dazzle-vps-meter-guard@%i.service\n",
                    "\nSlice=system.slice\n", "\nIPAddressAllow=localhost\nIPAddressDeny=any\n")
        if any(line not in text for line in required) or "BindsTo=" in text or "/current/" in text:
            raise ValueError("Future member template is not gated by its own guard")
        return text.encode()


def observe_unit(host, unit, properties=UNIT_PROPERTIES):
    fields = host.show(unit, properties)
    try:
        return {"load": fields.get("LoadState", ""), "active": fields.get("ActiveState", ""), "sub": fields.get("SubState", ""),
                "pid": int(fields.get("MainPID") or 0), "restarts": int(fields.get("NRestarts") or 0),
                "invocation": fields.get("InvocationID", ""), "fragment": fields.get("FragmentPath", ""),
                "dropins": fields.get("DropInPaths", ""), "binds_to": sorted(fields.get("BindsTo", "").split()),
                "after": sorted(fields.get("After", "").split()), "status": fields.get("StatusText", ""),
                "file_state": fields.get("UnitFileState", ""), "need_reload": fields.get("NeedDaemonReload", ""),
                "exec_start_us": int(fields.get("ExecMainStartTimestampMonotonic") or 0),
                "active_enter_us": int(fields.get("ActiveEnterTimestampMonotonic") or 0),
                "wants": sorted(fields.get("Wants", "").split()), "ip_deny": fields.get("IPAddressDeny", ""),
                "cgroup": fields.get("ControlGroup", "")}
    except ValueError:
        raise ValueError("Unit state could not be parsed") from None


def process_record(host, observed):
    record = {"pid": observed["pid"], "invocation": observed["invocation"], "restarts": observed["restarts"], "identity": None}
    if observed["active"] == "active" and observed["pid"] > 0:
        try:
            record["identity"] = host.identity(observed["pid"])
        except (OSError, ValueError):
            pass
    return record


CONTROL_DROPINS = Path("/run/systemd/system.control")


def gate_path(layout, unit):
    return layout.units / (unit + ".d") / GATE_DROP_IN


def unknown_dropins(host, dropins, unit):
    """Drop-ins other than the empty runtime resets that opening a member gate leaves behind."""
    unknown = []
    for path in dropins.split() if isinstance(dropins, str) else dropins:
        name = Path(path).name
        if Path(path).parent == CONTROL_DROPINS / (unit + ".d") and name in ("50-IPAddressDeny.conf", "50-IPAddressAllow.conf"):
            lines = [line for line in (host.read(path) or b"").decode("utf-8", "replace").splitlines() if line and not line.startswith("#")]
            if lines == ["[Service]", name[3:-5] + "="]:
                continue
        unknown.append(path)
    return unknown


def units_members(units):
    return [key for key, value in units.items() if value["role"] == "member"]


def worker_units(layout, policy):
    result = {}
    for identifier, worker in sorted(policy["workers"].items()):
        template = layout.admin_template if worker["role"] == "admin" else layout.member_template
        result[identifier] = {"role": worker["role"], "unit": layout.instance(template, identifier),
                              "public_port": worker["public_port"], "api_port": worker["api_port"]}
        if worker["role"] == "member":
            result[identifier]["guard"] = layout.instance(layout.guard_template, identifier)
    return result


def _issue(issues, code, message, *, volatile=False):
    issues.append({"code": code, "message": message, "volatile": volatile})


def build_plan(host, layout, renderer, *, new_release_id, plan_id=None, parameters=None, measurements=None):
    """Read-only. The same function re-derives the plan at apply time."""
    parameters = validate_parameters(parameters)
    if not RELEASE.fullmatch(new_release_id or ""):
        raise ValueError("An immutable 24-hex release identifier is required")
    plan_id = canonical_uuid(plan_id or str(uuid.uuid4()))
    issues = []
    policy_bytes = host.read_trusted(layout.policy)
    policy = validate_policy(json.loads(policy_bytes))
    if policy["version"] != 1:
        raise ValueError("Phase A keeps the reviewed v1 policy; v2 expansion is a later approval")
    previous = host.current_release()
    new_dir = layout.prefix / "releases" / new_release_id
    if previous.name == new_release_id:
        raise ValueError("The new release is already current")
    old_inventory = host.release_inventory(previous)
    if sha256(canonical(old_inventory))[:24] != previous.name:
        raise ValueError("The pinned fallback release no longer matches its identifier")
    new_inventory = host.release_inventory(new_dir)
    manifest = json.loads(host.read_trusted(new_dir / "release.json"))
    if (sha256(canonical(new_inventory))[:24] != new_release_id or manifest.get("release_id") != new_release_id
            or manifest.get("files") != new_inventory):
        raise ValueError("The staged new release does not match its immutable inventory")
    units = worker_units(layout, policy)
    members = {key: value for key, value in units.items() if value["role"] == "member"}
    new_writer = layout.instance(layout.writer_template, new_release_id)

    def source(path, expected_name):
        payload = host.read(path)
        if payload is None or sha256(payload) != old_inventory.get(expected_name):
            raise ValueError("A live unit differs from the pinned fallback release: " + Path(path).name)
        return payload

    writer_path, template_path = layout.units / layout.old_writer, layout.units / layout.member_template
    writer_source = source(writer_path, "deployment/systemd/" + OLD_WRITER)
    member_source = source(template_path, "deployment/systemd/dazzle-proxy@.service")
    if host.read(layout.control) != LAUNCHER:
        raise ValueError("Management entry differs from the reviewed fixed launcher")
    host.require_replaceable(layout.control)  # The hold swaps it in place during apply.
    registry_bytes = host.read(layout.registry)

    files = {}
    def plan_file(path, content, *, phase, mode, group="root", before=None):
        current = host.read(path)
        if (sha256(current) if current is not None else None) != before:
            raise ValueError("A planned path has unreviewed existing content: " + str(path))
        files[str(path)] = {"phase": phase, "before_sha256": before, "after_sha256": sha256(content),
                            "mode": "%04o" % mode, "group": group, "content": content.decode("utf-8")}

    plan_file(layout.snapshot, policy_bytes, phase="prepare", mode=0o640, group=layout.project_group)
    def template(name):
        return host.read_trusted(new_dir / "deployment/portal-systemd" / name).decode("utf-8")

    plan_file(layout.units / layout.guard_template, renderer.guard_template(template("meter-guard@.service"), new_release_id),
              phase="prepare", mode=0o644)
    plan_file(layout.units / layout.writer_template, renderer.writer_template(template("writer@.service")), phase="prepare", mode=0o644)
    plan_file(writer_path, renderer.old_writer_fallback(writer_source.decode("utf-8"), previous.name, layout.snapshot),
              phase="prepare", mode=0o644, before=sha256(writer_source))
    for identifier, value in members.items():
        plan_file(layout.units / value["unit"], renderer.member_override(member_source.decode("utf-8"), identifier, value["guard"], layout.old_writer),
                  phase="adopt", mode=0o644)
        plan_file(gate_path(layout, value["unit"]), GATE_SETTINGS, phase="adopt", mode=0o644)
    plan_file(template_path, renderer.guarded_member_template(template("guarded-member.service")), phase="finalize", mode=0o644,
              before=sha256(member_source))

    old = observe_unit(host, layout.old_writer)
    if (old["active"], old["sub"]) != ("active", "running") or old["pid"] <= 0:
        _issue(issues, "OLD_WRITER", "The original writer must be running throughout preparation")
    if old["fragment"] != str(writer_path) or old["dropins"]:
        _issue(issues, "OLD_WRITER_UNIT", "The original writer has an unreviewed unit source or drop-in")
    processes = {"old_writer": process_record(host, old), "workers": {}}
    for identifier, value in units.items():
        observed = observe_unit(host, value["unit"])
        processes["workers"][identifier] = process_record(host, observed)
        if (observed["active"], observed["sub"]) != ("active", "running") or observed["pid"] <= 0:
            _issue(issues, "WORKER_STATE", "A registered worker is not running: " + value["role"])
        if value["role"] == "member" and (observed["fragment"] != str(template_path) or unknown_dropins(host, observed["dropins"], value["unit"])
                                          or observed["binds_to"] != [layout.old_writer]):
            _issue(issues, "MEMBER_UNIT", "A member has an unreviewed unit source, drop-in or dependency")
        if value["role"] == "member" and observed["cgroup"] != "/system.slice/" + value["unit"]:
            _issue(issues, "MEMBER_SLICE", "A member must run directly in system.slice; a nested slice keeps a closed gate after reopening")
        if value["role"] == "admin" and (layout.old_writer in observed["binds_to"] or observed["dropins"]):
            _issue(issues, "ADMIN_UNIT", "The administrator must stay independent of the original writer")
    certsync = observe_unit(host, layout.certsync_unit)
    for unit in [new_writer, *(value["guard"] for value in members.values())]:
        observed = observe_unit(host, unit)
        if observed["active"] not in {"inactive", ""} or observed["pid"]:
            _issue(issues, "NEW_UNIT_ACTIVE", "A new unit is already present or active: " + unit)

    try:
        lock = host.lock_identity()
        holders = host.lock_holders()
        if holders != [{"pid": old["pid"], "mode": "WRITE"}]:
            _issue(issues, "LOCK_HOLDER", "The writer lock is not held exclusively by the original writer")
    except (OSError, ValueError):
        raise ValueError("The writer lock cannot be observed") from None

    now = host.wall()
    steal_before = host.steal_seconds()
    with host.ledger() as ledger:
        facts = ledger.facts()
        phase = observe_phase(host, ledger, units_members(units)) if measurements is None else None
    steal_during = round(host.steal_seconds() - steal_before, 3)
    if facts["meta"].get("server_id") != policy["server_id"] or facts["meta"].get("mode") != "production":
        raise ValueError("Ledger identity does not match the root policy")
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
        start_to_ready = (old["active_enter_us"] - old["exec_start_us"]) / 1e6
        latencies = host.helper_latency(next(iter(members)), 3) if members else [0.0]
        measurements = {"old_writer_start_to_ready_seconds": round(start_to_ready, 3),
                        "helper_status_latency_seconds": latencies,
                        "best_member_sample_age_seconds": round(phase[0], 3), "other_sample_age_at_best_seconds": round(phase[1], 3)}
    start_to_ready = measurements["old_writer_start_to_ready_seconds"]
    reserve = fallback_reserve(start_to_ready, max(measurements["helper_status_latency_seconds"]), len(units))
    best_age, other_age = measurements["best_member_sample_age_seconds"], measurements["other_sample_age_at_best_seconds"]
    window = parameters["takeover_deadline"] + parameters["safety_margin"]
    available = round(FRESHNESS_LIMIT - best_age - window, 3)
    measurements = {**measurements, "fallback_reserve_seconds": reserve, "available_for_fallback_seconds": available}
    if not 0 < start_to_ready < 60:
        _issue(issues, "FALLBACK_TIMING", "The original writer start-to-ready time is unknown")
    elif best_age > parameters["max_sample_age_at_stop"] or reserve > available or other_age + window > FRESHNESS_LIMIT:
        _issue(issues, "FALLBACK_BUDGET", "At the writer's best observed sample phase a fallback to the pinned old writer would not fit the remaining sample deadline; the old writer will not be stopped")
    # A paused VM resumes with every sample and watchdog expired; guards then stop members.
    stalls = host.host_stalls(parameters["host_stall_lookback_seconds"])
    longest = max((stall["seconds"] or 0.0 for stall in stalls), default=0.0)
    if stalls:
        _issue(issues, "HOST_STALLS", "The kernel reported %d pause(s) of this VM in the last %d h (longest %.1f s); wait for a stable host"
               % (len(stalls), parameters["host_stall_lookback_seconds"] // 3600, longest))
    if steal_during > parameters["max_steal_before_stop"]:
        _issue(issues, "HOST_STEAL", "The hypervisor did not run this VM for %.2f s while the writer was observed" % steal_during, volatile=True)

    reviewed = {
        "server_id": policy["server_id"], "policy_sha256": sha256(policy_bytes),
        "registry_sha256": sha256(registry_bytes) if registry_bytes is not None else None,
        "previous_release_id": previous.name, "new_release_id": new_release_id,
        "previous_inventory_sha256": sha256(canonical(old_inventory)), "new_inventory_sha256": sha256(canonical(new_inventory)),
        "units": {"old_writer": layout.old_writer, "new_writer": new_writer, "workers": units},
        "processes": processes, "old_writer_start": {"exec_start_us": old["exec_start_us"], "active_enter_us": old["active_enter_us"]},
        "lock": lock, "files": files,
        "ledger": {"revision": facts["meta"].get("revision"), "jobs_active": facts["jobs_active"],
                   "incidents_unresolved": facts["incidents_unresolved"], "incidents_total": facts["incidents_total"],
                   "cycle_id": facts["cycle"]["id"] if facts["cycle"] else None},
        "control": {"path": str(layout.control), "original_sha256": sha256(LAUNCHER), "hold_sha256": sha256(HOLD)},
        "directories": {str(layout.handoff): {"mode": "0750", "group": layout.project_group},
                        str(layout.guard_proofs): {"mode": "0750", "group": layout.project_group},
                        **{str(gate_path(layout, value["unit"]).parent): {"mode": "0755", "group": "root"} for value in members.values()}},
        "parameters": parameters,
        # The installed sync runs with whatever `current` is; finalize proves it once on the new release.
        "certificate_sync": {"unit": layout.certsync_unit, "loaded": certsync["load"] == "loaded", "dropins": certsync["dropins"]},
        "unchanged": ["policy.json stays v1", "no new ports, accounts, firewall, SSH or 9443 change", "no Core restart",
                      "a member's own unit filters its public traffic only while its gate is closed",
                      "ledger is never restored or reset", "registration stays closed", "certificate sources unchanged"],
    }
    blocking = [issue for issue in issues if not issue["volatile"]]
    return {"version": 1, "operation": OPERATION, "plan_id": plan_id, "reviewed": reviewed, "measurements": measurements,
            "observed": {"at": now.isoformat(), "ledger_age_seconds": {key: round(value, 3) for key, value in ages.items()},
                         "member_witness_connections": witness,
                         "host": {"stalls_in_lookback": len(stalls), "longest_stall_seconds": longest,
                                  "steal_during_observation_seconds": steal_during}},
            "issues": issues, "ready_for_approval": not issues, "blocking_issues": len(blocking),
            "notice": "Apply holds management, proves every check again and stops the old writer only inside the measured budget. A failed takeover falls back to the pinned old writer on a best-effort basis; guards stay fail-closed."}


def validate_approval(plan, approval):
    fields = {"version", "operation", "approved", "approval_id", "plan_sha256", "acknowledgements"}
    acknowledgements = {"abort_rather_than_restart_core", "fallback_is_best_effort_fail_closed", "registration_stays_closed"}
    if (not isinstance(approval, dict) or set(approval) != fields or approval["version"] != 1
            or approval["operation"] != OPERATION or approval["approved"] is not True):
        raise ValueError("A separate explicit live handoff approval is required")
    canonical_uuid(approval["approval_id"])
    if approval["plan_sha256"] != sha256(canonical(plan)) or not plan.get("ready_for_approval"):
        raise ValueError("Approval must bind the exact ready plan")
    if (not isinstance(approval["acknowledgements"], dict) or set(approval["acknowledgements"]) != acknowledgements
            or not all(value is True for value in approval["acknowledgements"].values())):
        raise ValueError("Every reviewed acknowledgement is required")


class Coordinator:
    def __init__(self, host, layout, renderer, plan, approval):
        validate_approval(plan, approval)
        self.host, self.layout, self.renderer = host, layout, renderer
        self.plan, self.reviewed, self.parameters = plan, plan["reviewed"], plan["reviewed"]["parameters"]
        self.run_dir = layout.handoff / plan["plan_id"]
        self.units = self.reviewed["units"]
        self.members = {key: value for key, value in self.units["workers"].items() if value["role"] == "member"}
        self.journal = {"version": 1, "operation": OPERATION, "plan_id": plan["plan_id"], "plan_sha256": approval["plan_sha256"],
                        "approval_id": approval["approval_id"], "status": "started", "steps": []}
        self.interrupted = False
        self.held = self.prepared = self.standby = self.old_stopped = False
        self.standby_pid = None
        self.guards, self.adopted, self.preflight_witness = {}, [], {}
        self.ledger = None

    # Journal and small helpers -----------------------------------------
    def step(self, name, **detail):
        self.journal["steps"].append({"step": name, "at": self.host.wall().isoformat(), **detail})
        self.persist()

    def persist(self):
        payload = json.dumps(self.journal, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
        self.host.write(self.run_dir / "receipt.json", payload, mode=0o600)

    def interrupt(self, *_):
        self.interrupted = True

    def check(self):
        if self.interrupted:
            raise Abort("Operator interrupt before the old writer was stopped")

    def require(self, condition, message):
        if not condition:
            raise Abort(message)

    def reload(self):
        return self.host.systemctl("daemon-reload", timeout=60) == 0

    def file(self, path):
        return self.reviewed["files"][str(path)]

    def original(self, path):
        return self.host.read(self.run_dir / ("original-" + Path(path).name))

    def write_planned(self, path):
        spec = self.file(path)
        current = self.host.read(path)
        if (sha256(current) if current is not None else None) != spec["before_sha256"]:
            raise Abort("A planned path changed since review: " + str(path))
        gid = 0 if spec["group"] == "root" else self.host.group(spec["group"])
        self.host.write(path, spec["content"].encode(), mode=int(spec["mode"], 8), gid=gid)

    def restore_planned(self, path):
        """Return one planned path to its reviewed prior content; refuse foreign edits."""
        spec = self.file(path)
        current = self.host.read(path)
        digest = sha256(current) if current is not None else None
        if digest == spec["before_sha256"]:
            return True
        if digest != spec["after_sha256"]:
            return False
        if spec["before_sha256"] is None:
            self.host.remove(path)
            return True
        original = self.original(path)
        if original is None or sha256(original) != spec["before_sha256"]:
            return False
        self.host.write(path, original, mode=int(spec["mode"], 8))
        return True

    def unit(self, name, properties=UNIT_PROPERTIES):
        return observe_unit(self.host, name, properties)

    def observe(self, name, properties=FAST_PROPERTIES):
        """After the stop, a failed observation must never end the monitor loop."""
        try:
            return observe_unit(self.host, name, properties)
        except (OSError, ValueError):
            return None

    def facts(self):
        try:
            return self.ledger.facts()
        except (OSError, ValueError):
            return None

    def same_process(self, record, observed):
        if (observed is None or observed["active"] != "active" or observed["pid"] != record["pid"]
                or observed["invocation"] != record["invocation"] or observed["restarts"] != record["restarts"]):
            return False
        try:
            return self.host.identity(observed["pid"]) == record["identity"]
        except (OSError, ValueError):
            return False

    def standby_ready(self, observed):
        if observed is None:
            return False
        status = parse_status(observed["status"])
        try:
            fresh = 0 <= self.host.monotonic_ns() - int(status["checked_ns"]) <= 1_000_000_000  # refreshed every 0.5s
            same = int(status["pid"]) == observed["pid"] and int(status["lock_inode"]) == self.reviewed["lock"]["inode"]
        except (KeyError, ValueError):
            return False
        return (observed["active"] == "activating" and status["_"] == "standby-ready" and status.get("writer") == "false"
                and fresh and same and (self.standby_pid is None or observed["pid"] == self.standby_pid))

    def guard_ready(self, identifier, observed):
        status = parse_status(observed["status"])
        return (observed["active"] == "active" and observed["sub"] == "running" and status["_"] == "member-guard-ready"
                and status.get("worker") == identifier and status.get("phase") == "running")

    def fresh_after(self, facts, instant, required=None, limit=2.0):
        """Each required worker (default: all) has a persisted sample newer than `instant`."""
        required = set(self.units["workers"]) if required is None else set(required)
        workers = running_workers(facts)
        if not required <= set(workers):
            return False
        ages = sample_ages(facts, self.host.wall())
        return all(ages[key] <= limit and parse_instant(workers[key][1]["last_sample_at"]) > instant for key in required)

    def live_workers(self):
        return [key for key, value in self.units["workers"].items()
                if self.same_process(self.reviewed["processes"]["workers"][key], self.observe(value["unit"], UNIT_PROPERTIES))]

    def exclusive(self, pid):
        try:
            return self.host.lock_identity() == self.reviewed["lock"] and self.host.lock_holders() == [{"pid": pid, "mode": "WRITE"}]
        except (OSError, ValueError):
            return False

    # Preparation (reversible; no Core or writer is changed) -------------
    def verify_plan(self):
        fresh = build_plan(self.host, self.layout, self.renderer, new_release_id=self.reviewed["new_release_id"],
                           plan_id=self.plan["plan_id"], parameters=self.parameters, measurements=self.plan["measurements"])
        self.require(fresh["reviewed"] == self.reviewed, "Reviewed facts changed since the approved plan")
        blocking = [issue["message"] for issue in fresh["issues"] if not issue["volatile"]]
        self.require(not blocking, "Current state has unresolved blocking issues: " + "; ".join(blocking))
        self.steal_at_verification = self.host.steal_seconds()
        self.step("plan_reverified")

    def hold_control(self):
        self.require(self.host.read(self.layout.control) == LAUNCHER, "Management entry differs from the reviewed launcher")
        self.host.write(self.layout.control, HOLD, mode=0o755)
        self.held = True
        self.step("management_held")
        deadline, quiet = self.host.monotonic() + self.parameters["control_drain_timeout"], 0
        while quiet < 3:
            self.check()
            quiet = quiet + 1 if not self.host.control_processes() else 0
            self.require(quiet >= 3 or self.host.monotonic() <= deadline, "In-flight management calls did not finish")
            self.host.sleep(0.1)
        self.step("management_drained")

    def release_control(self):
        if not self.held:
            return
        current = self.host.read(self.layout.control)
        if current == HOLD:
            self.host.write(self.layout.control, LAUNCHER, mode=0o755)
        self.journal["management_entry"] = "restored" if current in {HOLD, LAUNCHER} else "unexpected content left for review"
        self.held = False

    def require_witness(self, wait):
        deadline, observed = self.host.monotonic() + wait, {}
        while True:
            self.check()
            for identifier, value in self.members.items():
                pid = self.reviewed["processes"]["workers"][identifier]["pid"]
                observed[identifier] = self.host.witness(pid, value["public_port"])["established"]
            if all(observed.values()):
                return observed
            self.require(self.host.monotonic() < deadline, "A member has no live VLESS TCP witness connection")
            self.host.sleep(0.5)

    def backup(self):
        facts = self.ledger.facts()
        self.require(facts["meta"].get("revision") == self.reviewed["ledger"]["revision"] and not facts["jobs_active"],
                     "A management change happened after review")
        path = self.run_dir / "pre-handoff.sqlite3"
        self.host.write(path, self.ledger.backup(), mode=0o600)
        self.host.normalize_backup(path)
        payload = self.host.read(path)
        policy = json.loads(self.host.read(self.layout.policy))
        result = self.host.migration_check(self.layout.prefix / "releases" / self.reviewed["new_release_id"], path, policy)
        self.journal["backup"] = {"path": str(path), "sha256": sha256(payload), "bytes": len(payload),
                                  "automatic_restore": False, "additive_migration": result}
        self.step("backup_and_migration_verified")

    def prepare(self):
        self.check()
        self.host.directory(self.layout.guard_proofs, 0o750, self.host.group(self.layout.project_group))
        for path, spec in self.reviewed["files"].items():
            if spec["before_sha256"] is not None:
                current = self.host.read(path)
                self.require(current is not None and sha256(current) == spec["before_sha256"], "A replaced file changed since review")
                self.host.write(self.run_dir / ("original-" + Path(path).name), current, mode=0o600)
        self.prepared = True
        for path, spec in self.reviewed["files"].items():
            if spec["phase"] == "prepare":
                self.write_planned(path)
        self.require(self.reload(), "systemd daemon-reload failed")
        old = self.unit(self.units["old_writer"])
        self.require(self.same_process(self.reviewed["processes"]["old_writer"], old) and old["need_reload"] == "no",
                     "The original writer changed while unit definitions were prepared")
        execution = self.host.show(self.units["old_writer"], ("ExecStart",)).get("ExecStart", "")
        self.require("/releases/" + self.reviewed["previous_release_id"] + "/venv/bin/python" in execution
                     and Path(OLD_POLICY_SNAPSHOT).name in execution, "The pinned fallback definition is not loaded")
        self.step("units_prepared")

    def start_guards(self):
        for identifier, value in self.members.items():
            self.check()
            self.guards[identifier] = None
            self.host.systemctl("start", value["guard"], timeout=self.parameters["guard_ready_timeout"])
            observed = self.unit(value["guard"])
            self.require(self.guard_ready(identifier, observed), "A member guard did not prove a running trusted member")
            self.guards[identifier] = {"pid": observed["pid"], "invocation": observed["invocation"]}
        self.step("guards_ready", guards=len(self.guards))

    def start_standby(self):
        self.check()
        self.standby = True
        self.host.systemctl("start", "--no-block", self.units["new_writer"])
        deadline = self.host.monotonic() + self.parameters["standby_ready_timeout"]
        while True:
            self.check()
            observed = self.unit(self.units["new_writer"])
            if self.standby_ready(observed):
                self.standby_pid = observed["pid"]
                break
            self.require(observed["active"] not in {"active", "failed"} and observed["sub"] != "auto-restart"
                         and self.host.monotonic() <= deadline, "The read-only standby did not become ready")
            self.host.sleep(0.1)
        self.step("standby_ready", pid=self.standby_pid)

    def adopt(self):
        self.check()
        template = self.layout.units / self.layout.member_template
        current = self.host.read(template)
        self.require(current is not None and sha256(current) == self.file(template)["before_sha256"], "Member template changed since review")
        for identifier, value in self.members.items():
            observed = self.unit(value["unit"])
            self.require(self.same_process(self.reviewed["processes"]["workers"][identifier], observed)
                         and not unknown_dropins(self.host, observed["dropins"], value["unit"])
                         and observed["binds_to"] == [self.units["old_writer"]] and observed["fragment"] == str(template)
                         and observed["cgroup"] == "/system.slice/" + value["unit"], "A member changed before dependency adoption")
        for value in self.members.values():
            # Open first: once the default-closed gate drop-in loads, this runtime reset keeps traffic flowing.
            self.require(self.host.systemctl("set-property", "--runtime", value["unit"], *GATE_OPENED) == 0,
                         "A member gate could not be opened before adoption")
        for value in self.members.values():
            unit, gate = self.layout.units / value["unit"], gate_path(self.layout, value["unit"])
            self.adopted.extend([str(unit), str(gate)])
            self.write_planned(unit)
            self.host.directory(gate.parent, 0o755, 0)
            self.write_planned(gate)
        self.require(self.reload(), "systemd daemon-reload failed")
        for identifier, value in self.members.items():
            observed = self.unit(value["unit"])
            self.require(self.same_process(self.reviewed["processes"]["workers"][identifier], observed) and observed["need_reload"] == "no"
                         and not observed["binds_to"] and value["guard"] in observed["wants"] and value["guard"] in observed["after"]
                         and self.units["old_writer"] not in observed["after"] and not observed["ip_deny"]
                         and unknown_dropins(self.host, observed["dropins"], value["unit"]) == [str(gate_path(self.layout, value["unit"]))]
                         and observed["fragment"] == str(self.layout.units / value["unit"]),
                         "The actual member dependency and gate transfer was not proven")
        self.step("dependencies_adopted", members=len(self.members))

    def gate(self):
        """Every switch precondition, proven again immediately before the stop."""
        self.check()
        self.require(self.host.read(self.layout.control) == HOLD and not self.host.control_processes(), "Management is not held and quiescent")
        policy = self.host.read(self.layout.policy)
        self.require(policy is not None and sha256(policy) == self.reviewed["policy_sha256"], "Root policy changed")
        registry = self.host.read(self.layout.registry)
        self.require((sha256(registry) if registry is not None else None) == self.reviewed["registry_sha256"],
                     "A root worker operation happened during preparation")
        old = self.reviewed["processes"]["old_writer"]
        self.require(self.same_process(old, self.unit(self.units["old_writer"])), "The original writer is not the same live process")
        self.require(self.exclusive(old["pid"]), "The single writer lock is not held by the original writer")
        self.require(self.standby_ready(self.unit(self.units["new_writer"])), "The standby is not freshly ready")
        for identifier, value in self.members.items():
            observed, record = self.unit(value["guard"]), self.guards[identifier]
            self.require(self.guard_ready(identifier, observed) and observed["pid"] == record["pid"]
                         and observed["invocation"] == record["invocation"], "A member guard is not the same ready process")
        for identifier, value in self.units["workers"].items():
            observed = self.unit(value["unit"])
            self.require(self.same_process(self.reviewed["processes"]["workers"][identifier], observed),
                         "A registered Core is not the same live process")
            self.require(value["role"] != "member" or (not observed["binds_to"] and value["guard"] in observed["wants"]),
                         "A member is not owned by its own guard")
            self.require(value["role"] != "member" or not observed["ip_deny"], "A member gate is closed")
        facts, now, ledger = self.ledger.facts(), self.host.wall(), self.reviewed["ledger"]
        self.require(facts["meta"].get("revision") == ledger["revision"] and not facts["jobs_active"]
                     and facts["incidents_total"] == ledger["incidents_total"] and not facts["meta"].get("agent_recovery_only")
                     and (facts["cycle"] or {}).get("id") == ledger["cycle_id"], "Ledger state changed since review")
        users = {user["id"]: user for user in facts["users"]}
        for worker in facts["workers"]:
            value = self.units["workers"].get(worker["worker_id"])
            if value is not None:
                self.require(not worker_problems(worker, users.get(worker["user_id"]), value["role"], self.parameters, now, facts["cycle"]),
                             "A worker is no longer settled, trusted and authorized")
        self.require(self.fresh_after(facts, dt.datetime.min.replace(tzinfo=dt.timezone.utc)), "Ledger samples are not fresh")
        current = self.require_witness(min(5.0, self.parameters["witness_wait_seconds"]))
        # Only a session open since before preparation counts; a probe or scanner that
        # appears for a moment cannot stand in for a member's real long-lived client.
        witness = {key: sorted(set(value) & set(self.preflight_witness[key])) for key, value in current.items()}
        self.require(all(witness.values()), "No member TCP session lasted through preparation; keep one real client connected")
        self.step("gate_passed", witness={key: len(value) for key, value in witness.items()})
        return {"facts": facts, "witness": witness}

    # Switch (point of no return once the original writer is stopped) ---
    def takeover(self, baseline):
        parameters, reserve = self.parameters, self.plan["measurements"]["fallback_reserve_seconds"]
        window = parameters["takeover_deadline"] + parameters["safety_margin"]
        old_pid = self.reviewed["processes"]["old_writer"]["pid"]
        began = self.host.monotonic()
        deadline, history = began + parameters["fresh_moment_timeout"], []
        while True:
            self.check()
            facts = self.ledger.facts()
            decided = self.host.monotonic()
            age, other = split_ages(sample_ages(facts, self.host.wall()), self.members)
            # Wait for the best phase of the writer's own cadence seen over the last cycle.
            history = [(at, value) for at, value in history if decided - at <= 1.6] + [(decided, age)]
            settled = decided - began >= 1.1 and age <= min(value for _, value in history) + 0.06
            available = FRESHNESS_LIMIT - age - window
            if (settled and age <= parameters["max_sample_age_at_stop"] and available >= reserve and other + window <= FRESHNESS_LIMIT
                    and self.exclusive(old_pid) and self.standby_ready(self.unit(self.units["new_writer"], FAST_PROPERTIES))):
                break
            self.require(self.host.monotonic() <= deadline, "No safe stop moment: the remaining sample budget could not also cover a fallback")
            self.host.sleep(0.015)
        stolen = round(self.host.steal_seconds() - self.steal_at_verification, 3)
        self.journal["host_steal_before_stop_seconds"] = stolen
        self.require(stolen <= parameters["max_steal_before_stop"],
                     "The hypervisor paused this VM after verification; the old writer was not stopped")
        stopped_mono, stopped_wall = self.host.monotonic(), self.host.wall()
        guard_deadline = decided + FRESHNESS_LIMIT - age  # Member guards expire from the observed age, not from now.
        takeover_deadline = stopped_mono + parameters["takeover_deadline"]
        self.old_stopped = True  # Point of no return.
        self.host.systemctl("stop", "--no-block", self.units["old_writer"])
        timings, killed = {}, False
        self.journal["takeover"] = {"max_ledger_age_at_stop": round(age, 3), "available_for_fallback": round(available, 3),
                                    "fallback_reserve": reserve, "timings": timings}
        while True:
            elapsed = self.host.monotonic() - stopped_mono
            old = self.observe(self.units["old_writer"])
            new = self.observe(self.units["new_writer"])
            if old is not None and old["pid"] == 0:
                timings.setdefault("old_writer_exited", round(elapsed, 3))
            if not killed and old is not None and old["pid"] == old_pid and elapsed >= parameters["old_writer_kill_after"]:
                self.host.systemctl("kill", "--signal=SIGKILL", "--kill-whom=all", self.units["old_writer"])
                killed = timings["old_writer_killed"] = True
            if new is not None and new["active"] == "active" and new["pid"] == self.standby_pid and self.exclusive(self.standby_pid):
                # The new writer owns the lock: a cold fallback could only be slower, never safer.
                timings.setdefault("new_writer_ready", round(elapsed, 3))
                facts = self.facts()
                if parse_status(new["status"])["_"] == "writer-ready" and facts is not None and self.fresh_after(facts, stopped_wall):
                    timings["post_stop_samples_persisted"] = round(self.host.monotonic() - stopped_mono, 3)
                    self.step("writer_taken_over")
                    return True
                if self.host.monotonic() >= guard_deadline + 1.0:
                    self.journal["status"] = "taken_over_writer_review_required"
                    self.step("takeover_samples_unverified")
                    return False
            elif new is not None and (new["active"] in {"failed", "inactive", "deactivating"} or new["sub"] in {"auto-restart", "failed", "dead"}
                                      or new["pid"] != self.standby_pid):
                # A crashed standby shows activating/auto-restart with no PID under Restart=on-failure.
                return self.fallback("new writer exited", stopped_mono, guard_deadline)
            elif self.host.monotonic() >= takeover_deadline:
                return self.fallback("takeover deadline passed", stopped_mono, guard_deadline)
            self.host.sleep(0.02)

    def fallback(self, reason, stopped_mono, guard_deadline):
        """Best effort inside the remaining deadline; guards stay fail-closed."""
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
        restart_wall = self.host.wall()
        self.host.systemctl("start", "--no-block", self.units["old_writer"])
        fresh_at, watch_until, paused = None, guard_deadline + 10.0, set()
        while self.host.monotonic() < watch_until:
            # A guard whose samples aged past its limit closes the gate: traffic pauses, the Core stays.
            paused |= {key for key, value in self.members.items() if (self.observe(value["unit"], ("IPAddressDeny",)) or {}).get("ip_deny")}
            old = self.observe(self.units["old_writer"])
            if old is not None and old["active"] == "active" and self.exclusive(old["pid"]):
                # A Core already stopped by its guard can never sample again; it is reported below.
                facts = self.facts()
                if facts is not None and self.fresh_after(facts, restart_wall, self.live_workers()):
                    fresh_at = self.host.monotonic()
                    break
            self.host.sleep(0.05)
        interrupted = [key for key in self.members if key not in self.live_workers()]
        record.update({"old_writer_fresh_after": round(fresh_at - stopped_mono, 3) if fresh_at else None,
                       "within_sample_deadline": bool(fresh_at and fresh_at <= guard_deadline),
                       "members_interrupted": len(interrupted), "members_traffic_paused": len(paused)})
        if fresh_at is None:
            self.journal["status"] = "fallback_failed_manual_review"
            self.step("fallback_failed")
            return False
        # Only now that the original writer samples again may members be bound back to it.
        restored = self.restore_dependencies()
        if restored:
            self.stop_guards()
            restored = all([self.restore_planned(path) for path, spec in self.reviewed["files"].items() if spec["phase"] == "prepare"])
            restored = self.reload() and restored
        self.journal["status"] = ("fallback_complete_members_preserved" if restored and not interrupted else
                                  "fallback_complete_members_interrupted" if restored else "fallback_dependency_review_required")
        self.step("fallback_finished")
        return False

    def restore_dependencies(self):
        for path in list(self.adopted):
            if not self.restore_planned(Path(path)):
                return False
        if not self.reload():
            return False
        for value in self.members.values():
            # A guard may have closed the gate meanwhile; a restored member is never left closed.
            if self.host.systemctl("set-property", "--runtime", value["unit"], *GATE_OPENED) != 0:
                return False
            observed = self.observe(value["unit"], UNIT_PROPERTIES)
            if observed is None or (observed["active"] == "active" and (observed["binds_to"] != [self.units["old_writer"]] or observed["ip_deny"])):
                return False
        self.adopted = []
        return True

    def stop_guards(self):
        for identifier in list(self.guards):
            self.host.systemctl("stop", self.members[identifier]["guard"])
        self.guards = {}

    def accept(self, baseline):
        end, samples, health, preservation = self.host.monotonic() + self.parameters["acceptance_seconds"], 0, set(), set()
        facts = None
        while True:
            facts = self.facts()
            samples += 1
            new = self.observe(self.units["new_writer"])
            if new is None or new["active"] != "active" or new["pid"] != self.standby_pid or parse_status(new["status"])["_"] != "writer-ready":
                health.add("the new writer is not the steady writer")
            old = self.observe(self.units["old_writer"])
            if old is None or old["pid"] or not self.exclusive(self.standby_pid):
                health.add("the single writer lock is not held by the new writer alone")
            if facts is None or not self.fresh_after(facts, dt.datetime.min.replace(tzinfo=dt.timezone.utc)):
                health.add("ledger samples are not advancing")
            elif facts["incidents_total"] != baseline["facts"]["incidents_total"] or facts["jobs_active"]:
                health.add("a metering incident or managed operation appeared")
            for identifier, value in self.members.items():
                guard = self.observe(value["guard"])
                if guard is None or not self.guard_ready(identifier, guard) or guard["pid"] != self.guards[identifier]["pid"]:
                    preservation.add("a member guard restarted or stopped")
            for identifier, value in self.units["workers"].items():
                observed = self.observe(value["unit"], UNIT_PROPERTIES)
                if not self.same_process(self.reviewed["processes"]["workers"][identifier], observed):
                    preservation.add("a registered Core restarted or stopped")
                elif value["role"] == "member" and observed["ip_deny"]:
                    preservation.add("a member gate closed")
            if self.host.monotonic() >= end and samples >= 2:
                break
            self.host.sleep(0.5)
        if facts is not None:
            before = {user["id"]: user for user in baseline["facts"]["users"]}
            for user in facts["users"]:
                old = before.get(user["id"])
                if old is None or not old["last_sample_at"] or not user["last_sample_at"] or old["epoch_sha256"] != user["epoch_sha256"]:
                    continue
                used = user["used_upload"] + user["used_download"] - old["used_upload"] - old["used_download"]
                raw = user["last_uplink"] + user["last_downlink"] - old["last_uplink"] - old["last_downlink"]
                if used != raw or used < 0:
                    health.add("counter continuity is not exact across the handoff")
        preserved = {}
        for identifier, value in self.members.items():
            pid = self.reviewed["processes"]["workers"][identifier]["pid"]
            try:
                current = set(self.host.witness(pid, value["public_port"])["established"])
            except OSError:
                current = set()
            preserved[identifier] = len(current & set(baseline["witness"][identifier]))
            if not preserved[identifier]:
                preservation.add("no pre-switch member TCP witness connection survived")
        self.journal["acceptance"] = {"writer_health": sorted(health) or "passed", "connection_preservation": sorted(preservation) or "passed",
                                      "witness_connections_preserved": preserved, "observations": samples}
        self.step("acceptance_observed")
        return not health, not preservation

    def finalize(self):
        new_dir = self.layout.prefix / "releases" / self.reviewed["new_release_id"]
        self.host.switch_current(new_dir, self.layout.prefix / "releases" / self.reviewed["previous_release_id"])
        if self.host.current_release().name != self.reviewed["new_release_id"]:
            raise ValueError("Current release switch was not confirmed")
        self.write_planned(self.layout.units / self.layout.member_template)
        if not self.reload():
            raise ValueError("systemd daemon-reload failed")
        for value in self.members.values():
            observed = self.unit(value["unit"])
            if (observed["fragment"] != str(self.layout.units / value["unit"]) or observed["binds_to"]
                    or value["guard"] not in observed["wants"] or observed["ip_deny"]):
                raise ValueError("A member stopped using its complete gated unit")
        self.host.systemctl("disable", self.units["old_writer"])
        self.host.systemctl("enable", self.units["new_writer"])
        if (self.unit(self.units["old_writer"])["file_state"], self.unit(self.units["new_writer"])["file_state"]) != ("disabled", "enabled"):
            raise ValueError("Boot enablement was not confirmed")
        self.journal["certificate_sync_after_switch"] = self.certificate_sync()
        self.step("finalized", current=self.reviewed["new_release_id"])

    def certificate_sync(self):
        """Run the installed sync once on the new code; TLS consumers reload files, no Core restarts."""
        sync = self.reviewed.get("certificate_sync") or {}
        if not sync.get("loaded"):
            return "not_installed"
        code = self.host.systemctl("start", sync["unit"], timeout=60)
        result = self.host.show(sync["unit"], ("Result",)).get("Result")
        return "passed" if code == 0 and result == "success" else "failed"

    def revert(self, reason):
        """Undo preparation in reverse. Never stops a Core or the original writer."""
        self.journal["abort_reason"] = reason
        ok = True
        try:
            if self.adopted:
                ok = self.restore_dependencies()
            if self.standby:
                self.host.systemctl("stop", self.units["new_writer"])
                observed = self.observe(self.units["new_writer"])
                ok = ok and observed is not None and observed["pid"] == 0
            if ok and self.guards:
                self.stop_guards()
            if ok and self.prepared:
                ok = all([self.restore_planned(path) for path, spec in self.reviewed["files"].items() if spec["phase"] == "prepare"])
                ok = self.reload() and ok
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
                    self.start_guards()
                    self.start_standby()
                    self.adopt()
                    baseline = self.gate()
                    if self.takeover(baseline):
                        health, preserved = self.accept(baseline)
                        if health:
                            self.finalize()
                            self.journal["status"] = ("handoff_complete_certificate_sync_failed" if self.journal["certificate_sync_after_switch"] == "failed"
                                                      else "handoff_complete" if preserved else "handoff_complete_preservation_not_proven")
                        else:
                            self.journal["status"] = "taken_over_writer_review_required"
                except Exception as exc:
                    if not isinstance(exc, Abort):
                        # Like main(): only our own messages; foreign exception text may contain values.
                        own = isinstance(exc, (ValueError, HelperError)) and len(str(exc)) < 300
                        self.journal["unexpected_error"] = type(exc).__name__ + (": " + str(exc) if own else "")
                    if not self.old_stopped:
                        self.revert(str(exc) if isinstance(exc, Abort) else "Unexpected failure before the old writer was stopped")
                    elif self.journal["status"] == "started":
                        self.journal["status"] = "manual_review_required"
        finally:
            self.release_control()
            self.persist()
        return self.journal


def stage_release(host, layout, archive, approval):
    """Copy a reviewed portal release into a new immutable directory; nothing else."""
    from .portal_release import inspect_archive
    fields = {"version", "operation", "approved", "approval_id", "archive_sha256", "release_id"}
    if (not isinstance(approval, dict) or set(approval) != fields or approval["version"] != 1
            or approval["operation"] != STAGE_OPERATION or approval["approved"] is not True):
        raise ValueError("A separate explicit staging approval is required")
    canonical_uuid(approval["approval_id"])
    manifest, files = inspect_archive(archive)
    if manifest["_archive_sha256"] != approval["archive_sha256"] or manifest["release_id"] != approval["release_id"]:
        raise ValueError("Approval does not bind this exact archive")
    if platform.machine() != manifest["architecture"]:
        raise ValueError("Release architecture does not match this host")
    destination = layout.prefix / "releases" / manifest["release_id"]
    checked_path(destination.parent, layout.trusted_uid, directory=True)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Keep and inspect the existing release directory")
    destination.mkdir(mode=0o755)
    for name, body in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        atomic_bytes(target, body, mode=0o644, trusted_uid=layout.trusted_uid)
    clean = {key: value for key, value in manifest.items() if not key.startswith("_")}
    atomic_bytes(destination / "release.json", json.dumps(clean, sort_keys=True, indent=2).encode() + b"\n", mode=0o644, trusted_uid=layout.trusted_uid)
    runner = host.runner
    def run(arguments, timeout):
        if runner.run(arguments, timeout=timeout).returncode:
            raise ValueError("An explicit staging command failed")
    run(["/usr/bin/python3", "-m", "venv", str(destination / "venv")], 120)
    python = str(destination / "venv/bin/python")
    run([python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", "--no-cache-dir", "--disable-pip-version-check",
         "--only-binary=:all:", "--require-hashes", "--find-links", str(destination / "wheelhouse"),
         "-r", str(destination / "requirements.txt")], 180)
    site = destination / "venv/lib/python3.12/site-packages"
    shutil.copytree(destination / "backend/dazzle", site / "dazzle")
    shutil.copytree(destination / "deployment", site / "deployment", ignore=shutil.ignore_patterns("systemd", "portal-systemd"))
    check = ("import tempfile,google.protobuf,starlette,uvicorn; from dazzle.store import Store; "
             "from dazzle import production, collector, standby, meter_guard, portal; from deployment import coordinator, helper; "
             "assert google.protobuf.__version__=='7.36.2'; t=tempfile.TemporaryDirectory(); s=Store(t.name); "
             "assert s.conn.execute('PRAGMA quick_check').fetchone()[0]=='ok'; s.close(); t.cleanup()")
    run([python, "-I", "-c", check], 60)
    if host.release_inventory(destination) != manifest["files"]:
        raise ValueError("Staged release does not match its inventory")
    host.directory(layout.handoff, 0o750, host.group(layout.project_group))
    receipt = {"version": 1, "operation": STAGE_OPERATION, "approval_id": approval["approval_id"], "release_id": manifest["release_id"],
               "archive_sha256": manifest["_archive_sha256"], "current_switched": False, "services_changed": False,
               "production_database_opened": False, "at": host.wall().isoformat()}
    host.write(layout.handoff / ("stage-" + manifest["release_id"] + ".json"), json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n", mode=0o600)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description="Target-local exact-approved live writer handoff (phase A)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preview", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--stage", action="store_true")
    parser.add_argument("--new-release-id")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--parameters", type=Path, help="reviewed timing parameters (JSON) for --preview")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0 or platform.system() != "Linux":
            raise ValueError("Target root on Linux is required")
        layout = Layout()
        host = Host(layout)
        if args.stage:
            if not args.archive or not args.approval:
                raise ValueError("Staging requires the archive and its approval")
            result = stage_release(host, layout, args.archive, json.loads(args.approval.read_text()))
        elif args.preview:
            parameters = json.loads(args.parameters.read_text()) if args.parameters else None
            plan = build_plan(host, layout, ReleaseRenderer(), new_release_id=args.new_release_id, parameters=parameters)
            result = {"mode": "preview", "production_modified": False, "plan_sha256": sha256(canonical(plan)), "plan": plan}
        else:
            if not args.plan or not args.approval:
                raise ValueError("Apply requires the exact saved plan and a separate approval")
            plan = json.loads(args.plan.read_text())
            here = Path(__file__).resolve()
            if (layout.prefix / "releases" / plan["reviewed"]["new_release_id"]).resolve() not in here.parents:
                raise ValueError("Apply must run from the staged new release")
            result = Coordinator(host, layout, ReleaseRenderer(), plan, json.loads(args.approval.read_text())).run()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("status", "ok") in {"ok", "handoff_complete"} or args.preview or args.stage else 1
    except Exception as exc:
        # Our own messages only; never echo foreign exception text that may contain values.
        message = str(exc) if isinstance(exc, (ValueError, Abort)) and len(str(exc)) < 300 else "Checks failed"
        print(json.dumps({"ok": False, "error": message, "production_note": "No step beyond the recorded receipt was attempted"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
