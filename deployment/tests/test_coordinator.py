"""Coordinator decisions against a deterministic simulated host. No systemctl, no root."""
import copy
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from deployment import coordinator
from deployment.coordinator import (FRESHNESS_LIMIT, HOLD, LAUNCHER, Coordinator, Host, Layout, LedgerReader,
                                    ReleaseRenderer, build_plan, parse_locks, parse_stalls, parse_status, parse_tcp,
                                    process_identity, sample_ages, validate_parameters)
from deployment.helper import CORE_SHA256
from deployment.installer import canonical, sha256

ROOT = Path(__file__).resolve().parents[1]
UTC = dt.timezone.utc


class FakeLedger:
    def __init__(self, world):
        self.world = world

    def facts(self):
        if self.world.reader_broken:
            raise ValueError("reader stopped")
        return self.world.facts()

    def backup(self):
        return b"SQLite format 3\x00 isolated test image"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class World:
    """systemd units, one writer lock, Core processes and a sampled ledger."""
    def __init__(self):
        self.layout = Layout()
        self.time, self.base = 1000.0, dt.datetime(2026, 10, 25, 4, 0, tzinfo=UTC) - dt.timedelta(seconds=1000)
        self.files, self.dirs, self.calls, self.events = {}, set(), [], []
        self.reader_broken = False
        self.control_busy_until = 0.0
        self.unsafe_paths = set()  # Paths whose file or directory is writable by non-root users.
        self.steal, self.stalls = 0.0, []  # Hypervisor steal seconds and kernel-reported VM pauses.
        self.server_id, self.admin, self.member = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        self.policy = {"version": 1, "server_id": self.server_id, "server_endpoint": "8.8.8.8", "agent_uid": 991,
                       "core_sha256": CORE_SHA256, "workers": {self.admin: {"role": "admin", "public_port": 24430, "api_port": 34430},
                                                               self.member: {"role": "member", "public_port": 24431, "api_port": 34431}}}
        for path in ("/etc/dazzle-vps", "/etc/systemd/system", "/usr/local/bin", "/opt/dazzle-vps/releases"):
            self.dirs.add(path)
        self.files["/etc/dazzle-vps/policy.json"] = canonical(self.policy) + b"\n"
        self.files["/etc/dazzle-vps/registry.json"] = b'{"version":1}\n'
        self.files["/usr/local/bin/dazzle-vps-control"] = LAUNCHER
        writer, member = (ROOT / "systemd/dazzle-vps-agent.service").read_bytes(), (ROOT / "systemd/dazzle-proxy@.service").read_bytes()
        self.files["/etc/systemd/system/dazzle-vps-agent.service"] = writer
        self.files["/etc/systemd/system/dazzle-proxy@.service"] = member
        self.old_inventory = {"deployment/systemd/dazzle-vps-agent.service": sha256(writer),
                              "deployment/systemd/dazzle-proxy@.service": sha256(member), "backend/dazzle/production.py": "a" * 64}
        self.old_release = sha256(canonical(self.old_inventory))[:24]
        templates = {name: (ROOT / "portal-systemd" / name).read_bytes() for name in ("meter-guard@.service", "writer@.service", "guarded-member.service")}
        self.new_inventory = {"deployment/portal-systemd/" + name: sha256(body) for name, body in templates.items()}
        self.new_release = sha256(canonical(self.new_inventory))[:24]
        new_dir = "/opt/dazzle-vps/releases/" + self.new_release
        for name, body in templates.items():
            self.files[new_dir + "/deployment/portal-systemd/" + name] = body
        self.files[new_dir + "/release.json"] = json.dumps({"release_id": self.new_release, "files": self.new_inventory}).encode()
        self.current = self.old_release
        self.w1, self.w2 = "dazzle-vps-agent.service", "dazzle-vps-writer@" + self.new_release + ".service"
        self.guard, self.member_unit = "dazzle-vps-meter-guard@" + self.member + ".service", "dazzle-proxy@" + self.member + ".service"
        self.admin_unit = "dazzle-admin@" + self.admin + ".service"
        self.next_pid = 6000
        self.units = {
            self.w1: self.unit("writer_old", 4100, fragment="/etc/systemd/system/dazzle-vps-agent.service", file_state="enabled",
                               exec_start_us=1_000_000, active_enter_us=2_200_000),
            self.admin_unit: self.unit("admin", 4200, fragment="/etc/systemd/system/dazzle-admin@.service"),
            self.member_unit: self.unit("member", 4300, fragment="/etc/systemd/system/dazzle-proxy@.service",
                                        binds_to=[self.w1], after=["network-online.target", self.w1]),
        }
        self.exec_start = {self.w1: self.exec_line(writer)}
        self.identities = {4100: "4100:11", 4200: "4200:12", 4300: "4300:13"}
        self.connections = {4300: [9001, 9002]}
        # Like the production collector: one 1 s native stream per worker at its own
        # phase, persisted only on the writer's next drain tick, stamped with the frame time.
        self.lock_holder, self.persisting, self.frames = 4100, {4100}, {}
        self.phases, self.drain_lag = {self.member: 0.0, self.admin: 0.45}, 0.4
        self.revision, self.incidents = 7, 2
        self.users = {
            self.admin: {"id": self.admin, "role": "admin", "manual_disabled": 0, "revoked_at": None, "deleted_at": None,
                         "reasons_json": "[]", "trusted_sample": 1, "meter_state": "trusted", "unlimited": 1, "quota_bytes": None,
                         "topup_bytes": 0, "credential_version": 1},
            self.member: {"id": self.member, "role": "member", "manual_disabled": 0, "revoked_at": None, "deleted_at": None,
                          "reasons_json": "[]", "trusted_sample": 1, "meter_state": "trusted", "unlimited": 0,
                          "quota_bytes": 100_000_000_000, "topup_bytes": 0, "credential_version": 2},
        }
        for user in self.users.values():
            user.update(last_sample_at=self.iso(self.time - 0.7), last_uplink=5_000, last_downlink=50_000,
                        used_upload=4_000, used_download=40_000, epoch_sha256="e" * 64)
        self.pid_of = {self.admin: 4200, self.member: 4300}
        for identifier, phase in self.phases.items():
            self.frames[(4100, identifier)] = self.time + 0.3 + phase
        # Behaviour knobs.
        self.takeover_mode, self.takeover_delay, self.standby_delay = "ok", 0.25, 1.0
        self.old_stop_delay, self.old_cold_start, self.standby_warming = 0.3, 1.5, False
        self.standby_ready_at, self.reloads, self.hooks = None, 0, {}
        self.certsync_outcome, self.certsync_runs = None, []  # None: no certificate sync unit installed

    def install_certsync(self, outcome):
        self.certsync_outcome = outcome
        self.units["dazzle-vps-certsync.service"] = dict(self.unit("oneshot", 0), active="inactive", sub="dead", result="success",
                                                         dropins="/etc/systemd/system/dazzle-vps-certsync.service.d/20-direct-acme.conf")

    def unit(self, kind, pid, *, fragment="", binds_to=None, after=None, file_state="static", exec_start_us=0, active_enter_us=0):
        return {"kind": kind, "load": "loaded", "active": "active", "sub": "running", "pid": pid, "invocation": "inv-" + str(pid),
                "restarts": 0, "fragment": fragment, "dropins": "", "binds_to": binds_to or [], "after": after or ["network-online.target"],
                "status": "", "file_state": file_state, "exec_start_us": exec_start_us, "active_enter_us": active_enter_us}

    @staticmethod
    def exec_line(unit_bytes):
        line = next(line for line in unit_bytes.decode().splitlines() if line.startswith("ExecStart="))
        program = line.split("=", 1)[1].split()[0]
        return "{ path=" + program + " ; argv[]=" + line.split("=", 1)[1] + " ; ignore_errors=no }"

    def iso(self, moment):
        return (self.base + dt.timedelta(seconds=moment)).isoformat()

    def wall(self):
        return self.base + dt.timedelta(seconds=self.time)

    # Simulation ---------------------------------------------------------
    def advance(self, seconds):
        target = self.time + seconds
        while self.time < target - 1e-9:
            self.time = min(target, self.time + 0.005)
            self.tick()

    def at(self, delay, action):
        self.events.append((self.time + delay, action))

    def pid(self):
        self.next_pid += 1
        self.identities[self.next_pid] = str(self.next_pid) + ":" + str(int(self.time))
        return self.next_pid

    def exit(self, name, state="inactive"):
        unit = self.units[name]
        if unit["pid"] == self.lock_holder:
            self.lock_holder = None
        self.persisting.discard(unit["pid"])
        self.connections.pop(unit["pid"], None)
        unit.update(active=state, sub="dead" if state == "inactive" else "failed", pid=0)

    def record(self, identifier, frame):
        unit = self.units[self.member_unit if identifier == self.member else self.admin_unit]
        if unit["pid"] != self.pid_of[identifier]:
            return
        user = self.users[identifier]
        if (self.base + dt.timedelta(seconds=frame) - dt.datetime.fromisoformat(user["last_sample_at"])).total_seconds() > FRESHNESS_LIMIT:
            self.incidents += 1
            user.update(trusted_sample=0, meter_state="reconciliation_required")
        user.update(last_sample_at=self.iso(frame), last_uplink=user["last_uplink"] + 1000, last_downlink=user["last_downlink"] + 9000,
                    used_upload=user["used_upload"] + 1000, used_download=user["used_download"] + 9000)

    def start_writer(self, pid, *, seed, first):
        """A new writer opens fresh streams: optional seed transaction, then per-worker frames."""
        self.persisting.add(pid)
        if seed:
            for identifier in self.pid_of:
                self.record(identifier, self.time)
        for identifier in self.pid_of:
            self.frames[(pid, identifier)] = self.time + first

    def tick(self):
        for due, action in sorted([event for event in self.events if event[0] <= self.time], key=lambda event: event[0]):
            self.events.remove((due, action))
            action()
        for (pid, identifier), due in list(self.frames.items()):
            if pid not in self.persisting:
                del self.frames[(pid, identifier)]
            elif self.time >= due:
                self.frames[(pid, identifier)] = due + 1.0
                self.at(self.drain_lag, lambda pid=pid, identifier=identifier, frame=self.time:
                        pid in self.persisting and self.record(identifier, frame))
        w2 = self.units.get(self.w2)
        if w2 and w2["active"] == "activating" and w2.get("role") == "standby" and self.standby_ready_at is not None:
            if self.standby_warming:
                w2["status"] = "standby-warming; writer=false"
            elif self.time >= self.standby_ready_at:
                checked = self.standby_ready_at + int((self.time - self.standby_ready_at) / 0.5) * 0.5
                w2["status"] = "standby-ready; writer=false; pid=%d; lock_inode=777; checked_ns=%d" % (w2["pid"], int(checked * 1e9))
            if self.lock_holder is None and not w2.get("taking") and not self.standby_warming:
                w2["taking"] = True
                self.at(self.takeover_delay, self.take_over)
        guard = self.units.get(self.guard)
        member = self.units[self.member_unit]
        if guard and guard["active"] == "active":
            age = (self.wall() - dt.datetime.fromisoformat(self.users[self.member]["last_sample_at"])).total_seconds()
            if member["pid"] != 4300 or age > FRESHNESS_LIMIT:
                self.exit(self.guard)
        if member["active"] == "active" and any(self.units.get(name, {"active": "inactive"})["active"] in {"inactive", "failed", "deactivating"}
                                               for name in member["binds_to"]):
            self.exit(self.member_unit)

    def warm_off(self):
        # The real standby rewrites STATUS within one 0.1s verify loop when it stops being ready.
        self.standby_warming = True
        self.units[self.w2]["status"] = "standby-warming; writer=false"

    def take_over(self):
        w2 = self.units[self.w2]
        if w2["active"] != "activating" or self.lock_holder is not None:
            return
        if self.takeover_mode == "fail":
            self.exit(self.w2, "failed")
            return
        self.lock_holder = w2["pid"]
        w2["role"] = "writer"
        if self.takeover_mode == "hang":
            return
        self.start_writer(w2["pid"], seed=True, first=1.0)
        status = "writer-recovery; reconciliation-required=true" if self.takeover_mode == "recovery" else "writer-ready; trusted-samples=true"
        w2.update(active="active", sub="running", status=status)

    # Host interface -----------------------------------------------------
    def systemctl(self, *arguments, timeout=30):
        self.calls.append(arguments)
        verb, rest = arguments[0], [value for value in arguments[1:] if not value.startswith("--")]
        name = rest[0] if rest else None
        if verb == "daemon-reload":
            self.reload()
        elif verb == "start" and name == self.w2:
            self.units[self.w2] = dict(self.unit("writer_new", self.pid(), fragment="/etc/systemd/system/dazzle-vps-writer@.service"),
                                       active="activating", sub="start", role="standby")
            self.standby_ready_at = self.time + self.standby_delay
        elif verb == "start" and name == self.guard:
            age = (self.wall() - dt.datetime.fromisoformat(self.users[self.member]["last_sample_at"])).total_seconds()
            healthy = self.units[self.member_unit]["pid"] == 4300 and age <= FRESHNESS_LIMIT
            self.units[self.guard] = dict(self.unit("guard", self.pid() if healthy else 0),
                                          status="member-guard-ready; worker=%s; phase=running" % self.member if healthy else "",
                                          active="active" if healthy else "failed")
        elif verb == "start" and name == self.w1:
            unit = self.units[self.w1]
            unit.update(active="activating", sub="start", pid=self.pid(), invocation="inv-fallback")
            def ready():
                if self.lock_holder is None:
                    self.lock_holder = unit["pid"]
                    unit.update(active="active", sub="running")
                    self.start_writer(unit["pid"], seed=False, first=0.0)
                else:
                    self.exit(self.w1, "failed")
            self.at(self.old_cold_start, ready)
        elif verb == "stop" and name == self.w1:
            unit = self.units[self.w1]
            unit["active"] = "deactivating"
            self.persisting.discard(unit["pid"])
            self.at(self.old_stop_delay, lambda: self.exit(self.w1))
        elif verb == "stop" and name in self.units:
            if "--no-block" in arguments and self.units[name]["kind"] == "writer_new":
                self.at(0.1, lambda: self.exit(name))
            else:
                self.exit(name)
        elif verb == "kill" and name in self.units:
            self.exit(name, "failed")
        elif verb == "start" and name == "dazzle-vps-certsync.service" and self.certsync_outcome:
            self.certsync_runs.append(self.current)
            self.units[name]["result"] = self.certsync_outcome
            return 0 if self.certsync_outcome == "success" else 1
        elif verb in {"enable", "disable"} and name in self.units:
            self.units[name]["file_state"] = verb + "d"
        return 0

    def reload(self):
        self.reloads += 1
        self.hooks.pop(self.reloads, lambda: None)()
        for name, unit in self.units.items():
            if unit["kind"] == "member":
                path = "/etc/systemd/system/" + name
                source = self.files.get(path) or self.files["/etc/systemd/system/dazzle-proxy@.service"]
                unit["fragment"] = path if path in self.files else "/etc/systemd/system/dazzle-proxy@.service"
                lines = source.decode().splitlines()
                unit["binds_to"] = next(line for line in lines if line.startswith("BindsTo=")).split("=", 1)[1].split()
                unit["after"] = next(line for line in lines if line.startswith("After=")).split("=", 1)[1].split()
        self.exec_start[self.w1] = self.exec_line(self.files["/etc/systemd/system/dazzle-vps-agent.service"])

    def show(self, name, properties):
        unit = self.units.get(name)
        if unit is None:
            loaded = (name.startswith("dazzle-vps-writer@") and "/etc/systemd/system/dazzle-vps-writer@.service" in self.files or
                      name.startswith("dazzle-vps-meter-guard@") and "/etc/systemd/system/dazzle-vps-meter-guard@.service" in self.files)
            unit = self.unit("absent", 0)
            unit.update(load="loaded" if loaded else "not-found", active="inactive", sub="dead")
        values = {"LoadState": unit["load"], "ActiveState": unit["active"], "SubState": unit["sub"], "MainPID": str(unit["pid"]),
                  "NRestarts": str(unit["restarts"]), "InvocationID": unit["invocation"] if unit["pid"] else "",
                  "FragmentPath": unit["fragment"], "DropInPaths": unit["dropins"], "BindsTo": " ".join(unit["binds_to"]),
                  "After": " ".join(unit["after"]), "StatusText": unit["status"], "UnitFileState": unit["file_state"],
                  "NeedDaemonReload": "no", "ExecMainStartTimestampMonotonic": str(unit["exec_start_us"]),
                  "ActiveEnterTimestampMonotonic": str(unit["active_enter_us"]), "ExecStart": self.exec_start.get(name, ""),
                  "Result": unit.get("result", "")}
        return {key: values[key] for key in properties}

    def facts(self):
        workers = []
        for identifier, worker in self.policy["workers"].items():
            unit = self.units[self.member_unit if identifier == self.member else self.admin_unit]
            workers.append({"worker_id": identifier, "role": worker["role"], "user_id": identifier, "public_port": worker["public_port"],
                            "api_port": worker["api_port"], "generation": 3, "root_ack_generation": 3, "observed_generation": 3,
                            "observed_state": "running", "process_id": self.pid_of[identifier], "origin_pending": 0, "last_error": None,
                            "tombstoned": 0, "credential_version": self.users[identifier]["credential_version"], "provisioned": 1})
        return copy.deepcopy({"meta": {"revision": self.revision, "mode": "production", "server_id": self.server_id, "agent_recovery_only": False},
                              "users": list(self.users.values()), "workers": workers, "jobs_active": 0, "incidents_unresolved": 0,
                              "incidents_latest": None, "incidents_total": self.incidents,
                              "cycle": {"id": "cycle-1", "start_at": self.iso(-86400), "end_at": self.iso(self.time + 10 * 86400)}})


class FakeHost:
    def __init__(self, world):
        self.world, self.layout = world, world.layout

    def systemctl(self, *arguments, timeout=30): return self.world.systemctl(*arguments, timeout=timeout)
    def show(self, unit, properties=coordinator.UNIT_PROPERTIES): return self.world.show(unit, properties)

    def read(self, path):
        return self.world.files.get(str(path))

    def read_trusted(self, path):
        if str(path) not in self.world.files:
            raise ValueError("missing trusted file")
        return self.world.files[str(path)]

    def require_replaceable(self, path):
        if str(path) in self.world.unsafe_paths:
            raise ValueError("Management entry cannot be swapped safely: Unsafe project file ownership or mode")

    def steal_seconds(self): return self.world.steal
    def host_stalls(self, lookback_seconds): return list(self.world.stalls)

    def exists(self, path): return str(path) in self.world.files or str(path) in self.world.dirs

    def write(self, path, payload, *, mode, gid=None):
        if str(Path(path).parent) not in self.world.dirs:
            raise ValueError("parent directory missing: " + str(Path(path).parent))
        self.world.files[str(path)] = bytes(payload)

    def remove(self, path): del self.world.files[str(path)]

    def directory(self, path, mode, gid):
        if str(Path(path).parent) not in self.world.dirs:
            raise ValueError("parent directory missing")
        self.world.dirs.add(str(path))

    def group(self, name): return 1234

    def identity(self, pid):
        if pid not in self.world.identities or not any(unit["pid"] == pid for unit in self.world.units.values()):
            raise ValueError("no such process")
        return self.world.identities[pid]

    def lock_identity(self): return {"device": 2049, "inode": 777}
    def lock_holders(self): return [{"pid": self.world.lock_holder, "mode": "WRITE"}] if self.world.lock_holder else []

    def witness(self, pid, port):
        alive = any(unit["pid"] == pid for unit in self.world.units.values())
        return {"listening": alive, "established": list(self.world.connections.get(pid, [])) if alive else []}

    def control_processes(self): return [77] if self.world.time < self.world.control_busy_until else []
    def monotonic(self): return self.world.time
    def monotonic_ns(self): return int(self.world.time * 1e9)
    def wall(self): return self.world.wall()
    def sleep(self, seconds): self.world.advance(seconds)
    def ledger(self): return FakeLedger(self.world)
    def helper_latency(self, worker_id, count=3): return [0.2, 0.25, 0.21]
    def current_release(self): return Path("/opt/dazzle-vps/releases") / self.world.current

    def release_inventory(self, directory):
        return {self.world.old_release: self.world.old_inventory, self.world.new_release: self.world.new_inventory}[Path(directory).name]

    def switch_current(self, destination, previous):
        assert Path(previous).name == self.world.current
        self.world.current = Path(destination).name

    def migration_check(self, release_dir, backup, policy): return {"ok": True, "production_database_opened": False}
    def normalize_backup(self, path): pass


def approve(plan):
    return {"version": 1, "operation": coordinator.OPERATION, "approved": True, "approval_id": str(uuid.uuid4()),
            "plan_sha256": sha256(canonical(plan)),
            "acknowledgements": {"abort_rather_than_restart_core": True, "fallback_is_best_effort_fail_closed": True,
                                 "registration_stays_closed": True}}


class ParserTests(unittest.TestCase):
    def test_proc_locks_identify_the_exact_flock_owner_and_waiters(self):
        device = os.makedev(0xfd, 0x01)
        text = ("1: FLOCK  ADVISORY  WRITE 2266 fd:01:131098 0 EOF\n2: POSIX  ADVISORY  WRITE 99 fd:01:131098 0 EOF\n"
                "3: FLOCK  ADVISORY  WRITE 31 fd:01:5 0 EOF\n3: -> FLOCK  ADVISORY  WRITE 40 fd:01:131098 0 EOF\n")
        self.assertEqual(parse_locks(text, device, 131098), [{"pid": 2266, "mode": "WRITE"}, {"pid": 40, "mode": "WAITING"}])
        self.assertEqual(parse_locks(text, device, 6), [])

    def test_tcp_rows_keep_local_port_state_and_inode_only(self):
        text = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                "   0: 00000000:5EEF 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 4100 1\n"
                "   1: 0A00000A:5EEF 0B00000B:C350 01 00000000:00000000 00:00000000 00000000   990        0 4101 1\n"
                "   2: 0100007F:868F 0100007F:9A10 01 00000000:00000000 00:00000000 00000000   990        0 4102 1\n")
        self.assertEqual(parse_tcp(text), [(24303, "0A", 4100), (24303, "01", 4101), (34447, "01", 4102)])

    def test_status_and_process_identity_parsing(self):
        status = parse_status("member-guard-ready; worker=abc; phase=running")
        self.assertEqual((status["_"], status["worker"], status["phase"]), ("member-guard-ready", "abc", "running"))
        stat = "321 (sing box) (x) S " + " ".join(str(value) for value in range(1, 30))
        self.assertEqual(process_identity(stat, 321), "321:19")  # field 22, after a comm containing ") ("
        with self.assertRaises(ValueError):
            process_identity(stat, 322)

    def test_kernel_pause_lines_are_parsed_with_their_length(self):
        text = ("1792929085.1 vps kernel: clocksource: Long readout interval, skipping watchdog check: cs_nsec: 7898486955 wd_nsec: 7898482934\n"
                "1792929085.2 vps kernel: sched: RT throttling activated\n"
                "1792929090.0 vps kernel: [UFW BLOCK] IN=ens17 OUT= PROTO=TCP\n")
        self.assertEqual([(stall["kind"], stall["seconds"]) for stall in parse_stalls(text)],
                         [("clocksource_skip", 7.898), ("rt_throttling", None)])

    def test_parameters_cannot_extend_the_deadline_or_drop_the_fallback_budget(self):
        values = validate_parameters()
        self.assertEqual(values["takeover_deadline"], 1.2)
        for change in ({"takeover_deadline": 9.0}, {"max_sample_age_at_stop": 0}, {"freshness_limit": 6}, {"safety_margin": True},
                       {"acceptance_seconds": "3"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_parameters({**values, **change})

    def test_sample_ages_never_turn_missing_or_future_samples_into_fresh(self):
        now = dt.datetime(2026, 10, 25, tzinfo=UTC)
        facts = {"users": [{"id": "a", "last_sample_at": None}, {"id": "b", "last_sample_at": (now + dt.timedelta(seconds=3)).isoformat()},
                           {"id": "c", "last_sample_at": (now - dt.timedelta(seconds=1)).isoformat()}],
                 "workers": [{"worker_id": key, "user_id": key, "tombstoned": 0, "observed_state": "running"} for key in "abc"]}
        ages = sample_ages(facts, now)
        self.assertEqual((ages["a"], ages["b"]), (float("inf"), float("inf")))
        self.assertAlmostEqual(ages["c"], 1.0)


class LedgerReaderTests(unittest.TestCase):
    def test_reader_returns_no_secrets_and_backup_is_a_self_contained_rollback_snapshot(self):
        from dazzle.production import handle_request
        from dazzle.production_state import ProductionStore
        from dazzle.store import utcnow
        folder = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: __import__("shutil").rmtree(folder, ignore_errors=True))
        world = World()
        policy = dict(world.policy, agent_uid=max(os.getuid(), 1))
        store = ProductionStore(folder / "state", policy=policy, initialize=True)
        result = handle_request(store, {"api_version": 1, "request_id": str(uuid.uuid4()), "action": "user.add", "server_id": store.server_id,
                                        "expected_revision": store.revision, "params": {"name": "Reader fixture", "role": "member"}}, utcnow())
        self.assertTrue(result["ok"], result)
        credentials = store.get_credentials(result["data"]["user"]["id"])
        secret = store.worker(result["data"]["user"]["id"])["api_secret"]
        with LedgerReader(folder / "state/state.sqlite3") as reader:
            facts = reader.facts()
            image = reader.backup()
        text = json.dumps(facts)
        for value in (secret, credentials["subscription_token"], credentials["tuic_password"], credentials["vless_uuid"]):
            self.assertNotIn(value, text)
        self.assertEqual(facts["meta"]["server_id"], world.server_id)
        self.assertEqual(facts["jobs_active"], 1)  # The new user's provision job is visible, not hidden.
        backup = folder / "copy.sqlite3"
        backup.write_bytes(image)
        Host(Layout()).normalize_backup(backup)
        self.assertEqual(backup.read_bytes()[18:20], b"\x01\x01")
        connection = sqlite3.connect(backup.as_uri() + "?mode=ro", uri=True)
        self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
        connection.close()
        self.assertEqual(sorted(path.name for path in folder.iterdir()), ["copy.sqlite3", "state"])
        store.close()


class LedgerProtocolTests(unittest.TestCase):
    def test_a_reply_that_arrives_after_its_timeout_is_never_taken_for_a_newer_query(self):
        import subprocess, sys
        script = ("import json,sys,time\n"
                  "for line in sys.stdin:\n"
                  "    request=json.loads(line)\n"
                  "    time.sleep(0.4 if request['id']==1 else 0)\n"
                  "    sys.stdout.write(json.dumps({'ok':True,'id':request['id'],'data':{'answer':request['id']}})+'\\n');sys.stdout.flush()\n")
        reader = LedgerReader.__new__(LedgerReader)
        reader.process = subprocess.Popen([sys.executable, "-I", "-c", script], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        reader.buffer, reader.sequence = b"", 0
        try:
            with self.assertRaises(ValueError):
                reader.query("facts", timeout=0.1)
            self.assertEqual(reader.query("facts", timeout=3), {"answer": 2})
        finally:
            reader.close()


class RendererTests(unittest.TestCase):
    def setUp(self):
        self.renderer = ReleaseRenderer()

    def test_guard_and_writer_are_pinned_to_the_immutable_release_never_current(self):
        guard = self.renderer.guard_template((ROOT / "portal-systemd/meter-guard@.service").read_text(), "b" * 24).decode()
        self.assertIn("ExecStart=/opt/dazzle-vps/releases/" + "b" * 24 + "/venv/bin/python -I -m dazzle.meter_guard", guard)
        self.assertNotIn("@RELEASE_ID@", guard)
        writer = self.renderer.writer_template((ROOT / "portal-systemd/writer@.service").read_text()).decode()
        self.assertIn("/opt/dazzle-vps/releases/%i/venv/bin/python", writer)
        bad_guard = (ROOT / "portal-systemd/meter-guard@.service").read_text().replace("releases/@RELEASE_ID@", "current")
        bad_writer = (ROOT / "portal-systemd/writer@.service").read_text().replace("releases/%i", "current")
        with self.assertRaises(ValueError):
            self.renderer.guard_template(bad_guard, "b" * 24)
        with self.assertRaises(ValueError):
            self.renderer.writer_template(bad_writer)
        with self.assertRaises(ValueError):
            self.renderer.guard_template((ROOT / "portal-systemd/meter-guard@.service").read_text() + "BindsTo=x.service\n", "b" * 24)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.host = FakeHost(self.world)
        self.layout = self.world.layout

    def plan(self, **changes):
        plan = build_plan(self.host, self.layout, ReleaseRenderer(), new_release_id=self.world.new_release, **changes)
        return plan

    def run_coordinator(self, plan=None):
        plan = plan or self.plan()
        self.assertTrue(plan["ready_for_approval"], plan["issues"])
        result = Coordinator(self.host, self.layout, ReleaseRenderer(), plan, approve(plan)).run()
        receipt = json.loads(self.world.files[str(self.layout.handoff / plan["plan_id"] / "receipt.json")])
        self.assertEqual(receipt["status"], result["status"])
        return result

    def assert_never_restarted_a_core(self):
        for call in self.world.calls:
            self.assertNotIn("restart", call)
            self.assertNotIn(self.world.member_unit, call)
            self.assertNotIn(self.world.admin_unit, call)
        self.assertEqual(self.world.files["/usr/local/bin/dazzle-vps-control"], LAUNCHER)

    def assert_original_layout(self):
        self.assertEqual(self.world.current, self.world.old_release)
        self.assertEqual(self.world.files["/etc/systemd/system/dazzle-vps-agent.service"], (ROOT / "systemd/dazzle-vps-agent.service").read_bytes())
        for path in ("/etc/systemd/system/" + self.world.member_unit, "/etc/systemd/system/dazzle-vps-meter-guard@.service",
                     "/etc/systemd/system/dazzle-vps-writer@.service", str(self.layout.snapshot)):
            self.assertNotIn(path, self.world.files)
        self.assertEqual(self.world.units[self.world.member_unit]["binds_to"], [self.world.w1])

    def test_preview_is_read_only_and_reports_exact_rendered_changes(self):
        before = copy.deepcopy(self.world.files)
        plan = self.plan()
        self.assertEqual(self.world.files, before)
        self.assertEqual(self.world.calls, [])
        self.assertTrue(plan["ready_for_approval"], plan["issues"])
        files = plan["reviewed"]["files"]
        self.assertEqual(files["/etc/systemd/system/" + self.world.member_unit]["phase"], "adopt")
        self.assertIn("BindsTo=" + self.world.guard, files["/etc/systemd/system/" + self.world.member_unit]["content"])
        fallback = files["/etc/systemd/system/dazzle-vps-agent.service"]["content"]
        self.assertIn("/opt/dazzle-vps/releases/" + self.world.old_release + "/venv/bin/python", fallback)
        self.assertIn("previous-policy-v1.json", fallback)
        self.assertEqual(files[str(self.layout.snapshot)]["content"].encode(), self.world.files["/etc/dazzle-vps/policy.json"])
        self.assertEqual(plan["measurements"]["fallback_reserve_seconds"], round(0.6 + 1.2 + 2 * 0.25 + 0.7, 3))
        # The writer's own cadence never brings the member's persisted age below the drain lag.
        self.assertAlmostEqual(plan["measurements"]["best_member_sample_age_seconds"], self.world.drain_lag, delta=0.03)
        self.assertEqual(plan["reviewed"]["units"]["new_writer"], self.world.w2)

    def test_successful_handoff_keeps_cores_and_witness_and_leaves_one_writer(self):
        result = self.run_coordinator()
        self.assertEqual(result["status"], "handoff_complete", result)
        world = self.world
        self.assertEqual((world.units[world.member_unit]["pid"], world.units[world.admin_unit]["pid"]), (4300, 4200))
        self.assertEqual(world.units[world.member_unit]["binds_to"], [world.guard])
        self.assertEqual(world.lock_holder, world.units[world.w2]["pid"])
        self.assertEqual((world.units[world.w1]["pid"], world.units[world.w1]["file_state"], world.units[world.w2]["file_state"]), (0, "disabled", "enabled"))
        self.assertEqual(world.current, world.new_release)
        self.assertEqual(world.files["/etc/systemd/system/dazzle-proxy@.service"], (ROOT / "portal-systemd/guarded-member.service").read_bytes())
        # Stopped at the writer's best phase (the drain lag), which a fixed 0.35 s gate never reaches.
        self.assertGreater(result["takeover"]["max_ledger_age_at_stop"], 0.35)
        self.assertLessEqual(result["takeover"]["max_ledger_age_at_stop"], self.world.drain_lag + 0.07)
        self.assertLess(result["takeover"]["timings"]["post_stop_samples_persisted"], 1.2)
        self.assertEqual(result["acceptance"]["writer_health"], "passed")
        self.assertEqual(result["acceptance"]["connection_preservation"], "passed")
        self.assertEqual(result["management_entry"], "restored")
        self.assert_never_restarted_a_core()
        order = [call[0] for call in world.calls if call[0] in {"stop", "start"} and (world.w1 in call or world.w2 in call or world.guard in call)]
        self.assertEqual(order, ["start", "start", "stop"])  # guard, standby, then the original writer only.

    def test_installed_certificate_sync_is_proven_once_on_the_new_release(self):
        self.world.install_certsync("success")
        plan = self.plan()
        self.assertTrue(plan["reviewed"]["certificate_sync"]["loaded"])
        result = self.run_coordinator(plan)
        self.assertEqual((result["status"], result["certificate_sync_after_switch"]), ("handoff_complete", "passed"))
        self.assertEqual(self.world.certsync_runs, [self.world.new_release])  # Ran once, after the switch.
        self.assert_never_restarted_a_core()

    def test_failed_certificate_sync_after_the_switch_is_flagged_not_hidden(self):
        self.world.install_certsync("failed")
        result = self.run_coordinator()
        self.assertEqual((result["status"], result["certificate_sync_after_switch"]), ("handoff_complete_certificate_sync_failed", "failed"))
        self.assertEqual(self.world.current, self.world.new_release)
        self.assertEqual(self.world.units[self.world.member_unit]["pid"], 4300)

    def test_unready_standby_aborts_without_stopping_the_original_writer(self):
        # The standby stops proving readiness right after dependencies were adopted.
        self.world.hooks[2] = self.world.warm_off
        result = self.run_coordinator()
        self.assertIn("standby", result["abort_reason"])
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed", result)
        self.assertNotIn(("stop", "--no-block", self.world.w1), self.world.calls)
        self.assertEqual(self.world.units[self.world.w1]["pid"], 4100)
        self.assert_original_layout()
        self.assert_never_restarted_a_core()

    def test_management_change_during_preparation_aborts_at_the_gate(self):
        self.world.hooks[2] = lambda: setattr(self.world, "revision", self.world.revision + 1)
        result = self.run_coordinator()
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed")
        self.assertIn("Ledger state changed", result["abort_reason"])
        self.assert_original_layout()
        self.assertEqual(self.world.lock_holder, 4100)

    def test_missing_member_witness_refuses_before_any_unit_change(self):
        plan = self.plan(parameters={**validate_parameters(), "witness_wait_seconds": 1.0})
        self.world.connections[4300] = []
        outcome = Coordinator(self.host, self.layout, ReleaseRenderer(), plan, approve(plan)).run()
        self.assertEqual(outcome["status"], "aborted_no_core_or_writer_changed")
        self.assertIn("witness", outcome["abort_reason"])
        self.assertFalse(any(call[0] == "start" for call in self.world.calls))
        self.assert_original_layout()

    def test_preview_without_witness_or_with_too_small_fallback_budget_is_not_approvable(self):
        self.world.connections[4300] = []
        plan = self.plan()
        self.assertFalse(plan["ready_for_approval"])
        self.assertIn("WITNESS", {issue["code"] for issue in plan["issues"]})
        with self.assertRaises(ValueError):
            Coordinator(self.host, self.layout, ReleaseRenderer(), plan, approve(plan))
        self.world.connections[4300] = [9001]
        self.world.units[self.world.w1]["active_enter_us"] = 4_500_000
        self.assertIn("FALLBACK_BUDGET", {issue["code"] for issue in self.plan()["issues"]})

    def test_process_change_after_review_is_refused_before_holding_management(self):
        plan = self.plan()
        self.world.units[self.world.member_unit]["restarts"] = 1
        result = self.run_coordinator(plan)
        self.assertIn("Reviewed facts changed", result["abort_reason"])
        self.assertEqual(self.world.calls, [])

    def test_management_entry_in_a_directory_others_can_write_blocks_the_preview(self):
        # GitHub-hosted runners ship /usr/local/bin as 0777; the hold must not swap a root launcher there.
        self.world.unsafe_paths.add(str(self.layout.control))
        with self.assertRaisesRegex(ValueError, "cannot be swapped safely"):
            self.plan()
        self.assertEqual(self.world.calls, [])

    def test_unexpected_error_is_recorded_with_its_type_and_the_entry_is_untouched(self):
        original = self.host.write
        def write(path, payload, *, mode, gid=None):
            if str(path) == str(self.layout.control):
                raise PermissionError("foreign text that may carry a value")
            return original(path, payload, mode=mode, gid=gid)
        self.host.write = write
        result = self.run_coordinator()
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed", result)
        self.assertEqual(result["unexpected_error"], "PermissionError")  # Foreign text is never echoed.
        self.assertEqual(self.world.files["/usr/local/bin/dazzle-vps-control"], LAUNCHER)
        self.assertEqual(self.world.calls, [])
        self.assert_original_layout()

    def test_recent_vm_pause_blocks_approval_and_a_later_one_stops_apply_before_changes(self):
        # 2026-10-25: the live VM paused for 7.9 s and 29.5 s; 5 s guards would have stopped members.
        self.world.stalls.append({"at": 0.0, "kind": "clocksource_skip", "seconds": 7.898})
        plan = self.plan()
        self.assertFalse(plan["ready_for_approval"])
        self.assertIn("HOST_STALLS", {issue["code"] for issue in plan["issues"]})
        self.assertEqual(plan["observed"]["host"]["longest_stall_seconds"], 7.898)
        self.world.stalls.clear()
        plan = self.plan()
        self.world.stalls.append({"at": 1.0, "kind": "clocksource_skip", "seconds": 29.497})
        result = Coordinator(self.host, self.layout, ReleaseRenderer(), plan, approve(plan)).run()
        self.assertIn("pause(s) of this VM", result["abort_reason"])
        self.assertEqual(self.world.calls, [])

    def test_steal_after_verification_aborts_before_the_old_writer_is_stopped(self):
        plan = self.plan()
        self.world.at(2.0, lambda: setattr(self.world, "steal", self.world.steal + 7.9))  # a pause while guards warm up
        result = self.run_coordinator(plan)
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed", result)
        self.assertIn("paused this VM", result["abort_reason"])
        self.assertEqual(result["host_steal_before_stop_seconds"], 7.9)
        self.assertFalse(any(call[:3] == ("stop", "--no-block", self.world.w1) for call in self.world.calls))
        self.assert_original_layout()
        self.assert_never_restarted_a_core()

    def test_steal_while_the_preview_observes_the_writer_is_not_approvable(self):
        self.world.at(1.0, lambda: setattr(self.world, "steal", self.world.steal + 0.5))
        plan = self.plan()
        self.assertIn("HOST_STEAL", {issue["code"] for issue in plan["issues"]})
        self.assertFalse(plan["ready_for_approval"])

    def test_in_flight_management_call_that_never_ends_aborts_and_restores_entry(self):
        self.world.control_busy_until = self.world.time + 999
        plan = self.plan(parameters={**validate_parameters(), "control_drain_timeout": 2.0})
        result = Coordinator(self.host, self.layout, ReleaseRenderer(), plan, approve(plan)).run()
        self.assertIn("In-flight management", result["abort_reason"])
        self.assertEqual(self.world.files["/usr/local/bin/dazzle-vps-control"], LAUNCHER)
        self.assertEqual(self.world.calls, [])

    def test_failed_takeover_falls_back_within_budget_and_rebinds_after_fresh_samples(self):
        self.world.takeover_mode = "fail"
        result = self.run_coordinator()
        self.assertEqual(result["status"], "fallback_complete_members_preserved", result)
        self.assertTrue(result["fallback"]["within_sample_deadline"])
        world = self.world
        self.assertEqual(world.units[world.member_unit]["pid"], 4300)
        self.assertEqual(world.units[world.member_unit]["binds_to"], [world.w1])
        self.assertEqual(world.lock_holder, world.units[world.w1]["pid"])
        self.assertNotEqual(world.lock_holder, 4100)
        self.assertEqual(world.units[world.guard]["active"], "inactive")
        self.assert_original_layout()
        self.assert_never_restarted_a_core()
        self.assertEqual(world.incidents, 2)

    def test_hung_takeover_with_slow_fallback_is_reported_as_member_interruption(self):
        self.world.takeover_mode, self.world.old_cold_start = "hang", 4.5
        result = self.run_coordinator()
        self.assertEqual(result["status"], "fallback_complete_members_interrupted", result)
        self.assertFalse(result["fallback"]["within_sample_deadline"])
        self.assertEqual(result["fallback"]["members_interrupted"], 1)
        self.assertEqual(self.world.current, self.world.old_release)
        self.assertEqual(self.world.files["/usr/local/bin/dazzle-vps-control"], LAUNCHER)

    def test_slow_old_writer_exit_is_killed_and_takeover_still_inside_deadline(self):
        self.world.old_stop_delay = 5.0
        result = self.run_coordinator()
        self.assertEqual(result["status"], "handoff_complete", result)
        self.assertTrue(result["takeover"]["timings"]["old_writer_killed"])
        self.assertIn(("kill", "--signal=SIGKILL", "--kill-whom=all", self.world.w1), self.world.calls)

    def test_a_second_apply_of_the_same_plan_is_refused(self):
        plan = self.plan()
        self.run_coordinator(plan)
        with self.assertRaises(ValueError):
            Coordinator(self.host, self.layout, ReleaseRenderer(), plan, approve(plan)).run()

    def test_approval_must_bind_the_exact_plan_and_every_acknowledgement(self):
        plan = self.plan()
        approval = approve(plan)
        for change in ({"plan_sha256": "0" * 64}, {"acknowledgements": {**approval["acknowledgements"], "registration_stays_closed": False}},
                       {"approved": "yes"}, {"operation": "install"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                Coordinator(self.host, self.layout, ReleaseRenderer(), plan, {**approval, **change})

    def test_writer_that_owns_the_lock_is_never_replaced_by_a_slower_cold_fallback(self):
        original = self.world.systemctl
        def systemctl(*arguments, timeout=30):
            if arguments[:2] == ("stop", "--no-block") and arguments[2] == self.world.w1:
                self.world.reader_broken = True  # Facts unreadable for the rest of the window.
            return original(*arguments, timeout=timeout)
        self.world.systemctl = systemctl
        result = self.run_coordinator()
        self.assertEqual(result["status"], "taken_over_writer_review_required", result)
        self.assertNotIn("fallback", result)
        self.assertFalse([call for call in self.world.calls if call[0] == "start" and self.world.w1 in call])
        self.assertEqual(self.world.lock_holder, self.world.units[self.world.w2]["pid"])
        self.assertEqual(self.world.current, self.world.old_release)  # Not finalized without verified samples.
        self.assertEqual(self.world.files["/usr/local/bin/dazzle-vps-control"], LAUNCHER)

    def test_administrator_bound_to_the_original_writer_is_a_blocking_issue(self):
        self.world.units[self.world.admin_unit]["binds_to"] = [self.world.w1]
        issues = {issue["code"]: issue for issue in self.plan()["issues"]}
        self.assertIn("ADMIN_UNIT", issues)
        self.assertFalse(issues["ADMIN_UNIT"]["volatile"])

    def test_a_fixed_small_age_gate_would_never_find_a_stop_moment_with_real_cadence(self):
        # Regression for the original 0.35 s rule: the realistic writer never offers it.
        plan = self.plan(parameters={**validate_parameters(), "max_sample_age_at_stop": 0.35, "fresh_moment_timeout": 3.0})
        self.assertIn("FALLBACK_BUDGET", {issue["code"] for issue in plan["issues"]})
        self.world.drain_lag = 0.2
        plan = self.plan(parameters={**validate_parameters(), "max_sample_age_at_stop": 0.35})
        self.assertTrue(plan["ready_for_approval"], plan["issues"])
        self.world.drain_lag = 0.45  # The writer's phase drifted after review: refuse rather than stop late.
        result = Coordinator(self.host, self.layout, ReleaseRenderer(), plan, approve(plan)).run()
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed", result)
        self.assertIn("No safe stop moment", result["abort_reason"])
        self.assertNotIn(("stop", "--no-block", self.world.w1), self.world.calls)

    def test_witness_must_be_a_session_that_lasted_through_preparation(self):
        # The pre-switch connections close during preparation and new ones appear: not proof of a held session.
        self.world.hooks[1] = lambda: self.world.connections.__setitem__(4300, [9100])
        result = self.run_coordinator()
        self.assertEqual(result["status"], "aborted_no_core_or_writer_changed", result)
        self.assertIn("lasted through preparation", result["abort_reason"])
        self.assert_original_layout()
        self.assertEqual(self.world.lock_holder, 4100)

    def test_exclusive_new_writer_is_never_replaced_even_with_an_unexpected_status(self):
        self.world.takeover_mode = "recovery"
        result = self.run_coordinator()
        self.assertEqual(result["status"], "taken_over_writer_review_required", result)
        self.assertNotIn("fallback", result)
        self.assertEqual(self.world.lock_holder, self.world.units[self.world.w2]["pid"])
        self.assertFalse([call for call in self.world.calls if call[0] == "start" and self.world.w1 in call])

    def test_ledger_reader_failure_after_stop_does_not_skip_fallback(self):
        self.world.takeover_mode = "fail"
        original = self.world.systemctl
        def systemctl(*arguments, timeout=30):
            if arguments[:2] == ("stop", "--no-block") and arguments[2] == self.world.w1:
                self.world.reader_broken = True
                self.world.at(0.8, lambda: setattr(self.world, "reader_broken", False))
            return original(*arguments, timeout=timeout)
        self.world.systemctl = systemctl
        result = self.run_coordinator()
        self.assertTrue(result["status"].startswith("fallback_complete"), result)


if __name__ == "__main__":
    unittest.main()
