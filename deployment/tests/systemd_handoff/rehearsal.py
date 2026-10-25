"""Live writer handoff rehearsal on a disposable systemd host.

Runs the real deployment.coordinator (read-only preview, exact approval, apply),
the unmodified production unit templates, the real root helper and real systemd.
Only the processes behind ExecStart are stand-ins (rehearsal_dazzle and
rehearsal_core.py). It refuses to run unless the host is an isolated GitHub
runner or the dedicated marked container and no production path or account
exists, and it removes every path and account it created.
"""
from __future__ import annotations

import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
sys.path.insert(0, str(REPOSITORY))
from deployment.coordinator import LAUNCHER, LedgerReader  # noqa: E402
from deployment.helper import CORE_SHA256  # noqa: E402
from deployment.installer import canonical, sha256  # noqa: E402
from deployment.portal_release import portal_sources  # noqa: E402

OWNED_PATHS = ("/opt/dazzle-vps", "/etc/dazzle-vps", "/var/lib/dazzle-vps", "/var/lib/dazzle-vps-workers", "/run/dazzle-vps",
               "/usr/local/bin/dazzle-vps-control")
ACCOUNTS = ("dazzle-agent", "dazzle-proxy")
GROUPS = ("dazzle-agent", "dazzle-proxy", "dazzle-vps")
TEMPLATES = ("dazzle-vps-agent.service", "dazzle-proxy@.service", "dazzle-admin@.service", "dazzle-vps-helper.socket", "dazzle-vps-helper@.service")


def run(*arguments, check=True, timeout=60):
    result = subprocess.run(list(arguments), capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise AssertionError("command failed: " + " ".join(arguments[:3]) + " " + result.stderr[-800:])
    return result


def show(unit, *properties):
    output = run("/usr/bin/systemctl", "show", unit, "--property=" + ",".join(properties)).stdout
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def wait_for(check, timeout=15, message="rehearsal condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError(message + " deadline exceeded")


def install(path, payload, mode, uid=0, gid=0):
    path = Path(path)
    path.write_bytes(payload)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def directory(path, mode, uid=0, gid=0):
    path = Path(path)
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


class LongClient:
    def __init__(self, port):
        self.connection = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.connection.settimeout(2)
        self.reader = self.connection.makefile("rb")
        self.stopped, self.error, self.count, self.pids = threading.Event(), None, 0, set()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        try:
            while not self.stopped.is_set():
                value = str(self.count).encode()
                self.connection.sendall(value + b"\n")
                answer = self.reader.readline().split()
                assert answer[:2] == [b"ACK", value]
                self.pids.add(int(answer[2]))
                self.count += 1
                self.stopped.wait(0.02)
        except BaseException as exc:
            self.error = type(exc).__name__

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=3)
        self.reader.close()
        self.connection.close()


class Rehearsal:
    def __init__(self, scenario):
        self.scenario = scenario
        self.server, self.admin, self.member = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        self.client = None
        self.private = Path("/root") / ("dazzle-rehearsal-" + uuid.uuid4().hex[:10])

    # Environment --------------------------------------------------------
    def setup(self):
        for name in GROUPS:
            run("/usr/sbin/groupadd", "--system", name)
        for name in ACCOUNTS:
            run("/usr/sbin/useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin",
                "--gid", name, "--groups", "dazzle-vps", name)
        self.agent, self.vps = pwd.getpwnam("dazzle-agent"), grp.getgrnam("dazzle-vps").gr_gid
        directory(self.private, 0o700)
        for path, mode, gid in (("/opt/dazzle-vps", 0o755, 0), ("/opt/dazzle-vps/releases", 0o755, 0), ("/opt/dazzle-vps/core", 0o755, 0),
                                ("/etc/dazzle-vps", 0o750, self.vps), ("/etc/dazzle-vps/workers", 0o700, 0), ("/etc/dazzle-vps/tls", 0o750, self.vps)):
            directory(path, mode, 0, gid)
        directory("/var/lib/dazzle-vps", 0o700, self.agent.pw_uid, self.agent.pw_gid)
        install("/opt/dazzle-vps/core/sing-box", (HERE / "rehearsal_core.py").read_bytes(), 0o755)
        workers = {self.admin: {"role": "admin", "public_port": 24430, "api_port": 34430},
                   self.member: {"role": "member", "public_port": 24431, "api_port": 34431}}
        policy = {"version": 1, "server_id": self.server, "server_endpoint": "192.0.2.10", "agent_uid": self.agent.pw_uid,
                  "core_sha256": CORE_SHA256, "workers": workers}
        install("/etc/dazzle-vps/policy.json", canonical(policy) + b"\n", 0o640, 0, self.vps)
        install("/etc/dazzle-vps/registry.json", json.dumps({"version": 1, "server_id": self.server, "workers": {}}).encode(), 0o600)
        for identifier, worker in workers.items():
            install("/etc/dazzle-vps/workers/" + identifier + ".json",
                    json.dumps({"fixture": {"public_port": worker["public_port"], "api_port": worker["api_port"]}}).encode(), 0o600)
        far = "2036-01-01T00:00:00+00:00"
        users = [{"id": identifier, "role": worker["role"], "manual_disabled": 0, "revoked_at": None, "deleted_at": None, "reasons_json": "[]",
                  "trusted_sample": 1, "meter_state": "trusted", "meter_epoch": None, "last_sample_at": None, "last_uplink": 0,
                  "last_downlink": 0, "used_upload": 0, "used_download": 0, "quota_bytes": None if worker["role"] == "admin" else 100_000_000_000,
                  "topup_bytes": 0, "unlimited": int(worker["role"] == "admin"), "credential_version": 1} for identifier, worker in workers.items()]
        rows = [{"worker_id": identifier, "role": worker["role"], "user_id": identifier, "public_port": worker["public_port"],
                 "api_port": worker["api_port"], "generation": 3, "root_ack_generation": 3, "observed_generation": 3, "observed_state": "running",
                 "process_id": 0, "origin_pending": 0, "last_error": None, "tombstoned": 0, "credential_version": 1, "provisioned": 1}
                for identifier, worker in workers.items()]
        seed = {"meta": {"revision": 5, "mode": "production", "server_id": self.server, "agent_recovery_only": False}, "users": users,
                "production_workers": rows, "cycles": [{"id": "rehearsal-cycle", "start_at": "2026-01-01T00:00:00+00:00", "end_at": far, "status": "active"}]}
        install("/etc/dazzle-vps/fixture-seed.json", json.dumps(seed).encode(), 0o640, 0, self.vps)
        install("/etc/dazzle-vps/fixture-mode", b"\n", 0o644)
        self.old_release, self.new_release = self.release("old", manifest=False), self.release("new", manifest=True)
        os.symlink("/opt/dazzle-vps/releases/" + self.old_release, "/opt/dazzle-vps/current")
        install("/usr/local/bin/dazzle-vps-control", LAUNCHER, 0o755)
        for name in TEMPLATES:
            install("/etc/systemd/system/" + name, (REPOSITORY / "deployment/systemd" / name).read_bytes(), 0o644)
        run("/usr/bin/systemctl", "daemon-reload")
        run("/usr/bin/systemctl", "enable", "dazzle-vps-agent.service")
        run("/usr/bin/systemctl", "start", "dazzle-vps-helper.socket")
        run("/usr/bin/systemctl", "start", "dazzle-vps-agent.service")
        for unit in self.unit("admin"), self.unit("member"):
            run("/usr/bin/systemctl", "start", unit)
        wait_for(lambda: self.ledger_ready(), message="initial trusted samples")
        self.client = LongClient(24431)
        wait_for(lambda: self.client.count > 3, message="long member TCP session")
        self.before = {role: show(self.unit(role), "MainPID", "InvocationID", "NRestarts") for role in ("admin", "member")}

    def release(self, marker, *, manifest):
        files = {name: body for name, body in portal_sources(REPOSITORY).items() if not name.startswith("backend/dazzle/")}
        for path in (HERE / "rehearsal_dazzle").glob("*.py"):
            files["backend/dazzle/" + path.name] = path.read_bytes()
        files["backend/dazzle/release_marker.py"] = ("RELEASE = %r\n" % marker).encode()
        files["wheelhouse/rehearsal-placeholder.txt"] = b"no wheels are installed in the rehearsal\n"
        files["requirements.txt"] = b""
        inventory = {name: sha256(body) for name, body in sorted(files.items())}
        identifier = sha256(canonical(inventory))[:24]
        destination = Path("/opt/dazzle-vps/releases") / identifier
        directory(destination, 0o755)
        for name, body in files.items():
            target = destination / name
            for parent in reversed(target.relative_to(destination).parents):
                if parent != Path(".") and not (destination / parent).exists():
                    directory(destination / parent, 0o755)
            install(target, body, 0o644)
        if manifest:
            install(destination / "release.json", json.dumps({"release_id": identifier, "files": inventory}, sort_keys=True).encode(), 0o644)
        run("/usr/bin/python3", "-m", "venv", "--without-pip", str(destination / "venv"))
        site = destination / "venv/lib/python3.12/site-packages"
        shutil.copytree(destination / "backend/dazzle", site / "dazzle")
        shutil.copytree(destination / "deployment", site / "deployment", ignore=shutil.ignore_patterns("systemd", "portal-systemd", "tests"))
        return identifier

    def unit(self, role):
        return ("dazzle-admin@" + self.admin if role == "admin" else "dazzle-proxy@" + self.member) + ".service"

    def facts(self):
        with LedgerReader("/var/lib/dazzle-vps/state.sqlite3", python="/usr/bin/python3", user=self.agent.pw_uid,
                          group=self.agent.pw_gid, extra_groups=[self.vps]) as reader:
            return reader.facts()

    def ledger_ready(self):
        try:
            facts = self.facts()
        except (OSError, ValueError):
            return False
        pids = {worker["worker_id"]: worker["process_id"] for worker in facts["workers"]}
        return all(user["epoch_sha256"] and user["last_sample_at"] for user in facts["users"]) and \
            pids == {self.admin: int(show(self.unit("admin"), "MainPID")["MainPID"]), self.member: int(show(self.unit("member"), "MainPID")["MainPID"])}

    # Rehearsed operation ------------------------------------------------
    def coordinator(self, *arguments):
        python = "/opt/dazzle-vps/releases/" + self.new_release + "/venv/bin/python"
        result = run(python, "-I", "-m", "deployment.coordinator", *arguments, check=False, timeout=300)
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise AssertionError("coordinator printed no JSON: " + result.stderr[-1500:]) from None

    def execute(self):
        install("/etc/dazzle-vps/fixture-mode", (self.scenario if self.scenario.endswith("-takeover") else "").encode() + b"\n", 0o644)
        preview = self.coordinator("--preview", "--new-release-id", self.new_release)
        plan = preview.get("plan") or {}
        if not plan.get("ready_for_approval"):
            raise AssertionError("plan not ready: " + json.dumps(preview.get("error") or plan.get("issues"))[:1500])
        approval = {"version": 1, "operation": "live_writer_handoff", "approved": True, "approval_id": str(uuid.uuid4()),
                    "plan_sha256": sha256(canonical(plan)),
                    "acknowledgements": {"abort_rather_than_restart_core": True, "fallback_is_best_effort_fail_closed": True,
                                         "registration_stays_closed": True}}
        install(self.private / "plan.json", json.dumps(plan).encode(), 0o600)
        install(self.private / "approval.json", json.dumps(approval).encode(), 0o600)
        arguments = ("--apply", "--plan", str(self.private / "plan.json"), "--approval", str(self.private / "approval.json"))
        if self.scenario == "interrupt-after-adopt":
            # SIGTERM as soon as the complete member override exists: the gate must revert, never switch.
            python = "/opt/dazzle-vps/releases/" + self.new_release + "/venv/bin/python"
            process = subprocess.Popen([python, "-I", "-m", "deployment.coordinator", *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            wait_for(lambda: Path("/etc/systemd/system/" + self.unit("member")).exists() or process.poll() is not None, timeout=90,
                     message="dependency adoption")
            process.terminate()
            output, _ = process.communicate(timeout=120)
            result = json.loads(output)
        else:
            result = self.coordinator(*arguments)
        time.sleep(0.3)
        return plan, result

    def verify(self, plan, result):
        member, admin = self.unit("member"), self.unit("admin")
        now = {role: show(self.unit(role), "MainPID", "InvocationID", "NRestarts") for role in ("admin", "member")}
        assert now == self.before, ("a Core restarted", self.before, now)
        assert self.client.error is None and self.client.pids == {int(self.before["member"]["MainPID"])}, (self.client.error, self.client.pids)
        writer = "dazzle-vps-writer@" + self.new_release + ".service"
        old = show("dazzle-vps-agent.service", "ActiveState", "MainPID", "UnitFileState", "ExecStart")
        new = show(writer, "ActiveState", "MainPID", "UnitFileState")
        bound = show(member, "BindsTo", "FragmentPath")["BindsTo"].split()
        locks = Path("/proc/locks").read_text()
        current = os.readlink("/opt/dazzle-vps/current")
        assert Path("/usr/local/bin/dazzle-vps-control").read_bytes() == LAUNCHER
        assert show(admin, "BindsTo")["BindsTo"] == ""
        facts = self.facts()
        if self.scenario == "interrupt-after-adopt":
            assert result["status"] == "aborted_no_core_or_writer_changed", result
            assert "interrupt" in result["abort_reason"], result["abort_reason"]
            assert show("dazzle-vps-agent.service", "MainPID")["MainPID"] == str(plan["reviewed"]["processes"]["old_writer"]["pid"])
            assert (old["ActiveState"], old["UnitFileState"]) == ("active", "enabled") and new["ActiveState"] in {"inactive", "failed"}
            assert bound == ["dazzle-vps-agent.service"] and current.endswith(self.old_release)
            assert "/opt/dazzle-vps/current/venv/bin/python" in old["ExecStart"]
            assert not Path("/etc/systemd/system/" + member).exists() and not Path("/etc/systemd/system/dazzle-vps-writer@.service").exists()
            assert show("dazzle-vps-meter-guard@" + self.member + ".service", "ActiveState")["ActiveState"] in {"inactive", "failed"}
            assert "takeover" not in result
            return {"status": result["status"], "core_pids_preserved": True, "member_tcp_session_preserved": True,
                    "original_writer_never_stopped": True, "dependencies_restored": True}
        if self.scenario == "success":
            assert result["status"] == "handoff_complete", result
            assert (old["ActiveState"], old["UnitFileState"], new["ActiveState"], new["UnitFileState"]) == ("inactive", "disabled", "active", "enabled")
            assert bound == ["dazzle-vps-meter-guard@" + self.member + ".service"]
            assert current.endswith(self.new_release)
            assert (" " + new["MainPID"] + " ") in locks and "FLOCK" in locks
            assert Path("/etc/systemd/system/dazzle-proxy@.service").read_bytes() == (REPOSITORY / "deployment/portal-systemd/guarded-member.service").read_bytes()
            assert result["acceptance"]["connection_preservation"] == "passed" and result["acceptance"]["writer_health"] == "passed"
        else:
            assert result["status"] == "fallback_complete_members_preserved", result
            assert result["fallback"]["within_sample_deadline"] is True
            assert old["ActiveState"] == "active" and old["UnitFileState"] == "enabled" and new["ActiveState"] in {"inactive", "failed"}
            assert bound == ["dazzle-vps-agent.service"] and current.endswith(self.old_release)
            assert "/opt/dazzle-vps/current/venv/bin/python" in old["ExecStart"]  # Original definition restored.
            assert show("dazzle-vps-meter-guard@" + self.member + ".service", "ActiveState")["ActiveState"] in {"inactive", "failed"}
        assert facts["incidents_total"] == 0, "a metering gap was recorded"
        timings = result.get("takeover", {}).get("timings", {})
        fail_closed = None
        if self.scenario == "success":
            # A crash restarts the writer as a standby (Restart=on-failure, 3s). Whether it re-takes the lock
            # inside the unchanged five-second window is only observed here; it is never relied upon.
            run("/usr/bin/systemctl", "kill", "--signal=SIGKILL", "--kill-whom=main", writer)
            time.sleep(6.5)
            crash = {"member_survived": show(member, "MainPID")["MainPID"] == self.before["member"]["MainPID"],
                     "gap_incidents": self.facts()["incidents_total"]}
            # Protection stays on after the handoff: with no writer at all the guard stops the member, never the admin.
            run("/usr/bin/systemctl", "stop", writer)
            began = time.monotonic()
            wait_for(lambda: show(member, "ActiveState")["ActiveState"] in {"inactive", "failed"}, timeout=12, message="fail-closed member stop")
            assert show(admin, "MainPID", "InvocationID", "NRestarts") == self.before["admin"]
            stopped_after = round(time.monotonic() - began, 2)
            # The ledger was at most ~1s old; the guard must use the whole unchanged window, not fail early or late.
            assert 3.0 <= stopped_after <= 6.5, stopped_after
            fail_closed = {"member_stopped_after_writer_stop_seconds": stopped_after, "administrator_unaffected": True,
                           "observed_writer_crash_with_automatic_restart": crash}
        return {"status": result["status"], "core_pids_preserved": True, "member_tcp_session_preserved": True, "fail_closed_after_handoff": fail_closed,
                "max_ledger_age_at_stop": result["takeover"]["max_ledger_age_at_stop"], "timings": timings,
                "fallback": result.get("fallback"), "measured_fallback_reserve": plan["measurements"]["fallback_reserve_seconds"]}

    def diagnostics(self):
        """Unit states and journal tails; fixtures never log credentials."""
        units = run("/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", "dazzle-*", check=False).stdout
        journal = run("/usr/bin/journalctl", "--no-pager", "-n", "80", "-o", "cat", "-u", "dazzle-*", check=False).stdout
        return units[-3000:] + "\n--- journal ---\n" + journal[-6000:]

    def teardown(self):
        if self.client:
            self.client.close()
        units = run("/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", "dazzle-*", check=False).stdout.split("\n")
        names = [line.split()[0] for line in units if line.strip()]
        if names:
            run("/usr/bin/systemctl", "stop", *names, check=False)
            run("/usr/bin/systemctl", "reset-failed", *names, check=False)
        run("/usr/bin/systemctl", "disable", "dazzle-vps-agent.service", "dazzle-vps-writer@" + getattr(self, "new_release", "x" * 24) + ".service", check=False)
        for path in Path("/etc/systemd/system").glob("dazzle-*"):
            if path.is_file() or path.is_symlink():
                path.unlink()
        for path in OWNED_PATHS:
            path = Path(path)
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
        shutil.rmtree(self.private, ignore_errors=True)
        run("/usr/bin/systemctl", "daemon-reload", check=False)
        for name in ACCOUNTS:
            run("/usr/sbin/userdel", name, check=False)
        for name in GROUPS:
            run("/usr/sbin/groupdel", name, check=False)


def main():
    isolated = os.environ.get("GITHUB_ACTIONS") == "true" or (Path("/.dockerenv").exists() and Path("/etc/dazzle-handoff-isolated-container").exists())
    if not isolated or os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise SystemExit("Run only in an isolated GitHub Ubuntu24.04 systemd runner or the dedicated marked container, as root.")
    if 'VERSION_ID="24.04"' not in Path("/etc/os-release").read_text():
        raise SystemExit("Ubuntu24.04 is required")
    root = next(line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines() if line.split()[4] == "/")
    if not any(field.startswith("shared:") for field in root[6:root.index("-")]):
        # Docker starts with private propagation; systemd then cannot deliver LoadCredential=.
        raise SystemExit("The root mount must be shared (in Docker run `mount --make-rshared /` first).")
    present = [path for path in OWNED_PATHS if Path(path).exists() or Path(path).is_symlink()]
    for name in ACCOUNTS:
        try:
            pwd.getpwnam(name)
            present.append(name)
        except KeyError:
            pass
    if present or list(Path("/etc/systemd/system").glob("dazzle-*")):
        raise SystemExit("Refusing: a production path, unit or account already exists on this host.")
    scenarios = sys.argv[1:] or ["success", "fail-takeover", "hang-takeover", "interrupt-after-adopt"]
    results = {}
    for scenario in scenarios:
        rehearsal = Rehearsal(scenario)
        try:
            rehearsal.setup()
            results[scenario] = rehearsal.verify(*rehearsal.execute())
        except BaseException:
            print(rehearsal.diagnostics(), file=sys.stderr)
            raise
        finally:
            rehearsal.teardown()
    print(json.dumps({"live_writer_handoff_rehearsal": "passed", "results": results, "real_production_touched": False}, sort_keys=True))


if __name__ == "__main__":
    main()
