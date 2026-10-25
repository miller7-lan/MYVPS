#!/usr/bin/env python3
"""Fixed root SSH entry drops all privileges before accepting ONE JSON RPC."""
import os
import pwd
import sys


def main():
    try:
        if len(sys.argv) != 1 or os.geteuid() != 0:
            raise ValueError()
        account = pwd.getpwnam("dazzle-agent")
        os.initgroups(account.pw_name, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
        os.umask(0o077)
        # No environment-selected module path or executable. The interpreter is
        # the root-owned release venv selected by the installed fixed launcher.
        os.environ.clear()
        os.environ.update({"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"})
        from dazzle.production import main as production_main
        return production_main(["--policy", "/etc/dazzle-vps/policy.json", "--state-dir", "/var/lib/dazzle-vps", "rpc"])
    except BaseException:
        sys.stdout.write('{"ok":false,"request_id":null,"revision":0,"data":null,"error":{"code":"CONTROL_UNAVAILABLE","message":"Private production control is unavailable"}}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
