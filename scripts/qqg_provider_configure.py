#!/usr/bin/env python3
"""Hand the QQG API key to the server's provider sync without printing it.

Reads the private credential JSON (and optional token file) locally, reads the
current revision through the fixed SSH control entry, then submits one
provider.configure request on SSH stdin, so the token never appears in a
command line, log or output. Without --apply this is a dry run.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from dazzle import qqg  # noqa: E402
from dazzle.provider_sync import DEFAULT_INTERVAL, _mask  # noqa: E402

REMOTE = "/usr/local/bin/dazzle-vps-control rpc"


def call(host: str, identity: str, request: dict) -> dict:
    # Same fixed options as the Mac App's SSHManagementRPC.
    arguments = ["/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                 "-o", "UpdateHostKeys=no", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=8",
                 "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1", "-i", identity, "root@" + host, REMOTE]
    result = subprocess.run(arguments, input=(json.dumps(request) + "\n").encode(), capture_output=True, timeout=40)
    try:
        response = json.loads(result.stdout)
    except ValueError:
        raise SystemExit("服务器返回了无法解析的响应（原始输出已隐藏）") from None
    if not isinstance(response, dict) or response.get("request_id") != request["request_id"]:
        raise SystemExit("服务器响应与请求不匹配")
    return response


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Configure QQG automatic traffic sync on the server")
    parser.add_argument("--host", required=True)
    parser.add_argument("--identity", required=True, help="Existing SSH private key for the fixed control entry")
    parser.add_argument("--credentials", help="Private qqg-api.json (required unless --disable/--forget)")
    parser.add_argument("--token-file", help="Private file with only the API token")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--disable", action="store_true", help="Stop syncing; the budget returns to local only")
    mode.add_argument("--forget", action="store_true", help="Stop syncing and delete the stored key")
    parser.add_argument("--apply", action="store_true", help="Actually change the server; omitted = dry run")
    args = parser.parse_args(argv)
    creds = ignored = None
    if not (args.disable or args.forget):
        if not args.credentials:
            parser.error("--credentials is required to enable sync")
        try:
            creds, ignored = qqg.load_credentials(args.credentials, args.token_file)
        except qqg.QqgError as exc:
            print(json.dumps({"ok": False, "error": {"code": exc.code, "message": exc.message}}, ensure_ascii=False))
            return 1
    current = call(args.host, args.identity, {"api_version": 1, "request_id": "provider-preview-" + uuid.uuid4().hex,
                                              "action": "snapshot", "params": {}})
    if not current.get("ok"):
        print(json.dumps({"ok": False, "error": current.get("error")}, ensure_ascii=False))
        return 1
    data = current["data"]
    if "provider.configure" not in data.get("capabilities", {}).get("allowed_actions", []):
        print(json.dumps({"ok": False, "error": {"code": "NOT_DEPLOYED",
                          "message": "服务器版本尚不支持 provider.configure，请先上线包含 QQG 同步的新版本"}}, ensure_ascii=False))
        return 1
    if creds is None:
        params = {"enabled": False, **({"username": None, "token": None} if args.forget else {})}
        plan = {"server_id": data["server_id"], "expected_revision": current["revision"],
                "change": "forget_key" if args.forget else "disable", "current_sync": data.get("provider_sync")}
    else:
        params = {"enabled": True, "api_url": creds.api_url, "username": creds.username, "token": creds.token,
                  "host_id": creds.host_id, "interval_seconds": args.interval}
        plan = {"server_id": data["server_id"], "expected_revision": current["revision"], "change": "enable",
                "api_host": creds.host, "host_id": creds.host_id, "username": _mask(creds.username),
                "interval_seconds": args.interval, "ignored_fields": ignored, "current_sync": data.get("provider_sync")}
    if not args.apply:
        print(json.dumps({"ok": True, "dry_run": True, **plan}, ensure_ascii=False, indent=2))
        return 0
    request = {"api_version": 1, "request_id": "provider-configure-" + uuid.uuid4().hex, "action": "provider.configure",
               "server_id": data["server_id"], "expected_revision": current["revision"], "params": params}
    response = call(args.host, args.identity, request)
    sync = (response.get("data") or {}).get("provider_sync")
    print(json.dumps({"ok": response.get("ok"), "error": response.get("error"), "provider_sync": sync},
                     ensure_ascii=False, indent=2))
    return 0 if response.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
