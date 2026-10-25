"""dazzle-vps CLI. stdout is JSON; no live deployment operations exist."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid

from .rpc import MAX_REQUEST_BYTES, handle_request
from .store import Store


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dazzle-vps")
    parser.add_argument("--state-dir", default=str(Path.home() / "Library/Application Support/DazzleVPS/Simulation"))
    parser.add_argument("--json", action="store_true", help="Return structured JSON (default)")
    parser.add_argument("--dry-run", action="store_true", help="Evaluate locally without writing state")
    parser.add_argument("--expected-revision", type=int)
    parser.add_argument("--request-id")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("rpc", "snapshot", "status", "doctor", "list"):
        commands.add_parser(name)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("selector")
    request = commands.add_parser("request")
    request.add_argument("action")
    request.add_argument("--params", default="{}")
    user = commands.add_parser("user")
    user_commands = user.add_subparsers(dest="verb", required=True)
    add = user_commands.add_parser("add")
    add.add_argument("--name", required=True)
    add.add_argument("--role", choices=["member", "admin"], default="member")
    add.add_argument("--quota-bytes", type=int)
    for name in ("enable", "disable", "revoke", "rotate", "export", "topup", "update"):
        child = user_commands.add_parser(name)
        child.add_argument("user_id")
        if name == "export":
            child.add_argument("--format", choices=["shadowrocket", "mihomo", "uris"], default="shadowrocket")
        if name == "topup":
            child.add_argument("--bytes", type=int, required=True)
        if name == "update":
            child.add_argument("--params", required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("verb", choices=["initialize"])
    return parser


def main(argv=None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "rpc":
            raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
            if len(raw) > MAX_REQUEST_BYTES:
                raise ValueError("Request exceeds size limit")
            request = json.loads(raw)
        else:
            params = {}
            if args.command == "request":
                action, params = args.action, json.loads(args.params)
            elif args.command == "resolve":
                action, params = "user.resolve", {"name": args.selector}
            elif args.command == "list":
                action = "user.list"
            elif args.command == "demo":
                action = "demo.initialize"
            elif args.command == "user":
                action = "user." + args.verb
                if args.verb == "add":
                    params = {"name": args.name, "role": args.role}
                    if args.quota_bytes is not None:
                        params["quota_bytes"] = args.quota_bytes
                else:
                    params = {"user_id": args.user_id}
                    if args.verb == "topup":
                        params["bytes"] = args.bytes
                    elif args.verb == "export":
                        params["format"] = args.format
                    elif args.verb == "update":
                        params.update(json.loads(args.params))
            else:
                action = args.command
            request = {"api_version": 1, "request_id": args.request_id or str(uuid.uuid4()),
                       "action": action, "expected_revision": args.expected_revision, "params": params}
        if not isinstance(request, dict):
            raise ValueError("Request must be a JSON object")
        preview = args.dry_run or request.get("action") in {"deploy.preview", "rollback.preview", "history.preview"}
        with (Store.preview(args.state_dir) if preview else Store(args.state_dir)) as store:
            response = handle_request(store, request)
            if args.dry_run:
                response["dry_run"] = True
        sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
        return 0 if response["ok"] else 1
    except (ValueError, UnicodeError, TypeError):
        response = {"ok": False, "request_id": None, "revision": 0, "data": None,
                    "error": {"code": "VALIDATION", "message": "Invalid JSON request"}}
    except Exception:
        response = {"ok": False, "request_id": None, "revision": 0, "data": None,
                    "error": {"code": "INTERNAL", "message": "Local state could not be opened"}}
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
