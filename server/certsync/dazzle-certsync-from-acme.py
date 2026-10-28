#!/usr/bin/env python3
# Validated Dazzle certificate sync directly from the existing ACME lineage.
import grp
import json
import os
from pathlib import Path
from deployment.certsync import sync_certificate
from deployment.helper import Layout, read_json, validate_policy

def main():
    if os.geteuid() != 0:
        raise RuntimeError("Root service required")
    lineage = Path("/etc/letsencrypt/live/qqg-ip")
    archive = Path("/etc/letsencrypt/archive/qqg-ip")
    cert = (lineage / "fullchain.pem").resolve(strict=True)
    key = (lineage / "privkey.pem").resolve(strict=True)
    if cert.parent != archive or key.parent != archive:
        raise RuntimeError("Unexpected certificate lineage")
    cert_generation = cert.name.removeprefix("fullchain").removesuffix(".pem")
    key_generation = key.name.removeprefix("privkey").removesuffix(".pem")
    if not cert.name.startswith("fullchain") or not key.name.startswith("privkey") or not cert_generation.isdecimal() or cert_generation != key_generation:
        raise RuntimeError("Certificate generation mismatch")
    policy = validate_policy(read_json(Layout().policy))
    options = dict(source_cert=cert, source_key=key, tls_gid=grp.getgrnam("dazzle-vps").gr_gid)
    if policy["version"] == 2:
        options["portal_tls_gid"] = grp.getgrnam("dazzle-web").gr_gid
    result = sync_certificate(**options)
    if not result.get("ok"):
        raise RuntimeError("Certificate validation failed")
    print(json.dumps({"ok": True, "changed": result.get("changed", False), "source": "verified_acme_lineage", "services_restarted": False}))

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"ok": False, "error": "Direct ACME synchronization failed; existing project certificate retained"}))
        raise SystemExit(1)
