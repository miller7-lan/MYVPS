#!/usr/bin/env python3
"""Copy a validated legacy certificate pair into ONLY the new project namespace.

Never invokes certbot/systemctl or writes the source paths. On validation failure
the existing project pair remains intact. Two separate watched files are required
by sing-box 1.14.4; a combined same-path PEM cannot safely rotate the private key.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import ssl
import tempfile

from .helper import HelperError, Layout, Runner, atomic_bytes, atomic_json, checked_path, read_json, validate_policy

SOURCE_CERT = Path("/etc/s-box/cert.pem")
SOURCE_KEY = Path("/etc/s-box/private.key")


def _read_regular(path, trusted_uid):
    checked_path(path, trusted_uid)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        contents = stream.read(256 * 1024 + 1)
    if not contents or len(contents) > 256 * 1024:
        raise HelperError("TLS_INVALID", "Certificate material exceeds its size limit")
    return contents


def validate_pair(cert_path, key_path, endpoint, runner):
    def run(args):
        try:
            result = runner.run(args, timeout=10)
        except Exception:
            raise HelperError("TLS_INVALID", "Certificate validation failed") from None
        if result.returncode:
            raise HelperError("TLS_INVALID", "Certificate validation failed")
        return result.stdout
    run(["/usr/bin/openssl", "x509", "-in", str(cert_path), "-noout", "-checkip", endpoint])
    run(["/usr/bin/openssl", "x509", "-in", str(cert_path), "-noout", "-checkend", "86400"])
    # X509_check_host/checkend do not check notBefore. verify checks both validity
    # bounds using this exact end certificate as the explicitly trusted anchor.
    run(["/usr/bin/openssl", "verify", "-partial_chain", "-CAfile", str(cert_path), str(cert_path)])
    cert_public = run(["/usr/bin/openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"])
    key_public = run(["/usr/bin/openssl", "pkey", "-in", str(key_path), "-pubout"])
    if cert_public.strip() != key_public.strip():
        raise HelperError("TLS_INVALID", "Certificate and private key do not match")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try: context.load_cert_chain(str(cert_path), str(key_path))
    except (ssl.SSLError, OSError):
        raise HelperError("TLS_INVALID", "Certificate pair could not be loaded") from None


def sync_certificate(*, layout=None, source_cert=SOURCE_CERT, source_key=SOURCE_KEY, runner=None, tls_gid=None, portal_tls_gid=None, validator=validate_pair):
    layout, runner = layout or Layout(), runner or Runner()
    policy = validate_policy(read_json(layout.policy, layout.trusted_uid))
    checked_path(layout.etc / "tls", layout.trusted_uid, directory=True)
    if policy["version"] == 2:
        checked_path(layout.etc / "web-tls", layout.trusted_uid, directory=True)
        if type(portal_tls_gid) is not int or portal_tls_gid <= 0:
            raise HelperError("TLS_INVALID", "The separate installed portal TLS group is required")
    # Read the two immutable snapshots first, then validate those exact bytes.
    certificate = _read_regular(source_cert, layout.trusted_uid)
    private_key = _read_regular(source_key, layout.trusted_uid)
    with tempfile.TemporaryDirectory(prefix=".validate-", dir=layout.etc / "tls") as temporary:
        cert_stage, key_stage = Path(temporary) / "cert.pem", Path(temporary) / "key.pem"
        cert_stage.write_bytes(certificate); cert_stage.chmod(0o600)
        key_stage.write_bytes(private_key); key_stage.chmod(0o600)
        validator(cert_stage, key_stage, policy["server_endpoint"], runner)
    fingerprints = {"certificate_sha256": hashlib.sha256(certificate).hexdigest()}
    unchanged = False
    if layout.tls_certificate.exists() and layout.tls_key.exists():
        unchanged = (_read_regular(layout.tls_certificate, layout.trusted_uid) == certificate and
                     _read_regular(layout.tls_key, layout.trusted_uid) == private_key)
    if not unchanged:
        # Validation has finished; never roll either target back to an older pair.
        atomic_bytes(layout.tls_certificate, certificate, mode=0o640, trusted_uid=layout.trusted_uid, gid=tls_gid)
        atomic_bytes(layout.tls_key, private_key, mode=0o640, trusted_uid=layout.trusted_uid, gid=tls_gid)
        atomic_json(layout.etc / "tls" / "status.json", fingerprints, layout.trusted_uid)
    portal_changed = False
    if policy["version"] == 2:
        portal_cert, portal_key = layout.etc / "web-tls" / "cert.pem", layout.etc / "web-tls" / "key.pem"
        portal_changed = not (portal_cert.exists() and portal_key.exists() and
                              _read_regular(portal_cert, layout.trusted_uid) == certificate and
                              _read_regular(portal_key, layout.trusted_uid) == private_key)
        if portal_changed:
            atomic_bytes(portal_cert, certificate, mode=0o640, trusted_uid=layout.trusted_uid, gid=portal_tls_gid)
            atomic_bytes(portal_key, private_key, mode=0o640, trusted_uid=layout.trusted_uid, gid=portal_tls_gid)
            atomic_json(layout.etc / "web-tls" / "status.json", fingerprints, layout.trusted_uid)
    return {"ok": True, "changed": not unchanged or portal_changed, "legacy_modified": False,
            "services_restarted": False, "certificate_sha256": fingerprints["certificate_sha256"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Project-only validated TLS pair synchronization")
    parser.parse_args(argv)
    try:
        if os.geteuid() != 0: raise HelperError("FORBIDDEN", "TLS sync requires the installed root service")
        policy = validate_policy(read_json(Layout().policy))
        portal_gid = grp.getgrnam("dazzle-web").gr_gid if policy["version"] == 2 else None
        result = sync_certificate(tls_gid=grp.getgrnam("dazzle-vps").gr_gid, portal_tls_gid=portal_gid)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception:
        print(json.dumps({"ok": False, "error": "Project TLS synchronization failed; existing pair retained where possible"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
