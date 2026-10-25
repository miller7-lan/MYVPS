#!/usr/bin/env python3
"""Copy a validated, explicitly selected pair into ONLY the project namespace.

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
import re
import stat
from pathlib import Path
import ssl
import tempfile

from .helper import HelperError, Layout, Runner, atomic_bytes, atomic_json, checked_path, read_json, validate_policy

SOURCE_CERT = Path("/etc/s-box/cert.pem")
SOURCE_KEY = Path("/etc/s-box/private.key")
CERTBOT_ROOT = Path("/etc/letsencrypt")


def _file_signature(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_regular(path, trusted_uid):
    before = checked_path(path, trusted_uid)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != trusted_uid or
                    opened.st_mode & 0o022 or opened.st_nlink != 1 or
                    _file_signature(opened) != _file_signature(before)):
                raise HelperError("TLS_INVALID", "Certificate material changed while opening")
            contents = stream.read(256 * 1024 + 1)
            if _file_signature(os.fstat(stream.fileno())) != _file_signature(opened):
                raise HelperError("TLS_INVALID", "Certificate material changed while reading")
    except OSError:
        raise HelperError("TLS_INVALID", "Certificate material is unavailable") from None
    if not contents or len(contents) > 256 * 1024:
        raise HelperError("TLS_INVALID", "Certificate material exceeds its size limit")
    return contents


def _managed_directories(path, root, trusted_uid):
    # Root/UID injection exists only for isolated Python tests. The CLI always
    # uses root-owned /etc/letsencrypt and checks every ancestor, including /etc.
    ancestors = list(reversed(path.parents)) + [path]
    if root != CERTBOT_ROOT or trusted_uid != 0:
        ancestors = [parent for parent in ancestors if parent == root or root in parent.parents]
    for parent in ancestors:
        if parent == Path("/"):
            continue
        checked_path(parent, trusted_uid, directory=True)


def _managed_pair_paths(source_cert, source_key, trusted_uid, certbot_root):
    root = Path(certbot_root)
    cert, key = Path(source_cert), Path(source_key)
    if (not root.is_absolute() or ".." in root.parts or not cert.is_absolute() or
            not key.is_absolute() or ".." in cert.parts or ".." in key.parts):
        raise HelperError("TLS_INVALID", "Managed certificate paths must be explicit")
    try:
        cert_relative, key_relative = cert.relative_to(root), key.relative_to(root)
    except ValueError:
        raise HelperError("TLS_INVALID", "Managed certificate is outside the installed Certbot root") from None
    if (len(cert_relative.parts) != 3 or len(key_relative.parts) != 3 or
            cert_relative.parts[0] != "live" or key_relative.parts[0] != "live" or
            cert_relative.parts[1] != key_relative.parts[1] or
            cert_relative.parts[2] != "fullchain.pem" or key_relative.parts[2] != "privkey.pem"):
        raise HelperError("TLS_INVALID", "Exactly one managed Certbot lineage is required")
    name = cert_relative.parts[1]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", name):
        raise HelperError("TLS_INVALID", "Invalid Certbot lineage name")
    archive = root / "archive" / name
    _managed_directories(cert.parent, root, trusted_uid)
    _managed_directories(archive, root, trusted_uid)
    records = []
    for source, prefix in ((cert, "fullchain"), (key, "privkey")):
        try:
            link_info = source.lstat()
            if not stat.S_ISLNK(link_info.st_mode) or link_info.st_uid != trusted_uid:
                raise HelperError("TLS_INVALID", "Managed live entries must be trusted Certbot symlinks")
            link_text = os.readlink(source)
            target = Path(os.path.abspath(source.parent / link_text))
            if target.parent != archive:
                raise HelperError("TLS_INVALID", "Managed live entry leaves its Certbot archive")
            match = re.fullmatch(re.escape(prefix) + r"([1-9][0-9]*)\.pem", target.name)
            if not match:
                raise HelperError("TLS_INVALID", "Managed live entry has an unexpected archive filename")
            target_info = checked_path(target, trusted_uid)
            records.append((target, match.group(1), link_text,
                            _file_signature(link_info), _file_signature(target_info)))
        except OSError:
            raise HelperError("TLS_INVALID", "Managed certificate source is unavailable") from None
    if records[0][1] != records[1][1]:
        raise HelperError("TLS_INVALID", "Managed certificate and key versions differ; retry after renewal completes")
    return tuple(records)


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
    run(["/usr/bin/openssl", "verify", "-partial_chain", "-verify_ip", endpoint, "-CAfile", str(cert_path), str(cert_path)])
    cert_public = run(["/usr/bin/openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"])
    key_public = run(["/usr/bin/openssl", "pkey", "-in", str(key_path), "-pubout"])
    if cert_public.strip() != key_public.strip():
        raise HelperError("TLS_INVALID", "Certificate and private key do not match")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try: context.load_cert_chain(str(cert_path), str(key_path))
    except (ssl.SSLError, OSError):
        raise HelperError("TLS_INVALID", "Certificate pair could not be loaded") from None


def sync_certificate(*, layout=None, source_cert=SOURCE_CERT, source_key=SOURCE_KEY, runner=None,
                     tls_gid=None, portal_tls_gid=None, validator=validate_pair,
                     managed_certbot_source=False, certbot_root=CERTBOT_ROOT):
    layout, runner = layout or Layout(), runner or Runner()
    policy = validate_policy(read_json(layout.policy, layout.trusted_uid))
    checked_path(layout.etc / "tls", layout.trusted_uid, directory=True)
    if policy["version"] == 2:
        checked_path(layout.etc / "web-tls", layout.trusted_uid, directory=True)
        if type(portal_tls_gid) is not int or portal_tls_gid <= 0:
            raise HelperError("TLS_INVALID", "The separate installed portal TLS group is required")
    # Never generally enable symlink traversal. Only the explicit managed mode
    # resolves the two live leaves to pinned, same-version archive regular files.
    managed = None
    if managed_certbot_source:
        managed = _managed_pair_paths(source_cert, source_key, layout.trusted_uid, certbot_root)
        cert_target, key_target = managed[0][0], managed[1][0]
    else:
        cert_target, key_target = source_cert, source_key
    # Read the two immutable snapshots first, then validate those exact bytes.
    certificate = _read_regular(cert_target, layout.trusted_uid)
    private_key = _read_regular(key_target, layout.trusted_uid)
    with tempfile.TemporaryDirectory(prefix=".validate-", dir=layout.etc / "tls") as temporary:
        cert_stage, key_stage = Path(temporary) / "cert.pem", Path(temporary) / "key.pem"
        cert_stage.write_bytes(certificate); cert_stage.chmod(0o600)
        key_stage.write_bytes(private_key); key_stage.chmod(0o600)
        validator(cert_stage, key_stage, policy["server_endpoint"], runner)
    if managed is not None and managed != _managed_pair_paths(source_cert, source_key, layout.trusted_uid, certbot_root):
        raise HelperError("TLS_INVALID", "Managed source changed during validation; existing pair retained")
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
    parser.add_argument("--source-cert", type=Path, help="Explicit certificate file; paired with --source-key")
    parser.add_argument("--source-key", type=Path, help="Explicit private key file; paired with --source-cert")
    parser.add_argument("--managed-certbot-source", action="store_true",
                        help="Allow only matched /etc/letsencrypt/live/<name> managed archive symlinks")
    args = parser.parse_args(argv)
    if (args.source_cert is None) != (args.source_key is None):
        parser.error("--source-cert and --source-key must be supplied together")
    if args.managed_certbot_source and args.source_cert is None:
        parser.error("managed Certbot mode requires both explicit source paths")
    try:
        if os.geteuid() != 0: raise HelperError("FORBIDDEN", "TLS sync requires the installed root service")
        policy = validate_policy(read_json(Layout().policy))
        portal_gid = grp.getgrnam("dazzle-web").gr_gid if policy["version"] == 2 else None
        result = sync_certificate(source_cert=args.source_cert or SOURCE_CERT, source_key=args.source_key or SOURCE_KEY,
                                  managed_certbot_source=args.managed_certbot_source,
                                  tls_gid=grp.getgrnam("dazzle-vps").gr_gid, portal_tls_gid=portal_gid)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception:
        print(json.dumps({"ok": False, "error": "Project TLS synchronization failed; existing pair retained where possible"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
