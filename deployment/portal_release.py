"""Offline, exact-hash release format for the separately reviewed web expansion.

This builder never resolves/downloads dependencies or opens production state.
Its schema is deliberately distinct from the old protobuf-only program updater.
"""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import io
import json
from pathlib import Path
import re
import tarfile
import zipfile

from .helper import CORE_SHA256
from .installer import canonical, sha256
from .release import LICENSE_FILES, PROTOBUF_VERSION, source_files, validate_wheel

REQUIRED_PACKAGES = frozenset({"protobuf", "starlette", "uvicorn", "anyio", "click", "h11", "idna", "typing-extensions", "qrcode"})
OPTIONAL_PACKAGES = frozenset({"sniffio"})
PORTAL_TOOLS = ("portal_release.py", "portal_upgrade.py", "handoff.py", "coordinator.py")
STATIC_FILES = ("index.html", "app.css", "app.js")
TEMPLATES = ("subscription.service", "agent.conf", "certsync.conf", "tmpfiles.conf", "writer@.service", "meter-guard@.service", "guarded-member.service", "managed-certsync.conf")


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def validate_locked_wheels(wheelhouse, lock, *, architecture="x86_64"):
    wheelhouse = Path(wheelhouse)
    if wheelhouse.is_symlink() or not wheelhouse.is_dir() or not isinstance(lock, list):
        raise ValueError("A regular wheel directory and explicit dependency lock are required")
    payloads, entries = {}, {}
    for item in lock:
        if not isinstance(item, dict) or set(item) != {"name", "version", "filename", "sha256"}:
            raise ValueError("Invalid dependency lock entry")
        name, version, filename = normalized(item["name"]), item["version"], item["filename"]
        if name not in REQUIRED_PACKAGES | OPTIONAL_PACKAGES or name in entries:
            raise ValueError("Unexpected or duplicate dependency")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:\.post[0-9]+)?", version):
            raise ValueError("A stable exact dependency version is required")
        if not isinstance(filename, str) or Path(filename).name != filename or not filename.endswith(".whl"):
            raise ValueError("Invalid dependency wheel name")
        path = wheelhouse / filename
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r"[a-f0-9]{64}", str(item["sha256"])):
            raise ValueError("A regular dependency wheel with explicit SHA256 is required")
        body = path.read_bytes()
        if sha256(body) != item["sha256"]:
            raise ValueError("Dependency wheel digest changed")
        if name == "protobuf":
            if version != PROTOBUF_VERSION:
                raise ValueError("The existing pinned protobuf runtime must be retained")
            validate_wheel(path, item["sha256"], architecture)
        elif not filename.endswith("-py3-none-any.whl"):
            raise ValueError("Portal dependencies must be pure Python wheels")
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            members = archive.namelist()
            if len(members) > 10000 or len(set(members)) != len(members):
                raise ValueError("Unsafe dependency wheel inventory")
            if sum(member.file_size for member in archive.infolist()) > 32 * 1024 * 1024:
                raise ValueError("Expanded dependency wheel is too large")
            for member in archive.infolist():
                if member.filename.startswith("/") or ".." in Path(member.filename).parts or member.filename.endswith(".pth") or (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Unsafe dependency wheel path")
            metadata = [n for n in members if n.endswith(".dist-info/METADATA")]
            if len(metadata) != 1:
                raise ValueError("Dependency metadata is ambiguous")
            parsed = BytesParser().parsebytes(archive.read(metadata[0]))
            if normalized(parsed.get("Name", "")) != name or parsed.get("Version") != version:
                raise ValueError("Dependency identity does not match the lock")
        entries[name] = {"name": name, "version": version, "filename": filename, "sha256": item["sha256"]}
        payloads["wheelhouse/" + filename] = body
    if not REQUIRED_PACKAGES.issubset(entries):
        raise ValueError("The locked portal dependency set is incomplete")
    return [entries[name] for name in sorted(entries)], payloads


def requirements_bytes(entries):
    return "".join(item["name"] + "==" + item["version"] + " --hash=sha256:" + item["sha256"] + "\n" for item in entries).encode()


def portal_sources(repository):
    repository = Path(repository).resolve()
    result = source_files(repository)
    for name in PORTAL_TOOLS:
        path = repository / "deployment" / name
        if not path.is_file() or path.is_symlink(): raise ValueError("A portal deployment tool is unavailable")
        result["deployment/" + name] = path.read_bytes()
    for name in STATIC_FILES:
        path = repository / "backend/dazzle/portal_static" / name
        if not path.is_file() or path.is_symlink(): raise ValueError("A portal static resource is unavailable")
        result["backend/dazzle/portal_static/" + name] = path.read_bytes()
    for name in TEMPLATES:
        path = repository / "deployment/portal-systemd" / name
        if not path.is_file() or path.is_symlink(): raise ValueError("A portal service template is unavailable")
        result["deployment/portal-systemd/" + name] = path.read_bytes()
    for name in ("portal.py", "portal_rpc.py", "registration.py", "meter_guard.py"):
        if "backend/dazzle/" + name not in result: raise ValueError("Portal implementation is incomplete")
    return result


def build_release(repository, wheelhouse, lock, output, *, architecture="x86_64"):
    output = Path(output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("A new output under an existing directory is required")
    entries, wheels = validate_locked_wheels(wheelhouse, lock, architecture=architecture)
    files = portal_sources(repository) | wheels
    files["requirements.txt"] = requirements_bytes(entries)
    inventory = {name: sha256(body) for name, body in sorted(files.items())}
    manifest = {"schema_version": 2, "kind": "portal_resources", "release_id": sha256(canonical(inventory))[:24],
                "python": "3.12", "architecture": architecture, "core_sha256": CORE_SHA256,
                "wheels": entries, "files": inventory, "contains_production_state": False, "contains_real_credentials": False}
    files["release.json"] = json.dumps(manifest, sort_keys=True, indent=2).encode() + b"\n"
    with output.open("xb") as target, tarfile.open(fileobj=target, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, body in sorted(files.items()):
            entry = tarfile.TarInfo(name); entry.size = len(body); entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(body))
    output.chmod(0o600)
    return {"release_id": manifest["release_id"], "archive_sha256": sha256(output.read_bytes()), "production_modified": False}


def inspect_archive(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("A bounded regular portal release is required")
    payload = path.read_bytes(); files = {}; total = 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for member in archive.getmembers():
            target = Path(member.name)
            if not member.isfile() or target.is_absolute() or target.as_posix() != member.name or ".." in target.parts or member.name in files or not 0 <= member.size <= 16 * 1024 * 1024:
                raise ValueError("Unsafe portal release member")
            total += member.size
            if total > 64 * 1024 * 1024: raise ValueError("Expanded portal release is too large")
            allowed = (member.name in {"release.json", "requirements.txt", *LICENSE_FILES} or
                       member.name.startswith(("backend/dazzle/", "deployment/", "wheelhouse/")))
            if not allowed or (member.name.endswith((".sqlite3", ".key", ".pem", ".json")) and member.name != "release.json"):
                raise ValueError("Unexpected state or path in portal release")
            files[member.name] = archive.extractfile(member).read()
    manifest = json.loads(files.pop("release.json"))
    fields = {"schema_version", "kind", "release_id", "python", "architecture", "core_sha256", "wheels", "files", "contains_production_state", "contains_real_credentials"}
    if set(manifest) != fields or manifest["schema_version"] != 2 or manifest["kind"] != "portal_resources" or manifest["python"] != "3.12" or manifest["architecture"] not in {"x86_64", "aarch64"} or manifest["core_sha256"] != CORE_SHA256 or manifest["contains_production_state"] is not False or manifest["contains_real_credentials"] is not False:
        raise ValueError("Unsupported portal release metadata")
    inventory = {name: sha256(body) for name, body in sorted(files.items())}
    if inventory != manifest["files"] or manifest["release_id"] != sha256(canonical(inventory))[:24] or files["requirements.txt"] != requirements_bytes(manifest["wheels"]):
        raise ValueError("Portal release inventory changed")
    import tempfile
    with tempfile.TemporaryDirectory(prefix="dazzle-wheel-check-") as directory:
        for item in manifest["wheels"]:
            filename = item.get("filename", "")
            if Path(filename).name != filename or "wheelhouse/" + filename not in files: raise ValueError("Missing locked wheel")
            (Path(directory) / filename).write_bytes(files["wheelhouse/" + filename])
        validated, _ = validate_locked_wheels(directory, manifest["wheels"], architecture=manifest["architecture"])
        if validated != manifest["wheels"]: raise ValueError("Dependency lock must be canonical")
    manifest["_archive_sha256"] = sha256(payload)
    return manifest, files


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build a separately reviewed offline portal release")
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--architecture", choices=["x86_64", "aarch64"], default="x86_64")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(build_release(args.repository, args.wheelhouse, json.loads(args.lock.read_text()), args.output, architecture=args.architecture))); return 0
    except Exception:
        print(json.dumps({"ok": False, "error": "Portal release validation failed; no deployment was attempted"})); return 1


if __name__ == "__main__": raise SystemExit(main())
