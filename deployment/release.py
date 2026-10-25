#!/usr/bin/env python3
"""Explicit local release builder: allowlisted source plus one pinned Linux wheel.

No downloads, imports of production state, installation or network calls.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import zipfile

PROTOBUF_VERSION = "7.36.2"
LICENSE_FILES = ("third_party/sing-box-LICENSE.txt", "third_party/GPL-3.0.txt", "third_party/NOTICE.md")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_wheel(path, expected_sha256, architecture="x86_64"):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("A regular wheel and explicit SHA256 are required")
    payload = path.read_bytes()
    if digest(payload) != expected_sha256:
        raise ValueError("Protobuf wheel SHA256 does not match")
    if not path.name.startswith("protobuf-" + PROTOBUF_VERSION + "-") or not path.name.endswith(".whl"):
        raise ValueError("Only the pinned protobuf runtime wheel is allowed")
    if architecture not in {"x86_64", "aarch64"}:
        raise ValueError("Unsupported target architecture")
    if not path.name.endswith("-py3-none-any.whl") and ("manylinux" not in path.name or architecture not in path.name):
        raise ValueError("A pure Python or target Linux manylinux wheel is required")
    with zipfile.ZipFile(io.BytesIO(payload)) as wheel:
        names = wheel.namelist()
        if any(name.startswith("/") or ".." in Path(name).parts or name.endswith(".pth") for name in names):
            raise ValueError("Unsafe wheel content")
        metadata = wheel.read("protobuf-" + PROTOBUF_VERSION + ".dist-info/METADATA").decode()
        if "Name: protobuf\n" not in metadata or "Version: " + PROTOBUF_VERSION + "\n" not in metadata:
            raise ValueError("Wheel metadata does not match protobuf runtime")
        for name in names:
            if name.endswith("/"): continue
            if not name.startswith(("google/", "protobuf-" + PROTOBUF_VERSION + ".dist-info/")):
                raise ValueError("Unexpected protobuf runtime content")
    return payload


def source_files(repository):
    repository = Path(repository).resolve()
    files = {}
    for path in sorted((repository / "backend" / "dazzle").rglob("*")):
        if path.is_file() and path.suffix in {".py", ".proto"} and "__pycache__" not in path.parts:
            if path.is_symlink(): raise ValueError("Release sources cannot be symlinks")
            files["backend/" + path.relative_to(repository / "backend").as_posix()] = path.read_bytes()
    for name in ("__init__.py", "helper.py", "certsync.py", "control.py", "release.py", "installer.py", "repair.py", "update.py"):
        path = repository / "deployment" / name
        if not path.is_file() or path.is_symlink(): raise ValueError("A deployment source file is missing or unsafe")
        files["deployment/" + name] = path.read_bytes()
    for path in sorted((repository / "deployment" / "systemd").glob("*")):
        if path.is_symlink() or not path.is_file() or path.suffix not in {".service", ".socket", ".timer"}:
            raise ValueError("Unsafe service template")
        files["deployment/systemd/" + path.name] = path.read_bytes()
    for name in LICENSE_FILES:
        path = repository / name
        if not path.is_file() or path.is_symlink(): raise ValueError("Required source license is missing")
        files[name] = path.read_bytes()
    if not files or "backend/dazzle/production.py" not in files:
        raise ValueError("Production controller source is required")
    return files


def build_release(repository, wheel, wheel_sha256, output, *, architecture="x86_64"):
    output = Path(output)
    if output.exists() or output.is_symlink(): raise ValueError("Release output already exists")
    if not output.parent.is_dir(): raise ValueError("Release output parent must already exist")
    payload = validate_wheel(wheel, wheel_sha256, architecture)
    files = source_files(repository)
    files["wheelhouse/" + Path(wheel).name] = payload
    files["requirements.txt"] = ("protobuf==" + PROTOBUF_VERSION + " --hash=sha256:" + wheel_sha256 + "\n").encode()
    inventory = {name: digest(body) for name, body in sorted(files.items())}
    release_id = digest(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode())[:24]
    manifest = {"schema_version": 1, "release_id": release_id, "python": "3.12", "architecture": architecture,
                "protobuf_version": PROTOBUF_VERSION, "wheel_filename": Path(wheel).name,
                "wheel_sha256": wheel_sha256, "files": inventory,
                "contains_production_state": False, "contains_real_credentials": False}
    files["release.json"] = json.dumps(manifest, sort_keys=True, indent=2).encode() + b"\n"
    with output.open("xb") as target:
        with tarfile.open(fileobj=target, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            for name, body in sorted(files.items()):
                info = tarfile.TarInfo(name); info.size = len(body); info.mode = 0o644
                info.uid = info.gid = info.mtime = 0
                archive.addfile(info, io.BytesIO(body))
    output.chmod(0o600)
    return {"release_id": release_id, "archive": str(output), "archive_sha256": digest(output.read_bytes()),
            "files_count": len(files), "architecture": architecture, "production_modified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build a private allowlisted parallel pilot release")
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--architecture", choices=["x86_64", "aarch64"], default="x86_64")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(build_release(args.repository, args.wheel, args.wheel_sha256, args.output, architecture=args.architecture)))
        return 0
    except Exception:
        print(json.dumps({"ok": False, "error": "Release validation failed; no installation was attempted"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
