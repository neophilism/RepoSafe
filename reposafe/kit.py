"""Signed, hash-inventoried offline recovery software and public roots."""

import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .common import BackupError, command, sha256, write_json
from .datasets import tool_environment
from .format import safe_relative
from .signing import public_key, read_regular, sign_file, verify_bytes

TOOLS = {"age", "age-keygen", "git", "git-lfs", "rclone", "python", "os-image"}
REQUIRED_TOOLS = TOOLS - {"os-image"}
WHEEL_NAMES = {"cryptography", "boto3", "botocore", "cffi", "pycparser", "jmespath", "s3transfer", "python_dateutil", "six", "urllib3", "setuptools", "wheel", "packaging"}


def fsync_tree(root):
    paths = list(Path(root).rglob("*"))
    for path in paths:
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as source:
                os.fsync(source.fileno())
    for directory in sorted((p for p in paths if p.is_dir()), key=lambda p: len(p.parts), reverse=True) + [Path(root)]:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def file_inventory(root, *, excluded=()):
    result, total = [], 0
    for path in sorted(Path(root).rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise BackupError("recovery material contains an unsupported link or special file")
        if path.is_file() and path.relative_to(root).as_posix() not in excluded:
            name = path.relative_to(root).as_posix()
            safe_relative(name)
            size = path.stat().st_size
            total += size
            if len(result) >= 100000 or total > 20 * 1024 ** 3:
                raise BackupError("recovery material exceeds inventory limits")
            result.append({"path": name, "bytes": size, "sha256": sha256(path)})
    return result


def verify_files(root, entries, *, excluded=()):
    if not isinstance(entries, list) or len(entries) > 100000:
        raise BackupError("invalid recovery-material inventory")
    expected = {}
    for entry in entries:
        name = entry["path"]
        safe_relative(name)
        if name in expected or type(entry["bytes"]) is not int or entry["bytes"] < 0 or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]):
            raise BackupError("invalid recovery-material file record")
        expected[name] = entry
    if {e["path"]: e for e in file_inventory(root, excluded=excluded)} != expected:
        raise BackupError("recovery-material file set or contents differ from signed inventory")


def copy_file(source, destination, *, maximum=20 * 1024 ** 3):
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > maximum:
        raise BackupError("recovery input must be a regular bounded file")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with source.open("rb") as incoming, destination.open("xb") as output:
        destination.chmod(0o600)
        total = 0
        while chunk := incoming.read(1024 * 1024):
            total += len(chunk)
            if total > maximum:
                raise BackupError("recovery input exceeds its byte budget")
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if source.stat().st_size != total or sha256(source) != sha256(destination):
        raise BackupError("recovery input changed during copy")


def build_kit(source_root, revision, output, signing_key, public_roots, *, tools=None, wheels=()):
    source_root, output = Path(source_root).absolute(), Path(output).absolute()
    if (not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", revision) or output.exists() or output.is_symlink() or
        any(p.is_symlink() for p in output.parents) or output == source_root or source_root in output.parents):
        raise BackupError("kit needs an exact reviewed revision and a new output outside its source checkout")
    env = tool_environment()
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    git = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", source_root]
    if command([*git, "rev-parse", "HEAD"], env=env).decode().strip() != revision:
        raise BackupError("kit source checkout does not match the reviewed revision")
    command([*git, "diff", "--exit-code", "--quiet", "HEAD", "--"], env=env)
    paths = command([*git, "ls-files", "-z"], env=env).decode().split("\0")
    selected = [name for name in paths if name and (name in ("README.md", "pyproject.toml", "scripts/qualify_local.py") or
        name.startswith(("reposafe/", "tests/")) and name.endswith(".py") or
        name.startswith("docs/") and name.endswith(".md") or name.startswith("requirements") and name.endswith(".lock"))]
    if not {"reposafe/__init__.py", "pyproject.toml", "README.md"} <= set(selected) or not public_roots:
        raise BackupError("kit needs reviewed RepoSafe source and independently enrolled public roots")
    tools = tools or {}
    if set(tools) - TOOLS or any(not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) for name in public_roots):
        raise BackupError("invalid recovery tool/root enrollment")
    with tempfile.TemporaryDirectory(prefix=".kit-", dir=output.parent) as raw:
        stage = Path(raw)
        for name in selected:
            safe_relative(name)
            copy_file(source_root / name, stage / "source" / name, maximum=16 * 1024 ** 2)
        for name, path in public_roots.items():
            public_key(path)
            copy_file(path, stage / "pins" / (name + ".pem"), maximum=65536)
        for name, path in tools.items():
            # Only explicitly supplied software, never arbitrary config/key directories.
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as source:
                import stat
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise BackupError("recovery software must be a regular file")
                header = source.read(4096)
            if b"PRIVATE KEY" in header or b"AGE-SECRET-KEY-" in header:
                raise BackupError("recovery software enrollment contains private key material")
            copy_file(path, stage / "tools" / name)
        wheel_packages = set()
        for path in wheels:
            path = Path(path)
            if not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", path.name):
                raise BackupError("offline dependencies must be explicit wheel files")
            wheel_packages.add(path.name.split("-")[0].lower())
            copy_file(path, stage / "wheels" / path.name, maximum=1024 ** 3)
        manifest = {"schema_version": 1, "kind": "recovery-kit", "revision": revision,
            "built_at": datetime.now(timezone.utc).isoformat(), "tool_files": sorted(tools),
            "public_roots": sorted(public_roots), "wheel_packages": sorted(wheel_packages),
            "ready_for_drill": REQUIRED_TOOLS <= set(tools) and WHEEL_NAMES <= wheel_packages,
            "files": file_inventory(stage),
            "compatibility": "file presence is not a clean-machine qualification; validate OS/architecture/shared libraries and full offline restore"}
        write_json(stage / "kit.json", manifest)
        sign_file(stage / "kit.json", signing_key, stage / "kit.sig.json", "recovery-kit")
        fsync_tree(stage)
        os.rename(stage, output)
        descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return manifest


def verify_kit(directory, pinned_key, *, require_tools=False):
    directory = Path(directory)
    try:
        raw = read_regular(directory / "kit.json", 16 * 1024 ** 2)
        verify_bytes(raw, json.loads(read_regular(directory / "kit.sig.json", 4096)), pinned_key, "recovery-kit")
        manifest = json.loads(raw)
        if manifest["schema_version"] != 1 or manifest["kind"] != "recovery-kit" or type(manifest["ready_for_drill"]) is not bool:
            raise ValueError
        if require_tools and (not manifest["ready_for_drill"] or not REQUIRED_TOOLS <= set(manifest["tool_files"]) or
                              not WHEEL_NAMES <= set(manifest["wheel_packages"])):
            raise BackupError("offline export requires a kit with enrolled tools and dependency wheels")
        verify_files(directory, manifest["files"], excluded=("kit.json", "kit.sig.json"))
        return manifest
    except BackupError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise BackupError("recovery-kit validation failed") from None
