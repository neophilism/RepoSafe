"""Versioned payload inventory; paths are relative to the snapshot root."""

import re
from pathlib import Path, PurePosixPath

from .common import BackupError, sha256, write_json

CONTENT_MANIFEST = "content-manifest.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def safe_relative(name):
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        raise BackupError("invalid archive path")
    path = PurePosixPath(name)
    if not path.parts or path.is_absolute() or ".." in path.parts or str(path) != name:
        raise BackupError("invalid archive path")
    return path


def content_inventory(root):
    entries = []
    for path in sorted(Path(root).rglob("*")):
        if path.is_symlink():
            raise BackupError("snapshot payload contains an unsupported link")
        if path.is_file():
            name = path.relative_to(root).as_posix()
            safe_relative(name)
            entries.append({"path": name, "bytes": path.stat().st_size, "sha256": sha256(path)})
        elif not path.is_dir():
            raise BackupError("snapshot payload contains a special file")
    write_json(Path(root) / CONTENT_MANIFEST, {"schema_version": 1, "files": entries})
    return len(entries)
