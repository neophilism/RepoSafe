"""Versioned payload inventory; paths are relative to the snapshot root."""

import re
import json
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
    entries, visited, encoded_bytes = [], 0, 128
    for path in Path(root).rglob("*"):
        visited += 1
        if visited > 500000:
            raise BackupError("snapshot exceeds its content entry budget")
        if path.is_symlink():
            raise BackupError("snapshot payload contains an unsupported link")
        if path.is_file():
            name = path.relative_to(root).as_posix()
            safe_relative(name)
            entry = {"path": name, "bytes": path.stat().st_size, "sha256": sha256(path)}
            encoded_bytes += len(json.dumps(entry).encode()) + 64
            if encoded_bytes > 128 * 1024 ** 2:
                raise BackupError("snapshot exceeds its content manifest byte budget")
            entries.append(entry)
        elif not path.is_dir():
            raise BackupError("snapshot payload contains a special file")
    entries.sort(key=lambda entry: entry["path"])
    write_json(Path(root) / CONTENT_MANIFEST, {"schema_version": 1, "files": entries})
    return len(entries)
