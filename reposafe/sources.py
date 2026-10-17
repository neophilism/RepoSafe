"""Explicit additional sources: regular files only, no executable export hooks."""

import fnmatch
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Protocol

from .common import BackupError
from .config import FileSource


class Collector(Protocol):
    def collect(self, destination: Path) -> dict:
        """Write private source data and return consistency/coverage evidence."""


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class FileCollector:
    def __init__(self, source: FileSource, *, forbidden=()):
        self.source = source
        self.forbidden = tuple(Path(p).resolve() for p in forbidden if p is not None)

    def collect(self, destination: Path) -> dict:
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise BackupError("safe file collection requires a POSIX host with no-follow support")
        source = self.source.path
        copied = total = 0
        root = source.resolve()
        if any(root == p or root in p.parents or p in root.parents for p in self.forbidden):
            raise BackupError("file source overlaps backup output, state or scratch")

        def excluded(relative):
            return any(fnmatch.fnmatchcase(relative, p) or PurePosixPath(relative).match(p)
                       for p in self.source.exclude)

        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        directory_flags = flags | os.O_DIRECTORY

        def visit(parent_fd, name, target, relative):
            nonlocal copied, total
            if relative and excluded(relative):
                return
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                target.mkdir(mode=0o700)
                descriptor = os.open(name, directory_flags, dir_fd=parent_fd)
                try:
                    if fingerprint(os.fstat(descriptor)) != fingerprint(info):
                        raise BackupError("file source directory changed before capture")
                    with os.scandir(descriptor) as listing:
                        names = sorted(entry.name for entry in listing)
                    for child in names:
                        visit(descriptor, child, target / child, f"{relative}/{child}".lstrip("/"))
                    if fingerprint(os.fstat(descriptor)) != fingerprint(info):
                        raise BackupError("file source directory changed during capture")
                    if fingerprint(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != fingerprint(info):
                        raise BackupError("file source directory changed after capture")
                finally:
                    os.close(descriptor)
                return
            if not stat.S_ISREG(info.st_mode):
                raise BackupError("file source contains a symlink or unsupported special file")
            if total + info.st_size > self.source.maximum_bytes:
                raise BackupError("file source exceeds configured byte budget")
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            with os.fdopen(descriptor, "rb") as incoming:
                if fingerprint(os.fstat(incoming.fileno())) != fingerprint(info):
                    raise BackupError("file source changed before copy")
                with target.open("xb") as outgoing:
                    os.chmod(target, 0o600)
                    remaining = info.st_size
                    while remaining:
                        chunk = incoming.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise BackupError("file source shrank during copy")
                        outgoing.write(chunk)
                        remaining -= len(chunk)
                    if incoming.read(1) or fingerprint(os.fstat(incoming.fileno())) != fingerprint(info):
                        raise BackupError("file source changed during copy")
            if fingerprint(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != fingerprint(info):
                raise BackupError("file source changed after copy")
            copied += 1
            total += info.st_size

        try:
            if not source.is_absolute() or ".." in source.parts:
                raise BackupError("file source must be an absolute canonical path")
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Anchor every ancestor; no concurrent parent-to-symlink swap can escape.
            descriptor = os.open(source.anchor, directory_flags)
            try:
                for component in source.parent.parts[1:]:
                    child_fd = os.open(component, directory_flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child_fd
                info = os.stat(source.name, dir_fd=descriptor, follow_symlinks=False)
                visit(descriptor, source.name, destination, "" if stat.S_ISDIR(info.st_mode) else source.name)
            finally:
                os.close(descriptor)
            return {"files": copied, "bytes": total,
                    "consistency": "checked per-file copy; not a filesystem/database transaction"}
        except (OSError, ValueError):
            raise BackupError("file source unavailable or changed during capture") from None
