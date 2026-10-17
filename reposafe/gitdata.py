"""Git recovery evidence and LFS checks, without checking out or executing content."""

import re
from pathlib import Path

from .common import BackupError, command, sha256, write_json


def evidence(mirror, env, *, lfs):
    mirror = Path(mirror)
    prefix = ["git", "-c", "core.hooksPath=/dev/null", "-C", mirror]
    raw = command([*prefix, "for-each-ref", "--format=%(refname)%00%(objectname)"], env=env)
    refs = {}
    for line in raw.decode().splitlines():
        ref, oid = line.split("\x00")
        if not ref.startswith("refs/") or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
            raise BackupError("invalid Git ref evidence")
        refs[ref] = oid
    objects = []
    if lfs:
        listing = command([*prefix, "lfs", "ls-files", "--all", "--long"], env=env).decode()
        identifiers = set()
        for line in listing.splitlines():
            match = re.match(r"([0-9a-f]{64}) [*-] ", line)
            if not match:
                raise BackupError("unrecognized LFS inventory; cannot establish complete object coverage")
            identifiers.add(match[1])
        for oid in sorted(identifiers):
            path = mirror / "lfs/objects" / oid[:2] / oid[2:4] / oid
            if not path.is_file() or path.is_symlink() or sha256(path) != oid:
                raise BackupError("LFS object missing or corrupt")
            objects.append({"oid": oid, "bytes": path.stat().st_size})
    gitlinks = []
    for ref in refs:
        if not ref.startswith("refs/heads/"):
            continue
        # ls-tree records gitlinks without fetching or interpreting submodule URLs.
        tree = command([*prefix, "ls-tree", "-r", "-z", ref], env=env)
        for record in tree.split(b"\x00"):
            if record.startswith(b"160000 "):
                metadata, path = record.split(b"\t", 1)
                gitlinks.append({"ref": ref, "commit": metadata.split()[2].decode(),
                                 "path": path.decode("utf-8", "surrogateescape")})
    result = {"schema_version": 1, "head": (mirror / "HEAD").read_text().strip(),
              "refs": refs, "lfs_objects": objects, "gitlinks": gitlinks,
              "submodule_policy": "gitlinks preserved; target repositories require separate enrollment"}
    write_json(mirror.parent / "git-evidence.json", result)
    return result


def verify_restored(mirror, expected):
    prefix = ["git", "-c", "core.hooksPath=/dev/null", "-C", mirror]
    command([*prefix, "fsck", "--full", "--strict"])
    raw = command([*prefix, "for-each-ref", "--format=%(refname)%00%(objectname)"])
    actual = dict(line.split("\x00") for line in raw.decode().splitlines())
    if actual != expected["refs"] or (Path(mirror) / "HEAD").read_text().strip() != expected["head"]:
        raise BackupError("restored Git refs or HEAD do not match captured evidence")
    for entry in expected["lfs_objects"]:
        oid = entry["oid"]
        if not re.fullmatch(r"[0-9a-f]{64}", oid):
            raise BackupError("invalid LFS evidence")
        path = Path(mirror) / "lfs/objects" / oid[:2] / oid[2:4] / oid
        if not path.is_file() or path.stat().st_size != entry["bytes"] or sha256(path) != oid:
            raise BackupError("restored LFS object verification failed")
