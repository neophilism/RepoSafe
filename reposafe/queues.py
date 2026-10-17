"""Bounded queue sweeps for unattended isolated agents; never delete inputs."""

import json
from pathlib import Path

from .agents import deliver_agent, verify_catalog
from .common import BackupError
from .delivery import RUN_ID
from .signing import private_public_key, read_regular
from .witness import timestamp, witness


def directories(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise BackupError("queue root must be an enrolled regular directory")
    children = list(root.iterdir())
    if len(children) > 10000:
        raise BackupError("queue exceeds entry limit; archive completed inputs separately")
    return sorted(p for p in children if RUN_ID.fullmatch(p.name) and p.is_dir() and not p.is_symlink())


def agent_sweep(config, inbox, destination, state_dir, collector_key, writer_key, *, transport=None):
    counts = {"delivered": 0, "previously_delivered": 0, "failed": 0, "incomplete": 0}
    for directory in directories(inbox):
        if not (directory / "receipt.json").is_file():
            counts["incomplete"] += 1
            continue
        cached = Path(state_dir) / "catalogs" / directory.name / "catalog.json"
        try:
            if cached.exists():
                value, _ = verify_catalog(cached, private_public_key(writer_key), collector_key)
                if value["destination"] != destination or value["run_id"] != directory.name:
                    raise BackupError("cached catalog disagrees with queue identity")
                counts["previously_delivered"] += 1
            else:
                _, complete = deliver_agent(config, directory, destination, state_dir, collector_key, writer_key, transport=transport)
                counts["delivered"] += 1
                if not complete:
                    counts["incomplete"] += 1
        except (BackupError, OSError):
            counts["failed"] += 1
    return counts


def witness_sweep(config, inbox, writer_keys, collector_key, state_dir, signing_key, *, minimum_immutable=1, **kwargs):
    inbox = Path(inbox)
    required = [d.name for d in config.destinations if d.required]
    if not required:
        raise BackupError("witness queue needs required destinations")
    candidates = set()
    for name in required:
        candidates.update(p.name for p in directories(inbox / name))
    state = Path(state_dir) / "witness.json"
    previous = json.loads(read_regular(state, 1024 ** 2)) if state.exists() else {}
    anchor = timestamp(previous["captured_at"]) if previous.get("captured_at") else None
    counts = {"witnessed": 0, "previously_witnessed": 0, "failed": 0, "incomplete": 0}
    pending = []
    for run_id in sorted(candidates):
        paths = [inbox / name / run_id / "catalog.json" for name in required]
        if not all(p.is_file() and not p.is_symlink() for p in paths):
            counts["incomplete"] += 1
            continue
        try:
            _, receipt = verify_catalog(paths[0], writer_keys[required[0]], collector_key)
            captured = timestamp(receipt.get("captured_at", run_id[:16]))
            if receipt["run_id"] != run_id:
                raise BackupError("catalog is in the wrong queue directory")
            if anchor is not None and captured <= anchor:
                counts["previously_witnessed"] += 1
            else:
                pending.append((captured, paths))
        except (BackupError, OSError, KeyError):
            counts["failed"] += 1
    for _, paths in sorted(pending, key=lambda item: item[0]):
        try:
            witness(config, paths, writer_keys, collector_key, state_dir, signing_key,
                    minimum_immutable=minimum_immutable, **kwargs)
            counts["witnessed"] += 1
        except (BackupError, OSError):
            counts["failed"] += 1
    return counts
