"""Independent-host locking and durable, private, monotonic coverage state."""

import json
import os
import stat
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .common import BackupError
from .delivery import deliver_all, delivery_succeeded
from .snapshot import capture


@contextmanager
def run_lock(state_dir):
    try:
        import fcntl
    except ImportError:
        raise BackupError("independent runner locking requires a POSIX host") from None
    root = Path(state_dir).absolute()
    if root.is_symlink() or any(p.is_symlink() for p in root.parents):
        raise BackupError("state directory cannot have symlink ancestors")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.stat().st_mode & 0o077:
        raise BackupError("state directory must be private (0700)")
    descriptor = os.open(root / "run.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise BackupError("invalid runner lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError("another RepoSafe run is active") from None
        yield root
    finally:
        os.close(descriptor)


def read_state(root):
    path = root / "state.json"
    if path.is_symlink():
        raise BackupError("state file cannot be a symlink")
    if not path.exists():
        return {"schema_version": 1, "observed_repository_ids": [], "last_success": None}
    try:
        if path.stat().st_mode & 0o077:
            raise ValueError
        state = json.loads(path.read_text())
        if state["schema_version"] != 1 or not isinstance(state["observed_repository_ids"], list):
            raise ValueError
        if any(type(i) is not int or i < 1 for i in state["observed_repository_ids"]):
            raise ValueError
        return state
    except (OSError, KeyError, ValueError, TypeError):
        raise BackupError("runner state is invalid; preserve and investigate it") from None


def save_state(root, state):
    descriptor, name = tempfile.mkstemp(prefix=".state-", dir=root)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(state, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, root / "state.json")
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(name).unlink(missing_ok=True)


def execute(config, github, output, state_dir, *, capture_fn=capture, deliver_fn=deliver_all):
    with run_lock(state_dir) as root:
        state = read_state(root)
        result = capture_fn(config, github, output,
                            expected_repository_ids=state["observed_repository_ids"], forbidden=(root,))
        state["observed_repository_ids"] = sorted(set(state["observed_repository_ids"]) | set(result.repository_ids))
        state["last_attempt"] = {"run_id": result.run_id, "capture_complete": result.complete,
                                 "captured_at": datetime.now(timezone.utc).isoformat(), "delivered": False}
        save_state(root, state)
        deliveries = deliver_fn(result.directory, config.destinations)
        success = result.complete and delivery_succeeded(deliveries)
        state["last_attempt"]["delivered"] = delivery_succeeded(deliveries)
        state["last_attempt"]["destinations"] = [
            {"name": d.name, "required": d.required, "verified": d.verified} for d in deliveries]
        state["last_attempt"]["finished_at"] = datetime.now(timezone.utc).isoformat()
        if success:
            state["last_success"] = {"run_id": result.run_id, "finished_at": datetime.now(timezone.utc).isoformat()}
        save_state(root, state)
        return result, deliveries, success
