import hashlib
import json
import os
import selectors
import signal
import subprocess
import tempfile
import time
from pathlib import Path


class BackupError(Exception):
    """Safe to display: never include provider responses or command arguments."""


def command(args, *, env=None, cwd=None, timeout=3600, output_file=None,
            maximum_output_bytes=32 * 1024 ** 2, guard=None):
    """Bound output/time and terminate the entire tool process group on failure."""
    process, target = None, None
    try:
        if output_file is not None:
            target = Path(output_file).open("xb")
            os.chmod(output_file, 0o600)
        process = subprocess.Popen(
            [str(a) for a in args], env=env, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        captured, counts = bytearray(), {"stdout": 0, "stderr": 0}
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= deadline:
                    raise BackupError("external tool exceeded its deadline")
                if guard:
                    guard()
                for key, _ in selector.select(timeout=min(0.25, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 1024 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    counts[key.data] += len(chunk)
                    limit = maximum_output_bytes if key.data == "stdout" else 1024 ** 2
                    if counts[key.data] > limit:
                        raise BackupError("external tool exceeded its output budget")
                    if key.data == "stdout":
                        if target:
                            target.write(chunk)
                        else:
                            captured.extend(chunk)
        if process.wait() != 0:
            raise BackupError("external tool failed; inspect privately on the runner")
        if target:
            target.flush()
            os.fsync(target.fileno())
        return bytes(captured)
    except OSError:
        raise BackupError("external tool or private output unavailable") from None
    finally:
        if process is not None:
            # Children can outlive the direct tool, including with inherited pipes closed.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            process.stderr.close()
        if target:
            target.close()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    path = Path(path)
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def atomic_json(path, value):
    path = Path(path)
    descriptor, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(value, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)
