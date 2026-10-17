import hashlib
import json
import os
import subprocess
from pathlib import Path


class BackupError(Exception):
    """Safe to display: never include provider responses or command arguments."""


def command(args, *, env=None, cwd=None, timeout=3600):
    try:
        result = subprocess.run(
            [str(a) for a in args], env=env, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise BackupError("external tool unavailable or timed out") from None
    if result.returncode:
        raise BackupError("external tool failed; inspect privately on the runner")
    return result.stdout


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
