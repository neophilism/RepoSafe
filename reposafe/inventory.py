"""An operator-controlled, hash-pinned coverage registry supplements local history."""

import json
from .common import BackupError, sha256


def registry_ids(config):
    if config.registry is None:
        return set(), set()
    try:
        path = config.registry
        if path.is_symlink() or path.stat().st_size > 16 * 1024 ** 2 or sha256(path) != config.registry_sha256:
            raise ValueError
        data = json.loads(path.read_text())
        expected = data["repository_ids"]
        retired = data.get("retired", [])
        if data["schema_version"] != 1 or not isinstance(expected, list) or not isinstance(retired, list):
            raise ValueError
        retired_ids = []
        for item in retired:
            if not item["reason"] or not item["retired_at"]:
                raise ValueError
            retired_ids.append(item["id"])
        if any(type(i) is not int or i < 1 for i in expected + retired_ids):
            raise ValueError
        if len(set(expected)) != len(expected) or len(set(retired_ids)) != len(retired_ids):
            raise ValueError
        return set(expected), set(retired_ids)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise BackupError("coverage registry is invalid or does not match its independent digest") from None
