"""Synthetic measured end-to-end recovery; no real account credentials or cloud calls."""

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reposafe.agents import deliver_agent
from reposafe.common import BackupError, command, sha256, write_json
from reposafe.config import Config, Destination, FileSource
from reposafe.gitdata import evidence
from reposafe.monitor import MonitorPolicy, monitor
from reposafe.restore import restore
from reposafe.signing import generate_keys
from reposafe.snapshot import capture
from reposafe.witness import witness
from reposafe.delivery import verify_snapshot


def qualify(megabytes):
    for name in ("git", "age", "age-keygen", "rclone"):
        if not shutil.which(name):
            raise BackupError("qualification requires installed Git, age and rclone tools")
    if not 1 <= megabytes <= 16384:
        raise BackupError("qualification size must be between 1 MiB and 16 GiB")
    # This process deliberately discards all source/cloud/database/alert credentials.
    environment = {key: value for key, value in os.environ.items() if key in
                   ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")}
    os.environ.clear()
    os.environ.update(environment)
    with tempfile.TemporaryDirectory(prefix="reposafe-qualification-") as raw:
        root = Path(raw)
        if shutil.disk_usage(root).free < megabytes * 1024 ** 2 * 8 + 512 * 1024 ** 2:
            raise BackupError("insufficient free storage for the selected synthetic qualification size")
        source = root / "source"
        source.mkdir()
        command(["git", "init", "-b", "main", source])
        (source / "README").write_text("original synthetic data\n")
        command(["git", "-C", source, "add", "README"])
        commit = ["git", "-c", "core.hooksPath=/dev/null", "-C", source, "-c", "user.name=Fixture",
                  "-c", "user.email=fixture@example.test", "commit", "-am", "synthetic fixture"]
        command(commit)
        command(["git", "-C", source, "tag", "preserved-tag"])
        original = command(["git", "-C", source, "rev-parse", "HEAD"]).strip()
        documents = root / "documents"
        documents.mkdir()
        with (documents / "data.bin").open("xb") as output:
            for _ in range(megabytes):
                output.write(os.urandom(1024 ** 2))
        expected_file = sha256(documents / "data.bin")
        identity = root / "test-only-age-identity"
        command(["age-keygen", "-o", identity])
        recipient = command(["age-keygen", "-y", identity]).decode().strip()
        keys = {}
        for role in ("collector", "drive", "dropbox", "witness"):
            generate_keys(root / role)
            keys[role] = (root / role / "private.pem", root / role / "public.pem")
        destinations = tuple(Destination(name, str(root / (name + "-transport"))) for name in ("drive", "dropbox"))
        config = Config(("neophilism",), (recipient,), include_lfs=False, destinations=destinations,
            files=(FileSource("documents", documents, maximum_bytes=megabytes * 1024 ** 2 + 1024),),
            chunk_bytes=1024 ** 2, maximum_snapshot_bytes=max(32, megabytes * 2) * 1024 ** 2)
        class Inventory:
            token = "synthetic-unused-token"
            def inventory(self, config):
                return [{"id": 1, "full_name": "neophilism/synthetic-qualification"}]
        def mirror(repo, destination, env, include_lfs):
            local = {**env, "GIT_ALLOW_PROTOCOL": "file"}
            command(["git", "-c", "core.hooksPath=/dev/null", "clone", "--mirror", "--no-local", "--", source, destination], env=local)
            command(["git", "-C", destination, "fsck", "--full", "--strict"], env=local)
            evidence(destination, local, lfs=False)
            write_json(destination.parent / "repository.json", repo)
        timings = {}
        started = time.monotonic()
        os.environ["REPOSAFE_COLLECTOR_SIGNING_KEY_FILE"] = str(keys["collector"][0])
        captured = capture(config, Inventory(), root / "spool", mirror_fn=mirror)
        del os.environ["REPOSAFE_COLLECTOR_SIGNING_KEY_FILE"]
        timings["capture_seconds"] = round(time.monotonic() - started, 3)
        catalogs = []
        started = time.monotonic()
        for destination in destinations:
            path, complete = deliver_agent(config, captured.directory, destination.name, root / (destination.name + "-state"),
                keys["collector"][1], keys[destination.name][0])
            if not complete:
                raise BackupError("synthetic delivery unexpectedly incomplete")
            catalogs.append(path)
        timings["two_local_delivery_seconds"] = round(time.monotonic() - started, 3)
        event = witness(config, catalogs, {name: keys[name][1] for name in ("drive", "dropbox")},
            keys["collector"][1], root / "witness-state", keys["witness"][0], minimum_immutable=0)
        health = monitor(event.parent.parent, keys["witness"][1], root / "monitor-state",
                         MonitorPolicy(("drive", "dropbox"), minimum_immutable=0, maximum_offline_days=None))
        if not health["healthy"]:
            raise BackupError("synthetic signed evidence monitor failed")
        # Mutate/delete source refs after capture; old dated backup must still recover.
        (source / "README").write_text("changed after capture\n")
        command(commit)
        command(["git", "-C", source, "tag", "-d", "preserved-tag"])
        started = time.monotonic()
        copy = Path(destinations[0].remote) / captured.run_id
        restored = root / "restored"
        manifest = restore(copy, identity, restored, collector_key=keys["collector"][1])
        timings["offline_restore_seconds"] = round(time.monotonic() - started, 3)
        mirror_path = restored / "snapshot/repositories/1/mirror.git"
        if command(["git", "-C", mirror_path, "rev-parse", "refs/tags/preserved-tag"]).strip() != original:
            raise BackupError("old source refs were not preserved")
        if sha256(restored / "snapshot/files/documents/data.bin") != expected_file:
            raise BackupError("synthetic file recovery mismatch")
        wrong = root / "wrong-test-key"
        command(["age-keygen", "-o", wrong])
        try:
            restore(copy, wrong, root / "must-not-survive", collector_key=keys["collector"][1])
        except BackupError:
            pass
        else:
            raise BackupError("wrong recovery identity unexpectedly accepted")
        if (root / "must-not-survive").exists():
            raise BackupError("failed recovery published output")
        broken = Path(destinations[1].remote) / captured.run_id
        receipt = verify_snapshot(copy)
        payload = broken / receipt["files"][0]["name"]
        with payload.open("r+b") as output:
            output.write(b"CORRUPT")
        try:
            verify_snapshot(broken)
        except BackupError:
            pass
        else:
            raise BackupError("corrupted independent local transport unexpectedly verified")
        verify_snapshot(copy)
        return {"schema_version": 1, "kind": "synthetic-local-qualification", "passed": True,
            "fixture_bytes": megabytes * 1024 ** 2, "ciphertext_bytes": sum(e["bytes"] for e in receipt["files"]),
            "chunks": len(receipt["files"]), "recovery_checks": manifest["recovery_checks"], "timings": timings,
            "source_ref_change_survived": True, "wrong_identity_rejected": True, "local_copy_corruption_isolated": True,
            "real_account_credentials_used": False, "real_cloud_provider_qualified": False,
            "limits": "local synthetic size/timings only; no physical offline media, network namespace, production throughput or provider-enforced retention qualification"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--megabytes", type=int, default=32)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = qualify(args.megabytes)
        write_json(args.output, result)
        print(json.dumps({"passed": result["passed"], "fixture_bytes": result["fixture_bytes"], "timings": result["timings"]}, sort_keys=True))
    except (BackupError, OSError):
        print("synthetic qualification failed; inspect privately", file=sys.stderr)
        raise SystemExit(1)
