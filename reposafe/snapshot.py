import os
import secrets
import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .common import BackupError, command, sha256, write_json
from .sources import FileCollector
from .format import content_inventory
from .gitdata import evidence
from .inventory import registry_ids
from .metadata import export_repository
from .chunks import encrypt_archive
from .datasets import export_dataset


@dataclass(frozen=True)
class Capture:
    directory: Path
    run_id: str
    complete: bool
    repository_count: int
    failed_count: int
    repository_ids: tuple[int, ...] = ()
    missing_count: int = 0


def git_environment(token, askpass):
    allowed = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")
    env = {k: v for k, v in os.environ.items() if k in allowed}
    env.update({
        "GITHUB_BACKUP_TOKEN": token, "GIT_ASKPASS": str(askpass),
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ALLOW_PROTOCOL": "https", "GIT_NO_REPLACE_OBJECTS": "1",
    })
    return env


def mirror(repo, destination, env, include_lfs):
    url = f"https://github.com/{repo['full_name']}.git"
    safe = ["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "http.followRedirects=false"]
    command([*safe, "clone", "--mirror", "--", url, destination], env=env)
    command([*safe, "-C", destination, "fsck", "--full", "--strict"], env=env)
    if include_lfs:
        endpoint = url + "/info/lfs"
        command([*safe, "-C", destination, "-c", "lfs.url=" + endpoint,
                 "-c", "remote.origin.lfsurl=" + endpoint, "lfs", "fetch", "--all", "origin"], env=env)
    evidence(destination, env, lfs=include_lfs)
    write_json(destination.parent / "repository.json", repo)


def capture(config, github, output, *, mirror_fn=mirror, expected_repository_ids=(), forbidden=()):
    inventory = github.inventory(config)
    repository_ids = tuple(repo["id"] for repo in inventory)
    registered, retired = registry_ids(config)
    missing = sorted(((set(expected_repository_ids) | registered) - retired) - set(repository_ids))
    captured_at = datetime.now(timezone.utc)
    run_id = captured_at.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(8)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = output / run_id
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="reposafe-", dir=config.work_dir) as raw:
        root = Path(raw)
        os.chmod(root, 0o700)
        if shutil.disk_usage(root).free < config.minimum_free_bytes:
            raise BackupError("insufficient free scratch storage")
        payload = root / "payload"
        payload.mkdir(mode=0o700)
        askpass = root / "askpass"
        askpass.write_text(
            "#!/usr/bin/env python3\nimport os, sys\n"
            "print('x-access-token' if 'Username' in sys.argv[-1] else os.environ['GITHUB_BACKUP_TOKEN'])\n"
        )
        askpass.chmod(0o700)
        env = git_environment(github.token, askpass)
        outcomes = []
        for repo in inventory:
            repo_dir = payload / "repositories" / str(repo["id"])
            repo_dir.mkdir(parents=True, mode=0o700)
            try:
                scoped = github.for_repository(repo) if hasattr(github, "for_repository") else github
                repo_env = git_environment(scoped.token, askpass)
                mirror_fn(repo, repo_dir / "mirror.git", repo_env, config.include_lfs)
                if config.wiki and repo.get("has_wiki"):
                    wiki = {**repo, "full_name": repo["full_name"] + ".wiki"}
                    wiki_dir = repo_dir / "wiki"
                    wiki_dir.mkdir(mode=0o700)
                    mirror_fn(wiki, wiki_dir / "mirror.git", repo_env, False)
                if config.metadata:
                    export_repository(scoped, repo, repo_dir / "metadata", config.metadata,
                                      maximum_bytes=config.metadata_maximum_bytes)
                outcomes.append({"id": repo["id"], "full_name": repo["full_name"], "status": "complete"})
            except BackupError:
                outcomes.append({"id": repo["id"], "full_name": repo["full_name"], "status": "failed"})
        sources = []
        for source in config.files:
            source_dir = payload / "files" / source.name
            try:
                evidence = FileCollector(source, forbidden=(output, root, *forbidden)).collect(source_dir)
                sources.append({"name": source.name, "status": "complete", **evidence})
            except BackupError:
                sources.append({"name": source.name, "status": "failed"})
        for dataset in config.datasets:
            try:
                sources.append(export_dataset(dataset, payload / "datasets" / dataset.name))
            except BackupError:
                sources.append({"name": dataset.name, "kind": dataset.kind, "status": "failed"})
        failed = sum(r["status"] != "complete" for r in outcomes) + sum(s["status"] != "complete" for s in sources)
        complete = failed == 0 and not missing
        write_json(payload / "manifest.json", {
            "schema_version": 2, "run_id": run_id, "complete": complete,
            "captured_at": captured_at.isoformat(),
            "include_lfs": config.include_lfs, "repositories": outcomes,
            "sources": sources, "missing_repository_ids": missing,
            "metadata_groups": list(config.metadata), "wiki_requested": config.wiki,
            "selected_repository_grants_allowed": config.allow_selected_repositories,
            "coverage": "Git mirrors, LFS when enabled, repository metadata; see docs/COVERAGE.md",
        })
        content_inventory(payload)
        size = sum(p.stat().st_size for p in payload.rglob("*") if p.is_file())
        if size > config.maximum_snapshot_bytes:
            raise BackupError("snapshot exceeds its total byte budget")
        if shutil.disk_usage(root).free < size + config.minimum_free_bytes:
            raise BackupError("insufficient scratch space for archive packaging")
        archive = root / "snapshot.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(payload, arcname="snapshot", recursive=True)
        if shutil.disk_usage(destination).free < archive.stat().st_size + config.minimum_free_bytes:
            raise BackupError("insufficient output space for ciphertext")
        try:
            entries = encrypt_archive(archive, destination, config.recipients, config.chunk_bytes)
            pending = destination / "receipt.pending.json"
            write_json(pending, {
                "schema_version": 3 if config.chunk_bytes else 2, "run_id": run_id, "complete": complete,
                "captured_at": captured_at.isoformat(),
                "repositories": len(inventory), "failed": failed,
                "missing_repositories": len(missing), "sources": len(sources),
                "files": entries, "archive_format": "tar.gz", "compressed_bytes": archive.stat().st_size,
            })
            key = os.environ.get("REPOSAFE_COLLECTOR_SIGNING_KEY_FILE")
            if key:
                from .signing import sign_file
                sign_file(pending, key, destination / "receipt.sig.json", "collector-receipt")
            pending.replace(destination / "receipt.json")
        except BackupError:
            (destination / "receipt.pending.json").unlink(missing_ok=True)
            (destination / "receipt.sig.json").unlink(missing_ok=True)
            for ciphertext in destination.glob("*.age"):
                ciphertext.unlink(missing_ok=True)
            raise
    return Capture(destination, run_id, complete, len(inventory), failed, repository_ids, len(missing))
