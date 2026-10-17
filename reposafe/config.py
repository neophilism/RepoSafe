import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .common import BackupError

OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}\Z")
FULL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")


@dataclass(frozen=True)
class Destination:
    name: str
    remote: str = ""
    required: bool = True
    kind: str = "rclone"
    bucket: str = ""
    prefix: str = "reposafe"
    region: str = "us-east-1"
    endpoint: str | None = None
    retention_days: int = 90
    credential_prefix: str = ""
    expected_account: str = ""


@dataclass(frozen=True)
class FileSource:
    name: str
    path: Path
    exclude: tuple[str, ...] = ()
    maximum_bytes: int = 20 * 1024 ** 3
    maximum_entries: int = 100000


@dataclass(frozen=True)
class Dataset:
    name: str
    kind: str
    path: Path | None = None
    service: str = ""
    remote: str = ""
    credential_prefix: str = ""
    maximum_bytes: int = 20 * 1024 ** 3
    timeout_seconds: int = 3600
    include_roles: bool = False
    export_formats: tuple[str, ...] = ()
    owner: str = "operator"
    rpo_hours: int = 24
    rto_hours: int = 24


@dataclass(frozen=True)
class Config:
    owners: tuple[str, ...]
    recipients: tuple[str, ...]
    minimum_repositories: int = 1
    required_repositories: tuple[str, ...] = ()
    include_lfs: bool = True
    work_dir: Path | None = None
    destinations: tuple[Destination, ...] = ()
    files: tuple[FileSource, ...] = ()
    metadata: tuple[str, ...] = ()
    wiki: bool = False
    registry: Path | None = None
    registry_sha256: str | None = None
    allow_selected_repositories: bool = False
    metadata_maximum_bytes: int = 2 * 1024 ** 3
    chunk_bytes: int = 0
    maximum_snapshot_bytes: int = 100 * 1024 ** 3
    minimum_free_bytes: int = 128 * 1024 ** 2
    datasets: tuple[Dataset, ...] = ()


def load(path):
    try:
        with Path(path).open("rb") as source:
            data = tomllib.load(source)
        github, encryption = data["github"], data["encryption"]
        owners = tuple(github["owners"])
        recipients = tuple(encryption["recipients"])
        minimum = github.get("minimum_repositories", 1)
        required = tuple(github.get("required_repositories", []))
        lfs = github.get("include_lfs", True)
        if not owners or not all(isinstance(o, str) and OWNER.fullmatch(o) for o in owners):
            raise ValueError
        if not recipients or not all(isinstance(r, str) and re.fullmatch(r"age1[0-9a-z]{58}", r) for r in recipients):
            raise ValueError
        if type(minimum) is not int or minimum < 1 or type(lfs) is not bool:
            raise ValueError
        if any(not FULL_NAME.fullmatch(r) or r.split("/")[0].lower() not in {o.lower() for o in owners} for r in required):
            raise ValueError
        work = data.get("runner", {}).get("work_dir")
        destinations = []
        for item in data.get("destinations", []):
            name, remote = item["name"], item.get("remote", "")
            needed = item.get("required", True)
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) or type(needed) is not bool:
                raise ValueError
            kind = item.get("kind", "rclone")
            if kind == "rclone":
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*:[^\r\n\x00]*", remote):
                    raise ValueError
                destinations.append(Destination(name, remote.rstrip("/"), needed))
            elif kind in ("s3", "b2"):
                bucket, prefix = item["bucket"], item.get("prefix", "reposafe")
                region, endpoint = item["region"], item.get("endpoint")
                days = item.get("retention_days", 90)
                credentials, account = item["credential_prefix"], str(item["expected_account"])
                if (not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) or
                    not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/_-]{0,199}", prefix) or ".." in prefix or
                    not re.fullmatch(r"[a-z0-9-]+", region) or type(days) is not int or not 1 <= days <= 3650 or
                    not re.fullmatch(r"REPOSAFE_[A-Z0-9_]+", credentials) or not account):
                    raise ValueError
                if kind == "s3":
                    if endpoint or not re.fullmatch(r"[0-9]{12}", account):
                        raise ValueError
                else:
                    parsed = urlsplit(endpoint or "")
                    if (parsed.scheme != "https" or not re.fullmatch(r"s3\.[a-z0-9-]+\.backblazeb2\.com", parsed.hostname or "") or
                        parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/") or parsed.port not in (None, 443)):
                        raise ValueError
                destinations.append(Destination(name, "", needed, kind, bucket, prefix.strip("/"), region,
                                                endpoint, days, credentials, account))
            else:
                raise ValueError
        if len({d.name for d in destinations}) != len(destinations) or len({(d.kind,d.remote,d.bucket,d.prefix) for d in destinations}) != len(destinations):
            raise ValueError
        sources = []
        for item in data.get("files", []):
            name, source = item["name"], Path(item["path"])
            excludes = tuple(item.get("exclude", []))
            maximum = item.get("maximum_bytes", 20 * 1024 ** 3)
            entries = item.get("maximum_entries", 100000)
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) or not source.is_absolute():
                raise ValueError
            if type(maximum) is not int or maximum < 1 or type(entries) is not int or not 1 <= entries <= 500000 or any(not isinstance(x, str) or "\x00" in x for x in excludes):
                raise ValueError
            sources.append(FileSource(name, source, excludes, maximum, entries))
        if len({s.name for s in sources}) != len(sources):
            raise ValueError
        datasets = []
        for item in data.get("datasets", []):
            name, kind = item["name"], item["kind"]
            source_path = Path(item["path"]) if "path" in item else None
            service, remote, credentials = item.get("service", ""), item.get("remote", ""), item.get("credential_prefix", "")
            limit, seconds = item.get("maximum_bytes", 20 * 1024 ** 3), item.get("timeout_seconds", 3600)
            roles, formats = item.get("include_roles", False), tuple(item.get("export_formats", []))
            owner, rpo, rto = item.get("owner", "operator"), item.get("rpo_hours", 24), item.get("rto_hours", 24)
            if (not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) or kind not in ("sqlite", "postgres", "remote") or
                type(limit) is not int or limit < 1 or type(seconds) is not int or not 1 <= seconds <= 18000 or
                type(roles) is not bool or any(x not in ("docx", "xlsx", "pptx", "pdf", "svg", "odt", "ods", "odp", "txt", "csv") for x in formats) or
                not isinstance(owner, str) or not 1 <= len(owner) <= 128 or
                type(rpo) is not int or rpo < 1 or type(rto) is not int or rto < 1):
                raise ValueError
            if kind == "sqlite":
                if source_path is None or not source_path.is_absolute() or ".." in source_path.parts or remote or service or credentials or roles or formats:
                    raise ValueError
            else:
                if not re.fullmatch(r"REPOSAFE_[A-Z0-9_]+", credentials) or source_path is not None:
                    raise ValueError
                if kind == "postgres" and (not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", service) or remote or formats):
                    raise ValueError
                if kind == "remote" and (not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*:[^\r\n\x00]*", remote) or service or roles):
                    raise ValueError
            datasets.append(Dataset(name, kind, source_path, service, remote, credentials, limit, seconds,
                                    roles, formats, owner, rpo, rto))
        if len({s.name for s in sources} | {s.name for s in datasets}) != len(sources) + len(datasets):
            raise ValueError
        metadata = tuple(github.get("metadata", []))
        if any(x not in ("collaboration", "releases", "discussions", "settings", "actions") for x in metadata):
            raise ValueError
        wiki = github.get("wiki", False)
        selected = github.get("allow_selected_repositories", False)
        registry = github.get("registry")
        digest = github.get("registry_sha256")
        maximum = github.get("metadata_maximum_bytes", 2 * 1024 ** 3)
        if type(wiki) is not bool or type(selected) is not bool or type(maximum) is not int or maximum < 1:
            raise ValueError
        if bool(registry) != bool(digest) or (digest and not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError
        runner = data.get("runner", {})
        chunk = runner.get("chunk_bytes", 0)
        snapshot_limit = runner.get("maximum_snapshot_bytes", 100 * 1024 ** 3)
        free = runner.get("minimum_free_bytes", 128 * 1024 ** 2)
        if (type(chunk) is not int or chunk not in (0,) and not 1024 ** 2 <= chunk <= 1024 ** 3 or
            type(snapshot_limit) is not int or snapshot_limit < 1 or type(free) is not int or free < 0):
            raise ValueError
        return Config(owners, recipients, minimum, required, lfs, Path(work) if work else None,
                      tuple(destinations), tuple(sources), metadata, wiki, Path(registry) if registry else None,
                      digest, selected, maximum, chunk, snapshot_limit, free, tuple(datasets))
    except (KeyError, TypeError, ValueError, OSError, tomllib.TOMLDecodeError):
        raise BackupError("invalid configuration; see reposafe.example.toml") from None
