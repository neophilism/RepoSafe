import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .common import BackupError

OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}\Z")
FULL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")


@dataclass(frozen=True)
class Destination:
    name: str
    remote: str
    required: bool = True


@dataclass(frozen=True)
class FileSource:
    name: str
    path: Path
    exclude: tuple[str, ...] = ()
    maximum_bytes: int = 20 * 1024 ** 3


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
            name, remote = item["name"], item["remote"]
            needed = item.get("required", True)
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) or type(needed) is not bool:
                raise ValueError
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*:[^\r\n\x00]*", remote):
                raise ValueError
            destinations.append(Destination(name, remote.rstrip("/"), needed))
        if len({d.name for d in destinations}) != len(destinations) or len({d.remote for d in destinations}) != len(destinations):
            raise ValueError
        sources = []
        for item in data.get("files", []):
            name, source = item["name"], Path(item["path"])
            excludes = tuple(item.get("exclude", []))
            maximum = item.get("maximum_bytes", 20 * 1024 ** 3)
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name) or not source.is_absolute():
                raise ValueError
            if type(maximum) is not int or maximum < 1 or any(not isinstance(x, str) or "\x00" in x for x in excludes):
                raise ValueError
            sources.append(FileSource(name, source, excludes, maximum))
        if len({s.name for s in sources}) != len(sources):
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
        return Config(owners, recipients, minimum, required, lfs, Path(work) if work else None,
                      tuple(destinations), tuple(sources), metadata, wiki, Path(registry) if registry else None,
                      digest, selected, maximum)
    except (KeyError, TypeError, ValueError, OSError, tomllib.TOMLDecodeError):
        raise BackupError("invalid configuration; see reposafe.example.toml") from None
