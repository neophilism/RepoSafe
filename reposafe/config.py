import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .common import BackupError

OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}\Z")
FULL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")


@dataclass(frozen=True)
class Config:
    owners: tuple[str, ...]
    recipients: tuple[str, ...]
    minimum_repositories: int = 1
    required_repositories: tuple[str, ...] = ()
    include_lfs: bool = True
    work_dir: Path | None = None


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
        return Config(owners, recipients, minimum, required, lfs, Path(work) if work else None)
    except (KeyError, TypeError, ValueError, OSError, tomllib.TOMLDecodeError):
        raise BackupError("invalid configuration; see reposafe.example.toml") from None
