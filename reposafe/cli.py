import argparse
import os
import sys

from .common import BackupError
from .config import load
from .github import GitHub
from .snapshot import capture


def main(argv=None):
    parser = argparse.ArgumentParser(description="Encrypted GitHub backups; no secret output")
    parser.add_argument("--config", default="reposafe.toml")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("validate", help="validate configuration without network access")
    snapshot = commands.add_parser("snapshot", help="capture and encrypt configured repositories")
    snapshot.add_argument("--output", default="backups")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        config = load(args.config)
        if args.action == "validate":
            print("configuration valid")
            return 0
        result = capture(config, GitHub(os.environ.get("GITHUB_BACKUP_TOKEN", "")), args.output)
        print(f"encrypted snapshot created; repositories={result.repository_count}; failed={result.failed_count}")
        return 0 if result.complete else 1
    except BackupError as error:
        print(f"RepoSafe: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
