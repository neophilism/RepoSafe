"""Secret-free local preflight and optional explicit read-only live inspection."""

import configparser
import importlib.metadata
import os
import platform
import shutil
import sys
from pathlib import Path

from .common import BackupError, command, sha256
from .datasets import postgres_environment, private_setting
from .signing import private_public_key, public_key, read_regular

DEPENDENCIES = ("cryptography", "boto3", "botocore", "cffi", "pycparser", "jmespath", "s3transfer", "python-dateutil", "six", "urllib3")
TOOL_COMMANDS = {"git": ["git", "--version"], "git-lfs": ["git-lfs", "version"],
                 "age": ["age", "--version"], "age-keygen": ["age-keygen", "--version"],
                 "rclone": ["rclone", "--version"], "pg_dump": ["pg_dump", "--version"],
                 "pg_restore": ["pg_restore", "--version"], "psql": ["psql", "--version"]}


def inventory():
    components, tools = [], []
    for name in DEPENDENCIES:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            version = None
        components.append({"name": name, "version": version, "type": "library"})
    for name, args in TOOL_COMMANDS.items():
        path = shutil.which(args[0])
        try:
            version = command(args, timeout=10).decode().splitlines()[0].strip() if path else None
            digest = sha256(Path(path).resolve()) if path else None
        except (BackupError, OSError, UnicodeError, IndexError):
            version, digest = None, None
        tools.append({"name": name, "version": version, "sha256": digest})
    return {"schema_version": 1, "kind": "runtime-inventory", "python": platform.python_version(),
            "system": platform.system(), "machine": platform.machine(), "components": components, "tools": tools,
            "scope": "observed installed dependencies/tool executable bytes; not upstream build provenance"}


def doctor(config, role, *, destination=None, collector_key=None, writer_keys=None, witness_key=None,
           signing_key=None, state_dir=None, output_dir=None, live=False):
    issues, warnings, checks = [], [], {}
    if os.name != "posix" or sys.version_info < (3, 11):
        issues.append("unsupported_posix_python_runtime")
    required_tools = {"collector": ("git", "git-lfs", "age"), "writer": (), "witness": (),
                      "monitor": (), "recovery": ("git", "age")}.get(role)
    if required_tools is None:
        raise BackupError("unknown deployment role")
    if role == "collector" and config and not config.include_lfs:
        required_tools = tuple(name for name in required_tools if name != "git-lfs")
    for name in required_tools:
        if not shutil.which(name):
            issues.append("tool_missing_" + name)
    source_present = any(os.environ.get(name) for name in ("GITHUB_BACKUP_TOKEN", "GITHUB_APP_PRIVATE_KEY_FILE"))
    if role != "collector" and source_present:
        issues.append("source_credentials_in_noncollector_role")
    native_credentials = {d.credential_prefix for d in config.destinations if d.kind in ("s3", "b2")} if config else set()
    if role == "collector" and (os.environ.get("RCLONE_CONFIG") or any(os.environ.get(prefix + "_ACCESS_KEY_ID") for prefix in native_credentials)):
        issues.append("destination_credentials_in_collector_role")
    pins = {"collector": collector_key, "witness": witness_key}
    needed_pins = {"collector": (), "writer": ("collector",), "witness": ("collector",),
                   "monitor": ("witness",), "recovery": ("collector", "witness")}[role]
    for name in needed_pins:
        try:
            if not pins[name]:
                raise BackupError("missing public pin")
            path = Path(pins[name])
            if path.is_dir() and not path.is_symlink():
                members = list(path.glob("*.pem"))
                if not 1 <= len(members) <= 32:
                    raise BackupError("invalid public ring")
                for member in members:
                    public_key(member)
            else:
                public_key(path)
        except (BackupError, OSError):
            issues.append("public_pin_missing_or_invalid_" + name)
    if role in ("collector", "writer", "witness"):
        key = signing_key or (os.environ.get("REPOSAFE_COLLECTOR_SIGNING_KEY_FILE") if role == "collector" else None)
        try:
            if not key:
                raise BackupError("missing signer")
            private_public_key(key)
        except (BackupError, OSError):
            issues.append("role_signing_key_missing_or_invalid")
    for label, path in (("state", state_dir), ("output", output_dir)):
        if path:
            path = Path(path).absolute()
            if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.is_dir() or path.stat().st_mode & 0o077:
                issues.append(label + "_directory_not_private_or_missing")
    if role != "recovery" and not state_dir:
        issues.append("durable_state_directory_required")
    if role == "collector" and not output_dir:
        issues.append("collector_output_directory_required")
    if role == "collector":
        if os.environ.get("GITHUB_APP_PRIVATE_KEY_FILE") and not os.environ.get("GITHUB_APP_ID"):
            issues.append("source_app_id_missing")
        if not source_present:
            issues.append("source_runtime_credential_missing")
        if config is None:
            issues.append("collector_config_missing")
        else:
            if not config.recipients:
                issues.append("offline_recovery_public_recipient_missing")
            if os.environ.get("GITHUB_APP_ID"):
                try:
                    from .auth import client_from_environment
                    client_from_environment(config).auth.app_client()
                except BackupError:
                    issues.append("source_app_signing_credential_invalid")
            warnings.append("reconcile_private_inventory_and_repository_retirements_independently")
            warnings.append("confirm_encrypted_quota_limited_work_volume_and_no_online_recovery_identity")
            for source in config.files:
                if not source.path.exists():
                    issues.append("enrolled_file_source_unavailable")
            for dataset in config.datasets:
                try:
                    if dataset.kind == "postgres":
                        postgres_environment(dataset)
                        if any(not shutil.which(tool) for tool in ("pg_dump", "pg_restore", "psql")):
                            raise BackupError("missing PostgreSQL tools")
                    elif dataset.kind == "remote":
                        private_setting(dataset.credential_prefix, "_RCLONE_CONFIG")
                    elif not dataset.path.is_file() or dataset.path.is_symlink():
                        raise BackupError("missing SQLite source")
                    if dataset.rpo_hours < 24:
                        warnings.append("dataset_rpo_requires_more_frequent_than_daily_schedule")
                except (BackupError, OSError):
                    issues.append("enrolled_dataset_credentials_tools_or_source_unavailable")
            if live:
                try:
                    from .auth import client_from_environment
                    from .inventory import registry_ids
                    repos = client_from_environment(config).inventory(config)
                    expected, retired = registry_ids(config)
                    if expected - retired - {r["id"] for r in repos}:
                        raise BackupError("expected inventory missing")
                    checks["source_repositories_visible"] = len(repos)
                except BackupError:
                    issues.append("live_source_visibility_or_registry_failed")
    if role in ("writer", "witness"):
        selected = [d for d in config.destinations if d.name == destination] if role == "writer" and config else list(config.destinations) if config else []
        if not selected or role == "writer" and len(selected) != 1:
            issues.append("select_enrolled_destination")
        if role == "witness" and config:
            for target in config.destinations:
                if target.required:
                    key = (writer_keys or {}).get(target.name)
                    try:
                        if not key:
                            raise BackupError("missing writer pin")
                        if Path(key).is_dir():
                            members = list(Path(key).glob("*.pem"))
                            if not 1 <= len(members) <= 32:
                                raise BackupError("invalid writer ring")
                            for path in members:
                                public_key(path)
                        else:
                            public_key(key)
                    except (BackupError, OSError):
                        issues.append("required_writer_public_pin_missing_or_invalid")
        for target in selected:
            if target.kind == "rclone":
                if role == "writer":
                    try:
                        raw = read_regular(os.environ.get("RCLONE_CONFIG", ""), 1024 ** 2, private=True)
                        parser = configparser.ConfigParser(interpolation=None)
                        parser.read_string(raw.decode())
                        if set(parser.sections()) != {target.remote.split(":", 1)[0]} or not shutil.which("rclone"):
                            raise ValueError
                        section = parser[target.remote.split(":", 1)[0]]
                        if target.name in ("drive", "dropbox") and section.get("type") != {"drive": "drive", "dropbox": "dropbox"}[target.name]:
                            raise ValueError
                    except (BackupError, OSError, ValueError, configparser.Error):
                        issues.append("single_destination_rclone_credential_config_missing_or_invalid")
            else:
                if not all(os.environ.get(target.credential_prefix + suffix) for suffix in ("_ACCESS_KEY_ID", "_SECRET_ACCESS_KEY")):
                    issues.append("scoped_native_vault_credential_missing")
                if role == "writer" and any(os.environ.get(prefix + "_ACCESS_KEY_ID") for prefix in native_credentials - {target.credential_prefix}):
                    issues.append("other_destination_credentials_in_writer_role")
                if live:
                    try:
                        from .vault import ObjectVault
                        ObjectVault(target, read_only=role == "witness").inspect()
                        checks["native_vaults_inspected"] = checks.get("native_vaults_inspected", 0) + 1
                    except BackupError:
                        issues.append("live_native_identity_private_versioning_or_retention_check_failed")
        warnings.append("verify_provider_grants_host_isolation_and_account_recovery_outside_github")
    return {"schema_version": 1, "kind": "deployment-preflight", "role": role, "local_ready": not issues,
        "live_checks_requested": live, "checks": checks, "issues": sorted(set(issues)), "warnings": sorted(set(warnings)),
        "production_accepted": False, "acceptance_pending": ["initial_required_deliveries", "clean_recovery_drill",
            "independent_alert_delivery", "next_scheduled_run", "physical_offline_rotation", "owner_cost_and_custody_acceptance"]}
