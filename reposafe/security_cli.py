"""CLI for distinct collector, per-destination agent, verifier and recovery roles."""

import json
import os
import shutil
from pathlib import Path

from .common import BackupError, command
from .config import load
from .delivery import transfer_files, verify_snapshot
from .signing import PURPOSES, generate_keys, sign_file, verify_file
from .agents import deliver_agent, verify_catalog
from .witness import witness, verify_event


def register(commands):
    keygen = commands.add_parser("keygen-signing", help="create operator-owned Ed25519 signing keys")
    keygen.add_argument("--output", required=True)
    sign = commands.add_parser("sign", help="sign a JSON document under a specific role")
    sign.add_argument("document")
    sign.add_argument("--key", required=True)
    sign.add_argument("--output", required=True)
    sign.add_argument("--purpose", choices=sorted(PURPOSES), required=True)
    verify = commands.add_parser("verify-signature", help="verify against an independent public-key pin")
    verify.add_argument("document")
    verify.add_argument("--signature", required=True)
    verify.add_argument("--key", required=True)
    verify.add_argument("--purpose", choices=sorted(PURPOSES), required=True)
    agent = commands.add_parser("agent", help="deliver signed ciphertext to ONE destination without source credentials")
    agent.add_argument("directory")
    agent.add_argument("--destination", required=True)
    agent.add_argument("--state-dir", required=True)
    agent.add_argument("--collector-key", required=True)
    agent.add_argument("--writer-key", required=True)
    sweep = commands.add_parser("agent-queue", help="retry published queue entries for one isolated destination")
    sweep.add_argument("--inbox", required=True)
    sweep.add_argument("--destination", required=True)
    sweep.add_argument("--state-dir", required=True)
    sweep.add_argument("--collector-key", required=True)
    sweep.add_argument("--writer-key", required=True)
    watch = commands.add_parser("witness", help="verify required deliveries and cloud versions, then sign a monotonic event")
    watch.add_argument("--catalog", action="append", required=True)
    watch.add_argument("--writer-key", action="append", required=True, help="destination=public-key-file-or-ring")
    watch.add_argument("--collector-key", required=True)
    watch.add_argument("--state-dir", required=True)
    watch.add_argument("--signing-key", required=True)
    watch.add_argument("--minimum-immutable", type=int, default=1)
    sweep = commands.add_parser("witness-queue", help="witness complete destination catalog sets in an enrolled inbox")
    sweep.add_argument("--inbox", required=True)
    sweep.add_argument("--writer-key", action="append", required=True)
    sweep.add_argument("--collector-key", required=True)
    sweep.add_argument("--state-dir", required=True)
    sweep.add_argument("--signing-key", required=True)
    sweep.add_argument("--minimum-immutable", type=int, default=1)
    event = commands.add_parser("verify-witness", help="verify a witnessed event against independent sequence anchors")
    event.add_argument("event")
    event.add_argument("--key", required=True)
    event.add_argument("--minimum-sequence", type=int, default=1)
    event.add_argument("--previous-sha256")
    fetch = commands.add_parser("fetch", help="recover encrypted files by signed catalog and exact vault versions")
    fetch.add_argument("--catalog", required=True)
    fetch.add_argument("--writer-key", required=True)
    fetch.add_argument("--collector-key", required=True)
    fetch.add_argument("--output", required=True)


def mappings(values):
    result = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name or not path or name in result:
            raise BackupError("writer public keys use unique destination=path values")
        result[name] = path
    return result


def dispatch(args):
    if args.action == "keygen-signing":
        print("signing public-key SHA-256: " + generate_keys(args.output))
    elif args.action == "sign":
        sign_file(args.document, args.key, args.output, args.purpose)
        print("document signed")
    elif args.action == "verify-signature":
        verify_file(args.document, args.signature, args.key, args.purpose)
        print("signature verified against pinned key")
    elif args.action == "verify-witness":
        event = verify_event(args.event, args.key, minimum_sequence=args.minimum_sequence, previous_sha256=args.previous_sha256)
        print(f"witness signature/chain verified; sequence={event['sequence']}")
    elif args.action == "agent":
        _, complete = deliver_agent(load(args.config), args.directory, args.destination, args.state_dir,
                                    args.collector_key, args.writer_key)
        print(f"destination verified and catalog signed; capture complete={complete}")
        return 0 if complete else 1
    elif args.action == "witness":
        event = witness(load(args.config), args.catalog, mappings(args.writer_key), args.collector_key,
                        args.state_dir, args.signing_key, minimum_immutable=args.minimum_immutable)
        print("complete delivery independently witnessed; event=" + str(event))
    elif args.action in ("agent-queue", "witness-queue"):
        from .queues import agent_sweep, witness_sweep
        config = load(args.config)
        if args.action == "agent-queue":
            counts = agent_sweep(config, args.inbox, args.destination, args.state_dir, args.collector_key, args.writer_key)
        else:
            counts = witness_sweep(config, args.inbox, mappings(args.writer_key), args.collector_key,
                args.state_dir, args.signing_key, minimum_immutable=args.minimum_immutable)
        print(json.dumps(counts, sort_keys=True))
        return 1 if counts["failed"] or counts["incomplete"] else 0
    elif args.action == "fetch":
        config = load(args.config)
        catalog, receipt = verify_catalog(args.catalog, args.writer_key, args.collector_key)
        matches = [d for d in config.destinations if d.name == catalog["destination"]]
        if len(matches) != 1:
            raise BackupError("catalog destination is not enrolled")
        destination = matches[0]
        if destination.kind in ("s3", "b2"):
            from .vault import ObjectVault
            ObjectVault(destination, read_only=True).retrieve(args.output, receipt, catalog["evidence"],
                maximum_bytes=config.maximum_snapshot_bytes + 16 * 1024 ** 2, minimum_free_bytes=config.minimum_free_bytes)
        else:
            output = Path(args.output).absolute()
            if output.exists() or output.is_symlink() or any(p.is_symlink() for p in output.parents):
                raise BackupError("fetch output must be new with no symlink ancestors")
            budget = sum(entry["bytes"] for entry in receipt["files"]) + 16 * 1024 ** 2
            if budget > config.maximum_snapshot_bytes + 16 * 1024 ** 2 or shutil.disk_usage(output.parent).free < budget + config.minimum_free_bytes:
                raise BackupError("fetch exceeds configured byte/free-space budget")
            output.mkdir(mode=0o700)
            try:
                names = [entry["name"] for entry in receipt["files"]] + ["receipt.sig.json", "receipt.json"]
                flags = [flag for name in names for flag in ("--include", "/" + name)]
                command(["rclone", "copy", destination.remote + "/" + receipt["run_id"], output, "--immutable",
                         "--max-transfer", str(budget), "--cutoff-mode", "cautious", "--max-depth", "1", *flags])
                if verify_snapshot(output) != receipt:
                    raise BackupError("fetched ciphertext disagrees with signed catalog")
            except Exception:
                shutil.rmtree(output)
                raise BackupError("catalog-directed fetch failed") from None
        verify_file(Path(args.output) / "receipt.json", Path(args.output) / "receipt.sig.json", args.collector_key, "collector-receipt")
        print("encrypted snapshot fetched and authenticated; recovery identity stays offline")
    else:
        return None
    return 0
