# RepoSafe

Encrypted, recoverable backups of public and private GitHub repositories.

[Technical architecture](docs/TECHNICAL_ARCHITECTURE.md) ·
[Full PR development plan](docs/DEVELOPMENT_PLAN.md) ·
[Current implementation and deployment status](docs/STATUS.md)

RepoSafe inventories configured owners using a read-only GitHub credential,
mirrors Git history and LFS, checks Git object integrity, and encrypts the snapshot
with an **offline-held age recovery key** before it leaves the runner. Each run
has a new path; previous snapshots are never synchronized away.

## Capture a snapshot

Requires Python 3.11+, Git, Git LFS and [age](https://github.com/FiloSottile/age).

1. On a trusted recovery computer: `age-keygen -o recovery.key`. Store the private
   identity offline in two secure locations. Copy only its public recipient to
   the runner. Losing every identity makes encrypted backups unrecoverable.
2. Copy `reposafe.example.toml` to `reposafe.toml`; replace the recipient and set
   owners and coverage guards. The working config is ignored by Git.
3. Provide `GITHUB_BACKUP_TOKEN` through the runner secret store. A fine-grained
   token needs access to **all desired public and private repositories**, with
   Metadata: read and Contents: read. The repository's automatic Actions token
   cannot read all of your other private repositories. Track credential expiry.
4. Run `python -m reposafe --config reposafe.toml validate`, then
   `python -m reposafe --config reposafe.toml snapshot --output backups`.

Output contains ciphertext and a receipt with ciphertext hash, byte count,
aggregate counts and completion status. Private names are inside the encrypted
payload. A partial snapshot returns a failing exit status. The receipt detects
accidental corruption when trusted; it is not a signature against an attacker
who can replace both ciphertext and receipt.

See [coverage](docs/COVERAGE.md), [status](docs/STATUS.md), and
[development instructions](AGENTS.md). Run tests with
`python -m unittest discover -s tests -v`.

Snapshots temporarily require plaintext scratch space. Use a trusted, encrypted
volume; deleting a temporary file is not guaranteed secure erasure on SSDs.
Encryption protects uploaded contents, not a compromised collector reading sources.

## Daily copies to Google Drive and Dropbox

The [daily workflow](.github/workflows/backup.yml) runs at 08:23 UTC after setup.
Follow [SETUP.md](docs/SETUP.md) for provider OAuth, runtime credentials and enabling
the schedule. The routine copies ciphertext into a new run directory, checks
uploaded bytes by downloading them, then uploads and checks the receipt. Both
providers are attempted independently; all required providers must verify.

Locally, use `python -m reposafe --config reposafe.toml run --output backups`.
Retry with `python -m reposafe --config reposafe.toml deliver backups/RUN_ID`.
See [recovery instructions](docs/RECOVERY.md) before relying on a backup.

**Bootstrap security boundary:** a GitHub-hosted workflow holds provider tokens.
A GitHub compromise could therefore threaten those mutable copies. The hardened
design moves collection off GitHub and adds independently administered immutable
storage and offline copies. Merely adding providers does not force independent
compromises if credentials or account recovery are shared.

## Independent runner and offline recovery

The [independent Linux runner](docs/INDEPENDENT_RUNNER.md) includes a daily systemd
timer, exclusive run locking and durable coverage state. Previously observed IDs
cannot silently disappear from a successful backup. Opt-in regular-file roots use
`[[files]]`; see the example config and [format](docs/FORMAT.md).

Restore v2 on a clean machine without source/provider access:

```sh
python -m reposafe restore /recovery/RUN_ID \
  --identity /offline/recovery.key --output /recovery/new-directory
```

Supply an independently recorded digest with `--trusted-sha256` to anchor provenance.
Restore checks every content hash, rejects unsafe entries and requires a new output
directory. Local verify/restore need no config or GitHub token. Partial snapshots
require `--allow-partial`.

Native immutable vaults and chunked transfers are implemented; see [VAULTS.md](docs/VAULTS.md).
Separate delivery hosts, signed witnessing and independent alarms continue next. Activation needs runtime credentials and the public recipient
of a recovery identity retained offline by the owner.

Additional source metadata/App authentication: [GITHUB_EXPORTS.md](docs/GITHUB_EXPORTS.md).
