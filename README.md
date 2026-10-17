# RepoSafe

Encrypted, recoverable backups of public and private GitHub repositories.

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
