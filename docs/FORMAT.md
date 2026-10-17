# Snapshot and state format

## Outer directory

Each run uses `YYYYMMDDTHHMMSSZ-<16 random hex characters>` and contains only
`snapshot.tar.gz.age` and `receipt.json`. Transport explicitly selects those names;
unrelated local files cannot be uploaded accidentally.

Receipt schema v2 records run ID, aggregate repository/source counts, capture
completion, failed/missing counts, and ciphertext filename, size and SHA-256.
The v1 verifier remains supported. Receipts are unsigned: replacing both the
ciphertext and receipt defeats this adjacent integrity evidence. The restore
command accepts an independently trusted ciphertext SHA-256 to anchor provenance.
Independent signed witnessing remains H9 work.

## Encrypted content

After age decryption, the gzip tar contains one `snapshot/` root:

| Path | Meaning |
| --- | --- |
| `manifest.json` | v2 run ID, scope, completion, repository/source outcomes, missing observed IDs |
| `content-manifest.json` | v1 exact file list, relative paths, sizes and SHA-256; excludes itself |
| `repositories/<stable ID>/mirror.git/` | Bare mirror including fetched LFS storage |
| `repositories/<stable ID>/repository.json` | Repository metadata, including sensitive names/URLs |
| `files/<source name>/` | Explicitly enrolled regular-file source content |

Safe restore requires v2 manifests, matching run/completion values, no unlisted or
missing files, and matching content hashes. It rejects traversal, absolute paths,
links/hardlinks, devices/FIFOs, sparse entries, duplicate tar members, oversized
payloads and excessive members. Output is a new private directory: files 0600,
directories 0700. Original ownership, ACLs, xattrs and executable modes are not
restored. File sources reject links and special files instead of following them.

Defaults: at most 100 GiB extracted file bytes and 1,000,000 tar members; content
inventory JSON capped at 128 MiB, run manifest at 16 MiB, outer receipt at 1 MiB.
CLI byte/member limits are adjustable for reviewed larger restores. Temporary
decrypted archives are ordinary files on trusted encrypted recovery storage.
Cleanup does not promise SSD/block-level secure erasure.

V1 bootstrap archives use manual recovery; the constrained command refuses to
invent a missing content manifest. Future migrations retain readers for every
stored generation and never rewrite existing immutable archives in place.

## Independent runner state

The private 0700 state directory contains `run.lock` and atomically replaced 0600
`state.json`. Schema v1 contains the union of observed repository IDs, last-attempt
delivery results, and last-success run/time. Replacement is flushed with file
and directory fsync. Concurrent processes cannot acquire the nonblocking lock.

Missing observed IDs mark a new capture partial while preserving visible repos.
The union never shrinks automatically. Intentionally retiring a repository needs
an operator-reviewed state/registry change; retain all historical backups. State
is not independent evidence against a compromised host: H2/H9 add reconciliation
and witnessing. A fresh/ephemeral host has no historical coverage baseline.

The `deliver` command retries ciphertext without updating runner state. A successful
retry does not claim a new full collector run or advance last-success.
