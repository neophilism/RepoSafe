# RepoSafe

Unattended daily backups of public and private GitHub repositories to Google Drive
and Dropbox, with encryption before upload and downloaded-byte verification.
Additional roles provide independent S3/B2 compliance vaults, signed verification,
offline copies and deadline monitoring. Explicitly enrolled files, SQLite/PostgreSQL
and remote objects/documents share the same complete/partial backup boundary.

This repository is the backup application. It does not require Dropbox or Drive to
be connected to ChatGPT. Its runner uses its own read-only GitHub grant, unattended
provider OAuth and public age recipients; recovery identities stay offline.

| Deployment | Behavior | Setup |
| --- | --- | --- |
| Easy bootstrap | GitHub Actions at 08:23 UTC daily; encrypted mirrors to Drive and Dropbox | [SETUP.md](docs/SETUP.md) |
| Independent production | Fixed reviewed code; separate collector, one writer per provider, S3/B2 protected versions, independent witness/monitor, read-only queue feeds | [ACTIVATION.md](docs/ACTIVATION.md) |
| Offline recovery | Signed encrypted generations, enrolled removable media and verified software kit | [OFFLINE.md](docs/OFFLINE.md), [RECOVERY.md](docs/RECOVERY.md) |

The daily workflow is present and intentionally gated until runtime credentials,
the owner-held recovery key's public recipient and a successful recovery test are
provided. No production private-account backup or paid vault was activated during
development. [STATUS.md](docs/STATUS.md) distinguishes tested code from deployment.

## Use

Requires Python 3.11+, a POSIX host, Git/Git LFS, age and rclone. Native vaults and
signatures use the locked Python dependencies. Install a fixed reviewed local
release through [RELEASE.md](docs/RELEASE.md), then configure privately:

```sh
reposafe --config /etc/reposafe/reposafe.toml validate
reposafe --config /etc/reposafe/reposafe.toml run \
  --state-dir /var/lib/reposafe/state --output /var/lib/reposafe/backups
reposafe restore /recovery/RUN_ID --identity /offline/recovery.key \
  --collector-key /independent/pins/collector --output /recovery/new-directory
```

Unsigned bootstrap snapshots use an independently recorded digest instead of a
collector public key. See RECOVERY.md/FORMAT.md for v2/v3 trust and migration rules.
No backup path deletes remote history, checks out repositories, runs hooks, executes
source code or restores over an existing directory. A missing source or failed
required destination cannot become complete success. Old protected generations
remain necessary: a compromised source/collector can still poison future captures.

## Design, scope and development

- [Technical architecture](docs/TECHNICAL_ARCHITECTURE.md) and [complete PR development plan](docs/DEVELOPMENT_PLAN.md)
- [Coverage](docs/COVERAGE.md), [GitHub exports/App grants](docs/GITHUB_EXPORTS.md), [other-data enrollment](docs/DATASETS.md)
- [Native vaults/chunks](docs/VAULTS.md), [role signatures and provenance](docs/PROVENANCE.md), [operations](docs/OPERATIONS.md)
- [Read-only retention/cost proposals](docs/RETENTION.md), [qualification](docs/QUALIFICATION.md), [implementation log](docs/implementation-log.md)

```sh
python -m unittest discover -s tests -v
python scripts/qualify_local.py --megabytes 32 --output /private/qualification.json
```

CI tests Python 3.11/3.12/3.13, real local Git/age/rclone recovery, isolated PostgreSQL
export/restore, wheel installation and a public GitHub recovery smoke. Private grants,
real cloud enforcement, independent alert delivery and physical disconnection require
actual deployment evidence; mocks and a passing CI run do not establish them.
