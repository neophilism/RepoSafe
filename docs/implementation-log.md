# Continuing implementation

## Source completion — PR #5 (H2–H5)

Added read-only GitHub App token minting/refresh and owner-installation checks,
hash-pinned expected inventory with explicit retirement, exact Git/HEAD evidence,
LFS content verification, gitlink inventory, optional wiki mirrors, and bounded
exports for issues/PRs/reviews/threads, releases/binary assets, discussions/replies,
settings and available Actions artifacts/logs. Every selected export is part of
the capture completion boundary. See GITHUB_EXPORTS.md for scopes and limitations.

Tests include signed JWT verification, token expiry/permissions, incomplete owner
grants, registry replacement, LFS corruption, metadata failure/budget behavior,
GraphQL cursor safety and binary redirect credential stripping. Existing real Git,
age, rclone and safe-restore tests remain required. Real private-owner App visibility
and selected API scopes remain deployment acceptance tests requiring runtime grants.

The owner requested continued implementation beyond H1. Later code stages continue;
paid storage, permanent recovery-key custody and real cloud acceptance are separate
from committing tested source code.

## Native vaults and bounded transfers — PR #6 (H6/H7/H11)

Native S3/B2 account, private access, version and COMPLIANCE checks, per-version
read-back, receipt-last publication, idempotent resume and exact-version recovery
are implemented. Added independently encrypted v3 chunks, disk/size checks and a
reviewable AWS template. See VAULTS.md. All 58 local tests pass, including an installed boto3 request-model check; real provider
capability/retention/permission enforcement still needs authorized cloud accounts.

## Separate agents and witnessed provenance — PR #7 (H8/H9)

Added collector/writer/witness Ed25519 signatures with external public-key pins,
private bounded inbox sweeps, atomic signed catalogs, native version read-back by
a separate read-only witness, retention evidence and a monotonic signed event chain.
Source credentials are refused by writers; partial, mismatched, stale and replayed
runs cannot become complete witness events. Added isolated role timer/service
examples, direct catalog recovery and signed offline restore. See PROVENANCE.md.
All 67 tests pass locally; actual separate hosts, permission enforcement, independent
sequence anchoring and account recovery remain deployment requirements.

## Consistent other-data sources — PR #8 (H10)

Added SQLite online/WAL-consistent backup and integrity checks, streamed PostgreSQL
custom dumps with verified-TLS/private service files, readable role/extension evidence
and archive checks, and explicit remote object/document exports with stable inventories
and downloaded-byte checking. Dataset failures make the whole capture partial.
Tool execution now bounds stdout/stderr/time and kills child process groups on failure.
See DATASETS.md for scope and PITR boundaries. Local suite: 79 tests, with the isolated
PostgreSQL export/restore test required in CI rather than skipped silently there.

## Independent monitor — PR #9 (H12)

Added independent signed-witness chain ingestion with a durable high-water mark,
required destination/provider-diversity policy, freshness/future-clock/retention
checks, signed offline-copy age checks and aggregate HTTPS alert delivery. Missing
events and heartbeat-only claims never become success. Added hourly service/timer
samples. The 86-test local suite passes with PostgreSQL required in CI. No real
alert recipients/endpoints are configured or contacted by development.

## Offline escape copies and safe retention proposals — PR #10 (H13/H14)

Added clean-revision signed recovery-kit construction/verification, explicit software
wheel/public-root enrollment, signed filesystem-UUID media enrollment, atomic fsynced
offline generation export with complete read-back, and signed copy proofs. The monitor
checks capture age as well as copy age. Added an independently anchored read-only
retention planner with minimum surviving generations, live exact-version lock/legal-hold
checks and user-supplied storage-rate forecasts. No delete executor is shipped.
The local 95-test suite passes (PostgreSQL required in CI). See OFFLINE.md/RETENTION.md;
physical media, OS/runtime compatibility and disconnected clean-machine recovery
remain actual deployment acceptance, not claims from fixtures.

## Recovery/release qualification and activation tooling — PR #11 (H15/H16 tooling)

Added default offline Git/LFS and database structure checks, external-object-store
rejection, bounded tool process groups/staging entries/free-space guards, no-follow
source credential/registry reads and explicit file entry budgets. Added unattended
read-only SFTP feeds with independent host-key pins and no remote hash shell commands.
Added role doctor, tool/dependency inventory, exact hash locks, local wheel build,
Python 3.11/3.12/3.13 CI, measured synthetic recovery, private pending acceptance
templates and verification of owner-signed real evidence. See RELEASE.md,
QUALIFICATION.md and ACTIVATION.md. All 106 local tests pass with PostgreSQL required
in CI. A 32 MiB/33-chunk local drill passed; pinned runtime/build advisory scans
reported no known findings at the recorded check. Actual production H16 is pending
credentials, offline public recipients, authorized independent hosts, cost/account
approval, alert routing and physical media. No production success is fabricated.
