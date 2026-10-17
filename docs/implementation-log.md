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
