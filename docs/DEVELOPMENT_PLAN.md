# Complete RepoSafe PR development plan

Read TECHNICAL_ARCHITECTURE.md first. This plan covers implementation through
production acceptance, not only the next milestone. Scope is one owner's private
backup system with extensible source/destination adapters; a multi-tenant hosted
service or public dashboard is unnecessary. Sequence dependent PRs automatically,
fix failing checks, merge only after GitHub confirms safe merge, and update STATUS.md.

## Delivery map

| Stage | PR | Dependencies | Outcome | Current state |
| --- | --- | --- | --- | --- |
| Bootstrap | B1 | Empty repo | Encrypted GitHub mirrors and explicit coverage | PR #1 merged |
| Bootstrap | B2 | B1 | Daily Drive/Dropbox copy and verification | PR #2 merged |
| Design | H0 | B2 | Technical architecture, full plan, decisions and acceptance boundaries | This documentation PR |
| Foundation | H1 | H0 | Independent runner, source interface/files, durable coverage state, safe offline recovery | PR #4 |
| Source identity | H2 | H1 | GitHub App tokens and independently reconciled owner inventory | Implemented in PR #5; live acceptance pending |
| Git fidelity | H3 | H2 | Ref maps, LFS validation, submodule/wikis and repository lifecycle handling | Implemented in PR #5; live acceptance pending |
| Metadata | H4 | H3 | Issues/PR/review/comment/label/milestone exporters | Implemented in PR #5; live acceptance pending |
| Metadata | H5 | H4 | Releases/assets, discussions, settings and ephemeral artifacts | Implemented in PR #5; live acceptance pending |
| Immutability | H6 | H1 | Native S3 vault adapter, version catalog and fail-closed retention checks | Implemented in PR #6; cloud acceptance pending |
| Provider diversity | H7 | H6 | B2 compliance vault and independent permission verification | Implemented in PR #6; cloud acceptance pending |
| Isolation | H8 | H2, H6 | Collector/delivery separation, least-privilege roles and isolated runtime packaging | Implemented in PR #7; deployment acceptance pending |
| Provenance | H9 | H6, H8 | Signed receipts, independent witness and rollback detection | Implemented in PR #7; independent deployment pending |
| Other data | H10 | H1 | Database-consistent PostgreSQL/SQLite exports and object/document adapters | Implemented in PR #8; enrolled-service acceptance pending |
| Scale | H11 | H3, H6 | Chunked resumable transfer and capacity policies; measured hot-tier decision | Implemented in PR #6; cloud acceptance pending |
| Operations | H12 | H6, H7, H9 | Independent freshness/retention monitoring and failure alerting | Planned |
| Offline | H13 | H9, H11 | Rotated offline export, complete recovery kit and media verification | Planned |
| Retention | H14 | H9, H11, H12 | Separately authorized retention maintenance and budget reporting | Planned |
| Assurance | H15 | H5, H7–H14 | Restore drills, chaos/security verification and recovery benchmarks | Planned |
| Activation | H16 | H15 | Real-account daily production rollout and signed acceptance evidence | Planned |

Independent workstreams may be implemented in any dependency-valid order. No stage
may represent planned defenses as already deployed. The owner has requested continuation through the remaining implementation plan.
Code proceeds through production tooling; actual account enrollment, credentials and
cost decisions remain explicit acceptance inputs.

## B1 — encrypted GitHub snapshots (completed)

Files: reposafe/config.py, github.py, snapshot.py, common.py, cli.py; pyproject.toml;
CI; coverage documentation. Paginate authenticated inventory, filter explicit owners,
include public/private/forks/archived, enforce count/required guards, mirror all
advertised refs without checkout, fetch LFS, fsck, encrypt with native age recipients,
unique paths and aggregate integrity receipts. No cloud payload leaves unencrypted.

Validation: real age encrypt/decrypt; API pagination and 401/429 handling; empty
coverage failure; partial status; unique paths; secret-free subprocess diagnostics.
Acceptance: CI passed; PR #1 merged. All-account visibility remains deployment evidence.

## B2 — daily Drive/Dropbox delivery (completed)

Files: delivery.py, scripts/prepare_runtime.py, backup workflow, SETUP.md/RECOVERY.md.
Copy explicit ciphertext filenames with no delete/overwrite workflow, read bytes
back, publish receipt last, attempt both providers independently, retry existing
ciphertext. Scheduled and manual execution use private runtime config outside the
checkout. Document private-repo token scope, OAuth, expiry, quotas and GitHub schedule
limitations. No PR event receives backup tokens; no payload Actions artifacts.

Validation: real rclone local transport, same-size corruption, retry idempotence,
provider outage, receipt ordering, exclusion of unexpected plaintext. Acceptance:
18 tests and GitHub CI passed; PR #2 merged. Real Drive/Dropbox OAuth is not tested.

## H0 — architectural baseline (this PR)

Write architecture first, then this full dependency/validation plan. Record decisions
in ADRs and the threat model, including mutable-vs-immutable storage, key custody,
credential compromise, data scope and no-spending deployment constraints. Link from
README. Acceptance: design, operational boundaries and follow-on work are independently
understandable without ChatGPT memory; basic implementation remains test-green.

## H1 — hardened foundation (next PR)

* Introduce explicit file-source specifications and a collector interface without
  executing shell hooks. Copy regular files only, reject links/devices, check for
  mutation, honor declared exclusions and cap bytes. Include source results privately.
* Add content-hash manifests inside encryption with a versioned v2 receipt. Keep
  the v1 verifier for bootstrap ciphertext; safe restore requires v2 content manifests.
* Build offline restore into a new private directory, bounded extraction, path/link/
  duplicate-member defense, content hash verification, no overwrite/no network/no hooks.
  Allow an externally trusted ciphertext digest to anchor archive provenance.
* Add OS locking and atomic durable private state. Remember the union of observed
  repository IDs; missing IDs make future captures partial and cannot silently lower
  the baseline. Advance last-success only after every required provider verifies.
* Add systemd service/timer samples with missed-run catchup, restrictive service
  account and fixed installed code. No automatic pull-and-execute from GitHub.
* Add format/operation docs and update deployment/coverage matrix. Keep credentials,
  decryption identities and actual datasets out of the repo.

Validation: real Git branch/tag restore and fsck; wrong key; encrypted roundtrip;
file contents/exclusions; file mutation and symlink rejection; malicious archives;
corrupt/missing content; snapshot ID coverage shrink; locks; state failure and last-
success semantics; existing provider isolation tests; CI on supported Python.
Acceptance: code and tests merged/committed, with an honest deployment checklist.
This is a foundation, not a claim that Object Lock or alerting is operating.

## H2 — source identity and coverage registry

Files: auth.py, inventory.py, schemas, credential runbook. Support dedicated GitHub
App installation discovery and short-lived token minting; isolate private keys on
source collector only. Paginate every owner's inventory with stable IDs and full
grants. Record selected-repo restrictions and organization/SSO authorization.
Maintain an independently reviewed expected registry and explicit signed retirement
events; transfers/renames update metadata while preserving IDs. New private repos
are automatically captured when grants permit. Do not infer invisibility as deletion.

Tests: token expiry/refresh, installation pagination, revoked grant, rename/transfer,
rate limit exhaustion, new private repo, retired-vs-missing repository. Migration:
import H1 observed IDs with provenance marked local/unwitnessed; never drop history.
Acceptance: compare authenticated inventory to owner's admin-visible inventory in a
private run; no source write capability; failure is observable outside the collector.

## H3 — Git and LFS recovery fidelity

Record exact ref/object maps and captured HEAD with timestamps. Validate each LFS
object against its OID/size; track LFS missing objects and repository network failures.
Add wiki mirrors with explicit absent/empty/permission statuses. Inventory submodule
targets and signal unenrolled dependencies; do not execute them. Define treatment of
GitHub pull refs, hidden refs, large repos, Git replace refs and source mutation during
capture. Preserve full snapshots across force pushes and branch/repo deletion.

Tests: multi-branch/tag refs, empty repo, force push, packed refs, gitlinks, deleted
branch, missing LFS, unexpected endpoint, wiki permissions and source-change retry.
Acceptance: clean recovery compares all captured refs and LFS hashes, independently
of GitHub. Old formats remain readable; new metadata is additive/versioned.

## H4 — collaborative repository metadata

Export issues, PRs, comments, review threads/reviews, labels and milestones with
stable API identifiers and author/timestamp metadata. Preserve raw JSON plus a
normalized offline index; do not conflate issue and PR collections. Stream pages to
bounded storage. Track mandatory vs unavailable endpoints and API version/permission.
Define reproducible capture windows and record concurrent-change limitations.

Tests: >100-page fixtures, deleted users, edited/deleted comments, 403/404, secondary
rate limits, malformed data and resumable failure. Acceptance: compare counts to a
synthetic seeded repository and navigate exports with no source access. Re-import
limitations (IDs/timestamps/permissions) are documented honestly.

## H5 — remaining GitHub data and assets

Export release metadata and binary assets, discussions via GraphQL, settings/rules,
readable access metadata and opt-in Actions artifacts/logs before expiry. Use strict
host/redirect credential rules for downloads and streaming integrity checks; never
forward GitHub authorization to arbitrary asset URLs. Record encrypted-secrets names
only when authorized; secret values are not retrievable. Add opt-in package/export
coverage if the owner enrolls it. OAuth scope expands only for requested source data.

Tests: draft/private releases, zero-byte and large assets, redirects, expired assets,
GraphQL cursors, schema changes and inaccessible settings. Acceptance: offline asset
hash matches and complete endpoint coverage ledger; a missing mandatory asset fails
full status. No unsupported claim of an entire GitHub account backup.

## H6 — S3 immutable vault

Implement native SDK adapter and configuration schema rather than treating rclone's
`--immutable` as WORM proof. Inspect versioning/default Object Lock before writes;
require COMPLIANCE and minimum retain-until for each object version. Upload with
checksums, record object/version IDs and checksums in private/witnessed catalog, and
verify retention after each payload/receipt. Use conditional creates and version-
specific restores. Deny delete/version-delete, bypass/retention-policy updates and
bucket administration to writer; keep billing/admin recovery separate from GitHub.

Add reviewed IaC templates with blocked public access, TLS-only policy, account
separation, audit logs and bounded test/production retention parameters. Do not apply
paid or irreversible production retention without the owner's concrete budget/config
approval. Inspect cloud SDK credential/provider behavior before relying on policies.

Tests: mocked failure matrix plus live funded test bucket: correct upload/restore,
wrong mode/period rejected, writer delete denied, overwrite/delete-marker/version
behavior, interrupted multipart, expired temporary credentials. Acceptance: retained
version recovered after attempted deletion; permission and retention evidence saved
privately. Unit mocks alone never establish cloud immutability.

## H7 — B2 immutable provider diversity

Add a native B2/S3-compatible adapter with actual Object Lock inspection, bucket/key
capability restrictions, stable version IDs, minimum compliance retention, write/read
verification and no-delete capabilities. Separate provider account, recovery and
credentials from S3. Verify provider-specific lifecycle, retention and listing semantics.

Tests: API error fixtures and live funded bucket with restricted key; deny retention
shortening and deletion, recover a named protected version, isolate an S3 outage.
Acceptance: independently observed immutable backups survive loss of either provider;
each required vault's own completion is visible. No production bucket created blindly.

## H8 — compartmentalized runtime and supply chain

Separate source collector and per-vault delivery agents into trust zones with
authenticated append-only ciphertext queues. Define input size/format validation,
replay control, idempotency, retry/dead-letter behavior and egress allowlists. No
agent has every cloud credential. Restore/retention identities are never installed.
Use reviewed version/digest-pinned releases and signed updates distributed outside
GitHub's automatic execution path. Generate SBOM/tool inventory and verify provenance.

Tests: compromised/malformed queue item, replay, missing bytes, worker termination,
network partition, source token unavailable to uploader, vault token unavailable to
collector, unreviewed software update. Acceptance: credential inventory/host diagrams
match deployed isolation; systemd hardening verified on the chosen OS.

## H9 — signed, witnessed catalogs and rollback defense

Add established signature tooling, canonical receipt schema, key IDs and rotation.
Collector signatures attest collection only; independent verifier signs/witnesses
accepted provider versions and full verification. Pin public roots in offline recovery
kit and independent monitor. Hash-chain witness events with monotonic sequence/run
timestamps; defend against forged/replayed latest pointers and catalog replacement.
Keep metadata private by encrypting sensitive catalog contents before publication.

Tests: altered receipt, replaced ciphertext/receipt pair, old valid run replay,
clock skew, signer compromise/rotation, witness outage and catalog reconstruction from
providers. Migration: v1/v2 unsigned receipts stay explicitly untrusted; never retro-
actively label them authenticated. Acceptance: independently anchored clean recovery.

## H10 — other-data adapters and consistency

Add PostgreSQL logical export/restore with separate source credentials, database role
metadata and selected extension/version checks; SQLite online backup; optional provider
PITR/WAL enrollment with retention matching restore dependencies. Add object storage
and requested document/config exporters via fixed adapter commands, not arbitrary shell
hooks. Enroll each dataset with owner, scope, consistency, RPO/RTO and secret escrow.

Tests: active writes, transaction consistency, roles/extensions, SQLite WAL, truncated
dump, database version mismatch, object pagination/version deletion and source auth
failure. Acceptance: restore into isolated services and pass application consistency
checks. Never touch or overwrite production databases during a restore drill.

## H11 — scale, resumability and storage economics

Measure dataset/storage/throughput first. Add independently encrypted bounded chunks,
resumable per-object queues, compressed indexes and manifests, quotas/backpressure,
bounded concurrency, upload timeout/backoff and storage budget reports. If using
content dedup, retain all referenced chunks through each referencing snapshot's full
lock interval. Consider a separate append-only restic hot tier after benchmarking;
do not embed public-key-only claims or assume direct WORM pruning will work.

Tests: multi-gigabyte fixture, interrupted chunk/multipart resume, corrupt chunk,
shared-chunk retention dependency, quota errors and realistic restore bandwidth.
Migration: immutable v2 full archives remain readable; no destructive in-place rewrite.
Acceptance: measured cloud limits/cost estimate, complete restore and no unresolved
reference/prune hazards. Additional paid storage/egress needs explicit budget approval.

## H12 — monitoring and operational response

Deploy independent deadline monitoring, start/fail/verified-success events, per-vault
freshness, coverage and retention checks, token expiry warnings, quota/capacity, run
duration and offline-media age. Protect health credentials but do not equate heartbeat
possession with backup validity. Product alerts use operator-configured recipients
and providers; do not send unsolicited development messages.

Tests: stop timer, revoke source/destination token, job hangs, silent provider failure,
stale receipt, all-success heartbeat spoof, disk-full and provider outage. Acceptance:
an external alert arrives within agreed 30-hour stale window, including when GitHub
is unavailable. Runbooks include credential rotation and compromise freeze procedures.

## H13 — offline rotation and recovery kit

Export independently recoverable generations with signed indexes, checksums and tool
kit to enrolled encrypted removable devices. Require correct device identity/mount,
free space and read-back verification; never format disks automatically. Track last
verified copy and physical location without exposing recovery keys. At least one
device remains unplugged; no always-mounted NAS counts as air-gapped. Provide a
weekly rotation runbook and a small separate offline identity escrow process.

Tests: wrong/missing/read-only media, corrupt sectors/fixture files, partial copy,
stale catalog, lost cloud accounts, key retrieval and clean-room offline restore.
Acceptance: restore without network or original runner; media purchase/location and
physical rotation are owner actions, never falsely labeled autonomous software work.

## H14 — isolated retention maintenance

Implement report/dry-run first; require a separate operator identity and reviewed
policy to expire only eligible data. Respect all object versions, lock times,
legal holds, chunk dependencies and minimum surviving known-good generations. No
routine collector/uploader gains prune privileges. Source deletions/revocation do
not lower retention. Produce forecast costs and lifecycle drift checks.

Tests: clock skew, active locks, mixed versions, chunk references, provider retention
errors, account/region mismatch and rollback of a bad policy. Acceptance: reviewed
dry-run against funded test data, no production delete without separately authorized
concrete retention scope. A config edit cannot silently erase backup history.

## H15 — security, chaos and recovery qualification

Exercise source compromise (force push/deletion), collector outage/compromise,
provider account failure, wrong/lost key, corruption/rollback, partial inventory,
cross-tenant access mistakes, disk exhaustion and dependency supply-chain failures.
Review E2E data flows, scopes, logs and artifact leakage. Perform clean-host per-repo
and full-account restores, compare exact refs/LFS/files and database consistency.
Measure RPO/RTO instead of promising untested service levels. Add regression tests
only for meaningful properties and preserve evidence outside the source provider.

Acceptance: all required checks/security findings resolved or explicitly scoped;
independent retention/alerting evidence; documented recovery times; known limitations
and access/backup ownership signed off. Accessibility/browser tests are not applicable
to this CLI-only scope; apply them if a UI is added later.

## H16 — production activation and continuing operations

Enroll exact owners/data roots, accounts, scopes and retention/budget. Install a
fixed reviewed release on the authorized independent host. Supply credentials through
its private secret store. Run initial capture to every required destination, verify
real cloud retention and perform clean recovery. Enable the daily timer, independent
monitor and offline rotation; verify the next real daily run. Disable the bootstrap
GitHub schedule when independent deployment is authoritative to avoid duplicate cost.

Acceptance record: exact deployed commit/tool versions, private inventory, captured
data classes, per-destination version/retention evidence, restore report, last/next
run, monitor ownership, token expiry, offline custody and approved recurring costs.
Routine work: daily automated checks; weekly offline rotation; monthly sampled
restores/key-expiry review; quarterly full disaster drill; prompt patched-release
rollouts through the separate trust path. A missed acceptance item remains outstanding.

## Current external inputs (not a reason to stop local implementation)

1. Public age recipient from an offline-owned recovery identity; the owner retains
   the private key and tested copies. Do not generate the permanent recovery key
   on a transient chat/workspace machine and treat it as durable escrow.
2. Dedicated GitHub runtime credential covering all requested private/public repos.
3. Drive/Dropbox unattended rclone OAuth config; a ChatGPT connection is distinct.
4. Choice/access to an independent host and exact other-data roots to enroll.
5. Budget and separate accounts for immutable vaults, test retention and offline
   media before any spending or irreversible production retention is applied.

All code/configuration examples, schemas, source boundaries, migration notes,
validation and deployment requirements live in this repo, not in conversation memory.
