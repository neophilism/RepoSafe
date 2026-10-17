# Implementation status

## Basic PR 1 — encrypted GitHub snapshots

Implemented: authenticated paginated discovery, public/private owner filtering,
coverage guards, bare mirrors, optional all-object LFS fetch, metadata, offline
age recipient encryption, unique run paths, integrity receipts and partial-run
status. Tests use synthetic repositories and throwaway recovery keys.

PR 1 merged after 12 tests and GitHub Actions CI passed.

## Basic PR 2 — daily independent Drive/Dropbox delivery

Implemented: rclone copy-only delivery, downloaded-byte checking, receipt-last
publication, independent provider failures, retries from existing ciphertext,
daily scheduled/manual workflow, isolated runtime secret files, and setup/recovery
instructions. Real rclone integration tests use two local directories, check
same-size corruption, retries and preservation of previous data. These tests do
not establish actual Drive/Dropbox OAuth or provider behavior.

PR 2 merged after 18 tests and GitHub Actions CI passed.

## Hardened design H0

Written in order: TECHNICAL_ARCHITECTURE.md, then DEVELOPMENT_PLAN.md and ADR 0001.
The plan covers H1 through production acceptance H16, with dependencies, file/module
scope, migration, required verification and external deployment inputs. Next: H1
independent-runner foundation. Immutable vaults, isolated delivery hosts, signed
witnessing, independent monitoring and offline media remain planned features.

## Hardened foundation H1 — PR #4

Implemented: POSIX regular-file collector with descriptor-anchored no-follow access,
exclusions, mutation detection and source byte caps; v2 encrypted content inventories;
safe offline restore with content checks, digest anchoring, no overwrite and bounded
extraction rejecting traversal/links/devices/sparse/duplicate entries; exclusive run
lock; private atomic fsynced state; monotonic observed IDs; success only after complete
capture and all required copies. Missing repos preserve visible data as a partial run.
Includes independent daily systemd templates and deployment/format/recovery docs.

Verification: 39 local tests pass with real age, real Git branch/tag recovery and
fsck, real rclone transfers to two local fixtures, corruption, wrong key/digest,
archive attacks, source mutation, coverage loss, locks and state semantics. The
systemd service/timer passed isolated root-fixture syntax verification; the calendar
expression parsed. A read-only live public-repo smoke runs in GitHub CI; local live
GitHub access is restricted by sandbox DNS. Synthetic fixtures do not verify live
private-repo authorization, Drive/Dropbox OAuth, cloud retention or account recovery.

No real private-account backup or cloud transfer has been performed. Deployment
needs a dedicated read-only GitHub runtime credential, public age recipient and
destination OAuth config. The schedule is not activated; no independent host,
immutable vault, external monitor or offline media is provisioned. H2–H16 remain
the robust target plan rather than completed production defenses.
