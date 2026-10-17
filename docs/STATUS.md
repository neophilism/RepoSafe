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

No real account backup or cloud transfer has been performed. Deployment needs a
separate read-only GitHub credential, public age recipient and destination OAuth
configuration. ChatGPT app connections do not supply runtime OAuth credentials.
