# ADR 0001 — copy, key and execution boundaries

Status: accepted for implementation, 2026-10-17.

Use Python 3.11+ with standard-library core; mature age and rclone command-line
tools for bootstrap encryption/transport. Do not implement bespoke cryptography
or a new hosted application. Use a versioned encrypted inner manifest and aggregate
outer receipt, immutable unique run names, and a receipt-last commit protocol.

Drive/Dropbox are useful mutable copies. They do not establish ransomware-proof
retention. Client `--immutable` is an overwrite guard, not provider Object Lock.
Implement native retention-aware S3 and B2 adapters separately and test real scopes.

Keep recovery identities offline, collect on an independent trusted machine, and
eventually split destination writers into distinct trust zones. Install a fixed
reviewed code release; a daily auto-update from GitHub would restore the control-
plane dependency this project is intended to reduce.

Prefer simple full archives before chunk/dedup complexity. Tradeoff: higher storage,
scratch and verification bandwidth. Add measured capacity limits and chunk dependency
retention before scaling. No ordinary backup command may delete remote generations.

Unsigned checksums are useful for corruption, not hostile replacement. Encryption
provides confidentiality but does not attest who encrypted with a public key.
Add independent signed witnessing; never describe a local checksum as authenticity.

Consequences: runtime OAuth/private-repo credentials and an offline recovery recipient
are unavoidable deployment inputs. Permanent key escrow, hardware purchase and paid
vault provisioning cannot be fabricated by committing code. STATUS.md distinguishes
implemented/tested code from configured services and verified production behavior.
