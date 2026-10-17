# Read-only retention and storage proposals

Routine collectors, writers, witnesses and monitors have no prune/delete path.
`retention-plan` is a separate read-only maintenance operation. It does not execute
deletion, change retention/holds, apply lifecycle policies or spend money. Actual
expiration requires a separately authorized identity, exact reviewed scope and an
operator/provider procedure outside the backup daemon.

Use the latest sequence and event SHA-256 recorded independently by the monitor.
Keep event/catalog evidence private and provide pinned witness/writer/collector
roots. Never derive the trusted latest checkpoint solely from a mutable cloud pointer.

```sh
reposafe --config /etc/reposafe/maintenance.toml retention-plan \
  --events /private/events --witness-key /pins/witness \
  --writer-key aws=/pins/aws --writer-key b2=/pins/b2 \
  --writer-key drive=/pins/drive --writer-key dropbox=/pins/dropbox \
  --collector-key /pins/collector --latest-sequence TRUSTED_NUMBER \
  --latest-sha256 TRUSTED_HASH --minimum-generations 30 --minimum-age-days 90 \
  --safety-hours 72 --output /private/new-retention-proposal.json
```

The planner validates the anchored contiguous signed chain and each witnessed
catalog's exact hash and collector proof. It preserves at least the configured
number of known complete generations, minimum capture age and every protected
reference to a shared version. A changed required-copy policy blocks automatic
interpretation of older evidence and requires a separate migration review.

Older candidates require a **fresh read** of the exact object version, COMPLIANCE
retain-until and legal-hold state. Reads use a distinct maintenance grant, including
`s3:GetObjectLegalHold`/B2 `readFileLegalHolds`; permission failure is blocked, not
assumed to mean no hold. Active locks, legal holds, unknown state and the clock margin
block eligibility. Eligibility means only `eligible_for_separate_review`, not approval
to remove data. Convenience Drive/Dropbox copies are excluded from native version
expiration proposals. No custom deduplication is used; each chunk belongs to a full
independently recoverable generation.

Use `--without-live-audit` for a safe metadata/cost report without cloud credentials;
it never marks old versions eligible. Supply optional rates explicitly, for example
`--storage-rate aws=YOUR_USD_PER_GIB_MONTH --daily-bytes MEASURED_CIPHERTEXT_BYTES`.
No current provider price is assumed. Forecasts cover catalog-known storage and a
full-daily-copy retention model; requests, read-back/restore egress, taxes, unknown
versions and provider-specific overhead are excluded. This is not the actual bill.

Retain reports and reviewed changes with the independent operations records. Source
deletion, token revocation or a collector config edit never authorizes backup removal.
Test lifecycle behavior in an explicitly funded account before production; existing
COMPLIANCE locks cannot be shortened to undo a mistaken cost decision.
