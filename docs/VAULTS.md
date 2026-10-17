# Native immutable destinations and bounded transfers

Install `reposafe[vault]` to use boto3. Drive/Dropbox remain convenience copies;
native S3 and B2 adapters separately inspect private access, account identity,
versioning, default COMPLIANCE retention and every uploaded version's retention.
They read each exact version back and verify SHA-256/size before publishing a receipt.
No delete, policy-update or retention-shortening operation exists in the writer.

Example additions (placeholders are not deployed resources):

```toml
[runner]
chunk_bytes = 268435456
maximum_snapshot_bytes = 107374182400
minimum_free_bytes = 134217728

[[destinations]]
name = "vault_a"
kind = "s3"
bucket = "your-private-vault"
region = "us-east-1"
prefix = "reposafe"
expected_account = "123456789012"
credential_prefix = "REPOSAFE_VAULT_A"
retention_days = 90
required = true

[[destinations]]
name = "vault_b"
kind = "b2"
bucket = "your-second-private-vault"
region = "us-west-001"
endpoint = "https://s3.us-west-001.backblazeb2.com"
prefix = "reposafe"
expected_account = "your-b2-account-id"
credential_prefix = "REPOSAFE_VAULT_B"
retention_days = 365
required = true
```

Each agent receives only its own `PREFIX_ACCESS_KEY_ID`, `PREFIX_SECRET_ACCESS_KEY`
and optional `PREFIX_SESSION_TOKEN`. No shared ambient AWS credential selection is
used. S3 calls use explicit regional AWS HTTPS endpoints and ExpectedBucketOwner;
STS verifies the account. B2 checks the v4 authorization response for the exact
account, one bucket, prefix and read/write-only capabilities before connecting to
the approved regional B2 HTTPS endpoint. Destructive/unknown key capabilities fail.
Native recovery identities can be read-only and cannot call the upload operation.

B2 writer capabilities: listBuckets, listFiles, readFiles, writeFiles,
readBucketRetentions, readFileRetentions, optionally harmless read-only bucket/hold
metadata capabilities. Scope the key to one bucket and the exact `reposafe/` prefix.
Do not grant deleteFiles, retention writes, bypassGovernance, bucket/key administration
or unrestricted/all-bucket access. Account administrators/recovery must be separate.

The AWS CloudFormation template provides a retained private bucket, versioning,
COMPLIANCE defaults, AES256 server-side encryption, TLS-only policy and a scoped
writer role with explicit delete/retention/policy-change denies. It is source code,
not an applied stack. Review costs, account recovery, audit logging and irreversible
retention before applying it. Real IAM/key-denial and version-retention tests in an
authorized account remain production acceptance requirements; mocks do not prove
cloud enforcement. Root account closure/provider failure still require other copies.

## Resume and recovery semantics

Run IDs are unique. A retry inspects an existing object version, downloads that exact
version, verifies bytes/retention, and reuses it. It never substitutes a differing
existing payload. AWS uses conditional create; B2 relies on unique keys and protected
version IDs, preserving prior versions even in a concurrent upload race. A delete
marker or changed latest pointer cannot erase a cataloged protected version. A failed
payload/read-back/retention check prevents receipt publication; successful earlier
copies remain intact. Delivery evidence records keys, versions, hashes and retain-until
times for independent witnessing and version-specific recovery.

COMPLIANCE retention must cover the capture timestamp plus the configured duration
and remain unexpired at verification. Retrying an older run does not require extending
its retention or creating a new version. Routine writers cannot shorten or extend it.

## Format v3

Setting `chunk_bytes` produces independently age-encrypted `chunk-000000.age`, etc.,
plus a v3 receipt containing the ordered exact file list/hashes and compressed byte
count. Plaintext chunks are at most 1 GiB; the default example is 256 MiB. Native encrypted objects allow up to 2 GiB to accommodate encryption overhead. A complete snapshot
does not depend on earlier snapshots or shared deduplicated chunks. Transfer retries
reuse verified chunks. Restore decrypts/joins the ordered chunks, then performs the
existing bounded extraction and full content inventory checks. Missing/reordered/
duplicate chunks fail verification. V1/v2 readers remain available.

For v3, `--trusted-sha256` anchors the entire receipt, which names every ciphertext
chunk; for v2 it continues to anchor the single ciphertext file. Receipts are capped
at 8 MiB and 10,000 chunks. Source/output space checks and the global plaintext byte
budget fail before publication; dedicated host disk quotas still protect an individual
Git clone from exhausting its volume. No cross-run deduplication/pruning is introduced.
