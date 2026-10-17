# Isolated collection, delivery and witnessed evidence

Install `.[all]` from a reviewed fixed release. Run each trust role on a separate
host/account; separate Unix processes on one administrator-controlled host do not
provide the same compromise boundary. No component automatically updates from GitHub.

| Role | Holds | Must not hold |
| --- | --- | --- |
| Collector | Read-only source grants, age public recipients, collector signing key | Destination grants, recovery identities |
| One destination writer | Its own destination grant, writer signing key, pinned collector public keys | Other destination/source grants, recovery identities |
| Independent witness | Read-only vault grants, its signing key, pinned collector/writer public keys | Source or vault write/admin grants, recovery identities |
| Monitor/recovery | Independently pinned public roots and sequence checkpoints | Routine write/admin grants |

Generate an Ed25519 signing pair **on each trusted role's host**, never sharing its
private key. Recovery age identities are separate and remain offline:

```sh
reposafe keygen-signing --output /private/new-role-key
```

Deliver the public PEM/fingerprint through an independent reviewed channel. A public
key beside an untrusted downloaded catalog is not a trust anchor. Verification
accepts a single public PEM or an explicitly pinned directory of at most 32 PEMs
for rotation. Add reviewed new roots before rotation; retain historical public
keys and signed sequence checkpoints. Agent cached catalogs are verified with its
current signing key: preserve the previous agent state as a read-only historical
epoch and start a new state directory when rotating that private key. Never erase
the witness/monitor's monotonic anchor during rotation.

## Collection and delivery

The collector's private environment includes `REPOSAFE_COLLECTOR_SIGNING_KEY_FILE`.
`collect` requires that key and remembers every observed repository ID:

```sh
reposafe --config /etc/reposafe/collector.toml collect \
  --output /var/lib/reposafe-collector/spool --state-dir /var/lib/reposafe-collector/state
```

Ciphertexts and the collector signature are finalized before `receipt.json` is
published. Bootstrap `snapshot`/`run` remain compatible with unsigned v2 captures;
isolated writers require signatures. Unsigned historical captures are not silently
promoted into trusted evidence. `sign`/`verify-signature --purpose coverage-registry`
can approve expected-inventory/retirement documents before installing their hash
pin in the collector configuration.

Expose the collector spool through a **read-only** SFTP account/filesystem export.
Each writer independently pulls it into its enrolled inbox. Pin the SSH host key;
disable SFTP shell, forwarding and write access. The collector must have no writer
host login. Keep OAuth refresh tokens/config files only at the corresponding writer.
The product deliberately accepts a mounted/local inbox so network transport and
host ACLs are explicit deployment choices. Mount it read-only to the worker. An
attacker may withhold queue items; it cannot forge signed fresh success. Missing
items trigger the independent monitoring deadline.

```sh
reposafe --config /etc/reposafe/writer.toml agent-queue \
  --inbox /srv/reposafe-inbox --destination aws \
  --state-dir /var/lib/reposafe-writer/state \
  --collector-key /etc/reposafe/pins/collector \
  --writer-key /etc/reposafe/keys/writer.pem
```

An agent stages inputs through the regular-file collector, verifies ciphertexts and
the pinned collector signature, rejects source credentials/future/stale captures,
and can write only the selected destination. Retrying preserves the same protected
versions. A signed catalog is published atomically only after successful read-back.
Failed/partial input never becomes complete success. Sweeps preserve queue items,
attempt other generations after failure, and return nonzero for failures/incomplete
entries. Archive completed inbox entries separately before the 10,000-entry bound;
never use a collector-controlled retention policy to prune destination data.

## Witness and recovery

Pull each writer's private `catalogs/` tree read-only into
`INBOX/DESTINATION/RUN_ID/catalog.json` with its `catalog.sig.json`. Keep catalogs
private: they reveal buckets, version IDs and recovery metadata. If transporting
them through public/untrusted storage, encrypt that transport to witness/recovery
age recipients first; the normal deployment uses authenticated read-only SFTP,
encrypted disks and private files. No catalog is uploaded to GitHub or a public log.

```sh
reposafe --config /etc/reposafe/witness.toml witness-queue \
  --inbox /srv/reposafe-catalogs --writer-key aws=/etc/reposafe/pins/aws \
  --writer-key b2=/etc/reposafe/pins/b2 --collector-key /etc/reposafe/pins/collector \
  --state-dir /var/lib/reposafe-witness/state \
  --signing-key /etc/reposafe/keys/witness.pem --minimum-immutable 2
```

All required destinations must attest the identical complete signed capture. The
witness independently checks every native vault version's bytes and COMPLIANCE
retention with its own read-only grant. Drive/Dropbox writer claims are distinctly
marked as not independently checked immutable copies. The default requires at
least one native vault; only an explicit `--minimum-immutable 0` permits convenience
copies alone. Production should require both independent immutable providers.

Events are signed, hash-chained, sequenced and tied to increasing capture timestamps.
The witness rejects replay and captures older than 30 hours. Preserve signed events,
catalogs and an independently stored high-water sequence/hash outside the witness
host. Signature verification alone does not prove freshness or an unbroken chain.

`fetch --catalog ... --writer-key ... --collector-key ... --output NEW` recovers
ciphertext from signed catalogs; native vaults use the exact protected version IDs.
Keep public roots with the offline recovery kit. Then use offline `restore` with
the separately held age identity. A source/collector compromise may still poison
future contents; old immutable and disconnected generations remain essential.

The `deploy/systemd` role units are reviewed examples, not installed services. Set
the exact host accounts, read-only inbox mounts, network allowlists, secret files,
encrypted work volumes and service paths before enabling them. Validate with
`systemd-analyze security`. Keep firewall rules outside source control of GitHub.

Signatures use [cryptography's Ed25519 implementation](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/),
not a custom primitive. The v1 envelope signs the ASCII bytes
`RepoSafe signature v1\0PURPOSE\0LOWERCASE_SHA256_OF_EXACT_DOCUMENT_BYTES` and carries
the public-key SHA-256 fingerprint, purpose and 64-byte signature. JSON reformatting
changes the digest; an embedded public key is never accepted as its own authority.
