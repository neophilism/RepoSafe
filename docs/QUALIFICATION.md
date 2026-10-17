# Recovery qualification and evidence boundaries

The repository's tests exercise actual local Git refs/LFS, age encryption/wrong keys,
rclone copy/check/resume, bounded database/file adapters, safe extraction, inventory
shrink, role signatures, replay/future clocks, cloud-version/retention fixtures,
monitoring, offline copy/kit/media identity and read-only retention proposals.

CI requires a real temporary PostgreSQL server and restores a logical dump into a
new database, comparing rows and enforcing the captured primary-key constraint.
It never connects to or overwrites a production target. The only routine external
source smoke is a public test repository with no private account grant.

Run an independently sized local drill:

```sh
python scripts/qualify_local.py --megabytes 32 --output /private/qualification.json
```

The script drops source/cloud/database/alert credentials from its process, creates
synthetic data/test-only keys, captures real Git plus incompressible files, encrypts
bounded chunks, uses two real local rclone transports, signs/witnesses/monitors the
capture, changes/deletes upstream refs and restores the original refs/files. It
checks wrong-key cleanup and same-size corruption isolation. No source/provider
network calls or paid resources are used. The witness's explicit immutable minimum
is **zero for this local-only drill**; production policy remains two native providers.

The committed 32 MiB sample in `docs/evidence/qualification-local.json` records actual
measured times on the development host. It does not establish production bandwidth,
full-account RPO/RTO, multi-gigabyte qualification, a disconnected VM, real WORM or
physical media. The parameter supports larger datasets after checking local capacity;
measure representative account data and chosen host/region costs before sizing.

Default restore now checks captured Git refs/HEAD and LFS hashes, rejects external
Git object dependencies, runs SQLite integrity checks and inspects PostgreSQL archive
catalogs, after content hashes pass. No hooks, checkout or target DB writes occur.
Older archives without Git evidence remain readable; their exact-ref attestation
cannot be retroactively invented. `--content-only` explicitly defers these structure
checks when salvaging data on a machine lacking required tools. PostgreSQL archive
inspection does not replace a full database/application restore drill.

External qualification remains mandatory: source admin-visible/private coverage,
actual Drive/Dropbox OAuth refresh/quota behavior, native version restore after
writer delete/retention-shortening denial, cross-provider outage, independent alert
delivery/missing-monitor alarm, lost-account recovery, disconnected-media rotation,
age identity retrieval and a clean-machine restore using the software kit. Choose
authorized/funded test resources and retain signed private evidence through
ACTIVATION.md. The pending acceptance template cannot pass merely by signing it.

File collection and staging also have entry-count bounds so millions of empty files
cannot evade byte budgets. Per-source maximum_entries defaults to 100,000; the global
content inventory is bounded to 500,000 entries and a 128 MiB manifest. Use OS byte
and inode quotas as the final disk boundary; polling guards do not replace quotas.
