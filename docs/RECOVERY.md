# Recovery from an encrypted snapshot

Use a clean recovery computer, not the machine suspected of compromise. Retrieve
the chosen run from any surviving provider. Older dated runs survive upstream
deletions; select a known-good date, not simply the latest available run.

1. Obtain `snapshot.tar.gz.age` and `receipt.json` into a private directory.
2. Verify the ciphertext with `python -m reposafe --config reposafe.toml verify
   DIRECTORY`, or compare SHA-256 and size to an independently trusted receipt.
   Matching an adjacent unsigned receipt alone does not establish authenticity.
3. Decrypt locally: `age -d -i /offline/recovery.key -o restored.tar.gz
   DIRECTORY/snapshot.tar.gz.age`. Never copy the key to a collector or cloud job.
4. Inspect the tar listing before extraction. Extract to a fresh private directory
   with a safe archive tool. The hardened foundation supplies a constrained extractor.
5. Read `snapshot/manifest.json`. Check `complete`, per-repository failures, and
   whether LFS was included. Do not accept a partial run as account-wide recovery.
6. For each `snapshot/repositories/ID/mirror.git`, run `git fsck --full --strict`,
   inspect refs and repository.json, then `git clone mirror.git recovered-worktree`.
   Use `GIT_LFS_SKIP_SMUDGE=1` initially. LFS objects are under the mirror's `lfs`
   directory and must be copied/uploaded as part of recovery.

To restore to another Git host, first create an empty destination you control.
Review refs; use a carefully targeted push of branches/tags. `git push --mirror`
can delete destination refs and must never target a live repository casually.
Push LFS objects separately with Git LFS. GitHub-specific read-only refs may not
be pushable. JSON metadata is an export, not an automatic settings reconstruction.

A proper recovery drill compares branch/tag object IDs, expected files, LFS object
hashes, and any application/database consistency checks. Record the selected run,
receipt trust source, tools, elapsed time, exceptions and result outside GitHub.
No real-account cloud restore has been verified yet; CI uses synthetic fixtures.
