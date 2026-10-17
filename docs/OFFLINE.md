# Offline rotation and recovery kit

Use at least two encrypted removable devices with separate physical custody. Keep
one unplugged while updating the other. An always-mounted share does not create an
offline failure domain. Software cannot buy media, check its physical location or
prove disconnection; those are explicit operator acceptance steps.

## Build and pin a recovery kit

On a trusted build machine, use a clean checkout at a reviewed exact commit. Obtain
verified age, age-keygen, Git, Git LFS, rclone and Python distributions for the recovery
OS/architecture. Include their required shared libraries/standard library or an
offline OS/runtime image, plus all dependency wheels. The kit builder does not fetch
or execute unreviewed software. Supply files explicitly, never a credential directory.

```sh
reposafe kit-build --source-root /trusted/RepoSafe --revision REVIEWED_COMMIT \
  --output /private/recovery-kit --signing-key /private/kit-signer.pem \
  --public-root collector=/pins/collector.pem --public-root witness=/pins/witness.pem \
  --public-root offline=/pins/offline.pem --public-root kit=/pins/kit.pem \
  --tool age=/verified/age --tool age-keygen=/verified/age-keygen \
  --tool git=/verified/git --tool git-lfs=/verified/git-lfs \
  --tool rclone=/verified/rclone --tool python=/verified/python \
  --tool os-image=/verified/recovery-runtime.iso --wheel /verified/wheels/PACKAGE.whl
reposafe kit-verify /private/recovery-kit --key /independent/kit-public.pem --require-tools
```

Repeat `--wheel` for every dependency wheel; the required package set is recorded in
`kit.py`. Use the pinned dependency download workflow in the release runbook. File
presence sets `ready_for_drill`; it does **not** certify that binaries/shared libraries
boot on another machine. Perform a clean-machine offline restore before accepting the
kit. Keep a compatible OS installer/runtime and installation instructions alongside
it. Tool files are initially non-executable; verify signatures/hashes first, then set
execute permission only on reviewed binaries during recovery.

The kit contains tracked Python source/tests, Markdown recovery/architecture docs,
project metadata/lock files, explicitly supplied software/wheels and public roots.
It refuses a dirty/mismatched tracked source revision, ignores untracked files, and
never traverses `.git`, actual runtime configs, backup payloads or arbitrary include
directories. Obvious private-key files are refused as software. No age recovery or
role signing private key belongs in the kit. Keep those keys under separate offline
custody, with tested backups. The independent kit public root/fingerprint must be
obtainable outside the kit; an embedded key is not its own authority.

## Enroll existing mounted media

Prepare disk encryption and mount the intended device through the OS yourself.
Check its filesystem UUID and physical label. RepoSafe never formats or mounts disks.
Enrollment requires an exact mounted root, stable UUID and explicit acknowledgement
that encryption was configured. The acknowledgement is an operator statement, not
cryptographic detection of LUKS/BitLocker or protection from malicious device firmware.

```sh
reposafe media-enroll --root /media/rotation-a --media-id rotation-a \
  --filesystem-uuid ACTUAL_UUID --signing-key /private/offline-signer.pem \
  --encrypted-media-acknowledged
```

Use a POSIX filesystem supporting private permissions and fsync. Pin the media
enrollment signer outside the device. A wrong UUID, missing mount, altered enrollment
signature or symlink path prevents export. The production CLI has no test mount bypass.

## Copy and verify a witnessed generation

On the trusted rotation machine, obtain the encrypted run, its collector signature,
the independently witnessed event/catalog tree and reviewed recovery kit. These do
not require an age decryption identity to copy:

```sh
reposafe offline-export /private/RUN_ID --media-root /media/rotation-a \
  --media-key /pins/offline.pem --signing-key /private/offline-signer.pem \
  --collector-key /pins/collector.pem --event /private/events/EVENT/event.json \
  --witness-key /pins/witness.pem --kit /private/recovery-kit --kit-key /pins/kit.pem
reposafe offline-verify /media/rotation-a/RepoSafe/RUN_ID \
  --copy-key /pins/offline.pem --collector-key /pins/collector.pem \
  --witness-key /pins/witness.pem --kit-key /pins/kit.pem
```

Each new generation includes ciphertext/signature/receipt, witnessed catalogs and
the kit. The exporter checks free space, fsyncs data, reads all files back, verifies
every signature/hash, rechecks the mounted UUID and publishes an atomic signed
`copy.json` record. A failed copy never replaces an earlier generation. Idempotent
retries verify the existing record without renewing its timestamp. Same-size corrupt
bytes, extra files, altered evidence, wrong media and a partial copy fail verification.

Send only `copy.json` and `copy.sig.json` through the private read-only evidence feed
to the independent monitor. It checks both capture age and copy age, preventing a
newly copied ancient run from appearing to meet the seven-day offline RPO.

Then unmount/eject and physically disconnect the updated device. Record its private
location and disconnect date outside GitHub. Keep the other device disconnected
throughout the operation. Re-read media monthly, rotate weekly, and perform a
network-disconnected recovery drill with separately retrieved age identities.

If all cloud accounts and GitHub are unavailable, verify the copy and kit using
independent roots, install the reviewed software offline, and run `restore` against
the copy's `snapshot/` directory into a new encrypted local directory. Follow
RECOVERY.md and DATASETS.md to validate refs/LFS/files/database application behavior.
Measured clean-machine recovery and actual physical rotation remain acceptance
evidence; synthetic filesystem fixtures do not establish these outcomes.
