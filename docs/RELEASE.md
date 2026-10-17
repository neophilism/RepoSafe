# Reviewed releases and offline installation

Production executes a fixed reviewed version, never `git pull main && run`, an
unreviewed GitHub artifact, or a mutable package name fetched during a backup. Keep
the release approval/public roots outside GitHub's automatic execution path.

`requirements.lock` pins the full hardened runtime graph with SHA-256 hashes;
`requirements-build.lock` pins build prerequisites. Pins were resolved from PyPI
and exercised in the supported Python matrix. Update them deliberately, review
upstream release/security information, run the full suite/drills and re-sign the
release. Do not silently upgrade dependencies on collector/writer hosts.

On a trusted build computer with the exact reviewed checkout:

```sh
python3 -m venv /private/build-venv
/private/build-venv/bin/python -m pip install --require-hashes --only-binary=:all: \
  -r requirements.lock -r requirements-build.lock
/private/build-venv/bin/python -m pip download --require-hashes --only-binary=:all: \
  -r requirements.lock -r requirements-build.lock --dest /private/release/wheels
/private/build-venv/bin/python -m pip wheel --no-deps --no-build-isolation . \
  --wheel-dir /private/release/wheels
/private/build-venv/bin/python -m unittest discover -s tests -v
/private/build-venv/bin/python scripts/qualify_local.py \
  --output /private/release/qualification.json --megabytes 32
reposafe runtime-inventory --output /private/release/runtime-inventory.json
```

Build/download for each supported recovery OS, architecture and Python ABI; a wheel
cache from a different platform is not sufficient. Include verified OS/Python/pip
runtime/shared-library installers and the Git/Git-LFS/age/rclone distributions. Use
an operator-held kit signer to bundle the clean revision, public roots, verified tool
files, wheels and hash inventory with `kit-build` (OFFLINE.md). The kit manifest is
a signed software inventory. `runtime-inventory` records installed package versions
and tool executable hashes, not a claim of upstream build provenance or a complete
OS SBOM. Keep the original signed vendor distributions/provenance beside the kit.

Obtain the kit signer public root/fingerprint through the independent approval
channel. Verify `kit-verify --require-tools` before installing or making bundled
binaries executable. Recovery keys and runtime OAuth/App/vault tokens never enter
the software kit. An independently installed age tool and public root are the small
verification bootstrap; retain their verified installers outside GitHub as well.

On the authorized host, install the reviewed local wheel and cached requirements:

```sh
python3 -m venv /opt/reposafe/venv
/opt/reposafe/venv/bin/python -m pip install --no-index --find-links /verified/wheels \
  --require-hashes --only-binary=:all: -r /verified/requirements.lock
/opt/reposafe/venv/bin/python -m pip install --no-index --no-deps \
  /verified/wheels/reposafe-0.2.0-py3-none-any.whl
```

The reviewed kit/file manifest must cover this wheel as an explicitly supplied
wheel, or install the covered source using cached build dependencies and
`--no-build-isolation --no-deps`. Keep the OS/runtime interpreter's pip available
offline (`ensurepip` or verified distribution/pip wheel). Do not install an unrelated
package from the public `reposafe` name. Enable only the host's own role services;
run `doctor` and complete ACTIVATION.md before asserting production operation.

CI runs Python 3.11/3.12/3.13, real Git/age/rclone fixtures, an isolated PostgreSQL
dump/restore, an installed-wheel smoke, a measured synthetic local recovery and
a live public GitHub recovery smoke. A vulnerability scan of the locked runtime and
build graphs is recorded in `docs/evidence`; no known findings at that check is not
a permanent security guarantee. Repeat advisory review and clean recovery after
dependency/tool changes. Funded native-cloud and physical-media qualification are
separate acceptance evidence, never inferred from CI mocks.
