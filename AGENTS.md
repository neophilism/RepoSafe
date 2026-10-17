# RepoSafe development rules

Read README.md, docs/COVERAGE.md, and the technical architecture and development
plan when present. Keep the repo self-contained for subsequent developers.

* Never commit credentials, private age identities, private repo names, payloads,
  runner inventory, or customer data. Public logs contain aggregate status.
* Never replace backups with a destructive mirror/sync. The backup path has no
  delete/prune API. Retention administration is a different identity and workflow.
* Preserve old snapshots when sources disappear, permissions shrink, or uploads fail.
* No shell execution of repo content. No checkouts, hooks, submodule execution, or
  untrusted Actions with backup secrets. Backup jobs never run on pull_request.
* Public-key encryption before transfer; recovery keys never belong on collectors.
* New provider support needs failure, integrity and recovery tests. Do not claim
  live cloud validation, WORM retention, or complete recovery without evidence.
* Run `python -m unittest discover -s tests -v`. Integration tests need git,
  git-lfs, age and rclone; CI installs these tools.
* Chain dependency-ordered PRs after checks pass and GitHub confirms safe merge.
  Update docs/STATUS.md with verification and outstanding external setup.
