# Daily Drive and Dropbox setup

This configures an executable daily workflow, not an already-running backup.
Runtime credentials must be supplied through the chosen runner's secret store.
ChatGPT connections cannot be extracted or reused by an unattended Python job.

## Recovery key first

Use `age-keygen -o recovery.key` on a trusted recovery computer. Keep the identity
off the collector and outside GitHub, Drive and Dropbox; keep two secured offline
copies in different locations. Test decrypting a synthetic snapshot before relying
on it. Copy only the `age1...` public recipient into configuration.

## Provider authorization

Install Git, Git LFS, age and rclone from their official package sources.
Run `rclone config` interactively on a trusted computer:

* Create a Google Drive remote named `gdrive`, restricted to a dedicated backup
  folder. Prefer an OAuth client you control and `drive.file` scope where it fits
  your setup; verify rclone can create, list and download its own backup files.
* Create a Dropbox remote named `dropbox`. Prefer a dedicated App Folder app with
  only the metadata/content read/write permissions rclone requires. Complete its
  OAuth flow with offline refresh support.
* The config contains refresh tokens and is a secret, even when base64 encoded.
  Do not commit it, paste it into issues, or put it in an Actions artifact.
* Validate both remotes using synthetic encrypted data. OAuth approval in ChatGPT
  does not authorize the independent runtime application.

Drive/Dropbox credentials may allow deletion. RepoSafe never requests deletion,
but application-level no-delete behavior and `--immutable` cannot prevent someone
holding those credentials from using the provider API directly. These are useful
extra copies; hardening adds provider-enforced retention and independent identities.

## GitHub-hosted bootstrap

In RepoSafe's Settings → Secrets and variables → Actions, configure:

| Type | Name | Value |
| --- | --- | --- |
| Secret | `GITHUB_BACKUP_TOKEN` | Read-only credential with all desired public/private repos; Metadata and Contents read |
| Secret | `RCLONE_CONFIG_B64` | Single-line base64 of the rclone configuration containing `gdrive` and `dropbox` |
| Variable | `AGE_RECIPIENT` | Public `age1...` recipient, never the private identity |
| Variable | `REPOSAFE_ENABLED` | `true` after a successful manual run and recovery test |

Use your OS's base64 tool or Python to encode the file, then paste it directly in
the secret field. Base64 is transport encoding, not encryption. Never print it in
CI logs. Run **Daily encrypted backup** manually from the Actions UI. Confirm both
destinations contain the same run, download one, and follow RECOVERY.md. Set
`REPOSAFE_ENABLED=true` to enable the scheduled job at **08:23 UTC daily**.

The schedule exists on main; it is intentionally inert until credentials are ready.
GitHub may delay/drop scheduled jobs, and disables schedules in inactive public
repos after 60 days. A monitor outside GitHub and the independent runner are needed
for unattended reliability. Enable Actions failure notifications in your account.
Do not use self-hosted GitHub runners carrying backup secrets for PR jobs.

Runtime configuration is created outside the checkout with restrictive permissions,
the checkout token is not persisted, and no backup payloads are uploaded to GitHub
artifacts. Output contains only aggregate counts. The runner's temporary files are
removed on ordinary completion; host encryption protects residual blocks.

## Independent host

Copy `reposafe.example.toml` to `reposafe.toml`, set the recipient and coverage
guards, and export `GITHUB_BACKUP_TOKEN` and `RCLONE_CONFIG` from a private service
environment. Run `python -m reposafe --config reposafe.toml run --output backups`.
Use a dedicated OS account and encrypted disk. See INDEPENDENT_RUNNER.md for the
implemented systemd units, locking, file collector, durable coverage state and
offline restore verifier.

Every destination is attempted independently, including after a required provider
fails. Success requires the capture and every required destination to succeed.
`deliver DIRECTORY` retries an existing encrypted snapshot without recapturing.
Routine jobs never delete old remote snapshots. Storage therefore grows until a
separate, deliberately authorized retention mechanism is configured.
