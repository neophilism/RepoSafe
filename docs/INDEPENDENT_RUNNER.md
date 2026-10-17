# Independent Linux runner

These systemd templates are deployable code. No host or active timer is created by
committing them. Use an authorized existing machine with encrypted storage, or
approve a host/storage budget before provisioning. The final control plane must
not depend on GitHub Actions or auto-update executable code from GitHub.

## Install a fixed reviewed release

1. Create a dedicated unprivileged `reposafe` user/group. Install Python 3.11+, Git,
   Git LFS, age and rclone from trusted sources; record exact versions.
2. Copy a reviewed release to `/opt/reposafe/current`, owned by root and not writable
   by the service user. Create `/opt/reposafe/venv` and install the local package
   with trusted build tooling. Preserve source/wheel/tools in the recovery kit.
3. Create `/etc/reposafe`, root:reposafe, 0750. Put the working `reposafe.toml`
   there as 0640, with public age recipients, owners/count guards, destinations and
   opted-in sources. Create `runtime.env` from the example as 0640 and supply the
   read-only GitHub token privately. Keep private age identities off this host.
4. Create `/var/lib/reposafe`, reposafe:reposafe, 0700, on encrypted storage. Store
   OAuth config there as `rclone.conf`, 0600, so rclone can save refreshed tokens.
   Create `work`, `backups` and `state` subdirectories, 0700. Set
   `[runner].work_dir = "/var/lib/reposafe/work"` in TOML.
5. Grant read access to explicit input roots, preferably under `/srv/backup-input`.
   The service uses `ProtectHome=true` and `PrivateTmp=true`; home directories and
   other processes' temporary files require reviewed unit overrides. Source roots
   cannot overlap scratch, state or output.
6. Copy the service/timer from `deploy/systemd` to `/etc/systemd/system`. Review
   paths, encrypted volume mounts, disk quotas and source permissions. Validate
   with `systemd-analyze verify`, then run `systemctl daemon-reload`.
7. Run `systemctl start reposafe.service`. Inspect private journal/state, check both
   destinations, and recover on a clean computer. Verify actual private-repository
   coverage against the owner's inventory; synthetic CI is insufficient.
8. Enable/start `reposafe.timer` and inspect `systemctl list-timers reposafe.timer`.
   It runs daily at 08:23 UTC with up to ten minutes' jitter and catches a missed run
   when activated. Observe the next real scheduled run.

The equivalent CLI inside its private runtime environment is:

```sh
python -m reposafe --config /etc/reposafe/reposafe.toml run \
  --state-dir /var/lib/reposafe/state --output /var/lib/reposafe/backups
```

## Operational boundaries

The service cannot modify code/config or gain privileges. It can write private
scratch, state, encrypted output and refresh-token config. It still holds both
mutable-provider tokens; distinct delivery trust zones are H8. Multiple processes
under one root-controlled host do not establish independent compromise domains.

Normal jobs never prune old local/remote outputs. Allocate quotas and monitor
capacity: full clones and temporary archives can be large. File sources have byte
caps; global Git-clone/archive quotas remain future work. Failure cannot advance
last-success or erase surviving remote generations. A run without its receipt is
incomplete. Persistent local coverage state is useful; an ephemeral Actions runner
must rely on required/count guards until independently reconciled.

File mutation checks are not a cross-file transaction. Use read-only filesystem
snapshots/native database exports; do not enroll live database directories. Native
database adapters and actual immutable-vault retention verification remain planned.

An independent external monitor must detect missed/stale/failed runs even if this
host disappears. H12 adds it; the timer template alone does not provide alerting.
After independent production acceptance, disable the bootstrap GitHub schedule to
avoid duplicate storage/transfers. Preserve offline keys, tools and trusted receipts.
