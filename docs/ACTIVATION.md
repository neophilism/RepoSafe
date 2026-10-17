# Production activation: concrete inputs and acceptance

The repository implements the backup system. ChatGPT's Dropbox/Drive connections
are not runtime credentials and no such ChatGPT app is required. Source code, PRs,
unit fixtures and public-repository smoke tests do not mean your private accounts
are already backed up. The schedule stays unactivated until runtime setup succeeds.

## Bootstrap: daily Drive and Dropbox

Follow SETUP.md. On a trusted recovery computer, generate and securely retain the
age identity; provide **only its public recipient**. Authorize unattended rclone
remotes for Drive/Dropbox and provide a read-only GitHub runtime grant covering all
requested owners/private repositories. Put the runtime settings directly in the
runner's secret store, not chat, PRs or repository files.

Run the manual GitHub workflow, recover a synthetic and a private enrolled repository,
and inspect both providers. Then set `REPOSAFE_ENABLED=true` for 08:23 UTC daily.
This is the easy starting deployment. Its GitHub control plane and shared writer
credentials remain weaker than the isolated topology below.

## Hardened independent deployment

Start with `deploy/hardened.example.toml`, replacing every placeholder privately.
The 90/365-day lock periods are proposed configuration, not an approved expenditure.
Measure ciphertext volume, read-back traffic and restore bandwidth, approve a budget
and exact accounts/retention **before** creating paid or irreversible vaults. The AWS
template is reviewable source; nothing in these PRs applies it automatically.

| Role host | Daily/retry service | Inputs needed |
| --- | --- | --- |
| Collector | `reposafe-collector.timer` | All-repository read-only App/token, source datasets, offline public age recipients, collector Ed25519 key, expected inventory |
| One writer per destination | `reposafe-feed-writer.timer`, `reposafe-writer@NAME.timer` | Collector read-only SFTP feed/host-key pin, collector public root, own writer key and **only its own** provider grant |
| Independent witness | `reposafe-feed-witness@NAME.timer`, `reposafe-witness.timer` | Each writer's read-only catalog feed/public root, collector public root, read-only native vault grants, witness signing key |
| Independent monitor | `reposafe-feed-monitor.timer`, `reposafe-feed-offline.timer`, `reposafe-monitor.timer` | Witness/offline public roots and read-only feeds, independent durable high-water state, actual HTTPS alert receiver/recipient |
| Rotation/recovery computer | Manual weekly offline export and periodic recovery | At least two encrypted enrolled devices, reviewed recovery kit, separate age identity custody and offline signing key |

These are separate host/account failure domains, not several processes on a single
administrator-controlled host. Keep account recovery, billing and hardware MFA
independent. No normal host holds the age identity or retention-admin credentials.

Install the fixed reviewed release through RELEASE.md. Provision only on the chosen
authorized host(s); this development workspace is not the daily runner. Create private
service accounts/work/state directories, encrypted quota-limited work volumes and
role-specific mode-0600 environments. Adjust the sample work path for each role,
validate `systemd-analyze security`, OS quotas, disk capacity and exact network rules.
The sample services cap memory/tasks and kill the whole group on deadline. Monitor
capacity and archive completed local inboxes through separately reviewed maintenance;
the ordinary backup path never prunes remote history.

Apply host egress policy outside GitHub: collector → GitHub/enrolled source endpoints;
writer → its source SFTP host and own provider; witness → catalog SFTP hosts and
read-only vault endpoints; monitor → witness/offline feeds and alert receiver. Include
documented provider auth/CDN endpoints as needed. Do not blindly block an unmeasured
provider redirect or assume a hostname list alone establishes host isolation.

### Autonomous read-only feeds

Expose only the role's ciphertext spool, signed `catalogs/`, signed `events/`, or
offline proof outbox through a dedicated read-only SFTP principal/chroot. Disable
shell, forwarding and write access at the server; provide the necessary read-only
ACL/bind mount without exposing source plaintext or runtime secrets. Verify host
keys through an independent channel. `queue-pull` refuses non-SFTP remotes, unpinned
known-host files and configured remote shell hash helpers. It never deletes upstream.

Use `deploy/queue.conf.example` and `feed.env.example` for each feeder. The writer
feed pulls published captures into `/var/lib/reposafe-writer/inbox`. Each witness
feed instance pulls a different writer's catalog root into
`/var/lib/reposafe-witness/inbox/NAME` using `/etc/reposafe/feed-NAME.env`. Monitor
feeds pull events into `/var/lib/reposafe-monitor/inbox` and generation-named signed
copy proofs into `/var/lib/reposafe-monitor/offline-inbox`. The offline proof outbox
contains `RUN_ID/copy.json` and `copy.sig.json`, copied before media disconnection;
it need not expose the payload or any key. Consumers verify data independently;
an interrupted transfer/early receipt is retried and cannot publish complete success.

Enable feeds before consumers and run each manually first. Once all initial checks
pass, enable daily collection and 15-minute retry timers. The independent monitor
runs hourly with a 28-hour stale threshold in the example, leaving polling/notification
margin for the 30-hour alert objective. Measure actual scheduling and alert latency;
CLI thresholds are configurable. The receiver must alert on missing monitor requests
as well as unhealthy reports. Disable the GitHub bootstrap schedule once the isolated
deployment is authoritative to avoid duplicate cost and shared-token exposure.

### Role preflight and acceptance

```sh
reposafe --config /etc/reposafe/collector.toml doctor --role collector \
  --state-dir /var/lib/reposafe-collector/state --output-dir /var/lib/reposafe-collector/spool
reposafe --config /etc/reposafe/writer.toml doctor --role writer --destination aws \
  --collector-key /pins/collector --signing-key /private/writer.pem \
  --state-dir /var/lib/reposafe-writer/state --live
reposafe doctor --role monitor --witness-key /pins/witness \
  --state-dir /var/lib/reposafe-monitor/state
reposafe acceptance-template --output /private/acceptance/acceptance.json
```

`doctor` outputs aggregate issue codes and never claims production activation.
Without `--live`, it does not contact providers; live mode is explicit source/vault
**inspection**, not provisioning. It checks installed tools, public/private role
keys, dedicated grants, private state/output paths and selected source prerequisites.
It cannot prove IAM absence of privilege, physical media custody or full source
visibility without the enrollment/drill evidence. Reconcile grants and inventory
independently; real cloud tests must demonstrate writer delete/retention-shortening
denial and exact-version restore using approved test accounts.

The acceptance template begins with every item pending. Retain real private evidence
for the initial required deliveries, S3/B2 permissions/retention, clean restore,
failure/missing-monitor alerts, the next **real scheduled** run, disconnected media,
key/account custody and approved recurring cost. Hash-bind the exact witness event,
monitor report and evidence files; do not fill checks from test results alone.
After owner review, sign with an independently held owner key:

```sh
reposafe sign /private/acceptance/acceptance.json --key /private/owner.pem \
  --output /private/acceptance/acceptance.sig.json --purpose production-acceptance
reposafe acceptance-verify /private/acceptance/acceptance.json \
  --owner-key /independent/owner-public.pem --witness-key /independent/witness-public.pem
```

This verifies a signed historical **operator attestation** and hash-bound evidence;
it does not manufacture physical proof or replace ongoing monitoring. Store actual
acceptance/catalog/private inventory outside this public repository.

## Remaining real-world inputs

No runtime source/cloud OAuth grant, owner-held age public recipient, authorized
independent host, funded immutable account, alert endpoint/recipient or physical
media was provided during development. Those inputs and actual acceptance runs are
the remaining deployment work. No production cloud backup, paid resource, physical
disconnection or future scheduled execution is claimed from writing this repository.
