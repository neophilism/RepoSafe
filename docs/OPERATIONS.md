# Independent health checks and response

Run the monitor on a separate host/provider and administrator boundary from GitHub,
the collector, writers and witness. Give it pinned witness/offline public keys, a
read-only feed of signed events, its own durable state and an operator-configured
HTTPS alert endpoint. It needs no source, destination write or recovery credentials.

```sh
reposafe monitor --inbox /srv/reposafe-events \
  --witness-key /etc/reposafe/pins/witness --state-dir /var/lib/reposafe-monitor/state \
  --required-destination drive --required-destination dropbox \
  --required-destination aws --required-destination b2 --minimum-immutable 2 \
  --maximum-age-hours 30 --minimum-retention-hours 24 \
  --offline-report /srv/reposafe-offline/copy.json --offline-key /etc/reposafe/pins/offline \
  --maximum-offline-days 7 --notify
```

Pull the witness's `events/` tree read-only into the inbox; do not publish catalogs
or event contents to GitHub. `--notify` requires `REPOSAFE_ALERT_URL` in a private
monitor environment file. The endpoint receives aggregate JSON with health, sequence,
age and issue codes, without repository names, provider objects, credentials or keys.
It must accept HTTPS POST and return 2xx; redirects are refused. No alert is sent
by development. Configure the actual recipient/routing and test it during activation.

The monitor verifies signatures, complete capture status, required destinations,
immutable copy count, diversity across native provider kinds, retained-until evidence
and the signed sequence/hash chain. It advances its own high-water mark only through
contiguous accepted events. An old valid run, missing link, replaced sequence, forged
heartbeat, partial coverage or wrong signer cannot reset its deadline. Missing/invalid
state does not silently establish a new successful baseline. Preserve this state and
an independently recorded sequence/hash in the recovery kit; after rebuilding a
monitor, replay the chain from genesis or restore its trusted state checkpoint.

A successful signed witness records actual cloud read-back **at its timestamp**.
The monitor checks the observed retention horizon; it does not pretend to re-read
every object on every hourly check. Each new witness run re-inspects native bucket
policy and exact stored versions with separate read-only credentials. Real bucket
permission/retention drift drills remain part of cloud acceptance.

Offline proof is required by default. `--without-offline` is an explicit waiver,
useful only before physical media enrollment; it is not equivalent to a disconnected
copy. Signed copy evidence reports software read-back, not proof that a device was
subsequently unplugged or safely stored. Track physical custody separately.

Use the hourly `deploy/systemd/reposafe-monitor.*` examples with fixed reviewed code.
The alert receiver must also detect **missing hourly monitor requests**, since a
dead monitor cannot send its own failure. Independent external watchdog ownership,
account recovery and on-call response are deployment requirements. The JSON exit
status is nonzero for unhealthy evidence or failed alert delivery; timers should
continue retrying even after a failed service invocation.

## Required operational drills

1. Stop the collector timer or revoke a test source grant. Preserve the last valid
   event. Observe `backup_stale` and an external alert by the agreed 30-hour window.
2. Interrupt one required destination. Other writers retain their successful copies;
   a partial catalog set cannot become a new complete witness event.
3. Replace the newest pointer with an older signed event and omit a chain link.
   Confirm the independent high-water mark/freshness check fails.
4. Revoke only the witness read grant or shorten a **test** bucket's future default
   retention. Confirm witnessing fails without advancing complete-success evidence.
5. Expire offline proof and stop the monitor itself. Check both offline-age and the
   external receiver's missing-monitor alarms reach the designated owner.

Record actual alert delivery and acknowledgement privately. Unit fixtures demonstrate
code behavior; they do not establish that any owner receives production alerts.

## Incident response

Preserve old snapshots, catalogs, witness chain and monitor checkpoints. Freeze
suspected writers/collectors and automatic software rollout. Revoke only the exposed
runtime grants, leaving independent recovery/admin access intact. Choose a known-good
generation predating the suspected compromise; verify it against external public roots
and restore on a clean host. A compromised collector may poison future captures even
with valid signatures, so neither the latest timestamp nor a passing hash alone is
sufficient evidence of clean source data. Re-enroll credentials on fixed reviewed
code and complete another independent restore/alert drill before resuming normal use.

ACTIVATION.md and the feed units implement autonomous SFTP polling. Production
examples use a 28-hour stale threshold with hourly polling to reserve alert-delivery
margin within the 30-hour objective. A CLI maximum of 30 hours plus hourly polling
would allow roughly 31 hours before notification; measure and choose the threshold
with that latency included. Offline evidence can be a directory of signed generation
proofs; the monitor selects the freshest authenticated capture without trusting a
mutable latest pointer.
