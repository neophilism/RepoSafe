# Enrolled databases, objects and documents

Datasets are opt-in. They participate in the same complete/partial decision as Git
repositories. Failed exports are removed from staging; the encrypted manifest names
the failure and successful exports survive. Everything is encrypted before delivery.
There are no arbitrary shell export hooks or database connection strings in arguments.
Private runtime files, never this repository, hold connection details and credentials.

```toml
[[datasets]]
name = "appdb"
kind = "sqlite"
path = "/srv/app/database.sqlite"
owner = "operator"
rpo_hours = 24
rto_hours = 4
maximum_bytes = 21474836480
timeout_seconds = 3600

[[datasets]]
name = "postgres"
kind = "postgres"
service = "backup"
credential_prefix = "REPOSAFE_DATABASE"
include_roles = true

[[datasets]]
name = "documents"
kind = "remote"
remote = "source_drive:EnrolledDocuments"
credential_prefix = "REPOSAFE_DOCUMENTS"
export_formats = ["docx", "xlsx", "pptx", "svg"]
```

RPO/RTO fields are enrollment targets recorded with evidence, not achieved service
levels. A daily collector cannot achieve a one-hour RPO. Use an appropriately frequent
independent capture schedule and measured restore drills for stricter requirements.
Each dataset has a whole-export deadline and byte limit; the snapshot has its own
total budget. Use an encrypted, quota-limited work volume with adequate free space.

## SQLite

Uses SQLite's online backup API through a read-only source connection, including
committed WAL state. It does not copy the live `.sqlite`, `-wal` and `-shm` files
independently. It checks the resulting database with `integrity_check`, records SQLite
and user schema versions, and fails on links, missing databases, timeouts or budget
overflow. The SQLite account needs permission to read the database/WAL/SHM; consult
SQLite's WAL read-only requirements for the application's deployment.

Recover `snapshot/datasets/NAME/database.sqlite` from a verified offline restore into
a **new** application data directory. Keep the original service stopped while choosing
the production switch-over; test application semantics before replacing any data.

## PostgreSQL

Install matching `psql`, `pg_dump` and `pg_restore` tools on the collector. The dump
client must be at least the server major version. Use a dedicated read-only role
with SELECT/schema visibility over every enrolled schema, including large objects,
and appropriate RLS grants. A role that can only see a subset cannot prove coverage.
Reconcile the schema/table inventory with the database owner at enrollment.

Provide a mode-0600 service file via `REPOSAFE_DATABASE_SERVICE_FILE`; optionally
provide a separate mode-0600 `REPOSAFE_DATABASE_PASSFILE`. These paths must be absolute:

```ini
[backup]
host=database.example
port=5432
dbname=application
user=backup_reader
sslmode=verify-full
sslrootcert=/etc/reposafe/database-ca.pem
```

The adapter requires verified TLS for network hosts, or an explicitly enrolled Unix
socket. It rejects service credential-command helpers, removes ambient PG/source/cloud
credentials from child environments, disables prompts and adds read-only transaction
defaults. Service files are trusted operator configuration; grant read-only access at
the database itself as well. No passwords/URLs are printed on failure.

The custom-format dump uses a single serializable-deferrable snapshot. It streams to
private storage with bounded output, checks `pg_restore --list`, and records server,
client and installed extension versions. Optional `roles.json` preserves readable role
attributes for review; password hashes, role memberships, provider IAM and server-wide
configuration are **not** automatically recreated. Escrow secrets independently and
enroll provider/server configuration exports as additional regular files where needed.
The whole tool process group is killed on deadline/output-budget failure.

After an authenticated offline restore, prepare a new isolated PostgreSQL instance
with compatible extensions. Review required owners/grants from `roles.json` and the
archive catalog. Restore using `pg_restore --exit-on-error --single-transaction` into a
new empty database, with `--no-owner --no-acl` for a disposable drill. Run application
consistency checks before a separately reviewed production migration. RepoSafe never
connects to or overwrites a production target during an automated restore.

CI creates a fresh local PostgreSQL cluster, exports a real database, restores into a
new database, compares rows/primary-key constraints and checks extension/role evidence.
Local environments without PostgreSQL skip only that explicitly marked integration;
CI requires its tools and fails if it cannot run.

Logical daily dumps do not implement PITR. For an enrolled workload needing WAL/PITR,
retain provider-native base-backup/WAL exports and their dependency manifests using
an explicitly configured remote/file dataset, restore them with that provider's
documented tools, and qualify the chain independently. RepoSafe does not infer a valid
WAL chain from a directory of files or claim a one-hour RPO without that evidence.

## Remote object/document sources

Provide a distinct mode-0600 rclone config at
`REPOSAFE_DOCUMENTS_RCLONE_CONFIG`, with only the enrolled source's **read-only** grants.
The source collector must not receive destination writer OAuth tokens. A named remote
can read object stores, Drive exports, SFTP or other rclone-supported sources. Remote
types/scopes and SFTP host keys are reviewed operator configuration.

The adapter compares bounded before/after inventories, rejects duplicate/unsafe
names, copies only into new private staging, enforces transfer/size limits, and
performs a downloaded-byte check. It never syncs, deletes, runs source code or restores
to the source. Native cloud document export formats are explicit; conversion may
lose comments, revision history or provider-specific features. Duplicate names must
be resolved at enrollment rather than silently selecting one. Capture permissions
and export coverage are validated against the owner's independent inventory.

Current accessible object contents are backed up; remote version history, deleted
objects from before enrollment, provider ACLs and a cross-object transaction are not
implied. Source mutations cause a failed dataset rather than a false complete result.
Use provider snapshots/export manifests for stronger multi-object consistency.

References: [SQLite backup API](https://www.sqlite.org/backup.html),
[PostgreSQL pg_dump](https://www.postgresql.org/docs/current/app-pgdump.html),
[libpq service files](https://www.postgresql.org/docs/current/libpq-pgservice.html),
[rclone document exports](https://rclone.org/drive/#import-export-of-google-documents).
