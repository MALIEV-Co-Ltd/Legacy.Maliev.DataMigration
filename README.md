# Legacy.Maliev.DataMigration

Local PostgreSQL review snapshots use the fail-closed `MLVSNP02` contract. The exporter stages each
dump in a newly created owner-only directory, records the exact migration run id and canonical exact-25
semantic manifest digest, derives separate AES-GCM and HMAC-SHA256 keys from the external 32-byte root
key with HKDF-SHA256, binds every archive to the run id, database name, and manifest digest as AEAD AAD,
then authenticates the complete manifest including ciphertext metadata. Version 1 is not accepted.
An interrupted export leaves only an owner-only, incomplete directory; reruns refuse to reuse it and
require explicit operator removal after inspection. Root key bytes are never written to the snapshot.

[![CI - Main](https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.DataMigration/actions/workflows/ci-main.yml/badge.svg)](https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.DataMigration/actions/workflows/ci-main.yml)

This repository is the fail-closed execution boundary for the legacy SQL Server
to PostgreSQL data migration. It now contains two deliberately separated layers:

1. the approved signed backup/plan preflight; and
2. a guarded shadow-copy orchestration engine that can execute only through an
   injected read-only SQL Server source, PostgreSQL-only shadow target, and
   atomic migration-run journal.

The repository contains concrete database adapters and a guarded executable host.
The host accepts only protected configuration-file references and external runtime
references. It has no promotion or canonical-target adapter, and nothing in this
repository discovers or projects production credentials.

## Safety boundary

- The SQL Server adapter forces `ApplicationIntent=ReadOnly`, uses a snapshot
  transaction per source database, and exposes only deterministic catalog
  inspection and `SELECT` operations.
- The PostgreSQL adapter can create, inspect, transact within, and delete only a
  uniquely named `legacy_shadow_*` database carrying the exact run-ownership
  marker. It exposes no rename, swap, promotion, or canonical mutation API.
- The runner, not either adapter, owns and exhausts source enumeration in
  batches capped at both 512 rows and 4 MiB of estimated materialized payload.
  SQL Server large-value columns are preflighted with signed `DATALENGTH`
  evidence and streamed sequentially without plaintext filesystem artifacts or
  auxiliary database staging. PostgreSQL binary `COPY` pulls each signed-length
  field through a bounded in-memory pipe without client-side whole-value
  materialization; the final PostgreSQL varlena/WAL representation is capped by
  the signed source maximum and a conservative 1,000,000,000-byte target limit.
  The pinned Npgsql 10.0.3 converter receives an exact length-known, single-pass
  stream; replay or seek attempts fail closed and are covered by integration tests.
  PostgreSQL acknowledges each binary `COPY` batch
  inside one whole-database transaction. Commit is refused until the
  independently re-read schema and every planned table have been inspected.
  The transaction creates base schemas, tables, keys, checks, and indexes first;
  copies every table second; reseeds identities third; and only then adds and
  validates foreign keys. This ordering preserves cyclic relationships without
  disabling integrity checks or relying on table order.
- The persistent PostgreSQL journal atomically acquires run IDs and retains
  immutable completed or signed failure evidence across process restarts.
- No Kubernetes, GKE, GCS, Google Secret Manager, or GitHub client is present.
- No command, process, network, deployment, restore, promotion, or canonical
  database mutation method is exposed by the production assembly.
- The preflight still rejects target writes and requested external actions.
- The preflight service never invokes its injected external-command sentinel;
  tests verify this for both valid and rejected inputs.
- Every accepted receipt requires a valid ECDSA P-256 producer attestation. The
  signature binds the canonical receipt schema, capture time, inventory and
  manifest hashes, trusted key identifier, and every database artifact name,
  filename, byte count, declared hash, and independently observed hash.
- Trusted producer public keys are injected outside the receipt. A receipt
  cannot add or select a caller-controlled public key.
- This repository contains no credentials, connection strings, endpoints,
  production backup metadata, or migrated customer data.

The shadow runner accepts only signed `shadow-only` authorization. It binds the
run ID, exact source commit, fresh schema-plan hash, backup manifest hash, runner
digest, target generation, and exact database scope. It has no promotion API.

Each database is read inside one source snapshot and written inside one
whole-database PostgreSQL transaction in a deterministic, run-owned, uniquely
named empty shadow database. Reconciliation must pass before commit. Any failure
rolls back the active database, removes every shadow created by the run, and
releases the atomic journal lease. Completed replays return the immutable prior
receipt only after its exact identity and trusted P-256 signature are verified,
without database I/O; conflicting or concurrent replays fail closed. Ordered
and modular multiset content digests are computed in bounded memory. Success and
failure paths retain signed reconciliation and shadow-cleanup evidence.

## Approved database disposition

The contract contains all 27 currently known historical names. Exactly 25 are
active migration inputs. `Hangfire` and `Log` are preserved as read-only
archival data under `Legacy.Maliev.CompatibilityContracts`; `ContactRequest`
and `LocationData` are active inputs owned by ContactService and CatalogService.
Only `MachineLearning` and `MachineLearningData` are excluded because those
features were deliberately retired. A receipt, schema plan, and execution
authorization must cover every active database exactly once and cannot include
an excluded or unknown database. The machine-readable
`database-disposition.json` is hash-bound through
`BackupReceipt.DatabaseInventorySha256`, which is covered by the producer
signature.

The disposition and ownership mapping was independently transcribed from the
committed source contract at source HEAD
`6de82fd9760e86c71ddba3085879a63b43faff9f`; the original repository was read-only.
Relevant committed references were:

- `tools/migration/postgres_parity.py`
- `tools/migration/restore_rehearsal.py`
- `Maliev.SqlServer/database-backup-safe.ps1`

No executable migration logic was copied from those files.

## Receipt and execution contracts

The .NET 10 executable host exposes only `backup-full`, `restore-backups`, `plan`,
`authorize-shadow`, `execute-shadow`, `export-local-snapshot`, `cleanup-restore`,
`sign-provenance`, and `evidence`. Command lines may carry a protected
configuration-file reference only; connection strings, passwords, tokens,
credentials, and private keys are rejected as command-line arguments so they
cannot leak through process listings or logs. The host requires owner-only,
no-link files for every configuration, trust, signing-key,
and signed-artifact read. Authorization and execution also resolve the reviewed
backup, authorization, execution, provenance, and final-evidence public keys and
reject any duplicate fingerprint before shadow provisioning can begin. The
`execute-shadow` command independently requires `LEGACY_DEPLOY_ENABLED=false`;
the wrapper is not the security boundary.
The receipt producer independently re-reads all 25 local backup files and binds
their approved GCS object names,
immutable generations, sizes, and SHA-256 metadata into the P-256 attestation.
Signing keys are externally supplied and are never stored in this repository.

`Exact25FullBackupProducer` is the fail-closed producer used by the daily backup
adapter. It requires the exact 27-database source disposition inventory to be
`ONLINE`, but creates full backups only for the 25 approved migrate databases;
the retired `MachineLearning` and `MachineLearningData` databases are observed
but never copied. The producer binds the expected Kubernetes namespace, pod,
pod UID, container, approved UTC run date, and run identifier. SQL Server itself
reports the inventory observation time and the completion time of every full
backup. The signed receipt uses the latest observed backup completion time; it
does **not** claim that the sequential database backups share one immutable
source cutoff. A bounded source write freeze or reviewed complete CDC mechanism
remains a mandatory release gate before final synchronization. The adapter
creates a unique owner-only remote run directory and uniquely named full backups
with `COPY_ONLY` and `CHECKSUM`, performs `RESTORE VERIFYONLY`, compares the
remote SHA-256 to the owner-only retained local copy, then uploads with
create-only semantics. The exact immutable GCS generation, size, URI, and
SHA-256 metadata are read back before the canonical receipt is signed.
Ambiguous backup or upload operations are never retried; only an allowlist of
explicit copy transport failures has a bounded three-attempt maximum. Recovery
backups are retained on every failure.

Backup receipt schema `1.1` signs the authoritative SQL Server inventory
observation time and every artifact completion time in addition to the existing
inventory, local hash, immutable GCS generation, size, and hash evidence.

SQL credentials cross the `kubectl exec` child-process boundary only through
standard input. The invocation diagnostic redacts standard input, and neither
credentials nor SQL text appear in process arguments. The signed receipt is
written into an owner-only staging directory and becomes visible through one
new-directory atomic rename; an existing destination is never overwritten.
`KubernetesSqlServerFullBackupProcess` uses structured process arguments and
standard input, validates the observed pod JSON and full database inventory,
and copies through a unique temporary file before an atomic local rename.
`GoogleCloudImmutableBackupObjectStorage` uses Application Default Credentials,
so GKE Workload Identity or an authorized local ADC identity supplies access
without a key file. It sets `ifGenerationMatch=0`, records the local SHA-256 as
object metadata, and reads that exact generation back. Both adapters remain
injectable for deterministic no-network contract tests. Differential backups
and backup artifacts for either retired ML database are rejected.

`backup-full --config <protected-json-path>` is the guarded executable
composition path. The protected JSON must set `fullBackup.allowSourceBackup`
to `true`; `LEGACY_DEPLOY_ENABLED` must remain exactly `false`. SQL username and
password are read only from `LEGACY_MIGRATION_BACKUP_SQL_USERNAME` and
`LEGACY_MIGRATION_BACKUP_SQL_PASSWORD`, while the P-256 private-key path is read
only from `LEGACY_MIGRATION_RECEIPT_SIGNING_KEY_FILE`. No secret value is
accepted on the command line or written to standard output, standard error, or
the receipt. The default runtime composes the structured Kubernetes/sqlcmd
adapter, the Application Default Credentials GCS adapter, and atomic receipt
publisher. Contract tests replace that runtime before any process or network
operation, so repository validation never performs a live backup.

`restore-backups` re-verifies the producer signature and exact 25-item inventory,
derives every local recovery path from the signed filenames, securely reopens and
re-hashes each owner-only artifact, and retains the verified file handle while a pinned
helper image streams those exact bytes into a create-only object in a run-owned Docker
named volume. The helper verifies both byte length and SHA-256, changes ownership to the
SQL Server runtime UID, and exits before restore. The disposable SQL Server's exact
container name and image ID are verified and it must mount that separate volume read-only;
the original host recovery path is never mounted into SQL Server. The target runs scalable
`RESTORE VERIFYONLY ... WITH CHECKSUM` without the 2 GiB `SINGLE_BLOB` ceiling. Restore
and catalog commands disable the client-side 30-second command timeout and remain bounded
by the caller cancellation token. No unsigned intermediate restore manifest exists.
The guarded command itself provisions the create-only named volume and disposable SQL
Server 2022 container from a digest-pinned image. It rejects pre-existing run names,
publishes only to an explicit loopback port, binds a protected run label, and passes the
SA password through the child environment rather than command-line arguments. Partial
provisioning and partial database restores are cleaned up fail-closed.
The standalone receipt-signing command has been removed; callers cannot sign
hand-authored state. `scripts/restore-verified-sqlserver-backups.ps1` delegates only
to that guarded .NET command, which restores the exact signed inventory into a
disposable SQL Server 2022 instance. It runs `RESTORE
VERIFYONLY`, discovers every logical file with `RESTORE FILELISTONLY`, supplies
an explicit `WITH MOVE`, refuses existing targets, and makes every restored
source database snapshot-isolation capable, verifies that state, and then makes
it read-only. The former all-in-one orchestration script was removed because it
could regenerate a plan and cross the owner-review boundary in one invocation.
The replacements are deliberately separate: `prepare-shadow-migration.ps1`
stops after backup, restore, and plan; `execute-approved-shadow-migration.ps1`
requires the exact reviewed plan digest and explicit allow flag before signing
and executing; and `finalize-shadow-migration.ps1` exports the snapshot, removes
the disposable restore, signs provenance, and only then produces evidence. Every
phase requires `LEGACY_DEPLOY_ENABLED=false`. See
[`docs/shadow-migration-runbook.md`](docs/shadow-migration-runbook.md).

The `plan` command opens a SQL Server snapshot for each approved database and
generates a new deterministic plan directly from the restored source catalogs.
It binds exact column metadata and observed LOB maxima, primary/composite keys,
nullable unique constraints, indexes and includes, identities, foreign keys,
checks, defaults, generated columns, and lossless type mappings. Unsupported
types, untrusted constraints, or tables without a proven total ordering fail
closed; a checked-in or hand-maintained schema plan is not accepted as fresh.

`execute-shadow` reads the signed receipt, freshly generated plan, and separate
signed execution authorization from protected file references. SQL Server and
PostgreSQL connection strings plus the execution-signing private-key path are
accepted only through environment references. The target-administration
connection is supplied through `LEGACY_MIGRATION_POSTGRES_ADMIN_CONNECTION`.
That connection is the unprivileged shadow runtime role; it must be `NOCREATEDB`.
Database lifecycle is requested through the CloudNativePG `Database` API using
the fixed in-cluster `https://kubernetes.default.svc` endpoint and fixed projected
service-account token and CA paths. Caller-supplied API endpoints, trust paths,
namespaces, clusters, runner paths, and runner digests are rejected. The client
validates the API server against the projected CA and rereads the short-lived
bound token for every request. Authorization and execution independently measure
the owner-only, non-link Release publication and observe exactly
`maliev-legacy/legacy-postgres-main` before any journal or shadow mutation.
The durable journal uses an independently supplied
`LEGACY_MIGRATION_POSTGRES_CONTROL_CONNECTION` whose database must be exactly
`legacy_migration_control`. The protected command configuration names the
expected control and shadow-administration roles. Startup verifies the observed
database, role identities, and privileges: the control role has only local
`CONNECT`/`CREATE`, while a distinct non-superuser shadow role has neither
`CREATEDB` nor object-creation access in its administrative database.
The preflight enumerates every database each role can connect to and recursively
checks inherited roles. The control role may reach only `legacy_migration_control`;
the shadow role may reach only its configured administrative database and
role-owned names matching `legacy_shadow_*`. Canonical, unexpected, non-owned,
and privileged inherited access fails closed. Newly created shadow databases
immediately revoke `CONNECT` from `PUBLIC` before any data operation.

PostgreSQL bootstrap must therefore revoke `PUBLIC` `CONNECT` from the configured
administrative database, `template1`, the migration-control database, and every
canonical database, then grant access explicitly to their dedicated roles. The
shadow role receives `CONNECT` only on its administrative database and remains `NOCREATEDB`;
the control role receives database-local `CONNECT` and `CREATE` only on
`legacy_migration_control`. CloudNativePG first reconciles each exact run-owned
`Database` resource with `allowConnections: false`; only after the runtime owner
has revoked `PUBLIC` CONNECT and bound the ownership receipt does the resource
move to `allowConnections: true`. The runtime re-observes the exact Kubernetes
generation/status/spec and PostgreSQL owner/ACL before use. Direct SQL database
creation by the migration credential is forbidden.

The GitOps lane must supply namespace-scoped RBAC and a validating-admission
policy that selects every mutation made by the dedicated migration service account
and every current or old object whose metadata uses `legacy-shadow-*` or whose
database name uses `legacy_shadow_*`. Validation allows only the exact
service-account plus run-owned shadow-name combination. Migration attempts against
canonical or malformed resources and non-migration attempts against shadow resources
are denied, while unrelated identities acting on canonical Database resources are
not selected. The allowed `postgresql.cnpg.io/v1 Database` resources remain bound
to the pinned cluster, owner, labels, and `legacy_shadow_*` name contract. Those
dormant manifests are deliberately not applied by this repository. This repository also does not apply PostgreSQL ACL
changes automatically. Replay, fencing, lease expiry, crash cleanup,
and wrong-target checks remain enforced by the guarded runner. The command writes
a new signed execution receipt and has no canonical-target or deployment mode.

`PreflightService.Validate` accepts an in-memory `BackupReceipt` and
`MigrationPlan`. A valid receipt must:

- use receipt schema version `1.1`, including the observed source time and each
  artifact's completion time plus exact immutable GCS object, generation, size,
  and SHA-256 evidence;
- be no older than the caller-supplied positive maximum age and not be future-dated;
- match the immutable database-disposition inventory SHA-256;
- contain exactly one full `.bak` artifact for each of the 25 active databases;
- provide positive byte counts and well-formed declared and independently
  observed SHA-256 values;
- have matching declared and observed artifact hashes; and
- have a manifest SHA-256 that recomputes from the canonical artifact list; and
- carry a valid signature from a configured trusted producer key.

A valid preflight plan must remain `plan-only`, disallow target writes, request
no external actions, cover all 25 target schema versions exactly, and use only
target schema version `1.0`.

A fresh schema plan uses schema version `2.0`, binds an exact 40-character source
commit, and supplies distinct source/target schema fingerprints plus deterministic
table, column, type, ordering, identity, nullability, and foreign-key contracts.
The live snapshot must expose exactly the signed source table and ordered-column
inventory; omissions and additions fail closed even when a caller supplies a
matching-looking aggregate. SQL Server `datetime2(7)` and `datetimeoffset`
values must use the exact text representation so PostgreSQL does not discard a
100 ns digit or the original offset. Nullable SQL Server unique constraints and
indexes are emitted as PostgreSQL `NULLS NOT DISTINCT` objects and that semantic
is included in the target schema fingerprint.
This deliberately permits value-preserving SQL Server-to-PostgreSQL schema
conversion; it never pretends the two engines have byte-identical DDL.

The current remote source binding is
`7b4b2af697207d36a6e7b7784dddefa150193e97`. The reviewed source contract binds
the byte SHA-256 of the 2026-08-12 analytics lifecycle, 2026-08-23 qualified
quotation outcome, and 2026-08-30 analytics source-reconciliation scripts. It
also freezes the exact 19-column `dbo.GoogleAnalyticsOutbox` and seven-column
`dbo.QuotationOutcomeOutbox` inventories. Every run must still carry a newly
captured observed schema fingerprint matching its signed plan.

`QuotationOutcomeOutbox` adoption is a separately signed, deterministic,
lossless contract. It maps only the seven actual source fields into the
EF-created `QuotationAcceptedOutcome` table, preserves source identities,
nullable request/journey identifiers, `datetime2(7)` timestamps, and the next
identity value, and treats an exact replay as already applied. A conflicting
event key fails closed; the importer may not execute DDL or synthesize missing
accepted quotations. Consumer implementation remains owned by
Legacy.Maliev.QuotationService.

`GoogleAnalyticsOutbox` is retained only as
`legacy_compatibility.GoogleAnalyticsOutbox`: a SELECT-only compatibility
archive with no runtime worker and no direct Google Analytics credentials. The
adoption gate requires that the canonical target schema was created by EF,
compares its signed digest before DML, and rejects source/target digest drift,
extra archive privileges, importer DDL, worker configuration, or analytics
credentials.

Validation returns all detected errors as stable codes. It does not throw for a
normal invalid contract and performs no external work.

## Validation

```powershell
dotnet build .\Legacy.Maliev.DataMigration.slnx --configuration Release
dotnet test .\Legacy.Maliev.DataMigration.slnx --configuration Release
dotnet test .\Legacy.Maliev.DataMigration.slnx --configuration Release `
  --settings .\coverlet.runsettings --collect:"XPlat Code Coverage"
dotnet format .\Legacy.Maliev.DataMigration.slnx --verify-no-changes --no-restore
```

The unit tests use stateful source/target/journal doubles for orchestration. The
adapter suite also runs against a disposable PostgreSQL 18 Testcontainer to
prove shadow ownership, whole-database commit gating, binary copy, independent
schema/data reconciliation, atomic concurrent leases, persistent replay, and
failure retry. The concrete PostgreSQL journal and shadow target are also tested
together across an expired process lease: the restarted owner must discover and
delete the exact fenced run-owned shadow before the same immutable run can
replay. SQL Server command and connection behavior is covered by fail-closed
contract tests. A gated disposable SQL Server 2022 Testcontainer fixture
exercises snapshot/catalog/streaming behavior and proves that interrupted
adapter disposal rolls back the source snapshot before a fresh adapter restart
when
`MALIEV_RUN_SQLSERVER_INTEGRATION=1`; production SQL Server is never a test
fixture.

The gated current-source integration fixture executes the three pinned scripts
on disposable SQL Server 2022, derives the live catalog rather than using a
hand-written copy plan, inserts null-heavy and fully populated outbox rows, and
copies every discovered table, column, and row into disposable PostgreSQL 18.
It then reconciles schema, row/null inventories, and next-identity values before
commit. This fixture also protects mixed-case dynamic table names during
PostgreSQL identity reseeding and sequence inspection.

The fixture canonicalizes only line endings before checking its signed
canonical-text digest; the contract separately retains each source file's exact
byte digest. After exact-shadow reconciliation it creates the current
EF-owned `QuotationAcceptedOutcome` shape, performs DML-only adoption, verifies
all seven source facts including the seventh 100 ns tick, verifies the identity
sequence, and proves an unchanged replay inserts nothing. It also materializes
the analytics compatibility archive, inspects a real SELECT-only PostgreSQL
role, and verifies exact archive rows with no analytics worker or credential
role objects.

The three-table script fixture deliberately proves the current outbox/recent
quotation delta and its exact keys, indexes, and foreign-key columns. It is not
a substitute for the guarded runner's complete signed production database plan:
the full runner still derives every legacy table and column from the restored
snapshot and fails closed on any extra or missing schema object.

## Downstream evidence compatibility

The `evidence` command converts the signed execution result, signed backup
receipt, signed execution authorization, fresh plan, and separately signed
provenance receipt into the exact AppHost schema-version-2 contract. The
provenance receipt binds the backup URI and object generation, restore/evidence/
lease identities and lease times, run identity, plan, backup manifest, runner,
and target generation through an independently trusted key; unsigned console
configuration must match it exactly. Backup, authorization, execution,
provenance, and final evidence signing roles must also expose five distinct
canonical P-256 SPKI fingerprints, so different key identifiers cannot disguise
reused key material. It preserves
the independently observed SQL Server and PostgreSQL schema fingerprints; it
never fabricates an equal cross-engine schema hash. The signed result now retains
observed foreign-key relationship counts and source/target sequence-next-value
parity in addition to table rows, ordered content, null counts, aggregate hashes,
and zero-orphan evidence. The schema-v2 document emits a single whole-table
content batch backed by that signed table hash, the exact 25 migrated databases,
the two excluded databases, deterministic nested mapping inventories, and a
separate review baseline. The baseline is not self-approving: its byte SHA-256
must still be recorded independently and supplied to the AppHost verifier.

The final document is signed with an externally supplied ECDSA P-256 key using
the AppHost canonical JSON rules. Missing upstream signatures, relationship or
sequence observations, inventory members, binding hashes, signed provenance, or
one-hour evidence/lease timing fail closed. The console writes both outputs with
create-new semantics and removes the evidence document if baseline creation
fails. Evidence and baseline are first written into an owner-only staging
directory and published together by one atomic directory rename; a failed stage
leaves neither artifact available. No connection string, private key, raw row,
or filesystem path is emitted.

## Remaining release blockers

This slice does not approve a production run or daily production
synchronization. Before a real shadow copy is allowed, the program still needs:

1. owner-reviewed runtime configuration that binds the daily adapter to the
   concrete Kubernetes/sqlcmd and Workload Identity GCS adapters plus protected
   external signing-key injection;
2. a freshly generated and independently reviewed 25-database schema plan bound
   to the current source commit;
3. a bounded source write freeze or a reviewed change-capture mechanism (the
   legacy source does not currently provide a proven complete daily delta);
4. independent owner approval of the generated schema-v2 baseline hash and
   one-time AppHost verification receipt;
5. pre/post table, row, key, relationship, sequence, and business-invariant
   parity proofs;
6. a pinned, reviewable GitOps job and workload identity design; and
7. explicit authorization before any database, GKE, GCS, or secret mutation.

Canonical promotion, traffic cutover, application deployment, and production
database writes remain outside this slice and unauthorized.
