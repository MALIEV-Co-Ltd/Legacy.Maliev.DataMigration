# Legacy.Maliev.DataMigration

[![CI - Main](https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.DataMigration/actions/workflows/ci-main.yml/badge.svg)](https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.DataMigration/actions/workflows/ci-main.yml)

This repository is the fail-closed execution boundary for the legacy SQL Server
to PostgreSQL data migration. It now contains two deliberately separated layers:

1. the approved signed backup/plan preflight; and
2. a guarded shadow-copy orchestration engine that can execute only through an
   injected read-only SQL Server source, PostgreSQL-only shadow target, and
   atomic migration-run journal.

The repository now contains concrete database adapters, but no executable host,
cluster, cloud, process, secret, promotion, or canonical-target adapter. Runtime
composition requires connection strings supplied by a separately reviewed host;
nothing in this repository discovers or projects production credentials.

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

The .NET 10 executable host exposes only `receipt`, `plan`, `execute-shadow`,
`evidence`, and `export-local-snapshot`. Command lines may carry a protected
configuration-file reference only; connection strings, passwords, tokens,
credentials, and private keys are rejected as command-line arguments so they
cannot leak through process listings or logs. The receipt producer independently
re-reads all 25 local backup files and binds their approved GCS object names,
immutable generations, sizes, and SHA-256 metadata into the P-256 attestation.
Signing keys are externally supplied and are never stored in this repository.

`Exact25FullBackupProducer` is the fail-closed producer used by the daily backup
adapter. It accepts only the exact 25-database migrate inventory, requires every
source database to be `ONLINE`, binds the expected Kubernetes namespace, pod,
pod UID, container, and immutable UTC cutoff, and creates uniquely named full
backups only. It performs `RESTORE VERIFYONLY` before copying each artifact,
hashes the retained local copy, uploads with create-only semantics, and verifies
the immutable GCS generation, size, URI, and SHA-256 readback before producing
the canonical signed receipt. Ambiguous backup or upload operations are never
retried; only explicitly classified copy transport failures have a bounded
three-attempt maximum. Recovery backups are retained on every failure.

SQL credentials cross the `kubectl exec` child-process boundary only through
standard input. The invocation diagnostic redacts standard input, and neither
credentials nor SQL text appear in process arguments. The signed receipt is
written into an owner-only staging directory and becomes visible through one
new-directory atomic rename; an existing destination is never overwritten.
The process and immutable-object-storage adapters remain injectable so their
production implementations and workload identities can be reviewed separately.
Differential backups and the retired `MachineLearning` and
`MachineLearningData` databases are rejected by this contract.

`scripts/restore-verified-sqlserver-backups.ps1` restores only the exact signed
inventory into a disposable SQL Server 2022 instance. It runs `RESTORE
VERIFYONLY`, discovers every logical file with `RESTORE FILELISTONLY`, supplies
an explicit `WITH MOVE`, refuses existing targets, and makes every restored
source database read-only. `scripts/invoke-shadow-migration.ps1` then runs the
five gates in order and refuses to start unless `LEGACY_DEPLOY_ENABLED=false`.
Neither script contains deployment, GKE, GCS mutation, or Secret Manager logic.

The `plan` command opens a SQL Server snapshot for each approved database and
generates a new deterministic plan directly from the restored source catalogs.
It binds exact column metadata and observed LOB maxima, primary/composite keys,
nullable unique constraints, indexes and includes, identities, foreign keys,
checks, defaults, generated columns, and lossless type mappings. Unsupported
types, untrusted constraints, or tables without a proven total ordering fail
closed; a checked-in or hand-maintained schema plan is not accepted as fresh.

`execute-shadow` reads the signed receipt, freshly generated plan, and separate
signed execution authorization from protected file references. SQL Server and
PostgreSQL connection strings plus the evidence-signing private-key path are
accepted only through environment references. It uses the durable PostgreSQL
journal and uniquely named, run-owned `legacy_shadow_*` databases; replay,
fencing, lease expiry, crash cleanup, and wrong-target checks remain enforced by
the guarded runner. The command writes a new signed execution receipt and has no
canonical-target or deployment mode.

`PreflightService.Validate` accepts an in-memory `BackupReceipt` and
`MigrationPlan`. A valid receipt must:

- use receipt schema version `1.0`;
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

The current remote source binding is `25418c95b5ac79400029ce274541f0e51728da3e`.
The two commits after the previously recorded `6de82fd` schema baseline affect
Upload workload identity/storage authorization, not migration schema files.
Nevertheless, every run must still carry a newly captured observed schema
fingerprint matching its signed plan.

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

1. independently reviewed concrete Kubernetes/sqlcmd and immutable GCS adapters
   for the exact-25 producer, including workload identity and protected external
   signing-key injection;
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
