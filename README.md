# Legacy.Maliev.DataMigration

This repository is the fail-closed execution boundary for the legacy SQL Server
to PostgreSQL data migration. It now contains two deliberately separated layers:

1. the approved signed backup/plan preflight; and
2. a guarded shadow-copy orchestration engine that can execute only through an
   injected read-only SQL Server source, PostgreSQL-only shadow target, and
   atomic migration-run journal.

The repository still contains no concrete database, cluster, cloud, process, or
secret adapter. Nothing in this slice can connect to production by itself.

## Safety boundary

- No SQL Server or PostgreSQL client package is referenced yet; concrete adapters
  remain a separately reviewed slice.
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
receipt without database I/O; conflicting or concurrent replays fail closed.

## Approved database disposition

The contract contains all 27 currently known historical names. Exactly 21 are
active migration inputs. `Hangfire` and `Log` are archive-only;
`MachineLearning` and `MachineLearningData` are excluded; `ContactRequest` and
`LocationData` remain review-hold. A receipt, schema plan, and execution
authorization must cover every active database exactly once and cannot include
an inactive, review-hold, or unknown database.

The disposition and ownership mapping was independently transcribed from the
committed source contract at source HEAD
`6de82fd9760e86c71ddba3085879a63b43faff9f`; the original repository was read-only.
Relevant committed references were:

- `tools/migration/postgres_parity.py`
- `tools/migration/restore_rehearsal.py`
- `Maliev.SqlServer/database-backup-safe.ps1`

No executable migration logic was copied from those files.

## Receipt and execution contracts

`PreflightService.Validate` accepts an in-memory `BackupReceipt` and
`MigrationPlan`. A valid receipt must:

- use receipt schema version `1.0`;
- be no older than the caller-supplied positive maximum age and not be future-dated;
- match the immutable database-disposition inventory SHA-256;
- contain exactly one full `.bak` artifact for each of the 21 active databases;
- provide positive byte counts and well-formed declared and independently
  observed SHA-256 values;
- have matching declared and observed artifact hashes; and
- have a manifest SHA-256 that recomputes from the canonical artifact list; and
- carry a valid signature from a configured trusted producer key.

A valid preflight plan must remain `plan-only`, disallow target writes, request
no external actions, cover all 21 target schema versions exactly, and use only
target schema version `1.0`.

A fresh schema plan uses schema version `2.0`, binds an exact 40-character source
commit, and supplies distinct source/target schema fingerprints plus deterministic
table, column, type, ordering, identity, nullability, and foreign-key contracts.
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
dotnet format .\Legacy.Maliev.DataMigration.slnx --verify-no-changes --no-restore
```

Tests are zero-I/O unit tests using stateful source/target/journal doubles. They
prove orchestration, transaction, cleanup, authorization, disposition, schema
drift, and replay behavior. Concrete adapters must add disposable SQL Server and
PostgreSQL integration tests; PostgreSQL tests must use Testcontainers rather
than SQLite or an in-memory provider.

## Downstream evidence compatibility

`Legacy.Maliev.AppHost/scripts/verify-postgres-migration-evidence.ps1` currently
requires `sourceSchemaSha256 == targetSchemaSha256`. That schema-v1 rule is not a
valid semantic check for heterogeneous SQL Server-to-PostgreSQL conversion and
must not be satisfied with a fabricated equal hash. This runner therefore does
not emit that legacy aggregate. A separately reviewed AppHost schema-v2 evidence
contract must compare each engine against its signed expected schema fingerprint
while continuing to require exact row/data/null/FK/sequence parity.

## Remaining release blockers

This slice does not implement or approve a backup producer, concrete database
adapters, or daily production synchronization. Before a real shadow copy is
allowed, the program still needs:

1. an independently reviewed producer that creates current verified full-backup
   receipts, observes hashes itself, protects its private signing key, and emits
   the exact 21-database disposition;
2. a freshly generated and independently reviewed 21-database schema plan bound
   to the current source commit;
3. a bounded source write freeze or a reviewed change-capture mechanism (the
   legacy source does not currently provide a proven complete daily delta);
4. reviewed SQL Server snapshot and PostgreSQL shadow adapters with disposable
   integration tests, bounded streaming, deletion parity, and crash recovery;
5. signed reconciliation/rollback receipts and the corrected AppHost schema-v2
   aggregate described above;
6. pre/post table, row, key, relationship, sequence, and business-invariant
   parity proofs;
7. a pinned, reviewable GitOps job and workload identity design; and
8. explicit authorization before any database, GKE, GCS, or secret mutation.

Canonical promotion, traffic cutover, application deployment, and production
database writes remain outside this slice and unauthorized.
