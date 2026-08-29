# Legacy.Maliev.DataMigration

This repository is the fail-closed planning boundary for the legacy SQL Server
to PostgreSQL data migration. The current slice is deliberately **plan-only**:
it validates backup receipts and target-schema plans but cannot connect to,
read from, or write to a database, cluster, cloud service, or secret store.

## Safety boundary

- No SQL Server or PostgreSQL client package is referenced.
- No Kubernetes, GKE, GCS, Google Secret Manager, or GitHub client is present.
- No command, process, network, deployment, restore, copy, or migration method
  is exposed by the production assembly.
- Target writes and requested external actions are rejected during preflight.
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

Do not add execution behavior to this repository until the separate production
runner design has an approved write-freeze/capture strategy, a reviewed schema
bridge, rollback semantics, idempotency, complete parity checks, and an explicit
deployment authorization.

## Approved database disposition

The contract contains 23 historical databases. Exactly 21 are active migration
inputs. `Log` is retained as archive-only evidence and `MachineLearningData` is
excluded because the retired prediction path is outside the migration. A receipt
must cover every active database exactly once and cannot include either inactive
database or an unknown database.

The disposition and ownership mapping was independently transcribed from the
committed source contract at source HEAD
`6de82fd9760e86c71ddba3085879a63b43faff9f`; the original repository was read-only.
Relevant committed references were:

- `tools/migration/postgres_parity.py`
- `tools/migration/restore_rehearsal.py`
- `Maliev.SqlServer/database-backup-safe.ps1`

No executable migration logic was copied from those files.

## Receipt contract

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

A valid plan must be `plan-only`, disallow target writes, request no external
actions, cover all 21 target schema versions exactly, and use only target schema
version `1.0`.

Validation returns all detected errors as stable codes. It does not throw for a
normal invalid contract and performs no external work.

## Validation

```powershell
dotnet build .\Legacy.Maliev.DataMigration.slnx --configuration Release
dotnet test .\Legacy.Maliev.DataMigration.slnx --configuration Release
dotnet format .\Legacy.Maliev.DataMigration.slnx --verify-no-changes --no-restore
```

Tests are zero-I/O unit tests. Database integration tests are intentionally not
applicable until a separately approved execution layer exists; when introduced,
they must use PostgreSQL Testcontainers rather than SQLite or an in-memory provider.

## Remaining release blockers

This slice does not implement or approve a backup producer and does not make
daily production synchronization safe. Before any data copy is allowed, the
program still needs:

1. an independently reviewed producer that creates current verified full-backup
   receipts, observes hashes itself, protects its private signing key, and emits
   the exact 21-database disposition;
2. an approved legacy-schema to current EF Core PostgreSQL schema mapping;
3. a bounded source write freeze or a reviewed change-capture mechanism (the
   legacy source does not currently provide a proven complete daily delta);
4. an idempotent all-or-nothing copy runner with deletion propagation and safe
   resume/rollback behavior;
5. pre/post table, row, key, relationship, and business-invariant parity proofs;
6. a pinned, reviewable GitOps job and workload identity design; and
7. explicit authorization before any database, GKE, GCS, or secret mutation.
