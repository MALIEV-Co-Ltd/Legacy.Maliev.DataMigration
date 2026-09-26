# Daily read-only SQL Server comparison

The live read-only planner accepts Quotation source outboxes only with their
reviewed, signed dispositions: `QuotationOutcomeOutbox` must be adopted into
`QuotationAcceptedOutcome`, and `GoogleAnalyticsOutbox` must be preserved in the
read-only compatibility archive. Neither may be copied as an ordinary public
table to make a schema fingerprint pass.
The schema plan now signs explicit source-to-target bindings for these two
tables, including the reviewed source contract hash and target schema version.
Its expected PostgreSQL fingerprint uses the reviewed target shapes:
`legacy_compatibility.GoogleAnalyticsOutbox` retains the source fields,
while `public.QuotationAcceptedOutcome` uses the QuotationService EF outcome
schema, including the sub-microsecond timestamp remainder. It does not expect
either source-named outbox in `public`.
The analytics archive adds five checked `smallint` remainder columns for its
`datetime2(7)` values. The reviewed row mapper splits each source timestamp
into a PostgreSQL microsecond timestamp and its 0-9 sub-microsecond ticks;
nullable timestamps keep a null remainder. Disposable PostgreSQL tests prove
round-trip precision and reject out-of-range remainders. The live read-only
planner now hashes operations against mapped target rows and target table
names while reading the original SQL Server tables. Its schema-plan hash binds
the reviewed dispositions and target fingerprint. A table added without a
matching regenerated target fingerprint invalidates planning before row reads.
Live read-only schema-1.2 execution now projects the signed source plan onto
the reviewed target tables before metadata provisioning or target writes. It
reads the original SQL Server outboxes, verifies mapped row hashes against the
signed delta, applies archive/adoption operations in the existing atomic
per-database transaction, and binds both identity sequences and final
reconciliation to the target table names. The journal still makes exact-plan
replay a no-op; changed source rows, target rows, dispositions, or target
inventory fail closed. The ordinary shadow-copy path remains prohibited.
Captured-source schema-1.3 plan/replay code now applies the same reviewed
archive/adoption mapping to encrypted snapshot rows and target-shaped signed
operations. The operator console allows captured-source apply only for its
guarded disposable authority; persistent targets still fail closed pending the
full exact-23 disposable proof and operator review.
Component tests are not authorization for a live apply: fresh target-specific signed
plans, disposable proof, source/target schema parity, reviewed deletes, and
the owner approval gate still apply.

`scripts/invoke-daily-readonly-delta.ps1` is a backup-free row comparison path for
already populated exact-23 PostgreSQL targets. It reads every source and target
table in primary-key order, signs insert/update/reviewed-delete operations,
then uses the transactional executor, idempotency journal, and post-apply
reconciliation. It does not use SQL Server Change Tracking or CDC and does not
make daily SQL Server backups. Read volume is still a full table scan.
Persistent-local execution additionally requires a fresh, signed exact-23
reconciliation from an isolated disposable PostgreSQL target. The disposable
proof must use the same source observation, schema plan, runner digest, and
baseline provenance and identical per-table operation hashes/counts as the new
local plan. A changed source row or stale disposable target requires a fresh
proof. The proof uses a different PostgreSQL system
identifier and authority ID. A proof older than 12 hours is rejected. Proof
uses an `aspire://legacy-postgres-main-local/disposable-*` authority, while
the destination uses `aspire://legacy-postgres-main-local/persistent-*`.
does not authorize a production apply or permit an existing target to be
replaced.
For live-source runs, final reconciliation re-inspects each PostgreSQL table,
constraint, and sequence and matches its canonical digest to the atomic
checkpoint written during that database's apply. It does not require mutable
SQL Server rows or identity counters to remain unchanged after that checkpoint.
The evidence therefore attests to the 23 recorded per-database cutoffs, not a
single atomic cross-database snapshot or the source's state at the later
reconciliation time. Planning and apply still verify the live source identity
and snapshot/row fingerprints before writing.

The template's baseline `backupManifestSha256` remains provenance of the
original migrated dataset, not a fresh daily backup. Live plans use schema
`1.2`, bind a freshly observed SQL Server identity/inventory hash, and sign
the source capture start and completion times. Each database uses a separate
SQL Server snapshot transaction; there is no atomic cross-database cutoff.
Source or target drift from the signed plan fails closed.
The optional `useCapturedSource=true` mode is plan-only. It creates a fresh
owner-protected encrypted capture in the run directory and signs schema `1.3`
with per-database capture windows and selected changed-row bindings. Captured
rows are taken inside each database snapshot, so later source inserts cannot
silently change the planned row stream. The daily helper creates a new 32-byte
capture key and run-owned files; do not supply paths from an earlier run.
`-Execute` in captured mode is limited to a separately observed disposable
local Aspire target. It replays only the authenticated encrypted rows and
reconciles against signed snapshot evidence. Persistent local and production
captured execution remain rejected until a distinct disposable proof and
target-specific review are validated. A signed captured plan alone is not
data parity.
For the original schema `1.2` live-row path, databases with more signed row
operations run first; the signed
result is still published in the canonical exact-23 order. This narrows the
time between capture and apply for recently active databases, but it does not
make a changing source immutable. New rows arriving before a database's apply
may still invalidate the plan, requiring a new isolated proof and plan.
Schema `1.3` disposable execution instead replays its signed encrypted source
capture and reconciles each PostgreSQL transaction against the captured
database evidence. Later SQL Server inserts belong to a subsequent daily run.
Unattended local execution stops if the plan contains a deletion; deletion
sets require separate review. Production execution always requires separate
review, including plans containing only inserts or updates.

## Operator setup

1. Use clean synchronized protected `main` with green exact-head CI. Keep
   `LEGACY_DEPLOY_ENABLED=false`. Project only owner-protected connection/key
   file paths into an owner-only template JSON; never put credentials or
   connection strings in the template.
2. Keep the template and output root on a local owner-only Windows filesystem,
   outside the repository. Use the existing `DeltaCommandConfiguration` fields
   with `"sourceMode": "live-readonly-comparison"`, the original baseline
   backup-manifest hash and backup signer fingerprint, fresh target observation,
   and distinct trusted keys. Set `allowPlanSigning=true`; local automatic
   execution also needs `allowAuthorizationSigning=true` and
   `allowExecution=true`. For `-Execute`, set `disposableProofPlanPath` and
   `disposableProofResultPath` to owner-protected artifacts from a completed
   disposable exact-23 run. Supply its `disposableProofPlanKey` and
   `disposableProofEvidenceKey` public-key references as distinct, protected
   trust roots; do not reuse the persistent-local signing keys. The proof must
   finish before generating the persistent-local plan. Do not point either
   field at the persistent local target or an older daily run.
3. The operator host supplies the existing signing-key file environment
   variables through protected credential projection. The SQL Server login
   needs read-only access and complete metadata visibility; all 23 databases
   must be online with SNAPSHOT isolation enabled.
4. Use distinct templates, target observations, plans, and authorizations for
   local and production. The script refuses `-Execute` for production. Its
   production invocation produces a plan for separate review and signing.

```powershell
$env:LEGACY_DEPLOY_ENABLED = 'false'
$env:LEGACY_MIGRATION_CALLER = 'owner'
& .\scripts\invoke-daily-readonly-delta.ps1 `
  -TemplatePath '<owner-protected-local-template.json>' `
  -OutputRoot '<owner-only-local-output-root>' -Execute
```

Omit `-Execute` for plan-only. The script creates a unique owner-only run
directory, validates protected main and exact-head CI, builds in Release with
warnings as errors, and generates a signed live plan. For local execution it
verifies the signed disposable proof before authorization or any persistent
PostgreSQL write. A missing, stale, mismatched, or tampered proof stops the run.
It then signs a short-lived authorization immediately before apply and publishes new
owner-only plan, authorization, execution, and reconciliation artifacts. On
failure it stops without retrying or deleting artifacts. Never reuse a run
directory or an earlier authorization.

The daily automation may execute local sync only after the protected template,
source health, target identity, and credential projection are independently
reviewed. Production should plan daily and request owner review for the
separate execution action. No application deployment, traffic change,
database replacement, or SQL Server configuration change is included.

## Read-only target gap inspection

After generating the current source schema plan, use
`scripts/new-production-delta-template.ps1` from clean, exact-head-green
protected main to project a fresh production target connection and observation
into a new owner-only key directory. Its loopback tunnel must be either the
observed `maliev-legacy/legacy-postgres-main-rw` port-forward or the exact-main
identity-checked exec tunnel created with
`scripts/new-production-exec-tunnel-config.ps1` and admitted through
`-ExecTunnelConfigPath`. The latter is plan-only and cannot authorize or apply
production rows. Both paths verify cluster
health, archiving, primary identity, capacity, and all 23 canonical databases.
Supply the independently verified current source commit with
`-ExpectedSourceCommitSha`; a stale schema plan is rejected.
The generated template permits planning only; it cannot sign an execution
authorization or apply changes. Do not reuse its connection, observation, or
keys for another attempt.

When a production plan stops on a schema fingerprint mismatch, use a fresh
owner-protected production template with the same exact-23 source schema plan
and a fresh target observation, but set a new output path and run
`inspect-target-schema-gaps --config <protected-config-path>`. The command
verifies the PostgreSQL system identifier and canonical database inventory,
then reads table and column names in repeatable-read, read-only transactions.
It reports missing and target-only objects across all 23 databases without
altering either source or target. Target-only objects are reported, never
implicitly deleted or ignored.

This names-only output is a repair-review aid, **not** signed reconciliation,
an additive DDL authorization, or evidence that types, defaults, constraints,
indexes, sequences, and rows match. Build and run it only from clean,
exact-head-green protected main against production; validate any proposed
additive repair on an isolated copy before a separately reviewed target change.
