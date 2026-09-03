# Incremental migration with durable local database delivery

Status: owner-approved recovery design; adapter, admission/journal and coordinator slices reviewed. Protected console integration is implemented for review; exact-23 consumers and final acceptance remain separate gates. No live execution is authorized.

## Outcome and authorization

Process the 23 required databases sequentially, excluding Log. For each database,
copy into its run-owned PostgreSQL shadow, reconcile, commit, checkpoint, export an
encrypted copy onto the operator's local disk, and verify it before starting the
next database. Failure must not discard another database's completed work.

The owner approved a software repair, not another migration execution. This work
does not authorize a production run, renewed execution receipt, canonical writes,
deployment, publishing, or deletion of previously verified artifacts. Existing
approvals for the failed exact-24 execution must not be replayed for this new
inventory or runner. No background retry is permitted.

## Historical defects and current repair evidence

The failed run completed reconciliation for 15 databases and failed while
reconciling Order. Its journal records automatic deletion of all 16 shadows.
The original generic Order exception did not distinguish schema from table evidence.
Disposable reproduction established a deterministic default-expression fingerprint
mismatch: `Order.Name DEFAULT ('unnamed')` was observed as `'unnamed'::character varying`.
The reviewed Task 1 repair handles that representation and adds structured diagnostics.
This defect was sufficient to cause the historical failure; the deleted historical
target cannot be inspected, and this is not proof that all later real-data checks pass.

Before repair, `GuardedShadowMigrationRunner.ExecuteAsync` deleted all registered shadows after
failure and deleted pending shadows before retry. Evidence was held in memory until
terminal receipt publication. `CopyWholeDatabaseAsync` added evidence before its
commit succeeded. Reviewed repairs now retain evidence only after confirmed commit,
persist signed checkpoints and preserve remote shadows automatically. See the
[current operator console guide](../../incremental-operator-console.md).

`LocalSnapshotExporter.ExportAsync` requires the full inventory before any export,
refuses an existing output directory, and recursively deletes its output directory
on failure. Those semantics cannot deliver recoverable per-database local copies.

The failed run's deleted PostgreSQL data cannot be recovered by new checkpoints.
The existing backups and SQL restore may be reusable after required identity and
fresh authorization checks; the software must not claim they are current merely
because they exist.

## Chosen architecture

Use signed per-database checkpoints in the persistent control journal and
independently authenticated per-database local artifacts. A single coordinator
owns the run lease and advances one database at a time. Journal state and local
disk state are reconciled after interruption; neither alone implies completion.

Alternatives considered: preserving shadows without evidence does not establish
safe reuse; exporting only after all databases pass still loses local progress
when later databases fail. The chosen design addresses both failure boundaries.

### Per-database state machine

`pending -> copying -> reconciled/committed -> checkpointed -> local_verified`

- Copy and validation use the existing whole-database transaction. Never relax
  schema, row, content, aggregate, null, relationship, orphan, or sequence checks.
- A signed checkpoint is persisted only after PostgreSQL commit is confirmed.
  It binds immutable run identity, exact database plan, original shadow ownership
  attempt/fence, source/target reconciliation, and signing-key identity.
- After checkpoint publication, immediately export that database onto an
  owner-only local filesystem directory. A Docker-internal volume alone does not
  satisfy local delivery; the output must be on a verified host bind mount or be
  explicitly transferred and read back on the host.
- Authenticate/decrypt the full staged artifact, verify lengths and hashes, and
  perform disposable local PostgreSQL restore/reconciliation before publishing
  `local_verified`. Capture the actual dump-process exit status before success.
- Do not begin the next database until local verification is durable.
- Progress reports identify the database and phase and distinguish remote
  committed, downloaded, and locally verified counts. Counts cannot be inferred
  from Kubernetes resource existence.

### Checkpoint persistence and fencing

Add a dedicated checkpoint contract and journal storage separate from terminal
run receipts and pending-shadow cleanup. Checkpoint signatures use a domain-
separated canonical payload and configured trusted execution signing key.
The journal records checkpoints atomically under a live, owned lease and rejects
conflicting replacements. Run completion cannot precede all required checkpoints.

Resume acquires the run lease without deleting committed checkpoints. Original
shadow ownership attempt and fencing token remain bound to the checkpoint; a new
attempt may inspect a previous committed shadow but must not silently relabel it.
Read-only checkpoint inspection must validate ownership, owner role, ACLs, schema,
tables, content, relationships, and sequences. Journal operations still require
the newly acquired live lease. Stale workers must fail before publishing a
checkpoint, exporting, deleting, or declaring completion.

No automatic cross-run, cross-plan, cross-runner, or cross-backup adoption is
allowed. A missing, tampered, conflicting, or unowned checkpoint/artifact stops
that database and preserves other verified work. Unverified state never causes
fallback to a destructive full restart.

### Crash windows and failure handling

- Before confirmed commit: roll back only the current transaction. Cleanup may
  target only that attempt's exact uncheckpointed shadow, after ownership checks.
- Commit acknowledgement lost or process dies before checkpoint persistence:
  preserve the candidate. Recover only by independently re-reading source and
  target and producing complete matching evidence under the current lease.
- Checkpoint succeeds but export fails: preserve the committed shadow and retry
  that database's export; do not copy its source again.
- Local artifact publication succeeds but journal update fails: authenticate and
  reconcile the artifact with its signed checkpoint, then repair journal state;
  do not overwrite the artifact or download it again.
- Failure of database N preserves all completed checkpoints and local copies for
  databases 1 through N-1. Record a structured failure and stop. No retry loop.
- Unknown ownership or lease loss: stop without destructive recovery. Preserve
  diagnostic evidence and require controlled reconciliation.
- Finalization failure: preserve all verified local artifacts and retry only
  final assembly after its prerequisites are satisfied.

### Local artifact contract and final snapshot

Keep the final authenticated `MLVSNP02` format, external 32-byte root key, and
existing cryptographic primitives. Never persist plaintext database dumps or
place the root key inside artifact directories.

Per-database provisional encrypted artifacts are explicitly incomplete and not
accepted as final snapshots by AppHost. Bind each to the run ID, database,
checkpoint digest, and staging format version. Publish archive plus authenticated
metadata as a single atomic directory rename after flush/readback. Use create-new
files and owner-only permissions; reject links, path escapes, wrong keys, and
unexpected existing files. Recovery reuses only authenticated matching artifacts.

The final v2 semantic digest depends on every dump's plaintext hash and length.
Once all 23 local artifacts are verified, compute that digest and re-encrypt the
existing encrypted staging streams locally into their final AAD contexts, without
remote re-download or plaintext files. Publish the final manifest atomically only
after every final archive is authenticated and reconciled. Retain provisional
verified artifacts until final verification and explicit cleanup approval.

### Freshness and resume authorization

The existing fresh-run limits (26-hour backup receipt, six-hour schema plan,
one-hour execution authorization) remain enforced for fresh execution. They must
not be disabled globally to enable resume.

A resumed execution after those windows requires a separate, newly owner-approved
resume receipt, bound to the original validated immutable run and checkpoint set,
the verified restored-source identity, current runtime attestation, and a bounded
expiry. The resume path revalidates immutable source evidence and checkpoint
contents. It does not regenerate or mutate the old signed plan, silently accept
expired approval, or broaden database scope. A changed source, plan, inventory,
or executable blocks automatic resume and requires explicit recovery review.

### Log exclusion and consumers

Change Log to excluded in migration inventory and `database-disposition.json`.
Update every exact-inventory consumer in schema/backup validation, execution
evidence, exporter tests, and AppHost review/topology contracts. Remove AppHost's
Log snapshot migration resource. Keep the other 23 database names mandatory;
never replace exact-inventory validation with a count-only or subset check.

Historical signed exact-24 plans, evidence, and snapshots are immutable. The new
inventory produces a different digest and must not be described as compatible
with the failed run's approval. Aspire must not accept an incomplete 23-database
staging set or an old unencrypted v1 snapshot as a completed result.

## Order investigation and diagnostics

Retain stable top-level failure codes but add structured non-row diagnostics:
database, schema/table, check kind, and expected/observed count or digest where
applicable. Distinguish schema, row count, ordered content, aggregates, nulls,
foreign-key relationships/orphans, and sequence failures. Never emit row values,
LOB content, credentials, or connection strings. Preserve nested exceptions even
if rollback, journal recording, or cleanup also fails.

Reproduce Order with disposable SQL Server/PostgreSQL fixtures and the relevant
signed plan semantics. Start with a schema-only probe and then focused table
fixtures. A live restored-data probe is read-only at source and must not launch a
full migration or write the cluster. The root-cause fix must have a failing test
demonstrating the mismatch before implementation; no speculative relaxation of
reconciliation is allowed.

## Validation and commit boundaries

1. Diagnostic accuracy and Order regression: tests distinguish every check and
   preserve primary failures; reproduce and repair the actual defect separately.
2. Signed checkpoint/journal/runner recovery: use real PostgreSQL Testcontainers
   to kill/restart at each crash window, verify durable records, reject tampering,
   and prevent stale-lease publication. A later failure must not delete earlier
   committed databases. Confirm evidence is never checkpointed before commit.
3. Incremental local export: fail database N's dump, transport, authentication,
   restore, and metadata publication; prove prior artifacts survive and are not
   opened for writing or downloaded again. Fail finalization and resume using
   local files only. Validate invalid key, truncated archive, changed checkpoint,
   path/link attacks, and nonzero pg_dump exit status.
4. Exact-23 consumer alignment: migration emits the same set AppHost accepts;
   Log, missing required databases, duplicates, and incomplete staging all fail
   the appropriate final-completion gate. Never fabricate final execution evidence.
5. Build affected solutions with zero warnings/errors, focused tests, full
   affected suites, formatting/static checks, and relevant coverage. Commit only
   coherent validated slices, not partially integrated recovery infrastructure.

No live rerun is ready until the Order cause is fixed, interruption/resume and
incremental local-delivery tests pass, and new scope/runtime approvals are obtained.
