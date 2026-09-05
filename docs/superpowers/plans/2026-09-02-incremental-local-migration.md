# Incremental Local Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Finish and verify each required database locally before advancing, preserving completed work across interruption.

**Architecture:** Signed database checkpoints in the existing fenced PostgreSQL journal separate committed shadows from unfinished work. An incremental encrypted artifact store downloads and verifies each checkpoint immediately; only final assembly publishes a complete MLVSNP02 snapshot. Existing exact-inventory and authorization gates remain fail-closed.

**Tech Stack:** .NET 10, C#, Npgsql 10, SQL Server snapshots, PostgreSQL 18, xUnit, Testcontainers, existing AES-GCM/HMAC snapshot primitives.

**Spec:** `docs/superpowers/specs/2026-09-02-incremental-local-migration-design.md` (confirmed by owner in chat).

## Global Constraints

- Process the 23 required databases sequentially, excluding Log.
- Failure must not discard another database's completed work.
- The owner approved a software repair, not another migration execution.
- No background retry is permitted.
- Never persist plaintext database dumps or place the root key inside artifact directories.
- No automatic cross-run, cross-plan, cross-runner, or cross-backup adoption is allowed.
- Keep the other 23 database names mandatory; never replace exact-inventory validation with a count-only or subset check.
- Historical signed exact-24 plans, evidence, and snapshots are immutable.
- Build affected solutions with zero warnings/errors before focused tests, affected suites, and formatting checks. No push or live migration.

## Execution and ownership

Use isolated repair worktrees if the owner consents. Main checkouts initially have clean source trees. Documentation commit `462e3db` contains the confirmed design. Do not reuse another task's existing worktree or change its branch.

Implement tasks sequentially because tasks 1, 2, and 4 share runner/evidence interfaces and tasks 3 and 4 share exporter interfaces. Read-only Order investigation may run independently. Each task requires a spec/quality review before its dependent task begins.

## Task 1: Actionable reconciliation failures and Order reproduction

**Files:** `GuardedShadowMigrationRunner.cs`, new `ReconciliationDiagnostics.cs` in `src/Legacy.Maliev.DataMigration`; `GuardedShadowMigrationRunnerTests.cs`, focused PostgreSQL/SQL Server regression tests under `tests/Legacy.Maliev.DataMigration.Tests`.

**Interfaces:** Keep existing top-level exception codes. Add structured diagnostics to `MigrationExecutionException` without changing signed historical receipt payloads. A diagnostic contains database, optional qualified table, check kind, and expected/observed non-row evidence. Preserve primary errors when rollback also fails.

- [ ] Extend harness-driven tests to inject independent schema, row-count, ordered-content, aggregate, null-count, orphan, relationship, and sequence mismatches. Assert the reported location/check and no secret/row payload.

```csharp
Assert.Equal("shadow_reconciliation_failed", failure.Code);
Assert.Equal("Order", failure.Reconciliation?.Database);
Assert.Equal("schema", failure.Reconciliation?.Check);
```

- [ ] Build, then run `dotnet test Legacy.Maliev.DataMigration.slnx -c Release --no-build --filter FullyQualifiedName~GuardedShadowMigrationRunnerTests`; observe expected new failures before production edits.
- [ ] Implement explicit comparison reporting, keeping every existing rejection condition. Add reconciliation evidence only after confirmed transaction commit.
- [ ] Reproduce Order with the nonsecret signed plan in disposable PostgreSQL: test schema creation/introspection first, then narrowed conversion fixtures. Preserve the exact failing observation in a regression test. Do not claim the historical cause is established unless the reproduction supports it.
- [ ] Build, focused tests, full suite, formatting; record exact evidence and commit only the independently validated diagnostic/fix slice.

## Task 2: Signed durable database checkpoints

**Files:** new `DatabaseMigrationCheckpoint.cs`, `PostgreSqlMigrationRunJournal.cs`, `MigrationEvidence.cs`, journal interfaces in `GuardedShadowMigrationRunner.cs`; new checkpoint unit/integration tests and journal test doubles.

**Interfaces:**

```csharp
public sealed record DatabaseMigrationCheckpoint(
    MigrationRunIdentity Identity,
    ShadowDatabase Shadow,
    MigratedShadowDatabase Database,
    DatabaseReconciliationEvidence Reconciliation,
    DateTimeOffset CommittedAtUtc,
    string AttestationKeyId,
    string? AttestationSignature);
// IMigrationRunJournal additions:
Task RecordCheckpointAsync(MigrationRunLease lease,
    DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken);
Task<IReadOnlyList<DatabaseMigrationCheckpoint>> GetCheckpointsAsync(
    MigrationRunLease lease, CancellationToken cancellationToken);
```

- [ ] Write tests for canonical signature round-trip, changed ownership/identity/evidence, expired/stale leases, duplicate identical checkpoints, conflicting checkpoint replacement, and persistence across separate journal instances.
- [ ] Build and run `dotnet test Legacy.Maliev.DataMigration.slnx -c Release --no-build --filter "FullyQualifiedName~Checkpoint|FullyQualifiedName~MigrationRunJournal"`; verify expected failures.
- [ ] Add a domain-separated signature payload and verifier. Validate full immutable identity, database/schema plan, ownership, table/sequence evidence, and configured key trust before reuse.
- [ ] Add additive journal checkpoint storage. All writes hold the live run-row lock and verify exact lease owner/attempt/fence. Store canonical signed payload bytes without JSONB property-order corruption. Identical replay is idempotent; conflicting replay fails. Checkpoint deletion is not part of ordinary failure recording.
- [ ] Update interface doubles without adding permissive production fallback methods. Build, focused and full suites, format, review, commit.

## Task 3: Durable per-database encrypted local artifacts

**Files:** new `IncrementalLocalSnapshotStore.cs` and `LocalDatabaseArtifact.cs`, `LocalSnapshotExporter.cs`, existing encryption/security helpers only where reuse requires internal access; new `IncrementalLocalSnapshotStoreTests.cs` and real dump/restore integration tests.

**Interfaces:**

```csharp
public interface IDatabaseCheckpointDelivery
{
    Task DeliverAndVerifyAsync(DatabaseMigrationCheckpoint checkpoint,
        CancellationToken cancellationToken);
}
public interface ILocalDatabaseArchiveVerifier
{
    Task VerifyAsync(Stream authenticatedPlaintext,
        DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken);
}
```

`IncrementalLocalSnapshotStore` implements delivery and exposes finalization from the full signed checkpoint inventory. Constructor dependencies include protected local root, snapshot ID, external root key, trusted checkpoint verifier, dump source, and local archive verifier. No no-op verifier is used in the console.

- [ ] Write a two-database failure test: the second dump fails after the first is published; a retry must leave the first artifact bytes/metadata untouched and must not reopen its dump source.

```csharp
Assert.Equal(firstEncryptedHash, await HashFileAsync(firstArtifactPath));
Assert.Equal(1, dumpSource.OpenCount[firstDatabase]);
Assert.False(File.Exists(Path.Combine(outputRoot, "manifest.json")));
```

- [ ] Add failure cases for dispose/nonzero dump exit, torn metadata, wrong key, changed checkpoint, truncated ciphertext, links/path escapes, failed local restore, and finalization interruption. Observe red tests after build.
- [ ] Stream encrypt each dump with existing provisional encryption using a checkpoint-bound context. Wait for dump disposal/exit success, authenticate the whole archive and run the verifier before publication. Publish archive plus authenticated metadata with one atomic directory rename. Never recursively delete the shared staging root on failure.
- [ ] On replay, authenticate existing metadata and ciphertext and revalidate its checkpoint. Missing/invalid state fails without modifying unrelated verified artifacts. Flush and read back before success.
- [ ] Finalization requires the exact active set, computes semantic digest, and re-encrypts from local staged artifacts only. Publish complete final manifest atomically; retain verified staging on all failures. No remote dump source calls during final assembly.
- [ ] Build, focused tests, real pg_dump/pg_restore integration, full suite, formatting, review, commit.

## Task 4: Sequential runner recovery, delivery, and bounded resume authorization

**Files:** `GuardedShadowMigrationRunner.cs`, checkpoint recovery helpers, `PostgreSqlShadowTarget.cs`, `ExecutionAuthorization.cs` or separate resume receipt contract, `MigrationConsole.cs`, crash-recovery and console tests; operational documentation.

**Interfaces:** Consume task 2 journal/checkpoints and task 3 `IDatabaseCheckpointDelivery`. Runner requires delivery in the incremental console path. Add a read-only target checkpoint inspection API; it must not apply schema, copy rows, reseed sequences, or mutate original ownership markers.

- [ ] Write failing integration tests for later-database failure and restart, commit acknowledgement loss, checkpoint publication loss, local publication/journal disagreement, and expired lease takeover. Verify earlier databases are never recreated, recopied, or deleted.

```csharp
Assert.DoesNotContain(completedShadowName, target.Deleted);
Assert.Equal(1, source.CopyCount[completedDatabase]);
Assert.Equal(1, dumpSource.OpenCount[completedDatabase]);
Assert.True(delivery.VerifiedBeforeNextDatabaseStarted);
```

- [ ] Classify pending shadows before any cleanup: verified checkpoint, uncertain committed candidate, or definitely unfinished current transaction. Preserve checkpointed/uncertain state. Independently recover uncertain commits from full source/target reconciliation; do not infer committed state from nonempty tables.
- [ ] After confirmed database commit, sign and persist its checkpoint, then deliver/verify locally before starting the next database. After failure, retain earlier checkpoints and artifacts; perform only fenced cleanup of a definitely uncommitted current shadow. Record structured failure without obscuring primary diagnostics.
- [ ] Reuse signed checkpoints only after identity, signature, source restore evidence, live target ownership/ACL/schema/content/relationships/sequences, and local artifact checks. Refresh current lease before publication and destructive actions. Prevent stale workers from deleting checkpoints owned by later state.
- [ ] Add a separate fresh owner-approved resume receipt for an originally validated immutable run after freshness windows expire. Bind original identity/checkpoint set, restored-source observation, measured runner, target observation, issuer key, and bounded expiry. Keep fresh-run age validation unchanged. Reject changed runner/plan/source/scope instead of regenerating old approvals.
- [ ] Wire protected local delivery configuration, external key reference, dump executable, and disposable-local restore verifier into console. Preflight missing/unsafe delivery configuration before any cluster mutation. Expose per-database phase/count progress without secrets.
- [ ] Ensure terminal success contains the exact complete reconciliation inventory and local finalization remains separately authenticated. No partial receipt is accepted by existing final-evidence consumers.
- [ ] Build, focused runner/console/journal/crash tests, full suite, gated SQL Server plus dump/restore tests, formatting, review, commit.

## Task 5: Exclude Log across producer and AppHost

**Files:** DataMigration `DatabaseInventory.cs`, `database-disposition.json`, affected producer contract tests/docs; AppHost `LegacySnapshotReviewContract.cs`, `LegacyTopology.cs`, `AppHost.cs`, affected snapshot/evidence/topology tests/docs.

- [ ] Add producer/consumer behavioral tests requiring the same literal 23 names and excluding Log. Reject duplicate, missing, extra, unencrypted-v1, or incomplete staging input.
- [ ] Build both affected solutions and run focused tests to observe the new expected failures.
- [ ] Change only Log's disposition and remove its AppHost snapshot resource. Update active-inventory consumers and expected digests rather than accepting arbitrary subsets. Preserve historical artifacts and other excluded database dispositions.
- [ ] Build both solutions, run affected suites and formatting/static checks, verify producer/consumer exact sets, review each repo, commit coherent changes without pushing.

## Task 6: Final interruption demonstration and handoff

- [ ] Run the full repaired local-only test workflow, interrupt after one locally verified database, restart, and prove first database's dump was neither downloaded nor written again.
- [ ] Fail a later database reconciliation, retry only unfinished work under valid test authorization, and verify completed local artifacts survive.
- [ ] Rebuild both final solutions; run full applicable suites and gated integrations, formatting and diff checks; record actual pass/fail/skipped counts and coverage.
- [ ] Review complete branch diffs against every design requirement. Do not report migration complete or snapshot ready: live execution remains stopped pending fresh reviewed scope/runtime authorization.
- [ ] Report commits, verified behavior, exact remaining live prerequisites, and preserved original backup/restore identities. Do not merge, push, mint approval, or start a migration implicitly.
