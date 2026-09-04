using System.Runtime.ExceptionServices;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

/// <summary>Per-invocation confirmed/reconciled commits, completed downloads and durable local verifications; uncertain acknowledgements do not count.</summary>
public sealed record IncrementalMigrationProgress(string? Database, int RemoteCommitted, int Downloaded, int LocalVerified);
/// <summary>The authenticated terminal receipt, published manifest and actual invocation progress.</summary>
public sealed record IncrementalMigrationResult(MigrationExecutionReceipt Receipt, LocalSnapshotManifest Manifest, IncrementalMigrationProgress Progress);

internal sealed record AdmittedCoordinatorRuntime(
    IReadOnlySqlServerMigrationSource Source, IPostgreSqlShadowTarget Target, IPostgreSqlShadowRecoveryTarget Recovery,
    IAdmittedMigrationRunJournal Journal, IPostgreSqlDumpSource Dump, ILocalDatabaseArchiveVerifier LocalVerifier,
    Func<CancellationToken, Task> Readiness,
    Func<CancellationToken, Task<RestoredSourceObservation>> ObserveSource,
    Func<CancellationToken, Task<FreshRunnerObservation>> ObserveRunner,
    Func<CancellationToken, Task<FreshTargetObservation>> ObserveTarget,
    Func<ShadowDatabase, CancellationToken, Task<CloudNativePgShadowSettlement>> ObserveSettlement,
    Func<ValueTask> DisposeAsync);

/// <summary>Single-use admitted sequential execution with preserve-first recovery and a held Windows lifetime authority.</summary>
public sealed partial class AdmittedSequentialMigrationCoordinator : IAsyncDisposable
{
    private readonly InitialMigrationAdmission _admission;
    private readonly RecoveryAuthorityVerificationOptions _verification;
    private readonly RecoveryAuthorityVerifier _authorityVerifier;
    private readonly DatabaseMigrationCheckpointVerifier _checkpoints;
    private readonly FreshSchemaPlan _plan;
    private readonly IMigrationEvidenceSigner _signer;
    private readonly AdmittedCoordinatorRuntime _runtime;
    private readonly string _snapshotId, _output;
    private readonly byte[] _key;
    private readonly Action<IncrementalMigrationProgress>? _progress;
    private int _started;

    internal AdmittedSequentialMigrationCoordinator(InitialMigrationAdmission admission, RecoveryAuthorityVerificationOptions verification,
        IMigrationEvidenceSigner signer, AdmittedCoordinatorRuntime runtime, string snapshotId, ReadOnlyMemory<byte> rootKey,
        string outputDirectory, Action<IncrementalMigrationProgress>? progress = null)
    {
        _admission = admission ?? throw new ArgumentNullException(nameof(admission));
        _verification = verification ?? throw new ArgumentNullException(nameof(verification));
        _authorityVerifier = new(verification);
        _authorityVerifier.ValidateAdmission(admission, DateTimeOffset.UtcNow);
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        Require(signer.KeyId == verification.Roles.ExecutionKeyId &&
            verification.TrustStore.Verify(signer.KeyId, [1], signer.Sign([1])), "execution_signer_invalid");
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _plan = OriginalMigrationDocumentReader.Read<FreshSchemaPlan>(admission.Payload.OriginalSchemaPlanJson);
        _checkpoints = new(new(admission.Payload.Identity, _plan, verification.TrustStore));
        Require(_plan.Databases.Select(item => item.Database).Order(StringComparer.Ordinal)
            .SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal), StringComparer.Ordinal), "coordinator_inventory_invalid");
        if (rootKey.Length != 32) { throw new ArgumentException("An external 256-bit root key is required.", nameof(rootKey)); }
        _snapshotId = snapshotId; _output = outputDirectory; _progress = progress;
        Require(Path.IsPathFullyQualified(_output), "local_output_path_invalid");
        string output = Path.TrimEndingDirectorySeparator(Path.GetFullPath(_output));
        string staging = Path.TrimEndingDirectorySeparator(Path.GetFullPath(admission.Payload.LocalBinding.ArtifactRootCanonicalPath));
        Require(Path.GetDirectoryName(output) is not null && !string.Equals(output, staging, StringComparison.OrdinalIgnoreCase) &&
            !output.StartsWith(staging + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase), "local_output_path_invalid");
        SecureSnapshotFileCreation.RejectLinkedAncestors(output);
        _key = rootKey.ToArray();
    }

    /// <summary>Transfers ownership of the already-held, exact admitted binding; it is disposed only after all awaited execution and cleanup.</summary>
    public Task<IncrementalMigrationResult> ExecuteInitialAsync(WindowsLocalRunAuthority authority, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        Start();
        return RunOwnedAsync(authority, null, null, null, cancellationToken);
    }

    /// <summary>Acquires only the exact existing Windows binding, then validates signed continuity and current journal authority.</summary>
    public Task<IncrementalMigrationResult> ResumeAsync(SourceContinuityAttestation continuity, ResumeAuthorizationReceipt authorization,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(continuity); ArgumentNullException.ThrowIfNull(authorization);
        Start();
        return RunOwnedAsync(AcquireExistingAuthority(), continuity, authorization, null, cancellationToken);
    }

    /// <summary>Finalizes completed local state without acquiring a remote lease. Prefer the separate local-only finalizer when no execution runtime is available.</summary>
    public Task<IncrementalMigrationResult> FinalizeCompletedAsync(RecoveryJournalSnapshot snapshot, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        Start();
        return RunOwnedAsync(AcquireExistingAuthority(), null, null, snapshot, cancellationToken);
    }

    private WindowsLocalRunAuthority AcquireExistingAuthority()
    {
        try { return WindowsLocalRunAuthority.AcquireResume(_admission.Payload.LocalBinding.ArtifactRootCanonicalPath, _admission.Payload.LocalBinding); }
        catch
        {
            // No authority or execution has started; leave unused dependencies disposable.
            Volatile.Write(ref _started, 0);
            throw;
        }
    }

    private async Task<IncrementalMigrationResult> RunOwnedAsync(WindowsLocalRunAuthority authority,
        SourceContinuityAttestation? continuity, ResumeAuthorizationReceipt? authorization, RecoveryJournalSnapshot? completedSnapshot,
        CancellationToken token)
    {
        Exception? primary = null;
        MigrationLeaseHeartbeat? heartbeat = null;
        IncrementalLocalSnapshotStore? store = null;
        MigrationExecutionReceipt? completed = null;
        MigrationRunLease? acquired = null;
        List<DatabaseMigrationCheckpoint> verified = [];
        IncrementalMigrationProgress progress = new(null, 0, 0, 0);
        try
        {
            Require(authority.Binding == _admission.Payload.LocalBinding, "local_authority_mismatch");
            _authorityVerifier.ValidateAdmission(_admission, DateTimeOffset.UtcNow);
            store = new(authority.Binding.ArtifactRootCanonicalPath, _snapshotId, _key, _checkpoints, _runtime.Dump, _runtime.LocalVerifier, GuardAsync);
            IReadOnlyList<DatabaseMigrationCheckpoint> local = await store.ReadVerifiedCheckpointsAsync(token).ConfigureAwait(false);
            RecoveryJournalSnapshot? snapshot = completedSnapshot;
            if (authorization is not null) { snapshot = await _runtime.Journal.ReadRecoverySnapshotAsync(_admission.Payload.Identity, token).ConfigureAwait(false); }
            if (snapshot is not null)
            {
                Require(snapshot.Admission.ExactJson == _admission.ExactJson, "recovery_admission_mismatch");
                ValidateLocalSubset(local, snapshot.Baseline);
                if (snapshot.Baseline.Status == "completed")
                {
                    completed = ValidateCompletion(snapshot);
                    verified.AddRange(ReadCheckpoints(snapshot.Baseline));
                    Require(local.Count == verified.Count, "completed_local_inventory_incomplete");
                    progress = new(null, verified.Count, 0, verified.Count);
                    await GuardAsync(token).ConfigureAwait(false);
                    LocalSnapshotManifest replay = await store.FinalizeAsync(_output, verified, token).ConfigureAwait(false);
                    _progress?.Invoke(progress);
                    return new(completed, replay, progress);
                }
                Require(completedSnapshot is null, "completed_snapshot_required");
            }
            else { Require(local.Count == 0, "initial_local_state_conflict"); }

            RestoredSourceObservation source = await ObserveSourceAsync(token).ConfigureAwait(false);
            FreshRunnerObservation runner = await _runtime.ObserveRunner(token).ConfigureAwait(false);
            FreshTargetObservation target = await _runtime.ObserveTarget(token).ConfigureAwait(false);
            ValidateRuntime(runner, target, authorization);
            if (authorization is null)
            { _authorityVerifier.ValidateInitialAcquisition(_admission, source, authority.Binding, DateTimeOffset.UtcNow); }
            else
            { _authorityVerifier.ValidateResume(_admission, continuity!, authorization, snapshot!.Baseline, source, authority.Binding, runner, target, DateTimeOffset.UtcNow); }
            // This deliberately mutating local credential probe is execution-only and precedes remote writes.
            await _runtime.Readiness(token).ConfigureAwait(false);
            authority.ValidateHeld();
            acquired = authorization is null
                ? await _runtime.Journal.AcquireInitialAsync(_admission, source, authority.Binding, token).ConfigureAwait(false)
                : await _runtime.Journal.AcquireResumeAsync(continuity!, authorization, source, authority.Binding, runner, target, token).ConfigureAwait(false);
            Require(acquired.Identity == _admission.Payload.Identity && acquired.FencingToken != Guid.Empty, "run_journal_invalid");
            heartbeat = new(_runtime.Journal, acquired, token); heartbeat.Start();
            CancellationToken executionToken = heartbeat.ExecutionToken;
            IReadOnlyList<ShadowDatabase> registered = await _runtime.Journal.GetPendingShadowsAsync(heartbeat.CurrentLease, executionToken).ConfigureAwait(false);
            IReadOnlyList<DatabaseMigrationCheckpoint> persisted = await _runtime.Journal.GetCheckpointsAsync(heartbeat.CurrentLease, executionToken).ConfigureAwait(false);
            ValidateRegisteredState(registered, persisted, snapshot?.Baseline);
            List<DatabaseMigrationCheckpoint> expectedCheckpoints = [.. persisted];

            foreach (DatabaseSchemaPlan plan in _plan.Databases.OrderBy(item => item.Database, StringComparer.Ordinal))
            {
                await GuardAsync(executionToken).ConfigureAwait(false);
                _ = await ObserveSourceAsync(executionToken).ConfigureAwait(false);
                DatabaseMigrationCheckpoint? checkpoint = persisted.SingleOrDefault(item => item.Database.Database == plan.Database);
                ShadowDatabase? shadow = registered.SingleOrDefault(item => item.Database == plan.Database);
                await _runtime.Source.BeginDatabaseSnapshotAsync(plan.Database, executionToken).ConfigureAwait(false);
                try
                {
                    SourceSchemaEvidence schema = await _runtime.Source.InspectSchemaAsync(plan.Database, executionToken).ConfigureAwait(false);
                    Require(schema.Database == plan.Database && schema.SchemaSha256 == plan.SourceSchemaSha256, "source_schema_drift");
                    Require(GuardedShadowMigrationRunner.SourceInventoryMatches(plan, schema.Tables), "source_inventory_drift");
                    if (shadow is null)
                    {
                        shadow = new(GuardedShadowMigrationRunner.CreateShadowName(plan.Database, acquired.Identity.RunId), acquired.Identity.RunId.ToString("D"), plan.Database)
                        { OwnerAttempt = heartbeat.CurrentLease.Attempt, FencingToken = heartbeat.CurrentLease.FencingToken };
                        await GuardAsync(executionToken).ConfigureAwait(false);
                        await _runtime.Journal.RegisterShadowAsync(heartbeat.CurrentLease, shadow, executionToken).ConfigureAwait(false);
                        ShadowDatabase created = await _runtime.Target.CreateUniqueEmptyShadowAsync(shadow, executionToken).ConfigureAwait(false);
                        Require(created == shadow, "shadow_ownership_invalid");
                    }
                    CloudNativePgShadowSettlement settlement = await _runtime.ObserveSettlement(shadow, executionToken).ConfigureAwait(false);
                    Require(settlement.OriginalShadow == shadow && settlement.AllowConnections, "shadow_unsettled");
                    DatabaseReconciliationEvidence? reconciled = await ReconcileAsync(shadow, plan, checkpoint, executionToken).ConfigureAwait(false);
                    if (reconciled is null)
                    {
                        Require(checkpoint is null, "checkpoint_target_empty");
                        await GuardAsync(executionToken).ConfigureAwait(false);
                        List<DatabaseReconciliationEvidence> evidence = [];
                        _ = await GuardedShadowMigrationRunner.CopyWholeDatabaseAsync(_runtime.Source, _runtime.Target, shadow, plan, evidence, executionToken, ReportCommitted).ConfigureAwait(false);
                        reconciled = evidence.Single();
                    }
                    else { ReportCommitted(); }
                    await _runtime.Source.CompleteDatabaseSnapshotAsync(plan.Database, executionToken).ConfigureAwait(false);
                    _ = await ObserveSourceAsync(executionToken).ConfigureAwait(false);
                    if (checkpoint is null)
                    {
                        await GuardAsync(executionToken).ConfigureAwait(false);
                        DateTimeOffset committedAt = await ReadSigningTimeAsync(heartbeat.CurrentLease, expectedCheckpoints, shadow, executionToken).ConfigureAwait(false);
                        checkpoint = SignCheckpoint(shadow, reconciled, committedAt);
                        await _runtime.Journal.RecordCheckpointAsync(heartbeat.CurrentLease, checkpoint, executionToken).ConfigureAwait(false);
                        expectedCheckpoints.Add(checkpoint);
                    }
                    await GuardAsync(executionToken).ConfigureAwait(false);
                    await store.DeliverWithProgressAsync(checkpoint, localVerified =>
                    {
                        progress = localVerified ? progress with { LocalVerified = progress.LocalVerified + 1 }
                            : progress with { Downloaded = progress.Downloaded + 1 };
                        _progress?.Invoke(progress);
                    }, executionToken).ConfigureAwait(false);
                    verified.Add(checkpoint);

                    void ReportCommitted()
                    {
                        progress = progress with { Database = plan.Database, RemoteCommitted = progress.RemoteCommitted + 1 };
                        _progress?.Invoke(progress);
                    }
                }
                catch (Exception failure)
                {
                    try { await _runtime.Source.RollbackDatabaseSnapshotAsync(plan.Database, CancellationToken.None).ConfigureAwait(false); }
                    catch (Exception secondary) { failure.Data["source_rollback_failure"] = secondary.GetType().Name; }
                    throw;
                }
            }
            IReadOnlyList<DatabaseMigrationCheckpoint> full = await _runtime.Journal.GetCheckpointsAsync(heartbeat.CurrentLease, executionToken).ConfigureAwait(false);
            Require(SameCheckpoints(full, verified) && SameCheckpoints(await store.ReadVerifiedCheckpointsAsync(executionToken).ConfigureAwait(false), full), "terminal_checkpoint_divergence");
            DateTimeOffset completedAt = await ReadSigningTimeAsync(heartbeat.CurrentLease, full, null, executionToken).ConfigureAwait(false);
            MigrationExecutionReceipt receipt = SignCompletion(full, completedAt);
            await heartbeat.StopAsync().ConfigureAwait(false);
            heartbeat.ThrowIfFailed();
            await GuardAsync(token).ConfigureAwait(false);
            await _runtime.Journal.RecordCompletedAsync(heartbeat.CurrentLease, receipt, token).ConfigureAwait(false);
            completed = receipt;
            await GuardAsync(token).ConfigureAwait(false);
            LocalSnapshotManifest manifest = await store.FinalizeAsync(_output, full, token).ConfigureAwait(false);
            return new(receipt, manifest, progress);
        }
        catch (Exception failure)
        {
            primary = failure;
            if (acquired is not null && completed is null)
            {
                try
                {
                    var unsigned = new MigrationFailureReceipt(acquired.Identity.RunId, acquired.Identity.SourceCommitSha, acquired.Identity.SchemaPlanSha256,
                        acquired.Identity.BackupManifestSha256, acquired.Identity.RunnerDigestSha256, acquired.Identity.TargetGeneration, DateTimeOffset.UtcNow,
                        failure is MigrationExecutionException migration ? migration.Code : failure is OperationCanceledException ? "operation_cancelled" : "incremental_execution_failed",
                        verified.Select(item => item.Reconciliation).ToArray(), [], _signer.KeyId, null);
                    var signed = unsigned with { AttestationSignature = Convert.ToBase64String(_signer.Sign(MigrationEvidenceAttestation.CreatePayload(unsigned))) };
                    await _runtime.Journal.RecordFailedAsync(heartbeat?.CurrentLease ?? acquired, signed, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception secondary) { failure.Data["journal_failure_reporting_failure"] = secondary.GetType().Name; }
            }
            throw;
        }
        finally
        {
            bool failing = primary is not null;
            if (heartbeat is not null) { await CleanupAsync(() => heartbeat.DisposeAsync(), "heartbeat_cleanup_failure").ConfigureAwait(false); }
            if (store is not null) { await CleanupAsync(() => { store.Dispose(); return ValueTask.CompletedTask; }, "store_cleanup_failure").ConfigureAwait(false); }
            await CleanupAsync(_runtime.DisposeAsync, "runtime_cleanup_failure").ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(_key);
            await CleanupAsync(() => { authority.Dispose(); return ValueTask.CompletedTask; }, "authority_cleanup_failure").ConfigureAwait(false);
            Volatile.Write(ref _started, 2);
            if (!failing && primary is not null) { ExceptionDispatchInfo.Capture(primary).Throw(); }
        }

        async Task GuardAsync(CancellationToken cancellation)
        {
            cancellation.ThrowIfCancellationRequested(); authority.ValidateHeld();
            if (completed is not null)
            {
                // Finalize holds the store operation lock and verifies the full local inventory itself.
                // Never recursively acquire that operation lock from its publication callback.
                Require(verified.Count == DatabaseInventory.ActiveDatabases.Count &&
                    completed.Databases.Count == verified.Count, "completed_local_inventory_incomplete");
            }
            else
            {
                Require(heartbeat is not null, "publication_lease_required");
                heartbeat!.ThrowIfFailed();
                _ = await _runtime.Journal.HeartbeatAsync(heartbeat.CurrentLease, cancellation).ConfigureAwait(false);
            }
            authority.ValidateHeld(); cancellation.ThrowIfCancellationRequested();
        }

        async ValueTask CleanupAsync(Func<ValueTask> cleanup, string code)
        {
            try { await cleanup().ConfigureAwait(false); }
            catch (Exception secondary)
            {
                if (primary is not null) { primary.Data[code] = secondary.GetType().Name; }
                else { primary = secondary; }
            }
        }
    }

    private static void Require(bool valid, string code)
    { if (!valid) { throw new MigrationExecutionException(code, "The admitted migration boundary did not match its required evidence; state was preserved."); } }

    private void Start()
    {
        Require(Interlocked.CompareExchange(ref _started, 1, 0) == 0, "coordinator_already_used");
    }

    /// <summary>Disposes unused dependencies; running execution owns its cleanup and must be awaited before disposal.</summary>
    public async ValueTask DisposeAsync()
    {
        int prior = Interlocked.CompareExchange(ref _started, 2, 0);
        Require(prior != 1, "coordinator_execution_active");
        if (prior == 0)
        {
            try { await _runtime.DisposeAsync().ConfigureAwait(false); }
            finally { CryptographicOperations.ZeroMemory(_key); }
        }
    }
}
