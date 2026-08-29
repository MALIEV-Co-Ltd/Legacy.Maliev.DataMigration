using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed record GuardedRunnerPolicy(string ExpectedSourceCommitSha, string ExpectedRunnerDigestSha256)
{
    public static TimeSpan MaximumBackupReceiptAge { get; } = TimeSpan.FromHours(26);

    public static TimeSpan MaximumSchemaPlanAge { get; } = TimeSpan.FromHours(6);

    public static TimeSpan MaximumAuthorizationLifetime { get; } = TimeSpan.FromHours(1);

    public const int CopyBatchSize = 512;

    public const long CopyBatchByteLimit = 4 * 1024 * 1024;
}

public sealed record GuardedMigrationRequest(
    BackupReceipt BackupReceipt,
    FreshSchemaPlan SchemaPlan,
    ExecutionAuthorizationReceipt Authorization);

public sealed record SourceTableInventory(
    string SourceSchema,
    string SourceTable,
    IReadOnlyList<string> OrderedColumns);

public sealed record SourceSchemaEvidence(
    string Database,
    string SchemaSha256,
    IReadOnlyList<SourceTableInventory> Tables);

public sealed record MigrationRow(IReadOnlyDictionary<string, object?> Values);

public sealed record ShadowDatabase(string Name, string OwnerRunId, string Database)
{
    public int OwnerAttempt { get; init; }

    public Guid FencingToken { get; init; }
}

public sealed record TableReconciliationEvidence(
    string Table,
    long RowCount,
    string ContentSha256,
    string AggregateSha256,
    IReadOnlyDictionary<string, long> NullCounts,
    IReadOnlyDictionary<string, long> ForeignKeyOrphanCounts);

public sealed record DatabaseReconciliationEvidence(
    string Database,
    string SourceSchemaSha256,
    string TargetSchemaSha256,
    IReadOnlyList<TableReconciliationEvidence> Tables);

public sealed record MigratedShadowDatabase(
    string Database,
    string ShadowName,
    long TotalRows,
    string ContentSha256);

public sealed record MigrationExecutionReceipt(
    Guid RunId,
    string SourceCommitSha,
    string SchemaPlanSha256,
    string BackupManifestSha256,
    string RunnerDigestSha256,
    string TargetGeneration,
    DateTimeOffset CompletedAtUtc,
    IReadOnlyList<MigratedShadowDatabase> Databases,
    IReadOnlyList<DatabaseReconciliationEvidence> Reconciliation,
    string AttestationKeyId,
    string? AttestationSignature);

public sealed record ShadowCleanupOutcome(string ShadowName, bool Deleted, string? ErrorCode)
{
    public int OwnerAttempt { get; init; }

    public Guid FencingToken { get; init; }
}

public sealed record MigrationFailureReceipt(
    Guid RunId,
    string SourceCommitSha,
    string SchemaPlanSha256,
    string BackupManifestSha256,
    string RunnerDigestSha256,
    string TargetGeneration,
    DateTimeOffset FailedAtUtc,
    string FailureCode,
    IReadOnlyList<DatabaseReconciliationEvidence> Reconciliation,
    IReadOnlyList<ShadowCleanupOutcome> Cleanup,
    string AttestationKeyId,
    string? AttestationSignature);

public enum MigrationExecutionStatus
{
    Completed,
    AlreadyCompleted,
}

public sealed record MigrationExecutionResult(
    MigrationExecutionStatus Status,
    MigrationExecutionReceipt Receipt);

public sealed record MigrationRunIdentity(
    Guid RunId,
    string SourceCommitSha,
    string SchemaPlanSha256,
    string BackupManifestSha256,
    string RunnerDigestSha256,
    string TargetGeneration)
{
    public static MigrationRunIdentity FromRequest(GuardedMigrationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new(
            request.Authorization.RunId,
            request.SchemaPlan.SourceCommitSha,
            SchemaPlanCanonicalizer.ComputeSha256(request.SchemaPlan),
            request.BackupReceipt.ManifestSha256!,
            request.Authorization.RunnerDigestSha256!,
            request.Authorization.TargetGeneration!);
    }

    public static MigrationRunIdentity FromReceipt(MigrationExecutionReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        return new(
            receipt.RunId,
            receipt.SourceCommitSha,
            receipt.SchemaPlanSha256,
            receipt.BackupManifestSha256,
            receipt.RunnerDigestSha256,
            receipt.TargetGeneration);
    }
}

public enum MigrationRunStartStatus
{
    Acquired,
    AlreadyCompleted,
    Conflict,
    InProgress,
}

public sealed record MigrationRunStartResult(
    MigrationRunStartStatus Status,
    MigrationExecutionReceipt? CompletedReceipt,
    MigrationRunLease? Lease = null,
    IReadOnlyList<ShadowDatabase>? PendingShadows = null);

public sealed record MigrationRunLease(
    MigrationRunIdentity Identity,
    string Owner,
    int Attempt,
    DateTimeOffset ExpiresAtUtc)
{
    public Guid FencingToken { get; init; }
}

public sealed class MigrationExecutionException(string code, string message, Exception? innerException = null) : Exception(message, innerException)
{
    public string Code { get; } = code;
}

public interface IReadOnlySqlServerMigrationSource
{
    Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);

    Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken cancellationToken);

    IAsyncEnumerable<MigrationRow> ReadTableAsync(
        string database,
        TableCopyPlan table,
        CancellationToken cancellationToken);

    Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(
        string database,
        TableCopyPlan table,
        CancellationToken cancellationToken);

    Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);

    Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);
}

public interface IPostgreSqlShadowTarget
{
    Task<ShadowDatabase> CreateUniqueEmptyShadowAsync(
        ShadowDatabase plannedShadow,
        CancellationToken cancellationToken);

    Task<bool> IsEmptyAsync(ShadowDatabase shadow, CancellationToken cancellationToken);

    Task<IPostgreSqlWholeDatabaseTransaction> BeginWholeDatabaseTransactionAsync(
        ShadowDatabase shadow,
        CancellationToken cancellationToken);

    Task DeleteRunOwnedShadowAsync(ShadowDatabase shadow, CancellationToken cancellationToken);
}

public interface IPostgreSqlWholeDatabaseTransaction : IAsyncDisposable
{
    Task ApplySchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken);

    Task<long> CopyBatchAsync(
        TableCopyPlan table,
        IReadOnlyList<MigrationRow> rows,
        CancellationToken cancellationToken);

    Task<string> InspectSchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken);

    Task<TableReconciliationEvidence> InspectTableAsync(
        TableCopyPlan table,
        CancellationToken cancellationToken);

    Task CommitAsync(CancellationToken cancellationToken);

    Task RollbackAsync(CancellationToken cancellationToken);
}

public interface IMigrationRunJournal
{
    Task<MigrationRunStartResult> TryBeginAsync(
        MigrationRunIdentity identity,
        CancellationToken cancellationToken);

    Task RecordCompletedAsync(MigrationExecutionReceipt receipt, CancellationToken cancellationToken);

    Task RecordCompletedAsync(
        MigrationRunLease lease,
        MigrationExecutionReceipt receipt,
        CancellationToken cancellationToken);

    Task RecordFailedAsync(MigrationFailureReceipt receipt, CancellationToken cancellationToken);

    Task RecordFailedAsync(
        MigrationRunLease lease,
        MigrationFailureReceipt receipt,
        CancellationToken cancellationToken);

    Task<MigrationRunLease> HeartbeatAsync(
        MigrationRunLease lease,
        CancellationToken cancellationToken);

    Task RegisterShadowAsync(
        MigrationRunLease lease,
        ShadowDatabase shadow,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ShadowDatabase>> GetPendingShadowsAsync(
        MigrationRunLease lease,
        CancellationToken cancellationToken);

    Task RecordShadowCleanupAsync(
        MigrationRunLease lease,
        ShadowCleanupOutcome outcome,
        CancellationToken cancellationToken);
}

public interface IMigrationEvidenceSigner
{
    string KeyId { get; }

    byte[] Sign(ReadOnlySpan<byte> payload);
}

internal sealed class MigrationLeaseHeartbeat : IAsyncDisposable
{
    private readonly IMigrationRunJournal _journal;
    private readonly CancellationTokenSource _heartbeatStop = new();
    private readonly CancellationTokenSource _executionStop;
    private readonly TimeSpan _interval;
    private readonly Lock _gate = new();
    private Task? _loop;

    internal MigrationLeaseHeartbeat(
        IMigrationRunJournal journal,
        MigrationRunLease lease,
        CancellationToken cancellationToken)
    {
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        CurrentLease = lease ?? throw new ArgumentNullException(nameof(lease));
        _executionStop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        TimeSpan remaining = lease.ExpiresAtUtc - DateTimeOffset.UtcNow;
        _interval = remaining <= TimeSpan.Zero
            ? TimeSpan.FromMilliseconds(100)
            : TimeSpan.FromMilliseconds(Math.Clamp(remaining.TotalMilliseconds / 3d, 100d, 60_000d));
    }

    internal CancellationToken ExecutionToken => _executionStop.Token;

    internal MigrationRunLease CurrentLease
    {
        get
        {
            lock (_gate)
            {
                return field;
            }
        }

        private set;
    }

    internal Exception? Failure
    {
        get
        {
            lock (_gate)
            {
                return field;
            }
        }

        private set;
    }

    internal void Start()
    {
        _loop ??= RunAsync();
    }

    internal async Task StopAsync()
    {
        await _heartbeatStop.CancelAsync().ConfigureAwait(false);
        if (_loop is not null)
        {
            await _loop.ConfigureAwait(false);
        }
    }

    internal void ThrowIfFailed()
    {
        if (Failure is { } failure)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _heartbeatStop.Dispose();
        _executionStop.Dispose();
    }

    private async Task RunAsync()
    {
        try
        {
            while (true)
            {
                await Task.Delay(_interval, _heartbeatStop.Token).ConfigureAwait(false);
                MigrationRunLease renewed = await _journal
                    .HeartbeatAsync(CurrentLease, _heartbeatStop.Token)
                    .ConfigureAwait(false);
                lock (_gate)
                {
                    CurrentLease = renewed;
                }
            }
        }
        catch (OperationCanceledException) when (_heartbeatStop.IsCancellationRequested)
        {
            // Normal shutdown after completion or before failure cleanup.
        }
        catch (Exception exception)
        {
            lock (_gate)
            {
                Failure = exception;
            }

            await _executionStop.CancelAsync().ConfigureAwait(false);
        }
    }
}

public sealed partial class GuardedShadowMigrationRunner
{
    private readonly PreflightService _backupPreflight;
    private readonly IReceiptAttestationTrustStore _authorizationTrustStore;
    private readonly IReadOnlySqlServerMigrationSource _source;
    private readonly IPostgreSqlShadowTarget _target;
    private readonly IMigrationRunJournal _journal;
    private readonly IMigrationEvidenceSigner _evidenceSigner;
    private readonly TimeProvider _timeProvider;
    private readonly GuardedRunnerPolicy _policy;

    public GuardedShadowMigrationRunner(
        PreflightService backupPreflight,
        IReceiptAttestationTrustStore authorizationTrustStore,
        IReadOnlySqlServerMigrationSource source,
        IPostgreSqlShadowTarget target,
        IMigrationRunJournal journal,
        IMigrationEvidenceSigner evidenceSigner,
        TimeProvider timeProvider,
        GuardedRunnerPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(backupPreflight);
        ArgumentNullException.ThrowIfNull(authorizationTrustStore);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(evidenceSigner);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(policy);
        if (!CommitSha().IsMatch(policy.ExpectedSourceCommitSha) || !Sha256().IsMatch(policy.ExpectedRunnerDigestSha256))
        {
            throw new ArgumentException("Runner policy must bind an exact source commit and runner digest.", nameof(policy));
        }

        _backupPreflight = backupPreflight;
        _authorizationTrustStore = authorizationTrustStore;
        _source = source;
        _target = target;
        _journal = journal;
        _evidenceSigner = evidenceSigner;
        _timeProvider = timeProvider;
        _policy = policy;
    }

    public async Task<MigrationExecutionResult> ExecuteAsync(
        GuardedMigrationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        DateTimeOffset nowUtc = _timeProvider.GetUtcNow();
        ValidateRequest(request, nowUtc);

        MigrationRunIdentity identity = MigrationRunIdentity.FromRequest(request);
        string schemaPlanHash = identity.SchemaPlanSha256;
        MigrationRunStartResult start = await _journal
            .TryBeginAsync(identity, cancellationToken)
            .ConfigureAwait(false);
        if (start.Status == MigrationRunStartStatus.AlreadyCompleted && start.CompletedReceipt is not null)
        {
            ValidateCompletedReplay(start.CompletedReceipt, identity);
            return new MigrationExecutionResult(MigrationExecutionStatus.AlreadyCompleted, start.CompletedReceipt);
        }

        if (start.Status == MigrationRunStartStatus.Conflict)
        {
            throw new MigrationExecutionException(
                "run_replay_mismatch",
                "The run identifier is already associated with different immutable inputs.");
        }

        if (start.Status == MigrationRunStartStatus.InProgress)
        {
            throw new MigrationExecutionException(
                "run_already_in_progress",
                "The same immutable migration run is already in progress.");
        }

        if (start.Status != MigrationRunStartStatus.Acquired)
        {
            throw new MigrationExecutionException("run_journal_invalid", "The migration journal returned an invalid lease state.");
        }

        MigrationRunLease lease = start.Lease is { } acquiredLease && acquiredLease.Identity == identity
            ? acquiredLease
            : throw new MigrationExecutionException("run_journal_invalid", "The migration journal did not return an owned lease.");

        await using var heartbeat = new MigrationLeaseHeartbeat(_journal, lease, cancellationToken);
        heartbeat.Start();
        CancellationToken executionToken = heartbeat.ExecutionToken;

        List<ShadowDatabase> createdShadows = [];
        List<MigratedShadowDatabase> migrated = [];
        List<DatabaseReconciliationEvidence> evidence = [];
        try
        {
            IReadOnlyList<ShadowDatabase> pendingShadows = start.PendingShadows ??
                await _journal.GetPendingShadowsAsync(lease, executionToken).ConfigureAwait(false);
            if (pendingShadows.Count > 0)
            {
                IReadOnlyList<ShadowCleanupOutcome> recoveredCleanup = await DeleteCreatedShadowsAsync(lease, pendingShadows)
                    .ConfigureAwait(false);
                if (recoveredCleanup.Any(outcome => !outcome.Deleted))
                {
                    throw new MigrationExecutionException(
                        "shadow_cleanup_failed",
                        "A stale run-owned shadow could not be removed before retry.");
                }
            }

            foreach (DatabaseSchemaPlan databasePlan in request.SchemaPlan.Databases
                .OrderBy(database => database.Database, StringComparer.Ordinal))
            {
                executionToken.ThrowIfCancellationRequested();
                lease = heartbeat.CurrentLease;
                await _source.BeginDatabaseSnapshotAsync(databasePlan.Database, executionToken).ConfigureAwait(false);
                try
                {
                    SourceSchemaEvidence observedSchema = await _source
                        .InspectSchemaAsync(databasePlan.Database, executionToken)
                        .ConfigureAwait(false);
                    if (!string.Equals(observedSchema.Database, databasePlan.Database, StringComparison.Ordinal) ||
                        !string.Equals(observedSchema.SchemaSha256, databasePlan.SourceSchemaSha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new MigrationExecutionException(
                            "source_schema_drift",
                            $"{databasePlan.Database} no longer matches the signed schema plan.");
                    }

                    if (!SourceInventoryMatches(databasePlan, observedSchema.Tables))
                    {
                        throw new MigrationExecutionException(
                            "source_inventory_drift",
                            $"{databasePlan.Database} table and column inventory no longer matches the signed schema plan.");
                    }

                    string shadowName = CreateShadowName(databasePlan.Database, request.Authorization.RunId);
                    var plannedShadow = new ShadowDatabase(
                        shadowName,
                        request.Authorization.RunId.ToString("D"),
                        databasePlan.Database)
                    {
                        OwnerAttempt = lease.Attempt,
                        FencingToken = lease.FencingToken,
                    };
                    await _journal.RegisterShadowAsync(lease, plannedShadow, executionToken).ConfigureAwait(false);
                    createdShadows.Add(plannedShadow);
                    ShadowDatabase shadow = await _target
                        .CreateUniqueEmptyShadowAsync(plannedShadow, executionToken)
                        .ConfigureAwait(false);
                    if (shadow != plannedShadow)
                    {
                        await _journal.RegisterShadowAsync(lease, shadow, executionToken).ConfigureAwait(false);
                        createdShadows.Add(shadow);
                    }

                    ValidateShadowLease(shadow, shadowName, databasePlan.Database, request.Authorization.RunId, lease);
                    if (!await _target.IsEmptyAsync(shadow, executionToken).ConfigureAwait(false))
                    {
                        throw new MigrationExecutionException(
                            "shadow_database_not_empty",
                            $"{shadow.Name} is not an empty run-owned shadow database.");
                    }

                    MigratedShadowDatabase result = await CopyWholeDatabaseAsync(
                        shadow,
                        databasePlan,
                        evidence,
                        executionToken).ConfigureAwait(false);
                    migrated.Add(result);
                    await _source.CompleteDatabaseSnapshotAsync(databasePlan.Database, executionToken)
                        .ConfigureAwait(false);
                }
                catch
                {
                    await _source.RollbackDatabaseSnapshotAsync(databasePlan.Database, CancellationToken.None)
                        .ConfigureAwait(false);
                    throw;
                }
            }

            var unsignedReceipt = new MigrationExecutionReceipt(
                request.Authorization.RunId,
                request.SchemaPlan.SourceCommitSha,
                schemaPlanHash,
                request.BackupReceipt.ManifestSha256!,
                _policy.ExpectedRunnerDigestSha256,
                request.Authorization.TargetGeneration!,
                _timeProvider.GetUtcNow(),
                new ReadOnlyCollection<MigratedShadowDatabase>(migrated),
                new ReadOnlyCollection<DatabaseReconciliationEvidence>(evidence),
                _evidenceSigner.KeyId,
                null);
            MigrationExecutionReceipt receipt = SignAndVerify(unsignedReceipt);
            await heartbeat.StopAsync().ConfigureAwait(false);
            lease = heartbeat.CurrentLease;
            heartbeat.ThrowIfFailed();
            await _journal.RecordCompletedAsync(lease, receipt, cancellationToken).ConfigureAwait(false);
            return new MigrationExecutionResult(MigrationExecutionStatus.Completed, receipt);
        }
        catch (Exception exception)
        {
            lease = heartbeat.CurrentLease;
            Exception actualException = heartbeat.Failure ?? exception;
            IReadOnlyList<ShadowCleanupOutcome> cleanup = await DeleteCreatedShadowsAsync(lease, createdShadows)
                .ConfigureAwait(false);
            await heartbeat.StopAsync().ConfigureAwait(false);
            lease = heartbeat.CurrentLease;
            actualException = heartbeat.Failure ?? actualException;
            string failureCode = actualException is MigrationExecutionException migrationException
                ? migrationException.Code
                : actualException is OperationCanceledException ? "operation_cancelled" : "shadow_execution_failed";
            var unsignedFailure = new MigrationFailureReceipt(
                identity.RunId,
                identity.SourceCommitSha,
                identity.SchemaPlanSha256,
                identity.BackupManifestSha256,
                identity.RunnerDigestSha256,
                identity.TargetGeneration,
                _timeProvider.GetUtcNow(),
                failureCode,
                new ReadOnlyCollection<DatabaseReconciliationEvidence>(evidence),
                cleanup,
                _evidenceSigner.KeyId,
                null);
            await _journal.RecordFailedAsync(lease, SignAndVerify(unsignedFailure), CancellationToken.None)
                .ConfigureAwait(false);

            if (cleanup.Any(outcome => !outcome.Deleted))
            {
                throw new MigrationExecutionException(
                    "shadow_cleanup_failed",
                    "One or more run-owned shadow databases could not be removed.",
                    actualException);
            }

            if (actualException is OperationCanceledException or MigrationExecutionException)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(actualException).Throw();
            }

            throw new MigrationExecutionException(
                "shadow_execution_failed",
                "The guarded shadow migration failed and all run-owned shadows were removed.",
                actualException);
        }
    }

    private async Task<MigratedShadowDatabase> CopyWholeDatabaseAsync(
        ShadowDatabase shadow,
        DatabaseSchemaPlan databasePlan,
        List<DatabaseReconciliationEvidence> evidence,
        CancellationToken cancellationToken)
    {
        await using IPostgreSqlWholeDatabaseTransaction transaction = await _target
            .BeginWholeDatabaseTransactionAsync(shadow, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            await transaction.ApplySchemaAsync(databasePlan, cancellationToken).ConfigureAwait(false);
            List<TableReconciliationEvidence> sourceTables = [];
            foreach (TableCopyPlan table in databasePlan.Tables)
            {
                using var collector = new TableEvidenceCollector(table);
                long count = await CopySourceTableAsync(transaction, databasePlan.Database, table, collector, cancellationToken)
                    .ConfigureAwait(false);
                TableReconciliationEvidence sourceEvidence = collector.Finish();
                IReadOnlyDictionary<string, long> sourceOrphans = await _source
                    .InspectForeignKeyOrphansAsync(databasePlan.Database, table, cancellationToken)
                    .ConfigureAwait(false);
                sourceEvidence = sourceEvidence with { ForeignKeyOrphanCounts = sourceOrphans };
                if (count != sourceEvidence.RowCount)
                {
                    throw new MigrationExecutionException(
                        "shadow_copy_count_mismatch",
                        $"{databasePlan.Database} did not acknowledge every source row.");
                }

                sourceTables.Add(sourceEvidence);
            }

            string targetSchema = await transaction.InspectSchemaAsync(databasePlan, cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(targetSchema, databasePlan.TargetSchemaSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new MigrationExecutionException(
                    "shadow_reconciliation_failed",
                    $"{databasePlan.Database} failed shadow reconciliation.");
            }

            List<TableReconciliationEvidence> targetTables = [];
            foreach (TableCopyPlan table in databasePlan.Tables)
            {
                TableReconciliationEvidence targetEvidence = await transaction
                    .InspectTableAsync(table, cancellationToken)
                    .ConfigureAwait(false);
                TableReconciliationEvidence sourceEvidence = sourceTables.Single(item =>
                    string.Equals(item.Table, targetEvidence.Table, StringComparison.Ordinal));
                if (!EvidenceEquals(sourceEvidence, targetEvidence))
                {
                    throw new MigrationExecutionException(
                        "shadow_reconciliation_failed",
                        $"{databasePlan.Database} failed shadow reconciliation.");
                }

                targetTables.Add(targetEvidence);
            }

            evidence.Add(new DatabaseReconciliationEvidence(
                databasePlan.Database,
                databasePlan.SourceSchemaSha256,
                targetSchema,
                new ReadOnlyCollection<TableReconciliationEvidence>(targetTables)));

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new MigratedShadowDatabase(
                databasePlan.Database,
                shadow.Name,
                targetTables.Sum(item => item.RowCount),
                HashEvidence(targetTables));
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            if (exception is OperationCanceledException or MigrationExecutionException)
            {
                throw;
            }

            throw new MigrationExecutionException(
                "shadow_copy_failed",
                $"{databasePlan.Database} failed inside its whole-database transaction.",
                exception);
        }
    }

    private void ValidateRequest(GuardedMigrationRequest request, DateTimeOffset nowUtc)
    {
        IReadOnlyList<PreflightError> schemaErrors = SchemaPlanCanonicalizer.Validate(
            request.SchemaPlan,
            _policy,
            nowUtc,
            GuardedRunnerPolicy.MaximumSchemaPlanAge);
        if (schemaErrors.Count > 0)
        {
            throw FromPreflight(schemaErrors[0]);
        }

        IReadOnlyList<PreflightError> authorizationErrors = ExecutionAuthorizationValidator.Validate(
            request.Authorization,
            request.SchemaPlan,
            request.BackupReceipt,
            _policy,
            nowUtc,
            _authorizationTrustStore);
        if (authorizationErrors.Count > 0)
        {
            throw FromPreflight(authorizationErrors[0]);
        }

        var planOnly = new MigrationPlan(
            "plan-only",
            false,
            DatabaseInventory.ActiveDatabases.ToDictionary(
                database => database,
                _ => (string?)"1.0",
                StringComparer.Ordinal),
            []);
        PreflightResult backupResult = _backupPreflight.Validate(
            request.BackupReceipt,
            planOnly,
            nowUtc,
            GuardedRunnerPolicy.MaximumBackupReceiptAge);
        if (!backupResult.IsValid)
        {
            throw FromPreflight(backupResult.Errors[0]);
        }
    }

    private static MigrationExecutionException FromPreflight(PreflightError error)
    {
        return new(error.Code, error.Message);
    }

    private static void ValidateShadowLease(
        ShadowDatabase shadow,
        string expectedName,
        string expectedDatabase,
        Guid runId,
        MigrationRunLease lease)
    {
        if (!string.Equals(shadow.Name, expectedName, StringComparison.Ordinal) ||
            !string.Equals(shadow.OwnerRunId, runId.ToString("D"), StringComparison.Ordinal) ||
            !string.Equals(shadow.Database, expectedDatabase, StringComparison.Ordinal) ||
            shadow.OwnerAttempt != lease.Attempt ||
            shadow.FencingToken != lease.FencingToken)
        {
            throw new MigrationExecutionException(
                "shadow_ownership_invalid",
                "The PostgreSQL target did not return the expected run-owned shadow lease.");
        }
    }

    private async Task<IReadOnlyList<ShadowCleanupOutcome>> DeleteCreatedShadowsAsync(
        MigrationRunLease lease,
        IEnumerable<ShadowDatabase> shadows)
    {
        List<ShadowCleanupOutcome> outcomes = [];
        foreach (ShadowDatabase shadow in shadows.Reverse())
        {
            try
            {
                await _target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None).ConfigureAwait(false);
                var outcome = new ShadowCleanupOutcome(shadow.Name, true, null)
                {
                    OwnerAttempt = shadow.OwnerAttempt,
                    FencingToken = shadow.FencingToken,
                };
                outcomes.Add(outcome);
                await _journal.RecordShadowCleanupAsync(lease, outcome, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                var outcome = new ShadowCleanupOutcome(shadow.Name, false, "shadow_delete_failed")
                {
                    OwnerAttempt = shadow.OwnerAttempt,
                    FencingToken = shadow.FencingToken,
                };
                outcomes.Add(outcome);
                try
                {
                    await _journal.RecordShadowCleanupAsync(lease, outcome, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    // The durable lease may have expired. A later owner will retry the still-pending inventory.
                }
            }
        }

        return new ReadOnlyCollection<ShadowCleanupOutcome>(outcomes);
    }

    private static bool EvidenceEquals(TableReconciliationEvidence source, TableReconciliationEvidence target)
    {
        return source.RowCount == target.RowCount &&
        string.Equals(source.ContentSha256, target.ContentSha256, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(source.AggregateSha256, target.AggregateSha256, StringComparison.OrdinalIgnoreCase) &&
        source.NullCounts.OrderBy(item => item.Key, StringComparer.Ordinal)
            .SequenceEqual(target.NullCounts.OrderBy(item => item.Key, StringComparer.Ordinal)) &&
        source.ForeignKeyOrphanCounts.OrderBy(item => item.Key, StringComparer.Ordinal)
            .SequenceEqual(target.ForeignKeyOrphanCounts.OrderBy(item => item.Key, StringComparer.Ordinal));
    }

    private static string HashEvidence(IEnumerable<TableReconciliationEvidence> tables)
    {
        string canonical = string.Join('\n', tables.OrderBy(item => item.Table, StringComparer.Ordinal)
            .Select(item => $"{item.Table}|{item.RowCount}|{item.ContentSha256}|{item.AggregateSha256}"));
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private async Task<long> CopySourceTableAsync(
        IPostgreSqlWholeDatabaseTransaction transaction,
        string database,
        TableCopyPlan table,
        TableEvidenceCollector collector,
        CancellationToken cancellationToken)
    {
        List<MigrationRow> batch = new(GuardedRunnerPolicy.CopyBatchSize);
        long batchBytes = 0;
        long copied = 0;
        await foreach (MigrationRow row in _source.ReadTableAsync(database, table, cancellationToken)
            .WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            long rowBytes = MigrationRowSizeEstimator.Estimate(row);
            if (rowBytes > GuardedRunnerPolicy.CopyBatchByteLimit)
            {
                throw new MigrationExecutionException(
                    "source_row_exceeds_batch_byte_limit",
                    $"{database}.{table.SourceSchema}.{table.SourceTable} contains a row larger than the approved copy batch byte limit.");
            }

            collector.Append(row);
            if (batch.Count > 0 &&
                (batch.Count == GuardedRunnerPolicy.CopyBatchSize ||
                    rowBytes > GuardedRunnerPolicy.CopyBatchByteLimit - batchBytes))
            {
                copied += await CopyBatchExactlyAsync(transaction, table, batch, cancellationToken).ConfigureAwait(false);
                batch.Clear();
                batchBytes = 0;
            }

            batch.Add(row);
            batchBytes = checked(batchBytes + rowBytes);
            if (batch.Count == GuardedRunnerPolicy.CopyBatchSize ||
                batchBytes >= GuardedRunnerPolicy.CopyBatchByteLimit)
            {
                copied += await CopyBatchExactlyAsync(transaction, table, batch, cancellationToken).ConfigureAwait(false);
                batch.Clear();
                batchBytes = 0;
            }
        }

        if (batch.Count > 0)
        {
            copied += await CopyBatchExactlyAsync(transaction, table, batch, cancellationToken).ConfigureAwait(false);
        }

        return copied;
    }

    private static bool SourceInventoryMatches(
        DatabaseSchemaPlan plan,
        IReadOnlyList<SourceTableInventory> observed)
    {
        SourceTableInventory[] expected = [.. plan.Tables
            .Select(table => new SourceTableInventory(table.SourceSchema, table.SourceTable, table.OrderedColumns))
            .OrderBy(table => table.SourceSchema, StringComparer.Ordinal)
            .ThenBy(table => table.SourceTable, StringComparer.Ordinal)];
        SourceTableInventory[] actual = [.. observed
            .OrderBy(table => table.SourceSchema, StringComparer.Ordinal)
            .ThenBy(table => table.SourceTable, StringComparer.Ordinal)];
        return expected.Length == actual.Length && expected.Zip(actual).All(pair =>
            string.Equals(pair.First.SourceSchema, pair.Second.SourceSchema, StringComparison.Ordinal) &&
            string.Equals(pair.First.SourceTable, pair.Second.SourceTable, StringComparison.Ordinal) &&
            pair.First.OrderedColumns.SequenceEqual(pair.Second.OrderedColumns, StringComparer.Ordinal));
    }

    private static async Task<long> CopyBatchExactlyAsync(
        IPostgreSqlWholeDatabaseTransaction transaction,
        TableCopyPlan table,
        List<MigrationRow> batch,
        CancellationToken cancellationToken)
    {
        long copied = await transaction.CopyBatchAsync(table, batch, cancellationToken).ConfigureAwait(false);
        return copied != batch.Count
            ? throw new MigrationExecutionException(
                "shadow_copy_count_mismatch",
                "The PostgreSQL target did not acknowledge every row in the runner-owned batch.")
            : copied;
    }

    private void ValidateCompletedReplay(MigrationExecutionReceipt receipt, MigrationRunIdentity expectedIdentity)
    {
        if (MigrationRunIdentity.FromReceipt(receipt) != expectedIdentity ||
            string.IsNullOrWhiteSpace(receipt.AttestationKeyId) ||
            string.IsNullOrWhiteSpace(receipt.AttestationSignature))
        {
            throw new MigrationExecutionException(
                "completed_receipt_invalid",
                "Stored completion evidence does not match the requested immutable run.");
        }

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(receipt.AttestationSignature);
        }
        catch (FormatException exception)
        {
            throw new MigrationExecutionException(
                "completed_receipt_invalid",
                "Stored completion evidence signature is malformed.",
                exception);
        }

        if (!_authorizationTrustStore.Verify(
            receipt.AttestationKeyId,
            MigrationEvidenceAttestation.CreatePayload(receipt),
            signature))
        {
            throw new MigrationExecutionException(
                "completed_receipt_invalid",
                "Stored completion evidence signature is not trusted.");
        }
    }

    private MigrationExecutionReceipt SignAndVerify(MigrationExecutionReceipt receipt)
    {
        byte[] payload = MigrationEvidenceAttestation.CreatePayload(receipt);
        byte[] signature = _evidenceSigner.Sign(payload);
        return !_authorizationTrustStore.Verify(_evidenceSigner.KeyId, payload, signature)
            ? throw new MigrationExecutionException("evidence_signature_invalid", "Migration evidence signer is not trusted.")
            : (receipt with { AttestationSignature = Convert.ToBase64String(signature) });
    }

    private MigrationFailureReceipt SignAndVerify(MigrationFailureReceipt receipt)
    {
        byte[] payload = MigrationEvidenceAttestation.CreatePayload(receipt);
        byte[] signature = _evidenceSigner.Sign(payload);
        return !_authorizationTrustStore.Verify(_evidenceSigner.KeyId, payload, signature)
            ? throw new MigrationExecutionException("evidence_signature_invalid", "Migration evidence signer is not trusted.")
            : (receipt with { AttestationSignature = Convert.ToBase64String(signature) });
    }

    private static string CreateShadowName(string database, Guid runId)
    {
        return $"legacy_shadow_{database.ToLowerInvariant()}_{runId:N}";
    }

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitSha();

    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256();
}
