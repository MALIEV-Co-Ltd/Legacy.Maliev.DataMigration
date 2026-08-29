using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed record GuardedRunnerPolicy(string ExpectedSourceCommitSha, string ExpectedRunnerDigestSha256);

public sealed record GuardedMigrationRequest(
    BackupReceipt BackupReceipt,
    FreshSchemaPlan SchemaPlan,
    ExecutionAuthorizationReceipt Authorization,
    DateTimeOffset NowUtc,
    TimeSpan MaximumBackupReceiptAge,
    TimeSpan MaximumSchemaPlanAge);

public sealed record SourceSchemaEvidence(string Database, string SchemaSha256);

public sealed record MigrationRow(IReadOnlyDictionary<string, object?> Values);

public sealed record ShadowDatabase(string Name, string OwnerRunId, string Database);

public sealed record DatabaseReconciliationResult(
    bool IsValid,
    long TotalRows,
    string ContentSha256,
    IReadOnlyList<string> Errors);

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
    IReadOnlyList<MigratedShadowDatabase> Databases);

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
    MigrationExecutionReceipt? CompletedReceipt);

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

    Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);

    Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);
}

public interface IPostgreSqlShadowTarget
{
    Task<ShadowDatabase> CreateUniqueEmptyShadowAsync(
        string database,
        string shadowName,
        string ownerRunId,
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

    Task<long> CopyTableAsync(
        TableCopyPlan table,
        IAsyncEnumerable<MigrationRow> rows,
        CancellationToken cancellationToken);

    Task<DatabaseReconciliationResult> ReconcileAsync(
        DatabaseSchemaPlan plan,
        IReadOnlyDictionary<string, long> copiedRows,
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

    Task RecordFailedAsync(Guid runId, CancellationToken cancellationToken);
}

public sealed partial class GuardedShadowMigrationRunner
{
    private readonly PreflightService _backupPreflight;
    private readonly IReceiptAttestationTrustStore _authorizationTrustStore;
    private readonly IReadOnlySqlServerMigrationSource _source;
    private readonly IPostgreSqlShadowTarget _target;
    private readonly IMigrationRunJournal _journal;
    private readonly GuardedRunnerPolicy _policy;

    public GuardedShadowMigrationRunner(
        PreflightService backupPreflight,
        IReceiptAttestationTrustStore authorizationTrustStore,
        IReadOnlySqlServerMigrationSource source,
        IPostgreSqlShadowTarget target,
        IMigrationRunJournal journal,
        GuardedRunnerPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(backupPreflight);
        ArgumentNullException.ThrowIfNull(authorizationTrustStore);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(journal);
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
        _policy = policy;
    }

    public async Task<MigrationExecutionResult> ExecuteAsync(
        GuardedMigrationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);

        MigrationRunIdentity identity = MigrationRunIdentity.FromRequest(request);
        string schemaPlanHash = identity.SchemaPlanSha256;
        MigrationRunStartResult start = await _journal
            .TryBeginAsync(identity, cancellationToken)
            .ConfigureAwait(false);
        if (start.Status == MigrationRunStartStatus.AlreadyCompleted && start.CompletedReceipt is not null)
        {
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

        List<ShadowDatabase> createdShadows = [];
        List<MigratedShadowDatabase> migrated = [];
        try
        {
            foreach (DatabaseSchemaPlan databasePlan in request.SchemaPlan.Databases
                .OrderBy(database => database.Database, StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                await _source.BeginDatabaseSnapshotAsync(databasePlan.Database, cancellationToken).ConfigureAwait(false);
                try
                {
                    SourceSchemaEvidence observedSchema = await _source
                        .InspectSchemaAsync(databasePlan.Database, cancellationToken)
                        .ConfigureAwait(false);
                    if (!string.Equals(observedSchema.Database, databasePlan.Database, StringComparison.Ordinal) ||
                        !string.Equals(observedSchema.SchemaSha256, databasePlan.SourceSchemaSha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new MigrationExecutionException(
                            "source_schema_drift",
                            $"{databasePlan.Database} no longer matches the signed schema plan.");
                    }

                    string shadowName = CreateShadowName(databasePlan.Database, request.Authorization.RunId);
                    ShadowDatabase shadow = await _target
                        .CreateUniqueEmptyShadowAsync(
                            databasePlan.Database,
                            shadowName,
                            request.Authorization.RunId.ToString("D"),
                            cancellationToken)
                        .ConfigureAwait(false);
                    ValidateShadowLease(shadow, shadowName, databasePlan.Database, request.Authorization.RunId);
                    createdShadows.Add(shadow);
                    if (!await _target.IsEmptyAsync(shadow, cancellationToken).ConfigureAwait(false))
                    {
                        throw new MigrationExecutionException(
                            "shadow_database_not_empty",
                            $"{shadow.Name} is not an empty run-owned shadow database.");
                    }

                    MigratedShadowDatabase result = await CopyWholeDatabaseAsync(
                        shadow,
                        databasePlan,
                        cancellationToken).ConfigureAwait(false);
                    migrated.Add(result);
                    await _source.CompleteDatabaseSnapshotAsync(databasePlan.Database, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch
                {
                    await _source.RollbackDatabaseSnapshotAsync(databasePlan.Database, CancellationToken.None)
                        .ConfigureAwait(false);
                    throw;
                }
            }

            var receipt = new MigrationExecutionReceipt(
                request.Authorization.RunId,
                request.SchemaPlan.SourceCommitSha,
                schemaPlanHash,
                request.BackupReceipt.ManifestSha256!,
                _policy.ExpectedRunnerDigestSha256,
                request.Authorization.TargetGeneration!,
                request.NowUtc,
                new ReadOnlyCollection<MigratedShadowDatabase>(migrated));
            await _journal.RecordCompletedAsync(receipt, cancellationToken).ConfigureAwait(false);
            return new MigrationExecutionResult(MigrationExecutionStatus.Completed, receipt);
        }
        catch (Exception exception)
        {
            try
            {
                await DeleteCreatedShadowsAsync(createdShadows).ConfigureAwait(false);
            }
            finally
            {
                await _journal.RecordFailedAsync(request.Authorization.RunId, CancellationToken.None)
                    .ConfigureAwait(false);
            }

            if (exception is OperationCanceledException or MigrationExecutionException)
            {
                throw;
            }

            throw new MigrationExecutionException(
                "shadow_execution_failed",
                "The guarded shadow migration failed and all run-owned shadows were removed.",
                exception);
        }
    }

    private async Task<MigratedShadowDatabase> CopyWholeDatabaseAsync(
        ShadowDatabase shadow,
        DatabaseSchemaPlan databasePlan,
        CancellationToken cancellationToken)
    {
        await using IPostgreSqlWholeDatabaseTransaction transaction = await _target
            .BeginWholeDatabaseTransactionAsync(shadow, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            await transaction.ApplySchemaAsync(databasePlan, cancellationToken).ConfigureAwait(false);
            Dictionary<string, long> copiedRows = new(StringComparer.Ordinal);
            foreach (TableCopyPlan table in databasePlan.Tables)
            {
                long count = await transaction.CopyTableAsync(
                    table,
                    _source.ReadTableAsync(databasePlan.Database, table, cancellationToken),
                    cancellationToken).ConfigureAwait(false);
                copiedRows.Add($"{table.TargetSchema}.{table.TargetTable}", count);
            }

            DatabaseReconciliationResult reconciliation = await transaction
                .ReconcileAsync(databasePlan, copiedRows, cancellationToken)
                .ConfigureAwait(false);
            if (!reconciliation.IsValid || reconciliation.Errors.Count > 0 || !Sha256().IsMatch(reconciliation.ContentSha256))
            {
                throw new MigrationExecutionException(
                    "shadow_reconciliation_failed",
                    $"{databasePlan.Database} failed shadow reconciliation.");
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new MigratedShadowDatabase(
                databasePlan.Database,
                shadow.Name,
                reconciliation.TotalRows,
                reconciliation.ContentSha256);
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

    private void ValidateRequest(GuardedMigrationRequest request)
    {
        IReadOnlyList<PreflightError> schemaErrors = SchemaPlanCanonicalizer.Validate(
            request.SchemaPlan,
            _policy,
            request.NowUtc,
            request.MaximumSchemaPlanAge);
        if (schemaErrors.Count > 0)
        {
            throw FromPreflight(schemaErrors[0]);
        }

        IReadOnlyList<PreflightError> authorizationErrors = ExecutionAuthorizationValidator.Validate(
            request.Authorization,
            request.SchemaPlan,
            request.BackupReceipt,
            _policy,
            request.NowUtc,
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
            request.NowUtc,
            request.MaximumBackupReceiptAge);
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
        Guid runId)
    {
        if (!string.Equals(shadow.Name, expectedName, StringComparison.Ordinal) ||
            !string.Equals(shadow.OwnerRunId, runId.ToString("D"), StringComparison.Ordinal) ||
            !string.Equals(shadow.Database, expectedDatabase, StringComparison.Ordinal))
        {
            throw new MigrationExecutionException(
                "shadow_ownership_invalid",
                "The PostgreSQL target did not return the expected run-owned shadow lease.");
        }
    }

    private async Task DeleteCreatedShadowsAsync(IEnumerable<ShadowDatabase> shadows)
    {
        List<Exception> errors = [];
        foreach (ShadowDatabase shadow in shadows.Reverse())
        {
            try
            {
                await _target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                errors.Add(exception);
            }
        }

        if (errors.Count > 0)
        {
            throw new MigrationExecutionException(
                "shadow_cleanup_failed",
                "One or more run-owned shadow databases could not be removed.",
                new AggregateException(errors));
        }
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
