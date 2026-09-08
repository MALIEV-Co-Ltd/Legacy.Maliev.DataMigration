namespace Legacy.Maliev.DataMigration;

public enum DeltaExecutionDisposition
{
    Pending,
    AlreadyCommitted,
    Committed,
}

public sealed record DeltaDatabaseExecutionResult(
    string Database,
    DeltaExecutionDisposition Disposition,
    long AppliedOperations,
    string PlanSha256);

public sealed class DeltaExecutionException(string code, string message, Exception? innerException = null)
    : Exception(message, innerException)
{
    public string Code { get; } = code;
}

public interface IDeltaExecutionAuthorizationGate
{
    Task ValidateAsync(DeltaSynchronizationPlan plan, string database, CancellationToken cancellationToken);
}

public interface IDeltaExecutionRowProvider
{
    Task<MigrationRow?> ReadSourceAsync(
        string database,
        TableCopyPlan table,
        string keySha256,
        CancellationToken cancellationToken);

    Task<MigrationRow?> ReadTargetAsync(
        string database,
        TableCopyPlan table,
        string keySha256,
        CancellationToken cancellationToken);
}

public interface IDeltaCanonicalTarget
{
    Task<IDeltaCanonicalTransaction> BeginAsync(
        DeltaSynchronizationPlan plan,
        DatabaseSchemaPlan schema,
        string database,
        CancellationToken cancellationToken);
}

public interface IDeltaCanonicalTransaction : IAsyncDisposable
{
    DeltaExecutionDisposition Disposition { get; }

    Task ApplyAsync(
        TableCopyPlan table,
        CanonicalDeltaOperation operation,
        MigrationRow? source,
        MigrationRow? target,
        CancellationToken cancellationToken);

    Task CommitAsync(string planSha256, CancellationToken cancellationToken);
}

public sealed class DeltaExecutionCoordinator(
    IDeltaCanonicalTarget target,
    IDeltaExecutionRowProvider rows,
    IDeltaExecutionAuthorizationGate authorization,
    IReceiptAttestationTrustStore planTrust,
    TimeProvider timeProvider)
{
    public async Task<DeltaDatabaseExecutionResult> ExecuteDatabaseAsync(
        DeltaSynchronizationPlan plan,
        DatabaseSchemaPlan schema,
        string database,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentException.ThrowIfNullOrWhiteSpace(database);
        DateTimeOffset nowUtc = timeProvider.GetUtcNow();
        if (!DeltaSynchronizationPlanVerifier.Verify(plan, planTrust, nowUtc))
        {
            throw Error("delta_execution_plan_invalid", "The signed delta plan is invalid, stale, or untrusted.");
        }

        if (!string.Equals(schema.Database, database, StringComparison.Ordinal))
        {
            throw Error("delta_execution_schema_invalid", "The signed database schema does not match the requested database.");
        }

        DeltaDatabasePlan databasePlan = plan.Databases.SingleOrDefault(item =>
            string.Equals(item.Database, database, StringComparison.Ordinal)) ??
            throw Error("delta_execution_database_missing", "The signed delta plan does not contain the requested database.");
        Dictionary<string, TableCopyPlan> schemaTables = schema.Tables.ToDictionary(
            Qualified,
            StringComparer.Ordinal);
        if (!databasePlan.Tables.Select(table => table.Table).Order(StringComparer.Ordinal)
            .SequenceEqual(schemaTables.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw Error("delta_execution_table_inventory_invalid", "The delta and schema table inventories do not match exactly.");
        }

        await authorization.ValidateAsync(plan, database, cancellationToken).ConfigureAwait(false);
        string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        await using IDeltaCanonicalTransaction transaction = await target.BeginAsync(
            plan, schema, database, cancellationToken).ConfigureAwait(false);
        if (transaction.Disposition == DeltaExecutionDisposition.AlreadyCommitted)
        {
            return new(database, DeltaExecutionDisposition.AlreadyCommitted, 0, planSha256);
        }

        if (transaction.Disposition != DeltaExecutionDisposition.Pending)
        {
            throw Error("delta_execution_state_invalid", "The canonical target returned an invalid initial execution state.");
        }

        IReadOnlyList<TableCopyPlan> ordered = ForeignKeyExecutionOrder.Create(schema.Tables);
        long applied = 0;
        foreach (TableCopyPlan table in ordered)
        {
            DeltaTablePlan delta = databasePlan.Tables.Single(item => string.Equals(item.Table, Qualified(table), StringComparison.Ordinal));
            foreach (CanonicalDeltaOperation operation in delta.Operations.Where(item => item.Kind != DeltaOperationKind.Delete))
            {
                (MigrationRow? source, MigrationRow? currentTarget) = await ResolveAndVerifyAsync(
                    database, table, operation, cancellationToken).ConfigureAwait(false);
                await transaction.ApplyAsync(table, operation, source, currentTarget, cancellationToken).ConfigureAwait(false);
                applied++;
            }
        }

        foreach (TableCopyPlan table in ordered.Reverse())
        {
            DeltaTablePlan delta = databasePlan.Tables.Single(item => string.Equals(item.Table, Qualified(table), StringComparison.Ordinal));
            foreach (CanonicalDeltaOperation operation in delta.Operations.Where(item => item.Kind == DeltaOperationKind.Delete))
            {
                (MigrationRow? source, MigrationRow? currentTarget) = await ResolveAndVerifyAsync(
                    database, table, operation, cancellationToken).ConfigureAwait(false);
                await transaction.ApplyAsync(table, operation, source, currentTarget, cancellationToken).ConfigureAwait(false);
                applied++;
            }
        }

        await transaction.CommitAsync(planSha256, cancellationToken).ConfigureAwait(false);
        return new(database, DeltaExecutionDisposition.Committed, applied, planSha256);
    }

    private async Task<(MigrationRow? Source, MigrationRow? Target)> ResolveAndVerifyAsync(
        string database,
        TableCopyPlan table,
        CanonicalDeltaOperation operation,
        CancellationToken cancellationToken)
    {
        MigrationRow? source = operation.Kind == DeltaOperationKind.Delete
            ? null
            : await rows.ReadSourceAsync(database, table, operation.KeySha256, cancellationToken).ConfigureAwait(false);
        MigrationRow? currentTarget = operation.Kind == DeltaOperationKind.Insert
            ? null
            : await rows.ReadTargetAsync(database, table, operation.KeySha256, cancellationToken).ConfigureAwait(false);
        if (source is null && operation.Kind != DeltaOperationKind.Delete)
        {
            throw Error("delta_execution_source_row_missing", "A planned source row is unavailable at execution.");
        }
        if (currentTarget is null && operation.Kind != DeltaOperationKind.Insert)
        {
            throw Error("delta_execution_target_row_missing", "A planned target row is unavailable at execution.");
        }

        VerifyRow(table, source, operation.KeySha256, operation.SourceRowSha256, "source");
        VerifyRow(table, currentTarget, operation.KeySha256, operation.TargetRowSha256, "target");
        return (source, currentTarget);
    }

    private static void VerifyRow(
        TableCopyPlan table,
        MigrationRow? row,
        string expectedKeySha256,
        string? expectedRowSha256,
        string side)
    {
        if (row is null)
        {
            if (expectedRowSha256 is not null)
            {
                throw Error($"delta_execution_{side}_row_missing", $"A planned {side} row is unavailable at execution.");
            }
            return;
        }

        string keySha256;
        string rowSha256;
        try
        {
            keySha256 = CanonicalDeltaPlanner.ComputeKeySha256(table, row);
            rowSha256 = CanonicalRowFingerprint.Compute(table, [row]);
        }
        catch (Exception exception) when (exception is DeltaPlanningException or InvalidOperationException)
        {
            throw Error($"delta_execution_{side}_row_invalid", $"The {side} row cannot be safely canonicalized.", exception);
        }

        if (!string.Equals(keySha256, expectedKeySha256, StringComparison.Ordinal) ||
            !string.Equals(rowSha256, expectedRowSha256, StringComparison.Ordinal))
        {
            throw Error($"delta_execution_{side}_row_drift", $"The {side} row changed after the signed plan was produced.");
        }
    }

    private static string Qualified(TableCopyPlan table)
    {
        return $"{table.TargetSchema}.{table.TargetTable}";
    }

    private static DeltaExecutionException Error(string code, string message, Exception? exception = null)
    {
        return new(code, message, exception);
    }
}

public static class ForeignKeyExecutionOrder
{
    public static IReadOnlyList<TableCopyPlan> Create(IReadOnlyList<TableCopyPlan> tables)
    {
        ArgumentNullException.ThrowIfNull(tables);
        Dictionary<string, TableCopyPlan> byName = tables.ToDictionary(
            table => $"{table.TargetSchema}.{table.TargetTable}",
            StringComparer.Ordinal);
        Dictionary<string, HashSet<string>> dependencies = byName.ToDictionary(
            item => item.Key,
            item => item.Value.ForeignKeys.Select(foreignKey =>
                $"{foreignKey.ReferencedSchema}.{foreignKey.ReferencedTable}").ToHashSet(StringComparer.Ordinal),
            StringComparer.Ordinal);
        if (dependencies.Values.SelectMany(value => value).Any(reference => !byName.ContainsKey(reference)))
        {
            throw new DeltaExecutionException("delta_execution_fk_target_missing", "A foreign key references a table outside the signed database plan.");
        }

        var result = new List<TableCopyPlan>(tables.Count);
        var remaining = new HashSet<string>(byName.Keys, StringComparer.Ordinal);
        while (remaining.Count > 0)
        {
            string[] ready = [.. remaining.Where(name => dependencies[name].All(parent => !remaining.Contains(parent)))
                .Order(StringComparer.Ordinal)];
            if (ready.Length == 0)
            {
                throw new DeltaExecutionException("delta_execution_fk_cycle", "The signed table graph contains a non-deferrable foreign-key cycle.");
            }

            foreach (string name in ready)
            {
                result.Add(byName[name]);
                _ = remaining.Remove(name);
            }
        }

        return result;
    }
}
