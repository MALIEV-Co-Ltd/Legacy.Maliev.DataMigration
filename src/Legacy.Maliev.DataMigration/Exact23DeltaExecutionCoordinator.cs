using System.Collections.ObjectModel;

namespace Legacy.Maliev.DataMigration;

public sealed record Exact23DeltaExecutionResult(
    Guid PlanId,
    string PlanSha256,
    DateTimeOffset SourceCutoffUtc,
    IReadOnlyList<DeltaDatabaseExecutionResult> Databases);

public sealed class Exact23DeltaExecutionCoordinator(
    IReadOnlySqlServerMigrationSource source,
    Func<string, DeltaExecutionCoordinator> executorFactory)
{
    public async Task<Exact23DeltaExecutionResult> ExecuteAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schemaPlan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schemaPlan);
        ValidateInventory(plan, schemaPlan);
        var results = new List<DeltaDatabaseExecutionResult>(DatabaseInventory.ActiveDatabases.Count);
        foreach (DatabaseSchemaPlan schema in schemaPlan.Databases)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool snapshotOpen = false;
            try
            {
                await source.BeginDatabaseSnapshotAsync(schema.Database, cancellationToken).ConfigureAwait(false);
                snapshotOpen = true;
                DeltaDatabaseExecutionResult result = await executorFactory(schema.Database)
                    .ExecuteDatabaseAsync(plan, schema, schema.Database, cancellationToken).ConfigureAwait(false);
                await source.CompleteDatabaseSnapshotAsync(schema.Database, cancellationToken).ConfigureAwait(false);
                snapshotOpen = false;
                results.Add(result);
            }
            catch
            {
                if (snapshotOpen)
                {
                    try
                    {
                        await source.RollbackDatabaseSnapshotAsync(schema.Database, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception rollbackFailure) when (rollbackFailure is InvalidOperationException or IOException)
                    {
                        // Preserve the execution or reconciliation failure.
                    }
                }
                throw;
            }
        }

        return new(plan.PlanId, DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), plan.SourceCutoffUtc,
            new ReadOnlyCollection<DeltaDatabaseExecutionResult>(results));
    }

    private static void ValidateInventory(DeltaSynchronizationPlan plan, FreshSchemaPlan schemaPlan)
    {
        if (!plan.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !schemaPlan.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !string.Equals(plan.SourceCommitSha, schemaPlan.SourceCommitSha, StringComparison.Ordinal) ||
            !string.Equals(plan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(schemaPlan), StringComparison.Ordinal))
        {
            throw new DeltaExecutionException("delta_execution_inventory_invalid",
                "Exact-23 execution requires one matching signed plan and schema for the ordered active database inventory.");
        }
    }
}
