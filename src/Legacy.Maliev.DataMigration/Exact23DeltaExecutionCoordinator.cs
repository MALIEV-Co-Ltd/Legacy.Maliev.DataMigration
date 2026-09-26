using System.Collections.ObjectModel;

namespace Legacy.Maliev.DataMigration;

public sealed record Exact23DeltaExecutionResult(
    Guid PlanId,
    string PlanSha256,
    DateTimeOffset SourceCutoffUtc,
    IReadOnlyList<DeltaDatabaseExecutionResult> Databases);

public sealed class Exact23DeltaExecutionCoordinator(
    IReadOnlyMigrationSource source,
    Func<string, DeltaExecutionCoordinator> executorFactory,
    bool capturedSourceReplay = false)
{
    public async Task<Exact23DeltaExecutionResult> ExecuteAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schemaPlan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schemaPlan);
        if (plan.SchemaVersion == "1.3" != capturedSourceReplay)
        {
            throw new DeltaPlanException("delta_execution_capture_replay_required",
                "Captured-source plans require the authenticated replay execution path.");
        }
        ValidateInventory(plan, schemaPlan);
        var results = new List<DeltaDatabaseExecutionResult>(DatabaseInventory.ActiveDatabases.Count);
        // The live source can accept new rows after planning. Apply databases with
        // signed changes first, reducing the capture-to-apply window for active data.
        foreach (DatabaseSchemaPlan schema in schemaPlan.Databases
            .OrderByDescending(item => plan.Databases.Single(database => database.Database == item.Database)
                .Tables.Sum(table => checked(table.InsertCount + table.UpdateCount + table.DeleteCount))))
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool snapshotOpen = false;
            try
            {
                if (!capturedSourceReplay)
                {
                    await source.BeginDatabaseSnapshotAsync(schema.Database, cancellationToken).ConfigureAwait(false);
                    snapshotOpen = true;
                }
                DeltaDatabaseExecutionResult result = await executorFactory(schema.Database)
                    .ExecuteDatabaseAsync(plan, schema, schema.Database, cancellationToken).ConfigureAwait(false);
                if (snapshotOpen)
                {
                    await source.CompleteDatabaseSnapshotAsync(schema.Database, cancellationToken).ConfigureAwait(false);
                    snapshotOpen = false;
                }
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

        var byDatabase = results.ToDictionary(item => item.Database, StringComparer.Ordinal);
        return new(plan.PlanId, DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), plan.SourceCutoffUtc,
            new ReadOnlyCollection<DeltaDatabaseExecutionResult>(
                [.. DatabaseInventory.ActiveDatabases.Select(database => byDatabase[database])]));
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
