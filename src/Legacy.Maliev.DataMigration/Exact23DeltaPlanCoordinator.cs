namespace Legacy.Maliev.DataMigration;

public sealed record Exact23DeltaPlanRequest(
    FreshSchemaPlan SchemaPlan,
    DateTimeOffset SourceCutoffUtc,
    string BackupManifestSha256,
    string RunnerDigestSha256,
    string TargetNamespace,
    string TargetCluster,
    string TargetGeneration,
    string TargetObservationSha256,
    string BackupKeyFingerprintSha256,
    string ExecutionAuthorizationKeyFingerprintSha256);

public sealed class Exact23DeltaPlanCoordinator(
    IDeltaOrderedRowSource restoredSource,
    IDeltaOrderedRowSource canonicalTarget,
    P256MigrationEvidenceSigner planSigner,
    TimeProvider timeProvider)
{
    public async Task<DeltaSynchronizationPlan> ProduceAsync(
        Exact23DeltaPlanRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateInventory(request.SchemaPlan);
        var databases = new List<DeltaDatabasePlan>(DatabaseInventory.ActiveDatabases.Count);
        foreach (DatabaseSchemaPlan database in request.SchemaPlan.Databases)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var tables = new List<DeltaTablePlan>(database.Tables.Count);
            foreach (TableCopyPlan table in database.Tables.OrderBy(
                item => $"{item.TargetSchema}.{item.TargetTable}", StringComparer.Ordinal))
            {
                CanonicalTableDelta delta = await CanonicalAsyncDeltaPlanner.PlanAsync(
                    table,
                    restoredSource.ReadOrderedAsync(database.Database, table, cancellationToken),
                    canonicalTarget.ReadOrderedAsync(database.Database, table, cancellationToken),
                    cancellationToken).ConfigureAwait(false);
                tables.Add(new(delta.Table, delta.InsertCount, delta.UpdateCount, delta.DeleteCount,
                    delta.UnchangedCount,
                    DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(delta.Operations),
                    delta.Operations));
            }
            databases.Add(new(database.Database, tables));
        }

        DateTimeOffset nowUtc = timeProvider.GetUtcNow();
        return DeltaSynchronizationPlanProducer.Produce(new(
            request.SchemaPlan.SourceCommitSha,
            request.SourceCutoffUtc,
            request.BackupManifestSha256,
            SchemaPlanCanonicalizer.ComputeSha256(request.SchemaPlan),
            request.RunnerDigestSha256,
            request.TargetNamespace,
            request.TargetCluster,
            request.TargetGeneration,
            request.TargetObservationSha256,
            request.BackupKeyFingerprintSha256,
            request.ExecutionAuthorizationKeyFingerprintSha256,
            databases), planSigner, nowUtc);
    }

    private static void ValidateInventory(FreshSchemaPlan schema)
    {
        ArgumentNullException.ThrowIfNull(schema);
        if (!schema.Databases.Select(item => item.Database)
            .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            schema.Databases.Any(database => database.Tables.Count == 0))
        {
            throw new DeltaPlanException("delta_plan_inventory_invalid",
                "Delta planning requires the exact ordered active database and non-empty table inventory.");
        }
    }
}
