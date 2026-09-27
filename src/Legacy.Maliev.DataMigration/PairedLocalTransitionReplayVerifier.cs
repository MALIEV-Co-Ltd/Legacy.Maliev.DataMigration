namespace Legacy.Maliev.DataMigration;

/// <summary>Checks an already-committed database against the same signed captured cutoff.</summary>
public static class PairedLocalTransitionReplayVerifier
{
    public static async Task VerifyAsync(DatabaseSchemaPlan schema,
        IDeltaReconciliationInspector capturedSource,
        IDeltaReconciliationInspector target,
        CancellationToken cancellationToken)
    {
        DatabaseReconciliationEvidence expected = await capturedSource.InspectAsync(schema,
            cancellationToken).ConfigureAwait(false);
        DatabaseReconciliationEvidence observed = await target.InspectAsync(schema,
            cancellationToken).ConfigureAwait(false);
        DatabaseSchemaPlan mapped = new QuotationDeltaExecutionMapping(schema).TargetSchema;
        string[] inventory = [.. mapped.Tables.Select(item => $"{item.TargetSchema}.{item.TargetTable}")
            .Order(StringComparer.Ordinal)];
        if (expected.Database != schema.Database || observed.Database != schema.Database ||
            !expected.Tables.Select(item => item.Table).Order(StringComparer.Ordinal)
                .SequenceEqual(inventory, StringComparer.Ordinal) ||
            !observed.Tables.Select(item => item.Table).Order(StringComparer.Ordinal)
                .SequenceEqual(inventory, StringComparer.Ordinal))
        {
            throw new DeltaExecutionException("delta_paired_local_replay_shape_invalid",
                "The replayed LOCAL database does not have the signed target inventory.");
        }
        foreach (TableReconciliationEvidence table in expected.Tables)
        {
            ReconciliationDiagnostics.CompareTable(schema.Database, table,
                observed.Tables.Single(item => item.Table == table.Table));
        }
        ReconciliationDiagnostics.CompareSequences(mapped, expected.SequenceNextValues,
            observed.SequenceNextValues);
    }
}
