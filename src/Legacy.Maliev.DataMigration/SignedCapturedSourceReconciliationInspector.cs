namespace Legacy.Maliev.DataMigration;

/// <summary>Returns snapshot-bound source evidence from a trusted capture plan, never from current SQL rows.</summary>
public sealed class SignedCapturedSourceReconciliationInspector(
    DeltaSynchronizationPlan plan,
    FreshSchemaPlan schemaPlan,
    IReceiptAttestationTrustStore trust,
    TimeProvider timeProvider) : IDeltaReconciliationInspector
{
    public Task<DatabaseReconciliationEvidence> InspectAsync(
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(schema);
        if (plan.SchemaVersion is not ("1.3" or "1.4") || plan.SourceCaptureManifest is null ||
            !DeltaSynchronizationPlanVerifier.Verify(plan, trust, timeProvider.GetUtcNow()) ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(plan.SchemaPlanSha256,
                SchemaPlanCanonicalizer.ComputeSha256(schemaPlan)))
        {
            throw new DeltaExecutionException("delta_capture_source_invalid",
                "A fresh trusted source capture and matching schema plan are required.");
        }
        DatabaseSchemaPlan? expectedSchema = schemaPlan.Databases.SingleOrDefault(database =>
            string.Equals(database.Database, schema.Database, StringComparison.Ordinal));
        DeltaDatabaseCaptureBinding? binding = plan.SourceCaptureManifest.Databases.SingleOrDefault(database =>
            string.Equals(database.Database, schema.Database, StringComparison.Ordinal));
        return expectedSchema is null || binding is null ||
            !string.Equals(System.Text.Json.JsonSerializer.Serialize(expectedSchema),
                System.Text.Json.JsonSerializer.Serialize(schema), StringComparison.Ordinal) ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(
                binding.SourceReconciliation.SourceSchemaSha256, schema.SourceSchemaSha256) ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(
                binding.SourceReconciliation.TargetSchemaSha256, schema.TargetSchemaSha256)
            ? throw new DeltaExecutionException("delta_capture_schema_invalid",
                "The captured source reconciliation does not match the signed database schema.")
            : Task.FromResult(binding.SourceReconciliation);
    }
}
