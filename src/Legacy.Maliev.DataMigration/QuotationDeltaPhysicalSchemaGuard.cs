namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Keeps the additive Quotation bootstrap state distinct from a row-delta-ready target.
/// The retained public outboxes are part of the physical schema, even though they are
/// deliberately absent from the signed archive/adoption target inventory.
/// </summary>
internal static class QuotationDeltaPhysicalSchemaGuard
{
    internal static void RequireFinalSchema(DatabaseSchemaPlan schema, string observedSha256)
    {
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentException.ThrowIfNullOrWhiteSpace(observedSha256);

        if (schema.Database == "Quotation" &&
            schema.SourceDispositionProfile == ApprovedSourceDispositionManifest.QuotationOutboxesV1)
        {
            // This also validates that the signed final hash still derives from the
            // reviewed Quotation disposition, before classifying a transition state.
            string transition = PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(schema, true);
            if (!string.Equals(transition, schema.TargetSchemaSha256, StringComparison.Ordinal) &&
                string.Equals(observedSha256, transition, StringComparison.OrdinalIgnoreCase))
            {
                throw new DeltaPlanException("delta_quotation_transition_row_path_not_authorized",
                    "The retained Quotation outboxes require a separately signed transition row contract.");
            }
        }

        ReconciliationDiagnostics.CompareSchema(schema.Database, schema.TargetSchemaSha256, observedSha256);
    }
}
