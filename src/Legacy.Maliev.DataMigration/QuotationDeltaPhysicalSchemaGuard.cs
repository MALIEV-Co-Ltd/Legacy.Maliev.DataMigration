namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Keeps the additive Quotation bootstrap state distinct from a row-delta-ready target.
/// The retained public outboxes are part of the physical schema, even though they are
/// deliberately absent from the signed archive/adoption target inventory.
/// </summary>
internal static class QuotationDeltaPhysicalSchemaGuard
{
    internal static string ExpectedPhysicalSchema(DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schema);
        if (plan.SchemaVersion != "1.4")
        {
            return plan.QuotationTransitionSchemaSha256 is not null
                ? throw new DeltaPlanException("delta_quotation_transition_plan_invalid",
                    "A transition hash is not permitted by this signed plan version.")
                : schema.TargetSchemaSha256;
        }
        bool reviewedSource = schema.SourceDispositionProfile ==
            ApprovedSourceDispositionManifest.QuotationOutboxesV1;
        // The atomic target receives the mapped schema. Its source outbox shapes
        // were checked against the signed hash by QuotationDeltaExecutionPreflight
        // and DeltaExecutionCoordinator before BeginAsync.
        bool reviewedMappedTarget = schema.SourceDispositionProfile is null &&
            schema.Database == "Quotation" &&
            schema.TargetSchemaSha256 == PostgreSqlSchemaFingerprint.ComputeExpected(schema) &&
            schema.Tables.Count(table => table.SourceSchema == "disposition") == 2 &&
            schema.Tables.Any(table => table.SourceSchema == "disposition" &&
                table.TargetSchema == "legacy_compatibility" && table.TargetTable == "GoogleAnalyticsOutbox") &&
            schema.Tables.Any(table => table.SourceSchema == "disposition" &&
                table.TargetSchema == "public" && table.TargetTable == "QuotationAcceptedOutcome");
        return plan.SourceCaptureManifest is null ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(plan.TargetAuthority) ||
            (schema.Database == "Quotation" &&
                ((!reviewedSource && !reviewedMappedTarget) || (reviewedSource &&
                 !DeltaSynchronizationPlanProducer.FixedHashEquals(
                     plan.QuotationTransitionSchemaSha256 ?? string.Empty,
                     PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(schema, true)))))
            ? throw new DeltaPlanException("delta_quotation_transition_plan_invalid",
                "The signed disposable transition hash does not derive from the reviewed Quotation schema.")
            : schema.Database == "Quotation" ? plan.QuotationTransitionSchemaSha256! : schema.TargetSchemaSha256;
    }

    internal static void RequirePlanSchema(DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema,
        string observedSha256)
    {
        string expected = ExpectedPhysicalSchema(plan, schema);
        if (plan.SchemaVersion != "1.4")
        {
            RequireFinalSchema(schema, observedSha256);
            return;
        }
        ReconciliationDiagnostics.CompareSchema(schema.Database, expected, observedSha256);
    }

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
