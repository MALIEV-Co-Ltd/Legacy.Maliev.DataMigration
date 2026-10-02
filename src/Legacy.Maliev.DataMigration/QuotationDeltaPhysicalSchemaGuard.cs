using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Keeps the additive Quotation bootstrap state distinct from a row-delta-ready target.
/// The retained public outboxes are part of the physical schema, even though they are
/// deliberately absent from the signed archive/adoption target inventory.
/// </summary>
internal static class QuotationDeltaPhysicalSchemaGuard
{
    internal static string ExpectedPhysicalSchema(DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema,
        PairedLocalTransitionExecutionPermit? localPermit = null, FreshSchemaPlan? signedSourceSchemaPlan = null)
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
        if (DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(plan.TargetAuthority))
        {
            if (localPermit is null || plan.PairedTransitionPlanOnly != true)
            {
                throw new DeltaPlanException("delta_quotation_transition_plan_invalid",
                    "A signed paired LOCAL transition permit is required for this physical schema.");
            }
            localPermit.Require(plan, schema, localPermit.NowUtc);
            if (schema.Database == "Quotation")
            {
                return RequireMappedOrSource(plan, schema, localPermit.SourceQuotationSchema);
            }
            return schema.TargetSchemaSha256;
        }
        if (plan.SourceCaptureManifest is null || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(plan.TargetAuthority))
        { throw ReviewedQuotationPhysicalSchemaResolver.Invalid(); }
        if (schema.Database != "Quotation") { return schema.TargetSchemaSha256; }
        if (schema.SourceDispositionProfile == ApprovedSourceDispositionManifest.QuotationOutboxesV1)
        { return RequireMappedOrSource(plan, schema, schema); }
        if (signedSourceSchemaPlan is null || SchemaPlanCanonicalizer.ComputeSha256(signedSourceSchemaPlan) != plan.SchemaPlanSha256)
        { throw ReviewedQuotationPhysicalSchemaResolver.Invalid(); }
        DatabaseSchemaPlan original = signedSourceSchemaPlan.Databases.Single(database => database.Database == "Quotation");
        return RequireMappedOrSource(plan, schema, original);
    }

    private static string RequireMappedOrSource(DeltaSynchronizationPlan plan, DatabaseSchemaPlan supplied,
        DatabaseSchemaPlan signedSource)
    {
        string expected = ReviewedQuotationPhysicalSchemaResolver.RequireReviewedHash(signedSource,
            plan.QuotationTransitionSchemaSha256 ?? string.Empty);
        string serialized = JsonSerializer.Serialize(supplied);
        if (serialized != JsonSerializer.Serialize(signedSource) &&
            serialized != JsonSerializer.Serialize(new QuotationDeltaExecutionMapping(signedSource).TargetSchema))
        { throw ReviewedQuotationPhysicalSchemaResolver.Invalid(); }
        return expected;
    }

    internal static void RequirePlanSchema(DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema,
        string observedSha256, PairedLocalTransitionExecutionPermit? localPermit = null,
        FreshSchemaPlan? signedSourceSchemaPlan = null)
    {
        string expected = ExpectedPhysicalSchema(plan, schema, localPermit, signedSourceSchemaPlan);
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
