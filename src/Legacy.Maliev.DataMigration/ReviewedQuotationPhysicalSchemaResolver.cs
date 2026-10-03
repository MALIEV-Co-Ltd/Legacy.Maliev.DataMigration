namespace Legacy.Maliev.DataMigration;

internal enum ReviewedQuotationPhysicalVariant
{
    RetainedOutboxes,
    MappedFinal,
}

/// <summary>Derives the only two reviewed physical Quotation states from the signed source shape.</summary>
internal static class ReviewedQuotationPhysicalSchemaResolver
{
    internal static string GetExpected(DatabaseSchemaPlan signedSource, ReviewedQuotationPhysicalVariant variant)
    {
        ArgumentNullException.ThrowIfNull(signedSource);
        // This validates the complete reviewed source disposition and its declared final fingerprint.
        string final = PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(signedSource, false);
        return variant switch
        {
            ReviewedQuotationPhysicalVariant.RetainedOutboxes => PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(signedSource, true),
            ReviewedQuotationPhysicalVariant.MappedFinal => final,
            _ => throw Invalid(),
        };
    }

    internal static ReviewedQuotationPhysicalVariant ClassifyObserved(DatabaseSchemaPlan signedSource, string observedSha256)
    {
        string retained = GetExpected(signedSource, ReviewedQuotationPhysicalVariant.RetainedOutboxes);
        string final = GetExpected(signedSource, ReviewedQuotationPhysicalVariant.MappedFinal);
        return DeltaSynchronizationPlanProducer.FixedHashEquals(observedSha256, retained)
            ? ReviewedQuotationPhysicalVariant.RetainedOutboxes
            : DeltaSynchronizationPlanProducer.FixedHashEquals(observedSha256, final)
            ? ReviewedQuotationPhysicalVariant.MappedFinal
            : throw Invalid();
    }

    internal static string RequireReviewedHash(DatabaseSchemaPlan signedSource, string observedSha256)
    {
        return GetExpected(signedSource, ClassifyObserved(signedSource, observedSha256));
    }

    internal static DeltaPlanException Invalid()
    {
        return new("delta_quotation_transition_plan_invalid",
        "Quotation physical state must derive from the reviewed signed retained or final source schema.");
    }
}
