namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class DisposableDeltaProofVerifierTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reviewed_quotation_physical_variant_requires_exact_signed_source_and_mapped_context(bool mappedFinal)
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, physicalTargetHashes: true);
        DatabaseSchemaPlan source = fixture.Schema.Databases.Single(database => database.Database == "Quotation");
        ReviewedQuotationPhysicalVariant variant = mappedFinal ? ReviewedQuotationPhysicalVariant.MappedFinal : ReviewedQuotationPhysicalVariant.RetainedOutboxes;
        string expected = ReviewedQuotationPhysicalSchemaResolver.GetExpected(source, variant);
        Assert.Equal(variant, ReviewedQuotationPhysicalSchemaResolver.ClassifyObserved(source, expected));
        Assert.Equal(expected, ReviewedQuotationPhysicalSchemaResolver.RequireReviewedHash(source, expected));
        Assert.NotEqual(ReviewedQuotationPhysicalSchemaResolver.GetExpected(source, ReviewedQuotationPhysicalVariant.RetainedOutboxes),
            ReviewedQuotationPhysicalSchemaResolver.GetExpected(source, ReviewedQuotationPhysicalVariant.MappedFinal));
        using var signer = new P256MigrationEvidenceSigner("proof-plan", _planKey.ExportECPrivateKeyPem());
        DeltaSynchronizationPlan unsigned = fixture.ProofPlan with { QuotationTransitionSchemaSha256 = expected, AttestationSignature = null };
        DeltaSynchronizationPlan plan = unsigned with
        { AttestationSignature = Convert.ToBase64String(signer.Sign(DeltaSynchronizationPlanCanonicalizer.CreatePayload(unsigned))) };
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, fixture.Trust, fixture.Now));
        DatabaseSchemaPlan mapped = new QuotationDeltaExecutionMapping(source).TargetSchema;
        Assert.Equal(expected, QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(plan, source));
        Assert.Equal(expected, QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(plan, mapped,
            signedSourceSchemaPlan: fixture.Schema));
        _ = Assert.Throws<DeltaPlanException>(() => QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(plan, mapped));
        _ = Assert.Throws<DeltaPlanException>(() => QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(plan, mapped,
            signedSourceSchemaPlan: fixture.Schema with { SourceCommitSha = Hash('0') }));
        DatabaseSchemaPlan spoof = mapped with
        {
            Tables = [mapped.Tables[0] with { SourceTable = "forged-source" }, .. mapped.Tables.Skip(1)],
        };
        Assert.Equal(mapped.TargetSchemaSha256, PostgreSqlSchemaFingerprint.ComputeExpected(spoof));
        _ = Assert.Throws<DeltaPlanException>(() => QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(plan, spoof,
            signedSourceSchemaPlan: fixture.Schema));
        _ = Assert.Throws<DeltaPlanException>(() => QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(
            plan with { QuotationTransitionSchemaSha256 = Hash('0') }, source));
        _ = Assert.Throws<DeltaPlanException>(() => ReviewedQuotationPhysicalSchemaResolver.GetExpected(source,
            (ReviewedQuotationPhysicalVariant)99));
        QuotationDeltaPhysicalSchemaGuard.RequireFinalSchema(source, source.TargetSchemaSha256);
        _ = Assert.Throws<DeltaPlanException>(() => QuotationDeltaPhysicalSchemaGuard.RequireFinalSchema(source,
            ReviewedQuotationPhysicalSchemaResolver.GetExpected(source, ReviewedQuotationPhysicalVariant.RetainedOutboxes)));
    }
}
