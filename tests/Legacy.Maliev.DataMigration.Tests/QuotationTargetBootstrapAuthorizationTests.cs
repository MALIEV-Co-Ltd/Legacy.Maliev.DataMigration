using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class QuotationTargetBootstrapAuthorizationTests
{
    [Theory]
    [InlineData("expired")]
    [InlineData("wrong-source")]
    [InlineData("wrong-schema")]
    [InlineData("wrong-source-schema")]
    [InlineData("wrong-transition")]
    [InlineData("wrong-target")]
    [InlineData("wrong-set")]
    [InlineData("tampered-signature")]
    public void Gate_RejectsChangedOrExpiredDdlAuthority(string scenario)
    {
        TableCopyPlan[] tables =
        [
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        var draft = new DatabaseSchemaPlan("Quotation", "1.0", new string('a', 64), new string('0', 64), tables)
        {
            SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
            SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables),
        };
        DatabaseSchemaPlan schema = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("quotation-bootstrap", key.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        var authority = new DeltaTargetAuthority(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/disposable-test", new string('b', 64));
        DateTimeOffset now = new(2026, 9, 26, 12, 0, 0, TimeSpan.Zero);
        string commit = new string('c', 40);
        QuotationTargetBootstrapAuthorization signed = QuotationTargetBootstrapAuthorizationProducer.Produce(
            schema, commit, authority, now.AddMinutes(-1), now.AddMinutes(9), signer);
        Assert.True(QuotationTargetBootstrapAuthorizationVerifier.Verify(signed, schema, commit, authority,
            trust, now));
        QuotationTargetBootstrapAuthorization altered = scenario switch
        {
            "expired" => signed with { ExpiresAtUtc = now },
            "wrong-source" => signed with { SourceCommitSha = new string('d', 40) },
            "wrong-schema" => signed with { TargetSchemaSha256 = new string('d', 64) },
            "wrong-source-schema" => signed with { SourceSchemaSha256 = new string('d', 64) },
            "wrong-transition" => signed with { TransitionSchemaSha256 = new string('d', 64) },
            "wrong-target" => signed with { TargetAuthority = authority with { SystemIdentifierSha256 = new string('d', 64) } },
            "wrong-set" => signed with { ReviewedMissingTables = "public.QuotationAcceptedOutcome" },
            "tampered-signature" => signed with { AttestationSignature = Convert.ToBase64String([1, 2, 3]) },
            _ => signed,
        };
        Assert.False(QuotationTargetBootstrapAuthorizationVerifier.Verify(altered, schema, commit, authority,
            trust, now));
    }
}
