using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class QuotationTargetBootstrapProofTests
{
    [Fact]
    public void Signed_disposable_transition_admits_only_distinct_persistent_target()
    {
        (DatabaseSchemaPlan schema, P256MigrationEvidenceSigner signer,
            ReceiptAttestationTrustStore trust) = Fixture();
        using (signer)
        {
            DateTimeOffset now = new(2026, 9, 26, 16, 0, 0, TimeSpan.Zero);
            DeltaTargetAuthority disposable = Authority("disposable-proof", 'a');
            DeltaTargetAuthority persistent = Authority("persistent-main", 'b');
            QuotationTargetBootstrapProof proof = QuotationTargetBootstrapProofProducer.Produce(
                schema, new string('c', 40), disposable, new string('d', 64), "created", now, signer);

            Assert.True(QuotationTargetBootstrapProofVerifier.Verify(proof, schema, new string('c', 40),
                persistent, trust, now.AddMinutes(1)));
            Assert.False(QuotationTargetBootstrapProofVerifier.Verify(proof, schema, new string('c', 40),
                Authority("persistent-main", 'a'), trust, now.AddMinutes(1)));
            Assert.False(QuotationTargetBootstrapProofVerifier.Verify(proof, schema, new string('c', 40),
                persistent, trust, now.AddHours(13)));
            Assert.False(QuotationTargetBootstrapProofVerifier.Verify(proof with
            {
                TransitionSchemaSha256 = new string('e', 64),
            }, schema, new string('c', 40), persistent, trust, now.AddMinutes(1)));
            Assert.False(QuotationTargetBootstrapProofVerifier.Verify(proof with
            {
                ReviewedMissingTables = "public.QuotationAcceptedOutcome",
            }, schema, new string('c', 40), persistent, trust, now.AddMinutes(1)));
            Assert.Equal("quotation_target_bootstrap_proof_request_invalid",
                Assert.Throws<MigrationExecutionException>(() => QuotationTargetBootstrapProofProducer.Produce(
                    schema, new string('c', 40), persistent, new string('d', 64), "created", now, signer)).Code);
        }
    }

    [Fact]
    public void Persistent_authorization_binds_proof_hash_and_disposable_authorization_cannot_be_promoted()
    {
        (DatabaseSchemaPlan schema, P256MigrationEvidenceSigner signer,
            ReceiptAttestationTrustStore trust) = Fixture();
        using (signer)
        {
            DateTimeOffset now = new(2026, 9, 26, 16, 0, 0, TimeSpan.Zero);
            DeltaTargetAuthority persistent = Authority("persistent-main", 'b');
            string hash = new('e', 64);
            Assert.Equal("quotation_target_bootstrap_authorization_request_invalid",
                Assert.Throws<MigrationExecutionException>(() =>
                    QuotationTargetBootstrapAuthorizationProducer.Produce(schema, new string('c', 40),
                        persistent, now, now.AddMinutes(10), signer)).Code);
            QuotationTargetBootstrapAuthorization authorization =
                QuotationTargetBootstrapAuthorizationProducer.Produce(schema, new string('c', 40),
                    persistent, now, now.AddMinutes(10), signer, hash);
            Assert.Equal("1.1", authorization.SchemaVersion);
            Assert.True(QuotationTargetBootstrapAuthorizationVerifier.Verify(authorization, schema,
                new string('c', 40), persistent, trust, now.AddMinutes(1), hash));
            Assert.False(QuotationTargetBootstrapAuthorizationVerifier.Verify(authorization, schema,
                new string('c', 40), persistent, trust, now.AddMinutes(1), new string('f', 64)));
            Assert.False(QuotationTargetBootstrapAuthorizationVerifier.Verify(authorization, schema,
                new string('c', 40), Authority("disposable-proof", 'a'), trust, now.AddMinutes(1)));
            Assert.False(QuotationTargetBootstrapAuthorizationVerifier.Verify(authorization with
            {
                DisposableProofSha256 = new string('f', 64),
            }, schema, new string('c', 40), persistent, trust, now.AddMinutes(1), hash));
        }
    }

    private static (DatabaseSchemaPlan Schema, P256MigrationEvidenceSigner Signer,
        ReceiptAttestationTrustStore Trust) Fixture()
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
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new P256MigrationEvidenceSigner("quotation-proof", key.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        return (draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) },
            signer, trust);
    }

    private static DeltaTargetAuthority Authority(string suffix, char identity) =>
        new(DeltaTargetAuthorityKind.LocalAspire,
            $"aspire://legacy-postgres-main-local/{suffix}", new string(identity, 64));
}
