using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class TargetExtensionRepairAuthorizationTests
{
    [Theory]
    [InlineData("expired")]
    [InlineData("wrong-target")]
    [InlineData("wrong-schema")]
    [InlineData("wrong-set")]
    [InlineData("tampered-signature")]
    public void Gate_RejectsStaleOrChangedDdlAuthority(string scenario)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("extension-authorization", key.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        DateTimeOffset now = new(2026, 9, 26, 12, 0, 0, TimeSpan.Zero);
        DatabaseSchemaPlan schema = Schema();
        DeltaTargetAuthority authority = new(DeltaTargetAuthorityKind.LocalAspire,
            "aspire://legacy-postgres-main-local/disposable-test", new string('a', 64));
        TargetExtensionRepairAuthorization signed = TargetExtensionRepairAuthorizationProducer.Produce(
            schema, new string('d', 40), authority, "public.Country;public.Currency", now.AddMinutes(-1),
            now.AddMinutes(9), signer);
        TargetExtensionRepairAuthorization altered = scenario switch
        {
            "expired" => signed with { ExpiresAtUtc = now },
            "wrong-target" => signed with { TargetAuthority = authority with { SystemIdentifierSha256 = new string('b', 64) } },
            "wrong-schema" => signed with { TargetSchemaSha256 = new string('b', 64) },
            "wrong-set" => signed with { ReviewedMissingTables = "public.Country" },
            "tampered-signature" => signed with { AttestationSignature = Convert.ToBase64String([1, 2, 3]) },
            _ => signed,
        };

        Assert.False(TargetExtensionRepairAuthorizationVerifier.Verify(
            altered, schema, new string('d', 40), authority, "public.Country;public.Currency", trust, now));
        Assert.True(TargetExtensionRepairAuthorizationVerifier.Verify(
            signed, schema, new string('d', 40), authority, "public.Country;public.Currency", trust, now));
    }

    private static DatabaseSchemaPlan Schema()
    {
        var table = new TableCopyPlan("dbo", "Probe", "public", "Probe", ["ID"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["ID"] = "integer" },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Probe", ["ID"]),
        };
        var draft = new DatabaseSchemaPlan("Material", "1.0", new string('c', 64),
            new string('0', 64), [table])
        { TargetExtensionProfile = ApprovedTargetExtensionManifest.MaterialCatalogV1 };
        return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
    }
}
