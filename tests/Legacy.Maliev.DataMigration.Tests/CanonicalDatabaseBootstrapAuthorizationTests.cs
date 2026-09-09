using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CanonicalDatabaseBootstrapAuthorizationTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public void Producer_issues_a_short_lived_single_database_authorization()
    {
        DateTimeOffset now = new(2026, 9, 9, 2, 30, 0, TimeSpan.Zero);
        using var signer = new P256MigrationEvidenceSigner("canonical-bootstrap", _key.ExportECPrivateKeyPem());
        DatabaseSchemaPlan schema = Schema("ContactRequest");
        DeltaTargetAuthority authority = Authority();

        CanonicalDatabaseBootstrapAuthorization authorization =
            CanonicalDatabaseBootstrapAuthorizationProducer.Produce(
                schema,
                "legacy-postgres-contact-request",
                "database-uid-1",
                "17",
                authority,
                now,
                now.AddMinutes(10),
                signer);

        Assert.Equal("1.0", authorization.SchemaVersion);
        Assert.Equal("ContactRequest", authorization.Database);
        Assert.Equal("legacy-postgres-contact-request", authorization.DatabaseResourceName);
        Assert.Equal("database-uid-1", authorization.DatabaseResourceUid);
        Assert.Equal("17", authorization.DatabaseResourceGeneration);
        Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(schema), authorization.TargetSchemaSha256);
        Assert.Equal(authority, authorization.TargetAuthority);
        Assert.NotNull(authorization.AttestationSignature);
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("wrong-database")]
    [InlineData("wrong-schema")]
    [InlineData("wrong-resource")]
    [InlineData("wrong-authority")]
    [InlineData("tampered-signature")]
    public async Task Gate_rejects_stale_or_mismatched_bootstrap_authorization(string scenario)
    {
        DateTimeOffset now = new(2026, 9, 9, 2, 30, 0, TimeSpan.Zero);
        using var signer = new P256MigrationEvidenceSigner("canonical-bootstrap", _key.ExportECPrivateKeyPem());
        DatabaseSchemaPlan schema = Schema("ContactRequest");
        DeltaTargetAuthority authority = Authority();
        CanonicalDatabaseBootstrapAuthorization authorization =
            CanonicalDatabaseBootstrapAuthorizationProducer.Produce(
                schema,
                "legacy-postgres-contact-request",
                "database-uid-1",
                "17",
                authority,
                now.AddMinutes(-1),
                now.AddMinutes(9),
                signer);
        authorization = scenario switch
        {
            "expired" => authorization with { ExpiresAtUtc = now },
            "wrong-database" => authorization with { Database = "LocationData" },
            "wrong-schema" => authorization with { TargetSchemaSha256 = Hash('9') },
            "wrong-resource" => authorization with { DatabaseResourceUid = "database-uid-2" },
            "wrong-authority" => authorization with { TargetAuthority = authority with { AuthorityId = "gke://other" } },
            "tampered-signature" => authorization with { AttestationSignature = Convert.ToBase64String([1, 2, 3]) },
            _ => authorization,
        };
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        var gate = new SignedCanonicalDatabaseBootstrapAuthorizationGate(
            authorization, trust, new FixedTime(now));

        CanonicalDatabaseBootstrapException error = await Assert.ThrowsAsync<CanonicalDatabaseBootstrapException>(() =>
            gate.ValidateAsync(new(
                schema,
                "legacy-postgres-contact-request",
                "database-uid-1",
                "17",
                authority),
                CancellationToken.None));

        Assert.Equal("canonical_database_bootstrap_authorization_invalid", error.Code);
    }

    [Fact]
    public void Producer_rejects_non_inventory_database_and_long_authorization()
    {
        DateTimeOffset now = new(2026, 9, 9, 2, 30, 0, TimeSpan.Zero);
        using var signer = new P256MigrationEvidenceSigner("canonical-bootstrap", _key.ExportECPrivateKeyPem());

        CanonicalDatabaseBootstrapException unknown = Assert.Throws<CanonicalDatabaseBootstrapException>(() =>
            CanonicalDatabaseBootstrapAuthorizationProducer.Produce(
                Schema("Unknown"), "legacy-postgres-unknown", "database-uid-1", "17",
                Authority(), now, now.AddMinutes(10), signer));
        Assert.Equal("canonical_database_bootstrap_authorization_request_invalid", unknown.Code);

        CanonicalDatabaseBootstrapException longLived = Assert.Throws<CanonicalDatabaseBootstrapException>(() =>
            CanonicalDatabaseBootstrapAuthorizationProducer.Produce(
                Schema("ContactRequest"), "legacy-postgres-contact-request", "database-uid-1", "17",
                Authority(), now, now.AddMinutes(16), signer));
        Assert.Equal("canonical_database_bootstrap_authorization_request_invalid", longLived.Code);
    }

    private static DatabaseSchemaPlan Schema(string database)
    {
        var table = new TableCopyPlan("dbo", "Items", "public", "Items", ["Id"], ["Id"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Id"] = "integer" },
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Id"] = "int" },
            PrimaryKey = new("PK_Items", ["Id"]),
        };
        var draft = new DatabaseSchemaPlan(database, "1", Hash('1'), string.Empty, [table]);
        return draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
    }

    private static DeltaTargetAuthority Authority()
    {
        return new(
        DeltaTargetAuthorityKind.ProductionCloudNativePg,
        "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/cluster-uid",
        Hash('8'));
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    public void Dispose()
    {
        _key.Dispose();
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
