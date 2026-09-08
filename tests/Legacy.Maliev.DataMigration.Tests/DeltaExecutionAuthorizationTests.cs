using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DeltaExecutionAuthorizationTests : IDisposable
{
    private readonly ECDsa _planKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Matching_short_lived_authorization_is_accepted_for_exact_inventory()
    {
        DateTimeOffset now = new(2026, 9, 8, 7, 0, 0, TimeSpan.Zero);
        (DeltaSynchronizationPlan plan, P256MigrationEvidenceSigner signer) = Plan(now);
        using (signer)
        using (var authorizer = new P256MigrationEvidenceSigner("authorization", _authorizationKey.ExportECPrivateKeyPem()))
        {
            DeltaExecutionAuthorization authorization = DeltaExecutionAuthorizationProducer.Produce(
                plan, now.AddMinutes(-1), now.AddMinutes(9), authorizer);
            var trust = new ReceiptAttestationTrustStore([new(authorizer.KeyId, authorizer.ExportSubjectPublicKeyInfo())]);
            var gate = new SignedDeltaExecutionAuthorizationGate(authorization, trust, new FixedTime(now));

            await gate.ValidateAsync(plan, DatabaseInventory.ActiveDatabases[0], CancellationToken.None);
        }
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("wrong-plan")]
    [InlineData("wrong-target")]
    [InlineData("missing-database")]
    [InlineData("tampered-signature")]
    public async Task Stale_or_mismatched_authorization_is_rejected(string scenario)
    {
        DateTimeOffset now = new(2026, 9, 8, 7, 0, 0, TimeSpan.Zero);
        (DeltaSynchronizationPlan plan, P256MigrationEvidenceSigner signer) = Plan(now);
        using (signer)
        using (var authorizer = new P256MigrationEvidenceSigner("authorization", _authorizationKey.ExportECPrivateKeyPem()))
        {
            DeltaExecutionAuthorization authorization = DeltaExecutionAuthorizationProducer.Produce(
                plan, now.AddMinutes(-1), now.AddMinutes(9), authorizer);
            authorization = scenario switch
            {
                "expired" => authorization with { ExpiresAtUtc = now },
                "wrong-plan" => authorization with { PlanSha256 = Hash('9') },
                "wrong-target" => authorization with { TargetGeneration = "changed" },
                "missing-database" => authorization with { Databases = authorization.Databases.Skip(1).ToArray() },
                "tampered-signature" => authorization with { AttestationSignature = Convert.ToBase64String([1, 2, 3]) },
                _ => authorization,
            };
            var trust = new ReceiptAttestationTrustStore([new(authorizer.KeyId, authorizer.ExportSubjectPublicKeyInfo())]);
            var gate = new SignedDeltaExecutionAuthorizationGate(authorization, trust, new FixedTime(now));

            DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                gate.ValidateAsync(plan, DatabaseInventory.ActiveDatabases[0], CancellationToken.None));
            Assert.Equal("delta_execution_authorization_invalid", error.Code);
        }
    }

    private (DeltaSynchronizationPlan, P256MigrationEvidenceSigner) Plan(DateTimeOffset now)
    {
        var planSigner = new P256MigrationEvidenceSigner("plan", _planKey.ExportECPrivateKeyPem());
        using var authorizationSigner = new P256MigrationEvidenceSigner("authorization", _authorizationKey.ExportECPrivateKeyPem());
        string operations = DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([]);
        DeltaDatabasePlan[] databases = [.. DatabaseInventory.ActiveDatabases.Select(name =>
            new DeltaDatabasePlan(name, [new("public.items", 0, 0, 0, 0, operations, [])]))];
        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(new(
            new string('1', 40), now.AddMinutes(-2), Hash('a'), Hash('b'), Hash('c'), "maliev-legacy",
            "legacy-postgres-main", "generation-1", Hash('d'), Hash('e'),
            authorizationSigner.PublicKeyFingerprintSha256, databases), planSigner, now.AddMinutes(-1));
        return (plan, planSigner);
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    public void Dispose()
    {
        _planKey.Dispose();
        _authorizationKey.Dispose();
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
