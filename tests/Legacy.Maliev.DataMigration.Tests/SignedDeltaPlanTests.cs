using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SignedDeltaPlanTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public void Produces_and_verifies_exact23_canonical_plan_without_row_values()
    {
        using var signer = new P256MigrationEvidenceSigner("delta-plan-20260908", _key.ExportECPrivateKeyPem());
        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(Request(), signer, Now());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);

        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, Now()));
        Assert.Equal(DatabaseInventory.ActiveDatabases, plan.Databases.Select(database => database.Database));
        Assert.DoesNotContain("private-row-value", System.Text.Json.JsonSerializer.Serialize(plan), StringComparison.Ordinal);
        Assert.Matches("^[0-9a-f]{64}$", DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan));
    }

    [Fact]
    public void Rejects_tampering_in_operations_or_target_fence()
    {
        using var signer = new P256MigrationEvidenceSigner("delta-plan-20260908", _key.ExportECPrivateKeyPem());
        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(Request(), signer, Now());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        DeltaDatabasePlan first = plan.Databases[0];
        DeltaTablePlan table = first.Tables[0];
        DeltaSynchronizationPlan changedCount = plan with
        {
            Databases = [first with { Tables = [table with { InsertCount = table.InsertCount + 1 }] }, .. plan.Databases.Skip(1)],
        };
        DeltaSynchronizationPlan changedFence = plan with { TargetGeneration = "changed-generation" };
        DeltaSynchronizationPlan changedRole = plan with { BackupKeyFingerprintSha256 = new('1', 64) };

        Assert.False(DeltaSynchronizationPlanVerifier.Verify(changedCount, trust, Now()));
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(changedFence, trust, Now()));
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(changedRole, trust, Now()));
    }

    [Theory]
    [InlineData("incomplete-inventory")]
    [InlineData("stale-cutoff")]
    [InlineData("reused-backup-key")]
    [InlineData("reused-authorization-key")]
    public void Refuses_unreviewable_or_role_reused_plan(string scenario)
    {
        using var signer = new P256MigrationEvidenceSigner("delta-plan-20260908", _key.ExportECPrivateKeyPem());
        DeltaPlanSigningRequest request = Request();
        if (scenario == "incomplete-inventory") { request = request with { Databases = request.Databases.Skip(1).ToArray() }; }
        if (scenario == "stale-cutoff") { request = request with { SourceCutoffUtc = Now().AddHours(-27) }; }
        if (scenario == "reused-backup-key") { request = request with { BackupKeyFingerprintSha256 = signer.PublicKeyFingerprintSha256 }; }
        if (scenario == "reused-authorization-key") { request = request with { ExecutionAuthorizationKeyFingerprintSha256 = signer.PublicKeyFingerprintSha256 }; }

        DeltaPlanException exception = Assert.Throws<DeltaPlanException>(
            () => DeltaSynchronizationPlanProducer.Produce(request, signer, Now()));

        Assert.StartsWith("delta_plan_", exception.Code, StringComparison.Ordinal);
    }

    private static DateTimeOffset Now()
    {
        return new(2026, 9, 8, 8, 50, 0, TimeSpan.Zero);
    }

    private static DeltaPlanSigningRequest Request()
    {
        string hashA = new('a', 64);
        string hashB = new('b', 64);
        string hashC = new('c', 64);
        string hashD = new('d', 64);
        CanonicalDeltaOperation[] operations =
        [
            new(DeltaOperationKind.Insert, hashB, hashC, null),
            new(DeltaOperationKind.Update, hashC, hashD, hashA),
            new(DeltaOperationKind.Delete, hashD, null, hashB),
        ];
        string operationsHash = DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(operations);
        IReadOnlyList<DeltaDatabasePlan> databases = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new DeltaDatabasePlan(database,
            [
                new DeltaTablePlan("public.items", 1, 1, 1, 7, operationsHash, operations),
            ]))];
        return new(
            "5ac7d045c51194edd9e64d8564f1b726b001be34",
            Now().AddMinutes(-5),
            hashA,
            hashB,
            hashC,
            "maliev-legacy",
            "legacy-postgres-main",
            "resource-version-123",
            hashD,
            new('e', 64),
            new('f', 64),
            databases)
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.ProductionCloudNativePg,
                "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/uid-1", hashD),
        };
    }

    public void Dispose()
    {
        _key.Dispose();
    }

    [Fact]
    public void Local_aspire_authority_requires_the_dedicated_local_target_identity()
    {
        DateTimeOffset now = Now();
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        DeltaPlanSigningRequest request = Request() with
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/legacy-maliev-exact23-postgres-data", new('9', 64)),
            TargetNamespace = "local-aspire",
            TargetCluster = "legacy-postgres-main-local",
        };

        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(request, signer, now);

        Assert.Equal(DeltaTargetAuthorityKind.LocalAspire, plan.TargetAuthority!.Kind);
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, now));
        _ = Assert.Throws<DeltaPlanException>(() => DeltaSynchronizationPlanProducer.Produce(
            request with { TargetCluster = "legacy-postgres-main" }, signer, now));
    }
}
