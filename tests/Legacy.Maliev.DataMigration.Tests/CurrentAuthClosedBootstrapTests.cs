using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthClosedBootstrapTests
{
    [Fact]
    public void Named_seed_binds_completed_components_target_fleet_and_case_without_self_signature_cycle()
    {
        var seed = Fixture();
        string digest = CurrentAuthClosedBootstrap.SubjectSha256(seed);
        Assert.Equal(digest, CurrentAuthClosedBootstrap.SubjectSha256(seed with { Signature = "excluded-signature-only" }));
        Assert.NotEqual(digest, CurrentAuthClosedBootstrap.SubjectSha256(seed with { NativeComponentSha256 = H('9') }));
        Assert.NotEqual(digest, CurrentAuthClosedBootstrap.SubjectSha256(seed with { RecoveryComponentSha256 = H('9') }));
        Assert.NotEqual(digest, CurrentAuthClosedBootstrap.SubjectSha256(seed with { MaintenanceComponentSha256 = H('9') }));
        Assert.NotEqual(digest, CurrentAuthClosedBootstrap.SubjectSha256(seed with { DefinitionPrecursorSha256 = H('9') }));
        Assert.NotEqual(digest, CurrentAuthClosedBootstrap.SubjectSha256(seed with { TargetGeneration = "different" }));
        Assert.NotEqual(digest, CurrentAuthClosedBootstrap.SubjectSha256(seed with { TargetObservationSha256 = H('9') }));
        Assert.NotEqual(digest, CurrentAuthClosedBootstrap.SubjectSha256(seed with { FleetBeforeSha256 = H('9') }));
        Assert.NotEqual(digest, CurrentAuthClosedBootstrap.SubjectSha256(seed with { NativeBeforeSha256 = H('9') }));
        Assert.NotEqual(digest, CurrentAuthClosedBootstrap.SubjectSha256(seed with { CaseId = "replay" }));
    }

    [Theory]
    [InlineData("future-native")]
    [InlineData("future-recovery")]
    [InlineData("future-maintenance")]
    [InlineData("future-definition")]
    [InlineData("unknown-case")]
    [InlineData("expired")]
    [InlineData("overlong")]
    [InlineData("foreign-owner")]
    public void Seed_rejects_missing_completed_artifacts_bad_case_lease_or_owner(string fault)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("unit-only", key.ExportPkcs8PrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new TrustedAttestationKey(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        var seed = Fixture() with { KeyId = signer.KeyId };
        seed = fault switch
        {
            "future-native" => seed with { NativeComponentSha256 = string.Empty },
            "future-recovery" => seed with { RecoveryComponentSha256 = string.Empty },
            "future-maintenance" => seed with { MaintenanceComponentSha256 = string.Empty },
            "future-definition" => seed with { DefinitionPrecursorSha256 = string.Empty },
            "unknown-case" => seed with { CaseId = "marker-pass" },
            "expired" => seed with { ExpiresAtUtc = DateTimeOffset.UnixEpoch },
            "overlong" => seed with { ExpiresAtUtc = DateTimeOffset.UnixEpoch.AddMinutes(9) },
            _ => seed with { AuthOwnerCommitSha = new('f', 40) }
        };
        seed = seed with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthClosedBootstrap.Payload(seed))) };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthClosedBootstrap.RequireSeed(seed, trust, signer.KeyId,
            signer.PublicKeyFingerprintSha256, DateTimeOffset.UnixEpoch.AddMinutes(1)));
    }

    [Fact]
    public void Genuine_signature_is_required_and_mutation_is_rejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("unit-only", key.ExportPkcs8PrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new TrustedAttestationKey(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        var seed = Fixture() with { KeyId = signer.KeyId };
        DateTimeOffset now = DateTimeOffset.UnixEpoch.AddMinutes(1);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthClosedBootstrap.RequireSeed(seed, trust, signer.KeyId, signer.PublicKeyFingerprintSha256, now));
        seed = seed with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthClosedBootstrap.Payload(seed))) };
        CurrentAuthClosedBootstrap.RequireSeed(seed, trust, signer.KeyId, signer.PublicKeyFingerprintSha256, now);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthClosedBootstrap.RequireSeed(seed with { NativeBeforeSha256 = H('9') }, trust,
            signer.KeyId, signer.PublicKeyFingerprintSha256, now));
    }

    private static string H(char c)
    {
        return new(c, 64);
    }

    private static CurrentAuthClosedBootstrapSeed Fixture()
    {
        return new("current-auth-genuine-named-closed-bootstrap-seed-v1",
            new Guid("11111111-2222-3333-4444-555555555555"), "success", new('a', 40), H('b'), ApprovedCurrentAuthSchema.AuthServiceCommit,
            CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256, H('c'), H('d'), H('e'), H('f'), H('1'),
            H('2'), H('3'), H('4'), H('5'), H('6'), "unit-only-generation", H('7'), H('8'), DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch.AddMinutes(8), "unit-only", null);
    }
}
