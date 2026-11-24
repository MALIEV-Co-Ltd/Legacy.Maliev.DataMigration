using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuinePreflightSeedTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void Signed_original_case_cannot_be_reinterpreted_or_activate_execution(int number)
    {
        var selected = (CurrentAuthArchiveGenuinePreflightCase)number;
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("unit-preflight-review", reviewKey.ExportPkcs8PrivateKeyPem());
        static string Fingerprint(ECDsa key)
        {
            return Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
        }

        var pins = new CurrentAuthArchivePins(signer.KeyId, signer.PublicKeyFingerprintSha256,
            "unit-preflight-auth", Fingerprint(authorizationKey), "unit-preflight-evidence", Fingerprint(evidenceKey));
        var trust = new ReceiptAttestationTrustStore([
            new(signer.KeyId, reviewKey.ExportSubjectPublicKeyInfo()), new(pins.AuthorizationKeyId, authorizationKey.ExportSubjectPublicKeyInfo()),
            new(pins.EvidenceKeyId, evidenceKey.ExportSubjectPublicKeyInfo()),
        ]);
        DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var seed = new CurrentAuthArchiveComponentBootstrapSeed("current-auth-genuine-archive-component-seed-v1", Guid.NewGuid(),
            CurrentAuthArchiveGenuinePreflight.CaseId(selected), new string('a', 40), new string('b', 64),
            ApprovedCurrentAuthSchema.AuthServiceCommit, CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256,
            new string('c', 64), new string('d', 64), new string('e', 64), new string('1', 64), new string('2', 64), new string('3', 64),
            CurrentAuthLocalSessionArchivePolicy.Hash(pins), now, now.AddMinutes(8), pins.ReviewKeyId, null);
        seed = seed with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthArchiveComponentBootstrap.SeedPayload(seed))) };
        CurrentAuthArchiveGenuinePreflight.RequireSeed(seed, pins, trust, selected, now);
        var other = selected == CurrentAuthArchiveGenuinePreflightCase.LocalTrust ? CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk : CurrentAuthArchiveGenuinePreflightCase.LocalTrust;
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireSeed(seed, pins, trust, other, now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireSeed(seed with { CaseId = CurrentAuthArchiveGenuinePreflight.CaseId(other) }, pins, trust, other, now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireSeed(seed with { SourceSchemaPlanSha256 = new('f', 64) }, pins, trust, selected, now));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuinePreflight.RequireSeed(seed, pins, trust, selected, now.AddMinutes(8)));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionCases.RequireImplemented(
            selected == CurrentAuthArchiveGenuinePreflightCase.LocalTrust ? CurrentAuthArchiveGenuineExecutionCase.LocalTrust : CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveComponentBootstrap.RequireInitialSeed(seed, pins, trust, now));
    }
}
