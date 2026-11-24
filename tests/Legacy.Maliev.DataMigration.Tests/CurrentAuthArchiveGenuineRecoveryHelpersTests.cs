using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineRecoveryHelpersTests
{
    [Theory]
    [InlineData("dual-durable-readback")]
    [InlineData("first-only-recovery")]
    [InlineData("second-only-recovery")]
    [InlineData("key-corruption")]
    [InlineData("cipher-corruption")]
    public void Fresh_helper_seed_signature_binds_the_exact_fixed_case(string caseId)
    {
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var reviewer = new P256MigrationEvidenceSigner("unit-helper-review", reviewKey.ExportPkcs8PrivateKeyPem());
        static string Fingerprint(ECDsa key)
        {
            return Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
        }

        var pins = new CurrentAuthArchivePins(reviewer.KeyId, reviewer.PublicKeyFingerprintSha256,
            "unit-helper-authorization", Fingerprint(authorizationKey), "unit-helper-evidence", Fingerprint(evidenceKey));
        var trust = new ReceiptAttestationTrustStore([
            new(reviewer.KeyId, reviewKey.ExportSubjectPublicKeyInfo()),
            new(pins.AuthorizationKeyId, authorizationKey.ExportSubjectPublicKeyInfo()),
            new(pins.EvidenceKeyId, evidenceKey.ExportSubjectPublicKeyInfo()),
        ]);
        DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var seed = new CurrentAuthArchiveComponentBootstrapSeed("current-auth-genuine-archive-component-seed-v1", Guid.NewGuid(), caseId,
            new string('a', 40), new string('b', 64), ApprovedCurrentAuthSchema.AuthServiceCommit,
            CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256,
            new string('c', 64), new string('d', 64), new string('e', 64), new string('1', 64), new string('2', 64), new string('3', 64),
            CurrentAuthLocalSessionArchivePolicy.Hash(pins), now, now.AddMinutes(8), pins.ReviewKeyId, null);
        seed = seed with { Signature = Convert.ToBase64String(reviewer.Sign(CurrentAuthArchiveComponentBootstrap.SeedPayload(seed))) };
        var expected = CurrentAuthArchiveGenuineRecoveryHelpers.Parse(caseId);
        CurrentAuthArchiveGenuineRecoveryHelpers.RequireInitialSeed(seed, pins, trust, expected, now);
        var other = expected == CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery
            ? CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery : CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery;
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineRecoveryHelpers.RequireInitialSeed(seed, pins, trust, other, now));
        var relabeled = seed with { CaseId = CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(other) };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineRecoveryHelpers.RequireInitialSeed(relabeled, pins, trust, other, now));
        if (caseId != "dual-durable-readback")
        { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveComponentBootstrap.RequireInitialSeed(seed, pins, trust, now)); }
    }

    [Theory]
    [InlineData("complete")]
    [InlineData("first-only-decrypt-insert-readback")]
    [InlineData("FIRST-ONLY-RECOVERY")]
    [InlineData("")]
    public void Native_delete_recovery_and_unknown_cases_cannot_select_helper_faults(string value)
    { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineRecoveryHelpers.Parse(value)); }

    [Fact]
    public async Task Cancelled_provider_runner_stops_before_files_or_owned_resources()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAuthArchiveGenuineRecoveryHelpersRunner.ExecuteAsync(
            "untrusted", CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption, cancelled.Token));
    }
}
