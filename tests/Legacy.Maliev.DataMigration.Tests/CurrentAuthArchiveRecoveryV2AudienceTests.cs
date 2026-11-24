using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveRecoveryV2AudienceTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("audience")]
    [InlineData("seed")]
    [InlineData("case")]
    [InlineData("source")]
    [InlineData("expiry")]
    public void Case_binding_preserves_original_bytes_and_intended_rows_remain_distinct(string fault)
    {
        DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var original = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now);
        var seed = original.ComponentSubject!.Seed with { CaseId = CurrentAuthArchiveRecoveryV2.CaseId(CurrentAuthArchiveRecoveryV2Case.FirstOnly) };
        var pins = new CurrentAuthArchivePins("unit-review", new('a', 64), "unit-auth", new('b', 64), "unit-evidence", new('c', 64));
        var audience = new CurrentAuthArchiveProofAudienceV2("current-auth-archive-proof-audience-v2", Guid.NewGuid(), seed.AcceptedSourceCommitSha,
            new('d', 64), new('e', 64), CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256,
            seed.CoreAssemblySha256, seed.ConsoleAssemblySha256, seed.TestAssemblySha256, CurrentAuthLocalSessionArchivePolicy.Hash(pins),
            CurrentAuthLocalSessionArchivePolicy.Hash(CurrentAuthArchiveGenuineCases.Inventory()), new('1', 64), new('2', 64), new('3', 64), 0, now, now.AddHours(1));
        CurrentAuthArchiveRecoveryV2.RequireAudience(audience, seed, pins, now);
        Assert.NotEqual(original.DeleteSetSha256, audience.IntendedAuthRowsSha256);
        Assert.NotEqual(original.DeleteCount, audience.IntendedAuthRows);
        // Pure wire operands only; the real factory independently verifies signatures before using these claims.
        var claim = new CurrentAuthArchiveClaim(CurrentAuthArchiveRecoveryV2.AudienceDomain, pins.ReviewKeyId, pins.ReviewFingerprint,
            Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(audience)), "unit-placeholder");
        var binding = new CurrentAuthArchiveRecoveryCaseBindingV2("current-auth-archive-recovery-case-binding-v2", CurrentAuthLocalSessionArchivePolicy.Hash(claim),
            CurrentAuthLocalSessionArchivePolicy.Hash(seed), seed.OperationId, seed.CaseId, seed.SourceSchemaPlanSha256, now, new[] { now.AddMinutes(1), seed.ExpiresAtUtc }.Min());
        binding = fault switch
        {
            "none" => binding,
            "audience" => binding with { AudienceSha256 = new('f', 64) },
            "seed" => binding with { OriginalSeedSha256 = new('f', 64) },
            "case" => binding with { CaseId = CurrentAuthArchiveRecoveryV2.CaseId(CurrentAuthArchiveRecoveryV2Case.SecondOnly) },
            "source" => binding with { OriginalSourceFullSha256 = new('f', 64) },
            "expiry" => binding with { ExpiresAtUtc = seed.ExpiresAtUtc.AddTicks(1) },
            _ => throw new InvalidOperationException(),
        };
        if (fault == "none") { CurrentAuthArchiveRecoveryV2.RequireCaseBinding(binding, claim, seed, CurrentAuthArchiveRecoveryV2Case.FirstOnly, now); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2.RequireCaseBinding(binding, claim, seed, CurrentAuthArchiveRecoveryV2Case.FirstOnly, now)); }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2.RequireAudience(audience with { CaseInventorySha256 = new('f', 64) }, seed, pins, now));
    }
}
