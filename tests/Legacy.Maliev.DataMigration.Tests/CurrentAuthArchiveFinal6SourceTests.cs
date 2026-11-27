using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveFinal6SourceTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("expired")]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("reverse")]
    [InlineData("before-plan")]
    [InlineData("closed-before-open")]
    [InlineData("after-completion")]
    [InlineData("future")]
    [InlineData("offset")]
    public void Actual_per_database_window_contract_preserves_all_independent_clocks(string fault)
    {
        var now = new DateTimeOffset(2031, 1, 1, 1, 0, 0, TimeSpan.Zero);
        var plan = new FreshSchemaPlan("2.0", now.AddMinutes(-1), new string('a', 40), []);
        var windows = DatabaseInventory.ActiveDatabases.Select((name, index) =>
            new CurrentAuthArchiveRecoverySourceWindow(name, plan.CapturedAtUtc.AddSeconds(index),
                plan.CapturedAtUtc.AddSeconds(index).AddMilliseconds(1), plan.CapturedAtUtc.AddSeconds(index).AddMilliseconds(2))).ToArray();
        var source = new CurrentAuthArchiveRecoverySourceEvidence(plan, new('b', 64), new('c', 64), new('d', 64),
            plan.CapturedAtUtc.AddMilliseconds(-1), now.AddSeconds(-1), windows);
        byte[] original = JsonSerializer.SerializeToUtf8Bytes(source);
        source = fault switch
        {
            "expired" => source with { BeganAtUtc = now.AddMinutes(-6) },
            "missing" => source with { Windows = windows.Skip(1).ToArray() },
            "duplicate" => source with { Windows = [windows[0], windows[0], .. windows.Skip(2)] },
            "reverse" => source with { Windows = windows.Reverse().ToArray() },
            "before-plan" => source with { Windows = [windows[0] with { BeginRequestedAtUtc = plan.CapturedAtUtc.AddTicks(-1) }, .. windows.Skip(1)] },
            "closed-before-open" => source with { Windows = [windows[0] with { SnapshotClosedAtUtc = windows[0].BeginRequestedAtUtc }, .. windows.Skip(1)] },
            "after-completion" => source with { CompletedAtUtc = windows[^1].SnapshotClosedAtUtc.AddTicks(-1) },
            "future" => source with { CompletedAtUtc = now.AddTicks(1) },
            "offset" => source with { BeganAtUtc = source.BeganAtUtc.ToOffset(TimeSpan.FromHours(7)) },
            _ => source,
        };
        if (fault == "none")
        {
            CurrentAuthArchiveFinal6Source.RequireWindows(source, now);
            Assert.Equal(original, JsonSerializer.SerializeToUtf8Bytes(source));
        }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6Source.RequireWindows(source, now)); }
    }

    [Theory]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV3)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV2)]
    public void An_old_profile_plan_cannot_be_adopted_as_a_final6_capture(ConsumerOverlaySelection selection)
    {
        var plan = CurrentConsumerSchemaV2Tests.Schema(selection);
        byte[] original = JsonSerializer.SerializeToUtf8Bytes(plan);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6Source.RequireProfiles(plan, plan.CapturedAtUtc));
        Assert.Equal(original, JsonSerializer.SerializeToUtf8Bytes(plan));
    }

    [Fact]
    public void A_serialized_positive_capture_cannot_create_the_live_actual_source_holder()
    {
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentAuthArchiveFinal6SourceCapture.Captured>(
            "{\"Verified\":true,\"Profile\":6,\"Kind\":\"current-auth-archive-final6-actual-source-v1\"}"));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("phase3-kind")]
    [InlineData("source")]
    [InlineData("definition")]
    [InlineData("owner")]
    [InlineData("signing")]
    [InlineData("inventory")]
    [InlineData("target")]
    [InlineData("rows")]
    [InlineData("expired")]
    [InlineData("extended")]
    public void Final6_audience_is_a_new_current_baseline_contract_and_is_not_an_old_proof(string fault)
    {
        var now = new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var pins = new CurrentAuthArchivePins("review", new('1', 64), "authorization", new('2', 64), "evidence", new('3', 64));
        var audience = Audience(now, pins);
        audience = fault switch
        {
            "phase3-kind" => audience with { Kind = "current-auth-archive-proof-audience-v2" },
            "source" => audience with { SourceIdentitySha256 = "" },
            "definition" => audience with { SourceDefinitionSha256 = "" },
            "owner" => audience with { OwnerPinsSha256 = new('f', 64) },
            "signing" => audience with { SigningPinsSha256 = new('f', 64) },
            "inventory" => audience with { CaseInventorySha256 = new('f', 64) },
            "target" => audience with { IntendedComparisonIdentitySha256 = audience.IntendedLocalIdentitySha256 },
            "rows" => audience with { IntendedAuthRows = -1 },
            "expired" => audience with { ExpiresAtUtc = now },
            "extended" => audience with { ExpiresAtUtc = now.AddHours(13) },
            _ => audience,
        };
        if (fault == "none") { CurrentAuthArchiveFinal6AudiencePolicy.Require(audience, pins, now); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6AudiencePolicy.Require(audience, pins, now)); }
    }

    [Fact]
    public void Final6_audience_signatures_cannot_be_replayed_under_the_phase3_domain()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("review", key.ExportPkcs8PrivateKeyPem());
        var pins = new CurrentAuthArchivePins(signer.KeyId, signer.PublicKeyFingerprintSha256, "authorization", new('2', 64), "evidence", new('3', 64));
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, key.ExportSubjectPublicKeyInfo())]);
        var audience = Audience(DateTimeOffset.UtcNow, pins);
        var claim = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveFinal6AudiencePolicy.Domain, audience, signer);
        Assert.Equal(audience, CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(claim,
            CurrentAuthArchiveFinal6AudiencePolicy.Domain, signer.KeyId, signer.PublicKeyFingerprintSha256, trust));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveProofAudienceV2>(claim,
            CurrentAuthArchiveRecoveryV2.AudienceDomain, signer.KeyId, signer.PublicKeyFingerprintSha256, trust));
    }

    private static CurrentAuthArchiveFinal6Audience Audience(DateTimeOffset now, CurrentAuthArchivePins pins)
    {
        return new(
        CurrentAuthArchiveFinal6AudiencePolicy.Kind, Guid.NewGuid(), new('a', 40), new('b', 64), new('c', 64),
        CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256, new('d', 64), new('e', 64), new('f', 64),
        CurrentAuthLocalSessionArchivePolicy.Hash(pins), CurrentAuthLocalSessionArchivePolicy.Hash(CurrentAuthArchiveGenuineCases.Inventory()),
        new('4', 64), new('5', 64), new('6', 64), 2, now, now.AddHours(1));
    }
}
