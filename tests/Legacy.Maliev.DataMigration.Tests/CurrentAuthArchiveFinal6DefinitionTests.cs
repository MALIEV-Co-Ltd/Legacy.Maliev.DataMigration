using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveFinal6DefinitionTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("old-kind")]
    [InlineData("old-audience")]
    [InlineData("old-source")]
    [InlineData("foreign-parent")]
    [InlineData("foreign-anchor")]
    [InlineData("foreign-baseline")]
    [InlineData("foreign-absence")]
    [InlineData("missing-native")]
    [InlineData("missing-physical")]
    [InlineData("foreign-physical")]
    [InlineData("before-source")]
    [InlineData("after-case")]
    [InlineData("expired-source")]
    public void Definition_header_requires_distinct_source_family_exact_owned_roots_and_original_source_window(string fault)
    {
        var now = new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "structural-final6-definition"));
        var parent = new LocalExecutionBinding(1, "structural-only", "structural-only", root, "structural-only", "lock", "structural-only", 1);
        Guid operation = Guid.NewGuid(); string anchor = Path.Combine(root, "auth-definition-anchor-" + operation.ToString("N"));
        string prefix = Path.Combine(root, "archive-definition-anchor-" + operation.ToString("N")); string hash = new('a', 64);
        CurrentAuthArchiveProofArtifact File(string name)
        {
            return new(Path.Combine(anchor, name), hash);
        }

        var native = new CurrentAuthArchiveFreshDefinition(File("binding.json"), File("scope.json"), File("source.json"), File("helper.json"), hash);
        var plan = new FreshSchemaPlan("2.0", now.AddMinutes(-1), new('b', 40), []);
        var source = new CurrentAuthArchiveFinal6SourceEvidence(CurrentAuthArchiveFinal6Source.Kind,
            new(plan, hash, hash, hash, now.AddMinutes(-1), now.AddSeconds(-20), []));
        var value = new CurrentAuthArchiveFinal6Definition(CurrentAuthArchiveFinal6DefinitionReader.Kind, operation, parent.ComputeSha256(), hash, hash,
            native, new(Path.Combine(anchor, "baseline.json"), hash), File("native.json"), new(prefix + "-intent.json", hash),
            new(prefix + "-container.json", hash), new(prefix + "-volume.json", hash), new(prefix + "-absence.json", hash),
            DatabaseInventory.ActiveDatabases.Select(database => File("auth-final6-template-physical-" + database + ".json")).ToArray(), now.AddSeconds(-1));
        byte[] original = JsonSerializer.SerializeToUtf8Bytes(value);
        value = fault switch
        {
            "old-kind" => value with { Kind = "current-auth-helper-definition-proof-v1" },
            "old-audience" => value with { AudienceSha256 = new('f', 64) },
            "old-source" => value with { SourceFullSha256 = new('f', 64) },
            "foreign-parent" => value with { ParentBindingSha256 = new('f', 64) },
            "foreign-anchor" => value with { AnchorOperationId = Guid.NewGuid() },
            "foreign-baseline" => value with { AnchorBaseline = value.AnchorBaseline with { Path = Path.Combine(root, "baseline.json") } },
            "foreign-absence" => value with { Absence = value.Absence with { Path = prefix + "-other-absence.json" } },
            "missing-native" => value with { AnchorNative = value.AnchorNative with { Sha256 = "" } },
            "missing-physical" => value with { SourcePhysical = value.SourcePhysical.Skip(1).ToArray() },
            "foreign-physical" => value with { SourcePhysical = [value.SourcePhysical[0] with { Path = Path.Combine(root, "physical.json") }, .. value.SourcePhysical.Skip(1)] },
            "before-source" => value with { PublishedAtUtc = source.Capture.CompletedAtUtc.AddTicks(-1) },
            "after-case" => value with { PublishedAtUtc = now.AddTicks(1) },
            _ => value,
        };
        if (fault == "none")
        {
            // Header congruence only. The real reader additionally authenticates claims, full source6, actual TRX/native facts and cleanup.
            CurrentAuthArchiveFinal6DefinitionReader.RequireHeader(value, parent, source, hash, now);
            Assert.Equal(original, JsonSerializer.SerializeToUtf8Bytes(value));
        }
        else
        {
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6DefinitionReader.RequireHeader(value, parent, source,
            hash, fault == "expired-source" ? now.AddMinutes(5) : now));
        }
    }

    [Fact]
    public void Old_template_preparation_remains_phase3_only()
    {
        var old = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        CurrentAuthClosedTemplate.RequirePhase3Source(old);
        var changed = old with
        {
            Databases = [.. old.Databases.Select(database => database.Database == "Country" ? database with
        { TargetExtensionProfile = CurrentConsumerSchemaV3SourceOrderIsoManifest.Country } : database)]
        };
        byte[] original = JsonSerializer.SerializeToUtf8Bytes(changed);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthClosedTemplate.RequirePhase3Source(changed));
        Assert.Equal(original, JsonSerializer.SerializeToUtf8Bytes(changed));
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<CurrentAuthArchiveFinal6IntendedObservationRuntime>("{\"Verified\":true}"));
    }
}
