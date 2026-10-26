namespace Legacy.Maliev.DataMigration.Tests;

// Synthetic pre-effect contracts only; these do not establish native fixture observations.
public sealed class CurrentAuthArchiveFixtureSeedTests
{
    private static readonly DateTimeOffset Now = new(2031, 1, 1, 1, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Seed_input_requires_same_original_source_and_exact_side_inventory(bool comparison)
    {
        FreshSchemaPlan source = Source();
        var settings = CurrentAuthArchiveFixtureTarget.Settings(Guid.NewGuid(), comparison, new string('a', 64), Now);
        CurrentAuthArchiveFixtureSeed.RequireInput(source, source, comparison, settings.Databases, Now);
    }

    [Theory]
    [InlineData(false, 3)]
    [InlineData(true, 26)]
    public void Synthetic_private_sentinels_are_confined_to_fixed_non_source_databases(bool comparison, int expected)
    {
        FreshSchemaPlan source = Source();
        IReadOnlyList<string> names = CurrentAuthArchiveFixtureSeed.PrivateSentinelDatabases(source, comparison);
        Assert.Equal(expected, names.Count);
        Assert.Contains("Auth", names); Assert.Contains("postgres", names);
        Assert.DoesNotContain(names, name => source.Databases.Any(database => database.Database == name));
        var settings = CurrentAuthArchiveFixtureTarget.Settings(Guid.NewGuid(), comparison, new string('a', 64), Now);
        Assert.Equal(settings.Databases.Where(name => !source.Databases.Any(database => database.Database == name)).Order(StringComparer.Ordinal),
            names.Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("changed-source")]
    [InlineData("missing-fingerprint")]
    [InlineData("mixed-profile")]
    [InlineData("expired")]
    [InlineData("swapped-side")]
    [InlineData("renamed-database")]
    public void Seed_input_rejects_source_or_inventory_drift_before_effects(string fault)
    {
        FreshSchemaPlan source = Source();
        FreshSchemaPlan held = fault switch
        {
            "changed-source" => source with { SourceCommitSha = new string('b', 40) },
            "missing-fingerprint" => source with { Databases = source.Databases.Select((d, i) => i == 0 ? d with { TargetSchemaSha256 = "" } : d).ToArray() },
            "mixed-profile" => source with { Databases = source.Databases.Select((d, i) => i == 0 ? d with { TargetExtensionProfile = "unreviewed" } : d).ToArray() },
            _ => source,
        };
        string[] names = [.. CurrentAuthArchiveFixtureTarget.Settings(Guid.NewGuid(), fault == "swapped-side", new string('a', 64), Now).Databases];
        if (fault == "renamed-database") { names[0] = "unreviewed"; }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFixtureSeed.RequireInput(source, held, false, names,
            fault == "expired" ? Now.AddHours(3) : Now));
    }

    private static FreshSchemaPlan Source()
    {
        return CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3)
        with
        { CapturedAtUtc = Now.AddMinutes(-1) };
    }
}
