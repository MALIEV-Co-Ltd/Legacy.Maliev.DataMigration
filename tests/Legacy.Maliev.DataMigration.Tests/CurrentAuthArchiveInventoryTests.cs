using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveInventoryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Complete_observed_catalogs_bracket_each_fleet_with_fixed_logical_side(bool comparison)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var scope = CurrentAuthLocalSessionArchiveConsoleTests.Scope(now);
        var policy = comparison ? scope.ProductionObservationPolicy : scope.LocalObservationPolicy;
        var catalogs = Catalogs(policy, comparison, now);
        CurrentAuthLocalSessionArchivePolicy.RequireCatalogs(catalogs, policy, comparison, policy.BeforeDatabaseSha256.Keys, now.AddMinutes(-1), now);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("template0")]
    [InlineData("template1")]
    [InlineData("added-template")]
    [InlineData("disabled")]
    [InlineData("renamed")]
    [InlineData("system")]
    [InlineData("writable")]
    [InlineData("binding")]
    [InlineData("target")]
    [InlineData("chronology")]
    [InlineData("stale")]
    [InlineData("snapshot-name")]
    public void Missing_or_drifted_catalog_metadata_cannot_be_imported(string fault)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var policy = CurrentAuthLocalSessionArchiveConsoleTests.Scope(now).ProductionObservationPolicy;
        CurrentAuthArchiveFleetCatalogs? catalogs = Catalogs(policy, true, now);
        var after = catalogs.After; var flags = after.Databases.ToList();
        string[] names = policy.BeforeDatabaseSha256.Keys.ToArray();
        switch (fault)
        {
            case "missing": catalogs = null; break;
            case "template0": flags[flags.FindIndex(x => x.Name == "template0")] = new("template0", true, true); break;
            case "template1": flags[flags.FindIndex(x => x.Name == "template1")] = new("template1", false, true); break;
            case "added-template": flags.Add(new("template2", true, true)); break;
            case "disabled": flags[0] = flags[0] with { AllowsConnections = false }; break;
            case "renamed": flags[0] = flags[0] with { Name = "foreign" }; break;
            case "system": after = after with { SystemIdentifierSha256 = new string('0', 64) }; break;
            case "writable": after = after with { ReadOnly = false }; break;
            case "binding": after = after with { RunBindingSha256 = new string('0', 64) }; break;
            case "target": after = after with { TargetObservationSha256 = new string('0', 64) }; break;
            case "chronology": after = after with { BeganAtUtc = catalogs.CaptureBeganAtUtc }; break;
            case "stale": catalogs = catalogs with { Before = catalogs.Before with { BeganAtUtc = now.AddHours(-1) } }; break;
            case "snapshot-name": names[0] = "foreign"; break;
            default: throw new InvalidOperationException();
        }
        if (catalogs is not null) { catalogs = catalogs with { After = after with { Databases = flags } }; }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchivePolicy.RequireCatalogs(catalogs, policy, true, names, now.AddMinutes(-1), now));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Comparison_after_renamed_database_rejects_even_when_all_row_catalog_and_sequence_facts_are_identical(bool productionFault)
    {
        var before = ReviewedProductionRepairInventory.ExportProductionNames().Select(name => new CurrentAppOwnedDatabaseSnapshot(name, [], [], [])).ToArray();
        var after = before.ToArray(); after[0] = after[0] with { Database = "renamed" };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireComparisonFleetAfter(before, after, productionFault));
    }

    [Fact]
    public void Unchanged_reviewed_comparison_fleet_remains_valid()
    {
        var before = ReviewedProductionRepairInventory.ExportProductionNames().Select(name => new CurrentAppOwnedDatabaseSnapshot(name, [], [], [])).ToArray();
        CurrentAuthArchiveProofReader.RequireComparisonFleetAfter(before, before, false);
    }

    private static CurrentAuthArchiveFleetCatalogs Catalogs(CurrentAuthRepairScope policy, bool comparison, DateTimeOffset now)
    {
        // Synthetic unit operands only; these records never become native execution evidence.
        IReadOnlyList<ReviewedRepairDatabaseFlag> flags = comparison ? ReviewedProductionRepairInventory.ExportProductionCatalog() :
            policy.BeforeDatabaseSha256.Keys.Select(name => new ReviewedRepairDatabaseFlag(name, false, true))
                .Concat([new("template0", true, false), new("template1", true, true)]).ToArray();
        var before = new CurrentAuthArchiveCatalogObservation(policy.RunBindingSha256, policy.TargetObservationSha256,
            policy.Target.SystemIdentifierSha256, true, flags, now.AddSeconds(-8), now.AddSeconds(-7));
        return new(before, before with { BeganAtUtc = now.AddSeconds(-3), EndedAtUtc = now.AddSeconds(-2) }, now.AddSeconds(-6), now.AddSeconds(-4));
    }
}
