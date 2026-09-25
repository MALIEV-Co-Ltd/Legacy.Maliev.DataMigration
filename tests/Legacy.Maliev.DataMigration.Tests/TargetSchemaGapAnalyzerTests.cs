namespace Legacy.Maliev.DataMigration.Tests;

public sealed class TargetSchemaGapAnalyzerTests
{
    [Fact]
    public void ReportsMissingObjectsWithoutTreatingTargetOnlyTablesAsDeletions()
    {
        DatabaseSchemaPlan desired = Plan(
            new TableCopyPlan("dbo", "Country", "public", "Country", ["ID", "Name"], ["ID"]),
            new TableCopyPlan("dbo", "sysdiagrams", "public", "sysdiagrams", ["diagram_id"], ["diagram_id"]));
        ObservedTargetTable[] observed =
        [
            new("public", "Country", ["ID", "LegacyCode"]),
            new("public", "RuntimeCache", ["Key"]),
        ];

        TargetSchemaGap gap = TargetSchemaGapAnalyzer.Analyze(desired, observed);

        Assert.Equal(["public.sysdiagrams"], gap.MissingTables);
        Assert.Equal(["public.Country.Name"], gap.MissingColumns);
        Assert.Equal(["public.RuntimeCache"], gap.TargetOnlyTables);
        Assert.Equal(["public.Country.LegacyCode"], gap.TargetOnlyColumns);
        Assert.True(gap.HasDifferences);
    }

    [Fact]
    public void MatchingNamesAreOnlyA_PreliminaryCheck_NotFingerprintEvidence()
    {
        DatabaseSchemaPlan desired = Plan(
            new TableCopyPlan("dbo", "Country", "public", "Country", ["ID", "Name"], ["ID"]));

        TargetSchemaGap gap = TargetSchemaGapAnalyzer.Analyze(desired,
            [new ObservedTargetTable("public", "Country", ["Name", "ID"])]);

        Assert.False(gap.HasDifferences);
    }

    [Fact]
    public void DuplicateObservedColumnsFailClosed()
    {
        DatabaseSchemaPlan desired = Plan(
            new TableCopyPlan("dbo", "Country", "public", "Country", ["ID"], ["ID"]));

        _ = Assert.Throws<ArgumentException>(() => TargetSchemaGapAnalyzer.Analyze(desired,
            [new ObservedTargetTable("public", "Country", ["ID", "ID"])]));
    }

    private static DatabaseSchemaPlan Plan(params TableCopyPlan[] tables)
    {
        return new("Country", "1.0", new string('a', 64), new string('b', 64), tables);
    }
}
