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

    [Fact]
    public void ApprovedExtensionsAreDistinguishedFromUnknownAndMissingTargetTables()
    {
        DatabaseSchemaPlan desired = new("Material", "1.0", new string('a', 64), new string('b', 64),
            [new TableCopyPlan("dbo", "Material", "public", "Material", ["ID"], ["ID"])])
        {
            TargetExtensionProfile = ApprovedTargetExtensionManifest.MaterialCatalogV1,
        };

        TargetSchemaGap gap = TargetSchemaGapAnalyzer.Analyze(desired,
        [
            new("public", "Material", ["ID"]),
            new("public", "Country", ["ID", "Name"]),
            new("public", "Unexpected", ["ID"]),
        ]);

        Assert.Equal(["public.Country"], gap.ApprovedTargetExtensions);
        Assert.Equal(["public.Currency"], gap.MissingApprovedTargetExtensions);
        Assert.Equal(["public.Unexpected"], gap.TargetOnlyTables);
        Assert.True(gap.HasDifferences);
    }

    [Fact]
    public void Observed_source_shaped_quotation_outboxes_are_transition_objects_not_reviewed_targets()
    {
        DatabaseSchemaPlan desired = ReviewedQuotationPlan();
        TargetSchemaGap gap = TargetSchemaGapAnalyzer.Analyze(desired,
        [
            new("public", "GoogleAnalyticsOutbox", ["ID"]),
            new("public", "QuotationOutcomeOutbox", ["ID"]),
        ]);

        Assert.Equal(["legacy_compatibility.GoogleAnalyticsOutbox", "public.QuotationAcceptedOutcome"],
            gap.MissingTables);
        Assert.Equal(["public.GoogleAnalyticsOutbox", "public.QuotationOutcomeOutbox"],
            gap.TargetOnlyTables);
        Assert.Equal(gap.TargetOnlyTables, gap.RetainedSourceTransitionTables);
        Assert.True(gap.HasDifferences);
    }

    [Fact]
    public void Reviewed_quotation_targets_present_do_not_report_source_shaped_outboxes_as_missing()
    {
        DatabaseSchemaPlan desired = ReviewedQuotationPlan();
        ObservedTargetTable[] observed = [.. ApprovedSourceDispositionManifest.TargetTablesFor(desired)
            .Select(table => new ObservedTargetTable(table.TargetSchema, table.TargetTable, table.OrderedColumns))];

        TargetSchemaGap gap = TargetSchemaGapAnalyzer.Analyze(desired, observed);

        Assert.False(gap.HasDifferences);
        Assert.Empty(gap.RetainedSourceTransitionTables);
    }

    [Fact]
    public void Ordinary_exact_23_names_still_match_and_approved_extensions_stay_separate()
    {
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            var source = new TableCopyPlan("dbo", "Probe", "public", "Probe", ["ID"], ["ID"]);
            var desired = new DatabaseSchemaPlan(database, "1.0", new string('a', 64),
                new string('b', 64), [source])
            {
                TargetExtensionProfile = ApprovedTargetExtensionManifest.ProfileForDatabase(database),
            };
            ObservedTargetTable[] observed =
            [
                new("public", "Probe", ["ID"]),
                .. ApprovedTargetExtensionManifest.TablesFor(desired)
                    .Select(table => new ObservedTargetTable(table.TargetSchema, table.TargetTable,
                        table.OrderedColumns)),
            ];

            TargetSchemaGap gap = TargetSchemaGapAnalyzer.Analyze(desired, observed);

            Assert.False(gap.HasDifferences);
            Assert.Empty(gap.RetainedSourceTransitionTables);
            Assert.Equal(ApprovedTargetExtensionManifest.TablesFor(desired).Count,
                gap.ApprovedTargetExtensions.Count);
        }
    }

    private static DatabaseSchemaPlan ReviewedQuotationPlan()
    {
        TableCopyPlan[] tables =
        [
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        return new DatabaseSchemaPlan("Quotation", "1.0", new string('a', 64), new string('b', 64), tables)
        {
            SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
            SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables),
        };
    }

    private static DatabaseSchemaPlan Plan(params TableCopyPlan[] tables)
    {
        return new("Country", "1.0", new string('a', 64), new string('b', 64), tables);
    }
}
