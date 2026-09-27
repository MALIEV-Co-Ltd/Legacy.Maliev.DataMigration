namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ProductionSchemaComponentDiagnosticsTests
{
    [Fact]
    public void Compare_LabelsEachFacetWithoutInferringDdl()
    {
        var plan = new TableCopyPlan("dbo", "Sample", "public", "Sample", ["ID"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string> { ["ID"] = "integer" },
        };
        ProductionSchemaTableComponents expected = PostgreSqlSchemaFingerprint.ComputeExpectedComponents(plan);
        var observation = new ProductionSchemaObservation("Test", [new ObservedTargetTable("public", "Sample", ["ID"])],
            new string('a', 64))
        {
            TableComponents = [expected with { IndexesSha256 = new string('b', 64),
                WholeTableSha256 = new string('c', 64) }],
        };

        ProductionSchemaTableDiagnostic result = Assert.Single(
            ProductionSchemaComponentDiagnostics.Compare([plan], observation));
        Assert.Equal("shape-drift", result.Status);
        Assert.Equal(["indexes", "whole-table"], result.ChangedComponents);
    }

    [Fact]
    public void Compare_RequiresCompleteCatalogAndReportsMissingTables()
    {
        var plan = new TableCopyPlan("dbo", "Sample", "public", "Sample", ["ID"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string> { ["ID"] = "integer" },
        };
        var empty = new ProductionSchemaObservation("Test", [], new string('a', 64));
        Assert.Equal("missing-table", Assert.Single(
            ProductionSchemaComponentDiagnostics.Compare([plan], empty)).Status);
        var incomplete = empty with { Tables = [new ObservedTargetTable("public", "Sample", ["ID"])] };
        Assert.Equal("production_schema_components_incomplete", Assert.Throws<MigrationExecutionException>(
            () => ProductionSchemaComponentDiagnostics.Compare([plan], incomplete)).Code);
        var duplicate = empty with
        {
            Tables = [new ObservedTargetTable("public", "Sample", ["ID"]),
                new ObservedTargetTable("public", "Sample", ["ID"])],
            TableComponents = [PostgreSqlSchemaFingerprint.ComputeExpectedComponents(plan),
                PostgreSqlSchemaFingerprint.ComputeExpectedComponents(plan)],
        };
        Assert.Equal("production_schema_components_incomplete", Assert.Throws<MigrationExecutionException>(
            () => ProductionSchemaComponentDiagnostics.Compare([plan], duplicate)).Code);
    }
}
