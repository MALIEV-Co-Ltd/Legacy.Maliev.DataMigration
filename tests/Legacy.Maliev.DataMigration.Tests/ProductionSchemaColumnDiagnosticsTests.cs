namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ProductionSchemaColumnDiagnosticsTests
{
    [Fact]
    public void Compare_ClassifiesColumnFacetsWithoutPublishingExpressions()
    {
        var plan = new TableCopyPlan("dbo", "Sample", "public", "Sample", ["ID"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string> { ["ID"] = "integer" },
        };
        var observation = new ProductionSchemaObservation("Test",
            [new ObservedTargetTable("public", "Sample", ["ID"])], new string('a', 64));
        PostgreSqlSchemaFingerprint.ColumnShape actual = PostgreSqlSchemaFingerprint.ExpectedColumn(plan, "ID", 1)
            with
        { Type = "bigint", Nullable = true, DefaultExpression = "'private-value'" };

        ProductionSchemaColumnDiagnostic diagnostic = Assert.Single(
            ProductionSchemaColumnDiagnostics.Compare([plan], observation, [actual]));
        Assert.Equal("shape-drift", diagnostic.Status);
        Assert.Equal(["type", "nullability", "default"], diagnostic.ChangedComponents);
        Assert.DoesNotContain("private-value", System.Text.Json.JsonSerializer.Serialize(diagnostic),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Compare_FailsClosedOnIncompleteOrDuplicateColumnCatalog()
    {
        var plan = new TableCopyPlan("dbo", "Sample", "public", "Sample", ["ID"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string> { ["ID"] = "integer" },
        };
        var observation = new ProductionSchemaObservation("Test",
            [new ObservedTargetTable("public", "Sample", ["ID"])], new string('a', 64));
        Assert.Equal("production_schema_columns_incomplete", Assert.Throws<MigrationExecutionException>(
            () => ProductionSchemaColumnDiagnostics.Compare([plan], observation, [])).Code);
        PostgreSqlSchemaFingerprint.ColumnShape column = PostgreSqlSchemaFingerprint.ExpectedColumn(plan, "ID", 1);
        Assert.Equal("production_schema_columns_incomplete", Assert.Throws<MigrationExecutionException>(
            () => ProductionSchemaColumnDiagnostics.Compare([plan], observation, [column, column])).Code);
    }
}
