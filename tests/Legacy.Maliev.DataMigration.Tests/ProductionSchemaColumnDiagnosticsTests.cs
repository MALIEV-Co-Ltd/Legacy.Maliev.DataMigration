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
        Assert.Equal("bigint", diagnostic.ActualTypeCategory);
        Assert.Equal("inherited", diagnostic.ActualCollationMode);
        Assert.Equal("inherited", diagnostic.ActualCollationIdentity);
        Assert.Equal("unexpected-present", diagnostic.DefaultState);
        Assert.Equal("absent-both", diagnostic.GeneratedState);
        Assert.DoesNotContain("private-value", System.Text.Json.JsonSerializer.Serialize(diagnostic),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Compare_ReportsAbsentAndDifferentExpressions_WithoutRawOrUnreviewedMetadata()
    {
        var plan = new TableCopyPlan("dbo", "Sample", "public", "Sample", ["ID"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string> { ["ID"] = "text" },
            DefaultExpressions = new Dictionary<string, string> { ["ID"] = "'expected-private'" },
            GeneratedColumns = [new GeneratedColumnCopyPlan("ID", "lower(\"ID\")")],
        };
        var observation = new ProductionSchemaObservation("Test",
            [new ObservedTargetTable("public", "Sample", ["ID"])], new string('a', 64));
        PostgreSqlSchemaFingerprint.ColumnShape baseline = PostgreSqlSchemaFingerprint.ExpectedColumn(plan, "ID", 1);
        ProductionSchemaColumnDiagnostic absent = Assert.Single(ProductionSchemaColumnDiagnostics.Compare(
            [plan], observation, [baseline with { DefaultExpression = "", GeneratedExpression = "" }]));
        Assert.Equal("observed-absent", absent.DefaultState);
        Assert.Equal("observed-absent", absent.GeneratedState);

        ProductionSchemaColumnDiagnostic different = Assert.Single(ProductionSchemaColumnDiagnostics.Compare(
            [plan], observation, [baseline with { DefaultExpression = "'actual-private'",
                GeneratedExpression = "upper(\"ID\")", Collation = "secret-collation" }]));
        Assert.Equal("present-different", different.DefaultState);
        Assert.Equal("present-different", different.GeneratedState);
        Assert.Equal("explicit", different.ActualCollationMode);
        Assert.Equal("explicit-unreviewed", different.ActualCollationIdentity);
        string json = System.Text.Json.JsonSerializer.Serialize(different);
        Assert.DoesNotContain("actual-private", json, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-collation", json, StringComparison.Ordinal);

        MigrationExecutionException forbidden = Assert.Throws<MigrationExecutionException>(() =>
            ProductionSchemaColumnDiagnostics.Compare([plan], observation,
                [baseline with { Type = "private-type" }]));
        Assert.Equal("target_type_forbidden", forbidden.Code);
        Assert.DoesNotContain("private-type", forbidden.Message, StringComparison.Ordinal);
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
