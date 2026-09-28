namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ProductionSchemaColumnDiagnosticsTests
{
    [Fact]
    public void Compare_RecognizesPostgreSqlUtcClockDeparserWithoutAcceptingAnotherZone()
    {
        var plan = new TableCopyPlan("dbo", "Sample", "public", "Sample", ["CreatedDate"], ["CreatedDate"])
        {
            ColumnTypes = new Dictionary<string, string>
            {
                ["CreatedDate"] = "timestamp without time zone",
            },
            DefaultExpressions = new Dictionary<string, string>
            {
                ["CreatedDate"] = "(timezone('UTC'::text, CURRENT_TIMESTAMP))",
            },
        };
        var observation = new ProductionSchemaObservation("Test",
            [new ObservedTargetTable("public", "Sample", ["CreatedDate"])], new string('a', 64));
        PostgreSqlSchemaFingerprint.ColumnShape expected =
            PostgreSqlSchemaFingerprint.ExpectedColumn(plan, "CreatedDate", 1);

        ProductionSchemaColumnDiagnostic equivalent = Assert.Single(ProductionSchemaColumnDiagnostics.Compare(
            [plan], observation,
            [expected with { DefaultExpression = "(CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)" }], []));
        Assert.Equal("match", equivalent.Status);
        Assert.Equal("match", equivalent.DefaultState);

        ProductionSchemaColumnDiagnostic different = Assert.Single(ProductionSchemaColumnDiagnostics.Compare(
            [plan], observation,
            [expected with { DefaultExpression = "(CURRENT_TIMESTAMP AT TIME ZONE 'Asia/Bangkok'::text)" }], []));
        Assert.Equal("shape-drift", different.Status);
        Assert.Equal("present-different", different.DefaultState);
    }

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
            ProductionSchemaColumnDiagnostics.Compare([plan], observation, [actual], []));
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
            [plan], observation, [baseline with { DefaultExpression = "", GeneratedExpression = "" }], []));
        Assert.Equal("observed-absent", absent.DefaultState);
        Assert.Equal("observed-absent", absent.GeneratedState);

        ProductionSchemaColumnDiagnostic different = Assert.Single(ProductionSchemaColumnDiagnostics.Compare(
            [plan], observation, [baseline with { DefaultExpression = "'actual-private'",
                GeneratedExpression = "upper(\"ID\")", Collation = "secret-collation" }],
            [new ProductionCollationMetadata("public", "Sample", "ID", "i", false, "private-namespace",
                -1, 6, "private-version", "different-private-version")]));
        Assert.Equal("present-different", different.DefaultState);
        Assert.Equal("present-different", different.GeneratedState);
        Assert.Equal("explicit", different.ActualCollationMode);
        Assert.Equal("explicit-unreviewed", different.ActualCollationIdentity);
        Assert.Equal("icu", different.ActualCollationProvider);
        Assert.Equal("nondeterministic", different.ActualCollationDeterminism);
        Assert.Equal("mismatch", different.ActualCollationVersionState);
        Assert.Equal("non-pg-catalog", different.ActualCollationCatalogScope);
        string json = System.Text.Json.JsonSerializer.Serialize(different);
        Assert.DoesNotContain("actual-private", json, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-collation", json, StringComparison.Ordinal);
        Assert.DoesNotContain("private-namespace", json, StringComparison.Ordinal);
        Assert.DoesNotContain("private-version", json, StringComparison.Ordinal);

        MigrationExecutionException forbidden = Assert.Throws<MigrationExecutionException>(() =>
            ProductionSchemaColumnDiagnostics.Compare([plan], observation,
                [baseline with { Type = "private-type" }], []));
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
            () => ProductionSchemaColumnDiagnostics.Compare([plan], observation, [], [])).Code);
        PostgreSqlSchemaFingerprint.ColumnShape column = PostgreSqlSchemaFingerprint.ExpectedColumn(plan, "ID", 1);
        Assert.Equal("production_schema_columns_incomplete", Assert.Throws<MigrationExecutionException>(
            () => ProductionSchemaColumnDiagnostics.Compare([plan], observation, [column, column], [])).Code);
    }

    [Fact]
    public void Compare_FailsClosedOnMissingOrUnreviewedExplicitCollationMetadata()
    {
        var plan = new TableCopyPlan("dbo", "Sample", "public", "Sample", ["Value"], ["Value"])
        {
            ColumnTypes = new Dictionary<string, string> { ["Value"] = "text" },
            NullableColumns = ["Value"],
        };
        var observation = new ProductionSchemaObservation("Test",
            [new ObservedTargetTable("public", "Sample", ["Value"])], new string('a', 64));
        PostgreSqlSchemaFingerprint.ColumnShape column = PostgreSqlSchemaFingerprint.ExpectedColumn(plan, "Value", 1)
            with
        { Collation = "private-collation" };
        var metadata = new ProductionCollationMetadata("public", "Sample", "Value", "c", true,
            "private-namespace", -1, 6, null, null);
        Assert.Equal("production_schema_columns_incomplete", Assert.Throws<MigrationExecutionException>(() =>
            ProductionSchemaColumnDiagnostics.Compare([plan], observation, [column], [])).Code);
        Assert.Equal("production_schema_columns_incomplete", Assert.Throws<MigrationExecutionException>(() =>
            ProductionSchemaColumnDiagnostics.Compare([plan], observation, [column], [metadata, metadata])).Code);
        Assert.Equal("production_schema_columns_incomplete", Assert.Throws<MigrationExecutionException>(() =>
            ProductionSchemaColumnDiagnostics.Compare([plan], observation, [column],
                [metadata with { Encoding = 8 }])).Code);
        Assert.Equal("production_schema_collation_metadata_unreviewed", Assert.Throws<MigrationExecutionException>(() =>
            ProductionSchemaColumnDiagnostics.Compare([plan], observation, [column],
                [metadata with { Provider = "private-provider" }])).Code);
        ProductionSchemaColumnDiagnostic diagnostic = Assert.Single(ProductionSchemaColumnDiagnostics.Compare(
            [plan], observation, [column], [metadata]));
        Assert.Equal("libc", diagnostic.ActualCollationProvider);
        Assert.Equal("deterministic", diagnostic.ActualCollationDeterminism);
        Assert.Equal("unversioned", diagnostic.ActualCollationVersionState);
        Assert.Equal("non-pg-catalog", diagnostic.ActualCollationCatalogScope);
        string json = System.Text.Json.JsonSerializer.Serialize(diagnostic);
        Assert.DoesNotContain("private-collation", json, StringComparison.Ordinal);
        Assert.DoesNotContain("private-namespace", json, StringComparison.Ordinal);
    }
}
