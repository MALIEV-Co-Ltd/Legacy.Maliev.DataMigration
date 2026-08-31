using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SqlServerMigrationSourceContractTests
{
    [Fact]
    public void Constructor_EmptyConnectionString_FailsClosed()
    {
        _ = Assert.Throws<ArgumentException>(() =>
            new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(string.Empty)));
    }

    [Fact]
    public void CreateDatabaseConnectionString_UsesReadOnlyIntentAndSelectedCatalog()
    {
        var options = new SqlServerMigrationSourceOptions(
            "Server=sql.example;Database=master;User ID=reader;Password=not-used;Encrypt=True");

        string result = SqlServerMigrationSource.CreateDatabaseConnectionString(options, "Order");
        var builder = new SqlConnectionStringBuilder(result);

        Assert.Equal("Order", builder.InitialCatalog);
        Assert.Equal(ApplicationIntent.ReadOnly, builder.ApplicationIntent);
        Assert.True(builder.MultipleActiveResultSets);
    }

    [Fact]
    public void BuildReadTableCommand_QuotesIdentifiersAndPreservesApprovedColumnOrder()
    {
        var table = new TableCopyPlan(
            "sales]data",
            "Order",
            "public",
            "orders",
            ["Id", "select]value"],
            ["Id"])
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "int",
                ["select]value"] = "nvarchar",
            },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "integer",
                ["select]value"] = "text",
            },
        };

        string sql = SqlServerMigrationSource.BuildReadTableCommand(table);

        Assert.Equal(
            "SELECT [Id], [select]]value] FROM [sales]]data].[Order] ORDER BY [Id];",
            sql);
        Assert.DoesNotContain("WRITE", sql, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("")]
    [InlineData("master;DROP DATABASE production")]
    [InlineData("../master")]
    public void CreateDatabaseConnectionString_RejectsUnsafeCatalog(string database)
    {
        var options = new SqlServerMigrationSourceOptions(
            "Server=sql.example;Database=master;Integrated Security=True;Encrypt=True");

        _ = Assert.Throws<ArgumentException>(() =>
            SqlServerMigrationSource.CreateDatabaseConnectionString(options, database));
    }

    [Fact]
    public void BuildReadTableCommand_MissingDeterministicOrder_FailsClosed()
    {
        var table = new TableCopyPlan("dbo", "Orders", "public", "orders", ["Id"], []);

        _ = Assert.Throws<ArgumentException>(() => SqlServerMigrationSource.BuildReadTableCommand(table));
    }

    [Fact]
    public void BuildReadTableCommand_SourceProvenEmpty_DoesNotCompileAnUnnecessaryOrderExpression()
    {
        var table = new TableCopyPlan("Archive", "Counter", "archive", "Counter", ["Key", "Value"], ["Key", "Value"])
        {
            SourceKnownEmpty = true,
        };

        Assert.Equal(
            "SELECT [Key], [Value] FROM [Archive].[Counter];",
            SqlServerMigrationSource.BuildReadTableCommand(table));
    }

    [Fact]
    public void BuildStreamingReadTableCommand_QuotesReservedMaterializedIdentifiers()
    {
        var table = new TableCopyPlan(
            "Archive",
            "Hash",
            "public",
            "Hash",
            ["Key", "Field", "Value", "ExpireAt"],
            ["Key", "Field"])
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Key"] = "nvarchar(100)",
                ["Field"] = "nvarchar(100)",
                ["Value"] = "nvarchar(max)",
                ["ExpireAt"] = "datetime2(7)",
            },
        };

        string sql = SqlServerMigrationSource.BuildStreamingReadTableCommand(table);

        Assert.Equal(
            "SELECT [Key], [Field], [ExpireAt], DATALENGTH(CONVERT(varchar(max), [Value] COLLATE Latin1_General_100_BIN2_UTF8)) " +
            "FROM [Archive].[Hash] ORDER BY [Key], [Field];",
            sql);
    }

    [Theory]
    [InlineData("(getutcdate())", "(timezone('UTC'::text, CURRENT_TIMESTAMP))")]
    [InlineData("GETUTCDATE()", "timezone('UTC'::text, CURRENT_TIMESTAMP)")]
    [InlineData("(getdate())", "(CURRENT_TIMESTAMP)")]
    public void TranslateExpressionForPostgreSql_MapsSqlServerClockDefaults(
        string source,
        string expected)
    {
        Assert.Equal(expected, SqlServerMigrationSource.TranslateExpressionForPostgreSql(source));
    }

    [Theory]
    [InlineData(
        "(Trim(concat([FirstName],N' ',[LastName])))",
        "btrim((((COALESCE(\"FirstName\", ''::character varying))::text || ' '::text) || (COALESCE(\"LastName\", ''::character varying))::text))")]
    [InlineData(
        "(CONVERT([decimal](18,2),[UnitPrice]*[Quantity]))",
        "(((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2))::numeric(18,2)")]
    [InlineData(
        "(CONVERT([decimal](18,2),[UnitPrice]*[Quantity]-(([UnitPrice]*[Quantity])*[DiscountPercent])/(100)))",
        "(((((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2) - ((((((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2) * \"DiscountPercent\"))::numeric(35,4) / (100)::numeric))::numeric(38,7)))::numeric(38,7))::numeric(18,2)")]
    [InlineData(
        "(CONVERT([decimal](18,2),[Total]-[WithholdingTax]))",
        "(((\"Total\" - \"WithholdingTax\"))::numeric(19,2))::numeric(18,2)")]
    [InlineData(
        "(datediff(day,[CreatedDate],[FinishedDate]))",
        "(\"FinishedDate\" - (\"CreatedDate\")::date)")]
    [InlineData(
        "([Quantity]-[Manufactured])",
        "(\"Quantity\" - \"Manufactured\")")]
    public void TranslateExpressionForPostgreSql_MapsComputedColumnsToImmutablePostgreSqlExpressions(
        string source,
        string expected)
    {
        var targetColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["FirstName"] = "character varying(256)",
            ["LastName"] = "character varying(256)",
            ["UnitPrice"] = "numeric(18,2)",
            ["Quantity"] = "integer",
            ["Manufactured"] = "integer",
            ["DiscountPercent"] = "numeric(5,2)",
            ["Total"] = "numeric(18,2)",
            ["WithholdingTax"] = "numeric(18,2)",
            ["CreatedDate"] = "timestamp without time zone",
            ["FinishedDate"] = "date",
        };
        string translated = SqlServerMigrationSource.TranslateGeneratedExpressionForPostgreSql(source, targetColumnTypes);

        Assert.Equal(expected, translated);
        Assert.DoesNotContain("CONVERT", translated, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("datediff", translated, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("concat", translated, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TranslateGeneratedExpressionForPostgreSql_UnknownDecimalShape_FailsClosed()
    {
        var targetColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Total"] = "numeric(18,2)",
        };

        MigrationExecutionException exception = Assert.Throws<MigrationExecutionException>(() =>
            SqlServerMigrationSource.TranslateGeneratedExpressionForPostgreSql(
                "(CONVERT([decimal](18,2),ROUND([Total],0)))",
                targetColumnTypes));

        Assert.Equal("source_computed_decimal_unsupported", exception.Code);
    }

    [Theory]
    [InlineData("(getdate())")]
    [InlineData("(newid())")]
    [InlineData("(ABS([Quantity]))")]
    public void TranslateGeneratedExpressionForPostgreSql_UnknownOrVolatileShape_FailsClosed(string source)
    {
        var targetColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Quantity"] = "integer",
        };

        MigrationExecutionException exception = Assert.Throws<MigrationExecutionException>(() =>
            SqlServerMigrationSource.TranslateGeneratedExpressionForPostgreSql(source, targetColumnTypes));

        Assert.Equal("source_computed_expression_unsupported", exception.Code);
    }

    [Fact]
    public void TranslateGeneratedExpressionForPostgreSql_TextTemporalOperand_FailsClosed()
    {
        var targetColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["CreatedDate"] = "text",
            ["FinishedDate"] = "date",
        };

        MigrationExecutionException exception = Assert.Throws<MigrationExecutionException>(() =>
            SqlServerMigrationSource.TranslateGeneratedExpressionForPostgreSql(
                "(datediff(day,[CreatedDate],[FinishedDate]))",
                targetColumnTypes));

        Assert.Equal("source_computed_temporal_type_unsupported", exception.Code);
    }

    [Fact]
    public async Task DisposeAsync_WithoutActiveSnapshots_IsIdempotent()
    {
        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(
            "Server=sql.example;Database=master;Integrated Security=True;Encrypt=True"));

        await source.DisposeAsync();
    }

    [Theory]
    [InlineData(DateTimeKind.Local)]
    [InlineData(DateTimeKind.Utc)]
    [InlineData(DateTimeKind.Unspecified)]
    public void NormalizeSourceValue_Datetime2_IsAlwaysUnspecifiedWithoutChangingClockFields(DateTimeKind kind)
    {
        DateTime input = DateTime.SpecifyKind(new DateTime(2026, 8, 29, 17, 45, 12, 345), kind);

        object result = SqlServerMigrationSource.NormalizeSourceValue(input, "datetime2")!;
        DateTime normalized = Assert.IsType<DateTime>(result);

        Assert.Equal(DateTimeKind.Unspecified, normalized.Kind);
        Assert.Equal(input.Ticks, normalized.Ticks);
    }

    [Fact]
    public void NormalizeSourceValue_Datetime2SevenToText_PreservesEveryHundredNanoseconds()
    {
        DateTime input = new DateTime(2026, 8, 29, 17, 45, 12, DateTimeKind.Unspecified).AddTicks(1_234_567);

        object result = SqlServerMigrationSource.NormalizeSourceValue(input, "datetime2(7)", "text")!;

        Assert.Equal("2026-08-29T17:45:12.1234567", result);
    }

    [Fact]
    public void NormalizeSourceValue_DatetimeOffsetToText_PreservesOriginalOffsetAndPrecision()
    {
        var input = new DateTimeOffset(2026, 8, 29, 17, 45, 12, TimeSpan.FromHours(7)).AddTicks(1_234_567);

        object result = SqlServerMigrationSource.NormalizeSourceValue(input, "datetimeoffset(7)", "text")!;

        Assert.Equal("2026-08-29T17:45:12.1234567+07:00", result);
    }

    [Theory]
    [InlineData("archive", "Customers", "Id")]
    [InlineData("crm", "ArchivedCustomers", "Id")]
    [InlineData("crm", "Customers", "LegacyId")]
    public void ValidateObservedForeignKey_ReferencedShapeDrifts_FailsClosed(
        string referencedSchema,
        string referencedTable,
        string referencedColumn)
    {
        var plan = new ForeignKeyCopyPlan(
            "FK_orders_customer",
            ["CustomerId"],
            "crm",
            "Customers",
            ["Id"]);

        MigrationExecutionException exception = Assert.Throws<MigrationExecutionException>(() =>
            SqlServerMigrationSource.ValidateObservedForeignKey(
                plan,
                referencedSchema,
                referencedTable,
                ["CustomerId"],
                [referencedColumn]));

        Assert.Equal("source_foreign_key_drift", exception.Code);
    }

    [Fact]
    public void ValidateObservedForeignKey_ExactSourceSideOfRenamedMapping_Accepts()
    {
        var plan = new ForeignKeyCopyPlan(
            "FK_orders_customer",
            ["CustomerId"],
            "crm",
            "customers",
            ["id"])
        {
            SourceReferencedSchema = "dbo",
            SourceReferencedTable = "Customer",
            SourceReferencedColumns = ["ID"],
        };

        SqlServerMigrationSource.ForeignKeyMetadata metadata =
            SqlServerMigrationSource.ValidateObservedForeignKey(
                plan,
                "dbo",
                "Customer",
                ["CustomerId"],
                ["ID"]);

        Assert.Equal("dbo", metadata.ReferencedSchema);
        Assert.Equal("Customer", metadata.ReferencedTable);
        Assert.Equal(["ID"], metadata.ReferencedColumns);
    }

    [Fact]
    public void ValidateObservedForeignKey_ActionOrTrustDrifts_FailsClosed()
    {
        var plan = new ForeignKeyCopyPlan(
            "FK_orders_customer",
            ["CustomerId"],
            "crm",
            "Customers",
            ["Id"])
        {
            OnDelete = ReferentialAction.Cascade,
            OnUpdate = ReferentialAction.NoAction,
        };

        MigrationExecutionException exception = Assert.Throws<MigrationExecutionException>(() =>
            SqlServerMigrationSource.ValidateObservedForeignKey(
                plan,
                "crm",
                "Customers",
                ["CustomerId"],
                ["Id"],
                deleteAction: 0,
                updateAction: 0,
                disabled: false,
                notTrusted: false));

        Assert.Equal("source_foreign_key_drift", exception.Code);
    }
}
