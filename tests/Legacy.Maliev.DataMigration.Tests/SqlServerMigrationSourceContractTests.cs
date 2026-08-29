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
        Assert.False(builder.MultipleActiveResultSets);
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
