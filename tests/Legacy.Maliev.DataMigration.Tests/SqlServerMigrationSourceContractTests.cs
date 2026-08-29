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
}
