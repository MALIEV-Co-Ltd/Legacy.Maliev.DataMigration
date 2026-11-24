using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(SqlServerAdapterTestGroup.Name)]
public sealed class CurrentConsumerSchemaV3SourceOrderIsoGeneratorTests
{
    private static readonly string[] CountryColumns = ["ID", "Name", "Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"];

    [SqlServerIntegrationFact]
    public async Task Actual_SQL_Country_inventory_generates_new_profile_without_reordering_source()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(4));
        CancellationToken ct = deadline.Token;
        await using MsSqlContainer sqlServer = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04")
            .WithEnvironment("MSSQL_MEMORY_LIMIT_MB", "2560")
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 3L * 1024 * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 3L * 1024 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 2000000000;
            }).Build();
        await sqlServer.StartAsync(ct);
        await using (var setup = new SqlConnection(sqlServer.GetConnectionString()))
        {
            await setup.OpenAsync(ct);
            await using var create = new SqlCommand("CREATE DATABASE [Country]; ALTER DATABASE [Country] SET ALLOW_SNAPSHOT_ISOLATION ON;", setup);
            _ = await create.ExecuteNonQueryAsync(ct);
        }
        string connection = new SqlConnectionStringBuilder(sqlServer.GetConnectionString()) { InitialCatalog = "Country" }.ConnectionString;
        await using (var setup = new SqlConnection(connection))
        {
            await setup.OpenAsync(ct);
            await using var create = new SqlCommand("""
                CREATE TABLE dbo.Country (
                    ID int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Country PRIMARY KEY,
                    Name nvarchar(50) NOT NULL, Continent nvarchar(50) NULL, CountryCode nvarchar(30) NULL,
                    ISO2 nchar(2) NULL, ISO3 nchar(3) NULL,
                    CreatedDate datetime NULL DEFAULT (getutcdate()), ModifiedDate datetime NULL DEFAULT (getutcdate()));
                """, setup);
            _ = await create.ExecuteNonQueryAsync(ct);
        }
        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(connection)
        { ConsumerOverlays = ConsumerOverlaySelection.CurrentConsumerSchemaV3CompanyStorageSourceOrder });
        await source.BeginDatabaseSnapshotAsync("Country", ct);
        DatabaseSchemaPlan plan = await source.GenerateDatabasePlanAsync("Country", ct);
        TableCopyPlan logical = Assert.Single(plan.Tables);
        Assert.Equal(CountryColumns, logical.OrderedColumns);
        Assert.Equal(logical.OrderedColumns, logical.SourceColumns.Select(x => x.Column));
        Assert.Equal("nchar(2)", logical.SourceColumnTypes["ISO2"]);
        Assert.Equal("datetime", logical.SourceColumnTypes["CreatedDate"]);
        Assert.Equal("character(2)", logical.ColumnTypes["ISO2"]);
        Assert.Equal(CurrentConsumerSchemaV3SourceOrderIsoManifest.Country, plan.TargetExtensionProfile);
        TableCopyPlan physical = Assert.Single(ApprovedConsumerColumnOverlayManifest.ComposePhysical(plan));
        Assert.Equal("character varying(2)", physical.ColumnTypes["ISO2"]);
        Assert.Equal("character varying(3)", physical.ColumnTypes["ISO3"]);
        Assert.Equal(logical.SourceColumns, physical.SourceColumns);
        Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(plan), plan.TargetSchemaSha256);
        await source.CompleteDatabaseSnapshotAsync("Country", ct);
    }
}
