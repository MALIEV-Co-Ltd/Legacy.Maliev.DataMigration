using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SqlServerIntegrationFactAttribute : FactAttribute
{
    public SqlServerIntegrationFactAttribute()
    {
        if (!string.Equals(
            Environment.GetEnvironmentVariable("MALIEV_RUN_SQLSERVER_INTEGRATION"),
            "1",
            StringComparison.Ordinal))
        {
            Skip = "SQL Server container execution is explicitly gated: set MALIEV_RUN_SQLSERVER_INTEGRATION=1 when Docker can pull the licensed SQL Server image.";
        }
    }
}

public sealed class SqlServerMigrationSourceIntegrationTests
{
    [SqlServerIntegrationFact]
    public async Task SnapshotCatalogStreamingAndDispose_PreserveProductionSemantics()
    {
        const string password = "MALIEV_test_Only!123456";
        await using MsSqlContainer container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04")
            .WithPassword(password)
            .Build();
        await container.StartAsync();

        const string database = "MigrationTest";
        await using (var setup = new SqlConnection(container.GetConnectionString()))
        {
            await setup.OpenAsync();
            await using var command = setup.CreateCommand();
            command.CommandText = $"""
                CREATE DATABASE [{database}];
                ALTER DATABASE [{database}] SET ALLOW_SNAPSHOT_ISOLATION ON;
                """;
            _ = await command.ExecuteNonQueryAsync();
        }

        var builder = new SqlConnectionStringBuilder(container.GetConnectionString()) { InitialCatalog = database };
        await using (var setup = new SqlConnection(builder.ConnectionString))
        {
            await setup.OpenAsync();
            await using var command = setup.CreateCommand();
            command.CommandText = "CREATE SCHEMA sales;";
            _ = await command.ExecuteNonQueryAsync();
            command.CommandText = """
                CREATE TABLE sales.Parent (
                    TenantId int NOT NULL,
                    Id int NOT NULL,
                    CONSTRAINT PK_Parent PRIMARY KEY (TenantId, Id));
                CREATE TABLE sales.Child (
                    Id bigint IDENTITY(100, 5) NOT NULL,
                    TenantId int NOT NULL,
                    ParentId int NOT NULL,
                    ThaiName nvarchar(200) NOT NULL,
                    Amount decimal(19, 4) NOT NULL,
                    LocalTime datetime2(7) NOT NULL,
                    OffsetTime datetimeoffset(7) NOT NULL,
                    LargeText nvarchar(max) NULL,
                    LargeBinary varbinary(max) NULL,
                    CONSTRAINT PK_Child PRIMARY KEY (Id),
                    CONSTRAINT FK_Child_Parent FOREIGN KEY (TenantId, ParentId)
                        REFERENCES sales.Parent (TenantId, Id) ON DELETE CASCADE);
                CREATE INDEX IX_Child_Amount ON sales.Child (Amount DESC)
                    INCLUDE (ThaiName) WHERE Amount > 0;
                INSERT INTO sales.Parent (TenantId, Id) VALUES (1, 10);
                INSERT INTO sales.Child (TenantId, ParentId, ThaiName, Amount, LocalTime, OffsetTime)
                VALUES (1, 10, N'ชิ้นงานทดสอบ', 1234.5678, '2026-08-29T17:45:12.1234567', '2026-08-29T17:45:12.1234567+07:00');
                """;
            _ = await command.ExecuteNonQueryAsync();

            command.CommandText = "UPDATE sales.Child SET LargeText = @text, LargeBinary = @binary;";
            string largeText = new('ก', 3 * 1024 * 1024);
            byte[] largeBinary = Enumerable.Repeat((byte)0xA5, 5 * 1024 * 1024).ToArray();
            _ = command.Parameters.AddWithValue("@text", largeText);
            _ = command.Parameters.AddWithValue("@binary", largeBinary);
            _ = await command.ExecuteNonQueryAsync();
            command.Parameters.Clear();

            command.CommandText = """
                SELECT identity_column.seed_value, identity_column.increment_value, identity_column.last_value,
                       index_column.is_descending_key, index_column.is_included_column, index_row.filter_definition,
                       foreign_key.delete_referential_action, foreign_key.is_disabled, foreign_key.is_not_trusted
                FROM sys.identity_columns AS identity_column
                INNER JOIN sys.tables AS table_row ON table_row.object_id = identity_column.object_id
                INNER JOIN sys.indexes AS index_row ON index_row.object_id = table_row.object_id
                INNER JOIN sys.index_columns AS index_column
                    ON index_column.object_id = index_row.object_id AND index_column.index_id = index_row.index_id
                INNER JOIN sys.foreign_keys AS foreign_key ON foreign_key.parent_object_id = table_row.object_id
                WHERE table_row.name = 'Child' AND index_row.name = 'IX_Child_Amount'
                  AND foreign_key.name = 'FK_Child_Parent'
                ORDER BY index_column.index_column_id;
                """;
            await using SqlDataReader catalog = await command.ExecuteReaderAsync();
            Assert.True(await catalog.ReadAsync());
            Assert.Equal(100L, Convert.ToInt64(catalog.GetValue(0), System.Globalization.CultureInfo.InvariantCulture));
            Assert.Equal(5L, Convert.ToInt64(catalog.GetValue(1), System.Globalization.CultureInfo.InvariantCulture));
            Assert.Equal(100L, Convert.ToInt64(catalog.GetValue(2), System.Globalization.CultureInfo.InvariantCulture));
            Assert.True(catalog.GetBoolean(3));
            Assert.False(catalog.GetBoolean(4));
            Assert.Equal("([Amount]>(0))", catalog.GetString(5));
            Assert.Equal(1, catalog.GetByte(6));
            Assert.False(catalog.GetBoolean(7));
            Assert.False(catalog.GetBoolean(8));
            Assert.True(await catalog.ReadAsync());
            Assert.True(catalog.GetBoolean(4));
        }

        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(builder.ConnectionString));
        await source.BeginDatabaseSnapshotAsync(database, CancellationToken.None);
        SourceSchemaEvidence schema = await source.InspectSchemaAsync(database, CancellationToken.None);
        Assert.Matches("^[0-9a-f]{64}$", schema.SchemaSha256);
        Assert.Equal(
            ["TenantId", "Id"],
            Assert.Single(schema.Tables, table => table.SourceSchema == "sales" && table.SourceTable == "Parent").OrderedColumns);
        SourceTableInventory childInventory = Assert.Single(schema.Tables, table => table.SourceSchema == "sales" && table.SourceTable == "Child");
        Assert.Equal(
            ["Id", "TenantId", "ParentId", "ThaiName", "Amount", "LocalTime", "OffsetTime", "LargeText", "LargeBinary"],
            childInventory.OrderedColumns);
        Assert.Equal("datetime2(7)", Assert.Single(childInventory.Columns, column => column.Column == "LocalTime").DeclaredType);
        Assert.Equal(6L * 1024 * 1024, Assert.Single(childInventory.Columns, column => column.Column == "LargeText").MaxObservedDataLength);
        Assert.Equal(5L * 1024 * 1024, Assert.Single(childInventory.Columns, column => column.Column == "LargeBinary").MaxObservedDataLength);

        DatabaseSchemaPlan generatedPlan = await source.GenerateDatabasePlanAsync(database, CancellationToken.None);
        TableCopyPlan generatedChild = Assert.Single(generatedPlan.Tables, table => table.SourceTable == "Child");
        Assert.Equal(["Id"], generatedChild.PrimaryKey!.Columns);
        Assert.Equal(["TenantId", "Id"], Assert.Single(generatedPlan.Tables, table => table.SourceTable == "Parent").PrimaryKey!.Columns);
        Assert.Equal("text", generatedChild.ColumnTypes["LocalTime"]);
        Assert.Equal("text", generatedChild.ColumnTypes["OffsetTime"]);
        Assert.Equal(new IdentityCopyPlan("Id", 100, 5, 100, true), Assert.Single(generatedChild.Identities));
        IndexCopyPlan generatedIndex = Assert.Single(generatedChild.Indexes, index => index.Name == "IX_Child_Amount");
        Assert.Equal(["Amount"], generatedIndex.DescendingColumns);
        Assert.Equal(["ThaiName"], generatedIndex.IncludedColumns);
        ForeignKeyCopyPlan generatedForeignKey = Assert.Single(generatedChild.ForeignKeys);
        Assert.Equal(["TenantId", "ParentId"], generatedForeignKey.Columns);
        Assert.Equal(["TenantId", "Id"], generatedForeignKey.ReferencedColumns);
        Assert.Equal(ReferentialAction.Cascade, generatedForeignKey.OnDelete);
        Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(generatedPlan), generatedPlan.TargetSchemaSha256);

        var table = new TableCopyPlan(
            "sales", "Child", "sales", "child",
            ["Id", "TenantId", "ParentId", "ThaiName", "Amount", "LocalTime", "OffsetTime", "LargeText", "LargeBinary"],
            ["Id"])
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "bigint",
                ["TenantId"] = "int",
                ["ParentId"] = "int",
                ["ThaiName"] = "nvarchar",
                ["Amount"] = "decimal",
                ["LocalTime"] = "datetime2(7)",
                ["OffsetTime"] = "datetimeoffset(7)",
                ["LargeText"] = "nvarchar(max)",
                ["LargeBinary"] = "varbinary(max)",
            },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Id"] = "bigint",
                ["TenantId"] = "integer",
                ["ParentId"] = "integer",
                ["ThaiName"] = "text",
                ["Amount"] = "numeric(19,4)",
                ["LocalTime"] = "text",
                ["OffsetTime"] = "text",
                ["LargeText"] = "text",
                ["LargeBinary"] = "bytea",
            },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Child", ["Id"]),
            ForeignKeys =
            [
                new ForeignKeyCopyPlan("FK_Child_Parent", ["TenantId", "ParentId"], "sales", "parent", ["tenant_id", "id"])
                {
                    SourceReferencedSchema = "sales",
                    SourceReferencedTable = "Parent",
                    SourceReferencedColumns = ["TenantId", "Id"],
                    OnDelete = ReferentialAction.Cascade,
                },
            ],
        };

        List<MigrationRow> rows = [];
        await foreach (MigrationRow row in source.ReadTableAsync(database, table, CancellationToken.None))
        {
            rows.Add(row);
        }

        _ = Assert.Single(rows);
        Assert.Equal("ชิ้นงานทดสอบ", rows[0].Values["ThaiName"]);
        Assert.Equal(1234.5678m, rows[0].Values["Amount"]);
        Assert.Equal("2026-08-29T17:45:12.1234567", rows[0].Values["LocalTime"]);
        Assert.Equal("2026-08-29T17:45:12.1234567+07:00", rows[0].Values["OffsetTime"]);
        StreamingLob largeTextValue = Assert.IsType<StreamingLob>(rows[0].Values["LargeText"]);
        StreamingLob largeBinaryValue = Assert.IsType<StreamingLob>(rows[0].Values["LargeBinary"]);
        await largeTextValue.ConsumeAsync(Stream.Null, CancellationToken.None);
        await largeBinaryValue.ConsumeAsync(Stream.Null, CancellationToken.None);
        Assert.Equal(9L * 1024 * 1024, largeTextValue.CanonicalByteLength);
        Assert.Equal(5L * 1024 * 1024, largeBinaryValue.CanonicalByteLength);
        IReadOnlyDictionary<string, long> orphans = await source.InspectForeignKeyOrphansAsync(database, table, CancellationToken.None);
        Assert.Equal(0, orphans["FK_Child_Parent"]);

        await source.RollbackDatabaseSnapshotAsync(database, CancellationToken.None);
        await source.RollbackDatabaseSnapshotAsync(database, CancellationToken.None);
    }
}
