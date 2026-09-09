using Npgsql;
using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class OrderSchemaReconciliationTests(PostgreSqlAdapterFixture fixture)
{
    [SqlServerIntegrationFact]
    public async Task Copy_OrderDefaultsAndUnicode_FromSqlServer2022_ReconcilesOnPostgreSql18()
    {
        await using MsSqlContainer sqlServer = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04").Build();
        await sqlServer.StartAsync();
        await using (var setup = new SqlConnection(sqlServer.GetConnectionString()))
        {
            await setup.OpenAsync();
            await using var createDatabase = new SqlCommand("CREATE DATABASE [Order]; ALTER DATABASE [Order] SET ALLOW_SNAPSHOT_ISOLATION ON;", setup);
            _ = await createDatabase.ExecuteNonQueryAsync();
        }
        string sourceConnection = new SqlConnectionStringBuilder(sqlServer.GetConnectionString()) { InitialCatalog = "Order" }.ConnectionString;
        await using (var setup = new SqlConnection(sourceConnection))
        {
            await setup.OpenAsync();
            await using var createRows = new SqlCommand("""
                CREATE TABLE dbo.[Order] (
                    ID int NOT NULL CONSTRAINT PK_Order PRIMARY KEY,
                    Name nvarchar(100) NOT NULL DEFAULT ('unnamed'),
                    Manufactured int NOT NULL DEFAULT ((0)));
                INSERT dbo.[Order] (ID) VALUES (1);
                INSERT dbo.[Order] (ID, Name, Manufactured)
                    VALUES (2, N'งาน  ทดสอบ''s', 2147483647), (3, N'', -1);
                """, setup);
            _ = await createRows.ExecuteNonQueryAsync();
        }

        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(sourceConnection));
        await source.BeginDatabaseSnapshotAsync("Order", CancellationToken.None);
        DatabaseSchemaPlan plan = await source.GenerateDatabasePlanAsync("Order", CancellationToken.None);
        TableCopyPlan table = Assert.Single(plan.Tables);
        Assert.Equal("('unnamed')", table.DefaultExpressions["Name"]);
        Assert.Equal("character varying(100)", table.ColumnTypes["Name"]);

        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        Guid runId = Guid.NewGuid();
        var shadow = new ShadowDatabase($"legacy_shadow_order_{runId:N}", runId.ToString("D"), "Order")
        {
            OwnerAttempt = 1,
            FencingToken = Guid.NewGuid(),
        };
        _ = await target.CreateUniqueEmptyShadowAsync(shadow, CancellationToken.None);
        try
        {
            await using IPostgreSqlWholeDatabaseTransaction transaction = await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            var rows = new List<MigrationRow>();
            await foreach (MigrationRow row in source.ReadTableAsync("Order", table, CancellationToken.None))
            {
                rows.Add(row);
            }
            Assert.Equal(["unnamed", "งาน  ทดสอบ's", ""], rows.Select(row => Assert.IsType<string>(row.Values["Name"])));
            Assert.Equal([0, int.MaxValue, -1], rows.Select(row => Assert.IsType<int>(row.Values["Manufactured"])));
            Assert.Equal(3, await transaction.CopyBatchAsync(table, rows, CancellationToken.None));
            await transaction.FinalizeSchemaAsync(plan, CancellationToken.None);
            Assert.Equal(plan.TargetSchemaSha256, await transaction.InspectSchemaAsync(plan, CancellationToken.None));
            using var collector = new TableEvidenceCollector(table);
            rows.ForEach(collector.Append);
            TableReconciliationEvidence expected = collector.Finish();
            TableReconciliationEvidence observed = await transaction.InspectTableAsync(table, CancellationToken.None);
            ReconciliationDiagnostics.CompareTable("Order", expected, observed);
            Assert.Equal(3, observed.RowCount);
            ReconciliationDiagnostics.CompareSequences(plan,
                await source.InspectSequenceNextValuesAsync("Order", plan, CancellationToken.None),
                await transaction.InspectSequenceNextValuesAsync(plan, CancellationToken.None));
            await transaction.CommitAsync(CancellationToken.None);
            await source.CompleteDatabaseSnapshotAsync("Order", CancellationToken.None);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Theory]
    [InlineData("('unnamed')", "'unnamed'::character varying", "unnamed")]
    [InlineData("('customer''s order')", "'customer''s order'::character varying", "customer's order")]
    [InlineData("('order  with  spacing')", "'order  with  spacing'::character varying", "order  with  spacing")]
    public async Task ApplySchema_OrderVarcharDefault_ReconcilesWithPostgreSql18Catalog(
        string sourceDefault, string catalogDefault, string expectedValue)
    {
        DatabaseSchemaPlan plan = CreatePlan(sourceDefault);
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        Guid runId = Guid.NewGuid();
        var shadow = new ShadowDatabase($"legacy_shadow_order_{runId:N}", runId.ToString("D"), "Order")
        {
            OwnerAttempt = 1,
            FencingToken = Guid.NewGuid(),
        };
        _ = await target.CreateUniqueEmptyShadowAsync(shadow, CancellationToken.None);
        try
        {
            await using (IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None))
            {
                await transaction.ApplySchemaAsync(plan, CancellationToken.None);
                await transaction.FinalizeSchemaAsync(plan, CancellationToken.None);
                string observed = await transaction.InspectSchemaAsync(plan, CancellationToken.None);
                // Actual catalog introspection is independent of the expected fingerprint computation.
                Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(plan), observed);
                Assert.Equal(0, (await transaction.InspectTableAsync(plan.Tables[0], CancellationToken.None)).RowCount);
                await transaction.CommitAsync(CancellationToken.None);
            }

            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
            {
                Database = shadow.Name,
            }.ConnectionString);
            await connection.OpenAsync();
            await using var defaults = new NpgsqlCommand("""
                SELECT pg_get_expr(d.adbin, d.adrelid)
                FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum
                WHERE d.adrelid='public."Order"'::regclass AND a.attname='Name';
                """, connection);
            Assert.Equal(catalogDefault, await defaults.ExecuteScalarAsync());
            await using var insert = new NpgsqlCommand("""
                INSERT INTO public."Order" ("ID") VALUES (1) RETURNING "Name", "Manufactured";
                """, connection);
            await using NpgsqlDataReader reader = await insert.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(expectedValue, reader.GetString(0));
            Assert.Equal(0, reader.GetInt32(1));
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }

    [Theory]
    [InlineData("('unnamed')", "('different')")]
    [InlineData("('a  b')", "('a b')")]
    [InlineData("('abc')", "'abc'::character varying(2)")]
    [InlineData("('unnamed')", "'unnamed'::text")]
    [InlineData("'a  b'::text", "'a b'::text")]
    public void ComputeExpected_MeaningfullyDifferentDefaults_RemainDifferent(string first, string second)
    {
        Assert.NotEqual(PostgreSqlSchemaFingerprint.ComputeExpected(CreatePlan(first)),
            PostgreSqlSchemaFingerprint.ComputeExpected(CreatePlan(second)));
    }

    [Theory]
    [InlineData("'unnamed'::text")]
    [InlineData("'unnamed'::character varying(2)")]
    [InlineData("lower('UNNAMED')")]
    public void ComputeExpected_ExplicitCastsAndExpressions_AreNotErased(string expression)
    {
        DatabaseSchemaPlan plan = CreatePlan(expression);
        string actual = PostgreSqlSchemaFingerprint.ComputeExpected(plan);
        string exact = PostgreSqlSchemaFingerprint.Compute(
            [new("public", "Order")],
            [new("public", "Order", 1, "ID", "integer", false, false, "", "", ""),
                new("public", "Order", 2, "Name", "character varying(100)", false, false, expression, "", ""),
                new("public", "Order", 3, "Manufactured", "integer", false, false, "0", "", "")],
            [new("public", "Order", "PK_Order", 'p', ["ID"], "")], [], []);
        Assert.Equal(exact, actual);
    }

    internal static DatabaseSchemaPlan CreatePlan(string nameDefault)
    {
        var table = new TableCopyPlan("dbo", "Order", "public", "Order", ["ID", "Name", "Manufactured"], ["ID"])
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "int",
                ["Name"] = "nvarchar(100)",
                ["Manufactured"] = "int",
            },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "integer",
                ["Name"] = "character varying(100)",
                ["Manufactured"] = "integer",
            },
            DefaultExpressions = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Name"] = nameDefault,
                ["Manufactured"] = "((0))",
            },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Order", ["ID"]),
        };
        return new DatabaseSchemaPlan("Order", "1.0", new string('a', 64), new string('b', 64), [table]);
    }
}
