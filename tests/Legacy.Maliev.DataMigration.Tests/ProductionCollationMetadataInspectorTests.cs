using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ProductionCollationMetadataInspectorTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task InspectDatabaseAsync_DisposableCustomCollation_ClassifiesWithoutPublishingDefinition()
    {
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using (var setup = new NpgsqlCommand(
            "CREATE SCHEMA collation_probe; " +
            "CREATE COLLATION collation_probe.\"private-collation-name\" (provider = libc, locale = 'C'); " +
            "CREATE TABLE collation_probe.\"Sample\" (\"Value\" text " +
            "COLLATE collation_probe.\"private-collation-name\");", connection))
        {
            _ = await setup.ExecuteNonQueryAsync();
        }
        try
        {
            var table = new TableCopyPlan("dbo", "Sample", "collation_probe", "Sample",
                ["Value"], ["Value"])
            {
                ColumnTypes = new Dictionary<string, string> { ["Value"] = "text" },
                NullableColumns = ["Value"],
            };
            var database = new DatabaseSchemaPlan(fixture.CanonicalDatabase, "1.0", new string('a', 64), "",
                [table]);
            database = database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
            ProductionSchemaObservation observed = await ProductionSchemaCatalogInspector.InspectDatabaseAsync(
                database, fixture.ConnectionString, CancellationToken.None);
            ProductionSchemaColumnDiagnostic diagnostic = Assert.Single(observed.ColumnDiagnostics,
                item => item.Schema == "collation_probe" && item.Table == "Sample" && item.Column == "Value");
            Assert.Equal("shape-drift", diagnostic.Status);
            Assert.Contains("collation", diagnostic.ChangedComponents);
            Assert.Equal("explicit", diagnostic.ActualCollationMode);
            Assert.Equal("explicit-unreviewed", diagnostic.ActualCollationIdentity);
            Assert.Equal("libc", diagnostic.ActualCollationProvider);
            Assert.Equal("deterministic", diagnostic.ActualCollationDeterminism);
            Assert.Equal("non-pg-catalog", diagnostic.ActualCollationCatalogScope);
            Assert.True(diagnostic.ActualCollationVersionState is
                "current" or "unversioned" or "unverifiable");
            Assert.DoesNotContain("private-collation-name", JsonSerializer.Serialize(observed),
                StringComparison.Ordinal);
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("DROP SCHEMA collation_probe CASCADE;", connection);
            _ = await cleanup.ExecuteNonQueryAsync();
        }
    }
}
