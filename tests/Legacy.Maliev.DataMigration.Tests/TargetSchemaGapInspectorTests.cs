using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class TargetSchemaGapInspectorTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task InspectsDisposablePostgreSqlWithoutChangingItsSchemaOrRows()
    {
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using (var setup = new NpgsqlCommand(
            "CREATE SCHEMA schema_gap_probe; " +
            "CREATE TABLE schema_gap_probe.\"Country\" (\"ID\" integer PRIMARY KEY, \"LegacyCode\" text); " +
            "CREATE TABLE schema_gap_probe.\"RuntimeOnly\" (\"ID\" integer); " +
            "INSERT INTO schema_gap_probe.\"Country\" (\"ID\", \"LegacyCode\") VALUES (1, 'test-only');",
            connection))
        {
            _ = await setup.ExecuteNonQueryAsync();
        }

        try
        {
            var desired = new DatabaseSchemaPlan(fixture.CanonicalDatabase, "1.0", new string('a', 64),
                new string('b', 64),
                [new TableCopyPlan("dbo", "Country", "schema_gap_probe", "Country", ["ID", "Name"], ["ID"])]);

            TargetSchemaGap gap = await TargetSchemaGapInspector.InspectDatabaseAsync(
                desired, fixture.ConnectionString, CancellationToken.None);

            Assert.Contains("schema_gap_probe.Country.Name", gap.MissingColumns);
            Assert.Contains("schema_gap_probe.Country.LegacyCode", gap.TargetOnlyColumns);
            Assert.Contains("schema_gap_probe.RuntimeOnly", gap.TargetOnlyTables);
            await using var verify = new NpgsqlCommand(
                "SELECT COUNT(*) FROM schema_gap_probe.\"Country\";", connection);
            Assert.Equal(1L, await verify.ExecuteScalarAsync());
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand("DROP SCHEMA schema_gap_probe CASCADE;", connection);
            _ = await cleanup.ExecuteNonQueryAsync();
        }
    }
}
