using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class DeltaReconciliationInspectorsTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task PostgreSql_inspector_excludes_internal_delta_metadata_from_application_schema_evidence()
    {
        string database = fixture.CanonicalDatabase;
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = database,
        }.ConnectionString;
        await using (var connection = new NpgsqlConnection(connectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand("""
                DROP SCHEMA IF EXISTS legacy_migration_internal CASCADE;
                DROP SCHEMA IF EXISTS public CASCADE;
                CREATE SCHEMA public;
                CREATE TABLE public.delta_reconcile_items(id integer PRIMARY KEY, value text NULL);
                INSERT INTO public.delta_reconcile_items VALUES (1,'หนึ่ง'),(2,NULL);
                CREATE SCHEMA legacy_migration_internal;
                CREATE TABLE legacy_migration_internal.delta_journal(plan_sha256 text PRIMARY KEY);
                """, connection);
            _ = await command.ExecuteNonQueryAsync();
        }
        TableCopyPlan table = new("dbo", "delta_reconcile_items", "public", "delta_reconcile_items",
            ["id", "value"], ["id"])
        {
            SourceColumnTypes = new Dictionary<string, string> { ["id"] = "int", ["value"] = "nvarchar(100)" },
            ColumnTypes = new Dictionary<string, string> { ["id"] = "integer", ["value"] = "text" },
            NullableColumns = ["value"],
            PrimaryKey = new("delta_reconcile_items_pkey", ["id"]),
        };
        var draft = new DatabaseSchemaPlan(database, "1.0", Hash('a'), string.Empty, [table]);
        DatabaseSchemaPlan schema = draft with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft) };
        var inspector = new PostgreSqlDeltaReconciliationInspector(new(fixture.ConnectionString));

        DatabaseReconciliationEvidence evidence = await inspector.InspectAsync(schema, CancellationToken.None);

        Assert.Equal(schema.TargetSchemaSha256, evidence.TargetSchemaSha256);
        TableReconciliationEvidence observed = Assert.Single(evidence.Tables);
        Assert.Equal(2, observed.RowCount);
        Assert.Equal(1, observed.NullCounts["value"]);
        Assert.Empty(evidence.SequenceNextValues);
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }
}
