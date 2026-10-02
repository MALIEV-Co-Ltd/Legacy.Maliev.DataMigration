using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class SourceBackedLocalRepairPreimageTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [InlineData("unchanged-source")]
    [InlineData("extension")]
    [InlineData("metadata")]
    [InlineData("sequence-state")]
    [InlineData("sequence-cache")]
    [InlineData("sequence-privilege")]
    [InlineData("sequence-dependency")]
    [InlineData("schema-privilege")]
    [InlineData("default-privilege")]
    [InlineData("composite-type")]
    [InlineData("internal-schema")]
    [InlineData("function")]
    [InlineData("database-config")]
    [InlineData("database-set")]
    [InlineData("role-set")]
    [InlineData("role-database-set")]
    [InlineData("trigger-state")]
    [InlineData("internal-trigger-state")]
    [InlineData("policy")]
    [InlineData("index-valid")]
    [InlineData("index-ready")]
    public async Task CompletePreimageDetectsChurnOutsideSelectedOperations(string mutation)
    {
        const string database = "ContactRequest";
        await Execute(fixture.ConnectionString, "CREATE DATABASE \"ContactRequest\";");
        string cs = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = database, Pooling = false }.ConnectionString;
        try
        {
            await Execute(cs, """
                CREATE TABLE public.source_rows(id bigint PRIMARY KEY, value text NOT NULL);
                INSERT INTO public.source_rows VALUES(1,'unchanged-source-row');
                ALTER TABLE public.source_rows ADD CONSTRAINT source_self_fk FOREIGN KEY(id) REFERENCES public.source_rows(id);
                CREATE FUNCTION public.source_row_trigger() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
                CREATE TRIGGER source_row_trigger BEFORE UPDATE ON public.source_rows FOR EACH ROW EXECUTE FUNCTION public.source_row_trigger();
                CREATE SCHEMA legacy_migration_internal;
                CREATE TABLE legacy_migration_internal.delta_fence(database_name text NOT NULL);
                INSERT INTO legacy_migration_internal.delta_fence VALUES('ContactRequest');
                CREATE TABLE legacy_migration_internal.delta_journal(reconciliation_sha256 text);
                INSERT INTO legacy_migration_internal.delta_journal VALUES('settled');
                CREATE TABLE legacy_migration_internal.effects(id bigint PRIMARY KEY, value text NOT NULL);
                INSERT INTO legacy_migration_internal.effects VALUES(9007199254740993,'application-effect');
                CREATE SEQUENCE legacy_migration_internal.authority_seq AS bigint START 9007199254740993 CACHE 7;
                """);
            SourceBackedLocalRepairDatabasePreimage before = await Read(cs, database);
            SourceBackedLocalRepairDatabasePreimage repeated = await Read(cs, database);
            SourceBackedLocalRepairPreimage.RequireMatches(before, repeated);
            Assert.False(SourceBackedLocalRepairDatabasePreimage.AuthorizesExecution);
            Assert.Equal(4, before.Relations.Count);
            Assert.Equal(9007199254740993L, Assert.Single(before.Sequences).LastValue);
            Assert.False(Assert.Single(before.Sequences).IsCalled);
            await Execute(cs, mutation switch
            {
                "unchanged-source" => "UPDATE public.source_rows SET value='changed' WHERE id=1;",
                "extension" => "UPDATE legacy_migration_internal.effects SET value='changed' WHERE id=9007199254740993;",
                "metadata" => "UPDATE legacy_migration_internal.delta_fence SET database_name='other';",
                "sequence-privilege" => "GRANT SELECT ON SEQUENCE legacy_migration_internal.authority_seq TO PUBLIC;",
                "sequence-dependency" => "ALTER SEQUENCE legacy_migration_internal.authority_seq OWNED BY legacy_migration_internal.effects.id;",
                "default-privilege" => "ALTER DEFAULT PRIVILEGES IN SCHEMA legacy_migration_internal GRANT SELECT ON TABLES TO PUBLIC;",
                "composite-type" => "CREATE TYPE legacy_migration_internal.probe_type AS (value bigint);",
                "schema-privilege" => "GRANT USAGE ON SCHEMA legacy_migration_internal TO PUBLIC;",
                "sequence-state" => "SELECT nextval('legacy_migration_internal.authority_seq');",
                "internal-schema" => "ALTER TABLE legacy_migration_internal.effects ADD COLUMN extra text;",
                "function" => "CREATE FUNCTION legacy_migration_internal.probe() RETURNS integer LANGUAGE sql AS 'SELECT 1';",
                "database-config" => "ALTER DATABASE \"ContactRequest\" CONNECTION LIMIT 17;",
                "database-set" => "ALTER DATABASE \"ContactRequest\" SET application_name='changed';",
                "role-set" => "ALTER ROLE CURRENT_USER SET application_name='changed';",
                "role-database-set" => "ALTER ROLE CURRENT_USER IN DATABASE \"ContactRequest\" SET statement_timeout='37s';",
                "trigger-state" => "ALTER TABLE public.source_rows DISABLE TRIGGER source_row_trigger;",
                "internal-trigger-state" => "DO $x$ DECLARE trigger_name text; BEGIN SELECT tgname INTO trigger_name FROM pg_trigger WHERE tgrelid='public.source_rows'::regclass AND tgisinternal ORDER BY tgname LIMIT 1; EXECUTE format('ALTER TABLE public.source_rows DISABLE TRIGGER %I',trigger_name); END $x$;",
                "policy" => "CREATE POLICY source_rows_policy ON public.source_rows USING (id>0);",
                "index-valid" => "UPDATE pg_index SET indisvalid=false WHERE indexrelid='public.source_rows_pkey'::regclass;",
                "index-ready" => "UPDATE pg_index SET indisready=false WHERE indexrelid='public.source_rows_pkey'::regclass;",
                _ => "ALTER SEQUENCE legacy_migration_internal.authority_seq CACHE 9;",
            });
            SourceBackedLocalRepairDatabasePreimage after = await Read(cs, database);
            Assert.NotEqual(SourceBackedLocalRepairPreimage.ComputeSha256(before), SourceBackedLocalRepairPreimage.ComputeSha256(after));
            Assert.Equal("delta_source_repair_preimage_changed", Assert.Throws<DeltaExecutionException>(() =>
                SourceBackedLocalRepairPreimage.RequireMatches(before, after)).Code);
            await Execute(cs, "INSERT INTO legacy_migration_internal.delta_journal VALUES(NULL);");
            DeltaExecutionException pending = await Assert.ThrowsAsync<DeltaExecutionException>(() => Read(cs, database));
            Assert.Equal("delta_source_repair_preimage_unsettled", pending.Code);
        }
        finally
        {
            if (mutation == "role-set") { await Execute(fixture.ConnectionString, "ALTER ROLE CURRENT_USER RESET application_name;"); }
            await Execute(fixture.ConnectionString, "DROP DATABASE \"ContactRequest\" WITH (FORCE);");
        }
    }

    [Fact]
    public async Task SerializableInspectionAndCallerRollbackPreserveCompletePreimageAndBigintSequence()
    {
        const string database = "ContactRequest";
        await Execute(fixture.ConnectionString, "CREATE DATABASE \"ContactRequest\";");
        string cs = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = database, Pooling = false }.ConnectionString;
        try
        {
            await Execute(cs, """
                CREATE SCHEMA legacy_migration_internal;
                CREATE TABLE legacy_migration_internal.delta_fence(database_name text NOT NULL);
                INSERT INTO legacy_migration_internal.delta_fence VALUES('ContactRequest');
                CREATE TABLE legacy_migration_internal.delta_journal(reconciliation_sha256 text);
                INSERT INTO legacy_migration_internal.delta_journal VALUES('settled');
                CREATE TABLE public.source_rows(id bigint PRIMARY KEY,value text NOT NULL);
                INSERT INTO public.source_rows VALUES(1,'original');
                CREATE TABLE legacy_migration_internal.effects(id bigint PRIMARY KEY,value text NOT NULL);
                INSERT INTO legacy_migration_internal.effects VALUES(9007199254740993,'preserved');
                CREATE SEQUENCE legacy_migration_internal.authority_seq AS bigint START 9007199254740993;
                """);
            SourceBackedLocalRepairDatabasePreimage original = await Read(cs, database);
            await using (var connection = new NpgsqlConnection(cs))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
                var schema = new DatabaseSchemaPlan(database, "1", new string('a', 64), new string('b', 64), []);
                SourceBackedLocalRepairDatabasePreimage inTransaction = await SourceBackedLocalRepairPreimage.InspectAsync(connection, transaction, schema, CancellationToken.None);
                SourceBackedLocalRepairPreimage.RequireMatches(original, inTransaction);
                await using (var mutation = new NpgsqlCommand("""
                    UPDATE public.source_rows SET value='rolled-back';
                    UPDATE legacy_migration_internal.effects SET value='rolled-back';
                    UPDATE legacy_migration_internal.delta_fence SET database_name='rolled-back';
                    ALTER SEQUENCE legacy_migration_internal.authority_seq RESTART WITH 9007199254740995;
                    """, connection, transaction)) { _ = await mutation.ExecuteNonQueryAsync(); }
                SourceBackedLocalRepairDatabasePreimage changed = await SourceBackedLocalRepairPreimage.InspectAsync(connection, transaction, schema, CancellationToken.None);
                Assert.Equal("delta_source_repair_preimage_changed", Assert.Throws<DeltaExecutionException>(() => SourceBackedLocalRepairPreimage.RequireMatches(original, changed)).Code);
                await transaction.RollbackAsync();
            }
            SourceBackedLocalRepairPreimage.RequireMatches(original, await Read(cs, database));
        }
        finally { await Execute(fixture.ConnectionString, "DROP DATABASE \"ContactRequest\" WITH (FORCE);"); }
    }

    private static async Task<SourceBackedLocalRepairDatabasePreimage> Read(string cs, string database)
    {
        await using var connection = new NpgsqlConnection(cs);
        await connection.OpenAsync();
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction)) { _ = await readOnly.ExecuteNonQueryAsync(); }
        var schema = new DatabaseSchemaPlan(database, "1", new string('a', 64), new string('b', 64), []);
        SourceBackedLocalRepairDatabasePreimage value = await SourceBackedLocalRepairPreimage.InspectAsync(connection, transaction, schema, CancellationToken.None);
        await transaction.RollbackAsync();
        return value;
    }

    private static async Task Execute(string cs, string sql)
    {
        await using var connection = new NpgsqlConnection(cs);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }
}
