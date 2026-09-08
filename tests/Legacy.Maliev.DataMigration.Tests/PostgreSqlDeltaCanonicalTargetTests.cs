using System.Globalization;
using System.Reflection;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PostgreSqlDeltaCanonicalTargetApiTests
{
    [Fact]
    public void CanonicalApi_HasNoDatabaseLifecycleOrSchemaDdlMethods()
    {
        string api = string.Join(' ', new[] { typeof(IDeltaCanonicalTarget), typeof(IDeltaCanonicalTransaction), typeof(PostgreSqlDeltaCanonicalTarget) }
            .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)).Select(member => member.Name));
        foreach (string forbidden in new[] { "CreateDatabase", "DropDatabase", "RenameDatabase", "Truncate", "ApplySchema", "FinalizeSchema" })
        {
            Assert.DoesNotContain(forbidden, api, StringComparison.OrdinalIgnoreCase);
        }
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlDeltaCanonicalTargetIntegrationTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task Commit_DmlAndCheckpoint_AreAtomicAndReplayIsNoOp()
    {
        (string cs, DatabaseSchemaPlan schema, PostgreSqlDeltaCanonicalTarget target) = await SetupAsync();
        MigrationRow old = Row(1, "old"), updated = Row(1, "updated"), deleted = Row(2, "delete"), inserted = Row(3, "inserted");
        CanonicalDeltaOperation update = Operation(schema.Tables[0], [updated], [old]);
        CanonicalDeltaOperation delete = Operation(schema.Tables[0], [], [deleted]);
        CanonicalDeltaOperation insert = Operation(schema.Tables[0], [inserted], []);
        DeltaSynchronizationPlan plan = Plan(schema.Database, schema.Tables[0], [update, delete, insert]);
        string hash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        await using (IDeltaCanonicalTransaction tx = await target.BeginAsync(plan, schema, schema.Database, CancellationToken.None))
        {
            await tx.ApplyAsync(schema.Tables[0], update, updated, old, CancellationToken.None);
            await tx.ApplyAsync(schema.Tables[0], delete, null, deleted, CancellationToken.None);
            await tx.ApplyAsync(schema.Tables[0], insert, inserted, null, CancellationToken.None);
            await tx.CommitAsync(hash, CancellationToken.None);
        }
        Assert.Equal([(1, "updated"), (3, "inserted")], await RowsAsync(cs));
        Assert.Equal(1L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_delta_journal"));
        await using IDeltaCanonicalTransaction replay = await target.BeginAsync(plan, schema, schema.Database, CancellationToken.None);
        Assert.Equal(DeltaExecutionDisposition.AlreadyCommitted, replay.Disposition);
        await replay.CommitAsync(hash, CancellationToken.None);
    }

    [Fact]
    public async Task DisposeAfterFingerprintFailure_RollsBackEarlierDmlAndCheckpoint()
    {
        (string cs, DatabaseSchemaPlan schema, PostgreSqlDeltaCanonicalTarget target) = await SetupAsync();
        MigrationRow inserted = Row(3, "inserted"), updated = Row(1, "updated"), old = Row(1, "old");
        CanonicalDeltaOperation insert = Operation(schema.Tables[0], [inserted], []);
        CanonicalDeltaOperation update = Operation(schema.Tables[0], [updated], [old]) with { TargetRowSha256 = Hash('8') };
        DeltaSynchronizationPlan plan = Plan(schema.Database, schema.Tables[0], [insert, update]);
        await using (IDeltaCanonicalTransaction tx = await target.BeginAsync(plan, schema, schema.Database, CancellationToken.None))
        {
            await tx.ApplyAsync(schema.Tables[0], insert, inserted, null, CancellationToken.None);
            DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() => tx.ApplyAsync(schema.Tables[0], update, updated, old, CancellationToken.None));
            Assert.Equal("canonical_delta_target_row_drift", error.Code);
        }
        Assert.Equal([(1, "old"), (2, "delete")], await RowsAsync(cs));
        Assert.Equal(0L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_delta_journal"));
    }

    [Fact]
    public async Task Begin_StaleFence_FailsClosed()
    {
        (string cs, DatabaseSchemaPlan schema, PostgreSqlDeltaCanonicalTarget target) = await SetupAsync();
        DeltaSynchronizationPlan plan = Plan(schema.Database, schema.Tables[0], []) with { TargetObservationSha256 = Hash('9') };
        DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(() => target.BeginAsync(plan, schema, schema.Database, CancellationToken.None));
        Assert.Equal("canonical_delta_fence_stale", error.Code);
        Assert.Equal([(1, "old"), (2, "delete")], await RowsAsync(cs));
    }

    private async Task<(string, DatabaseSchemaPlan, PostgreSqlDeltaCanonicalTarget)> SetupAsync()
    {
        string db = fixture.CanonicalDatabase;
        string cs = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = db }.ConnectionString;
        await using var connection = new NpgsqlConnection(cs); await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"""
            DROP TABLE IF EXISTS legacy_migration_delta_journal; DROP TABLE IF EXISTS legacy_migration_delta_fence; DROP TABLE IF EXISTS public.delta_items;
            CREATE TABLE public.delta_items(id integer PRIMARY KEY, value text NOT NULL); INSERT INTO public.delta_items VALUES (1,'old'),(2,'delete');
            CREATE TABLE legacy_migration_delta_fence(database_name text PRIMARY KEY, schema_plan_sha256 text NOT NULL, target_schema_sha256 text NOT NULL, target_generation text NOT NULL, target_observation_sha256 text NOT NULL);
            INSERT INTO legacy_migration_delta_fence VALUES ('{db}','{Hash('7')}','{Hash('b')}','generation-1','{Hash('c')}');
            CREATE TABLE legacy_migration_delta_journal(plan_sha256 text PRIMARY KEY, plan_id uuid NOT NULL UNIQUE, source_cutoff_utc timestamptz NOT NULL, target_observation_sha256 text NOT NULL, operations_sha256 text NOT NULL, committed_at_utc timestamptz NOT NULL);
            """, connection); _ = await command.ExecuteNonQueryAsync();
        DatabaseSchemaPlan schema = new(db, "1", Hash('d'), Hash('b'), [Table()]);
        return (cs, schema, new PostgreSqlDeltaCanonicalTarget(new(cs, db, "generation-1")));
    }

    private static TableCopyPlan Table()
    {
        return new("dbo", "items", "public", "delta_items", ["id", "value"], ["id"]) { ColumnTypes = new Dictionary<string, string> { ["id"] = "integer", ["value"] = "text" }, PrimaryKey = new("pk_delta_items", ["id"]) };
    }

    private static MigrationRow Row(int id, string value)
    {
        return new(new Dictionary<string, object?> { ["id"] = id, ["value"] = value });
    }

    private static CanonicalDeltaOperation Operation(TableCopyPlan table, IReadOnlyList<MigrationRow> source, IReadOnlyList<MigrationRow> target)
    {
        return Assert.Single(CanonicalDeltaPlanner.Plan(table, source, target).Operations);
    }

    private static DeltaSynchronizationPlan Plan(string database, TableCopyPlan table, IReadOnlyList<CanonicalDeltaOperation> operations)
    {
        DeltaTablePlan delta = new($"{table.TargetSchema}.{table.TargetTable}", operations.LongCount(x => x.Kind == DeltaOperationKind.Insert), operations.LongCount(x => x.Kind == DeltaOperationKind.Update), operations.LongCount(x => x.Kind == DeltaOperationKind.Delete), 0, DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(operations), operations);
        IReadOnlyList<DeltaDatabasePlan> databases = [new(database, [delta]), .. DatabaseInventory.ActiveDatabases
            .Where(name => !string.Equals(name, database, StringComparison.Ordinal))
            .Select(name => new DeltaDatabasePlan(name, [new("public.items", 0, 0, 0, 0, DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([]), [])]))];
        return new("1.0", Guid.NewGuid(), new string('1', 40), DateTimeOffset.Parse("2026-09-08T05:00:00Z", CultureInfo.InvariantCulture), Hash('a'), Hash('7'), Hash('d'), "maliev-legacy", "legacy-postgres-main", "generation-1", Hash('c'), Hash('e'), Hash('f'), DateTimeOffset.Parse("2026-09-08T05:01:00Z", CultureInfo.InvariantCulture), databases, "test", null);
    }
    private static string Hash(char value)
    {
        return new(value, 64);
    }

    private static async Task<long> ScalarAsync(string cs, string sql) { await using var c = new NpgsqlConnection(cs); await c.OpenAsync(); await using var cmd = new NpgsqlCommand(sql, c); return Convert.ToInt64(await cmd.ExecuteScalarAsync(), CultureInfo.InvariantCulture); }
    private static async Task<List<(int, string)>> RowsAsync(string cs) { var rows = new List<(int, string)>(); await using var c = new NpgsqlConnection(cs); await c.OpenAsync(); await using var cmd = new NpgsqlCommand("SELECT id,value FROM public.delta_items ORDER BY id", c); await using var r = await cmd.ExecuteReaderAsync(); while (await r.ReadAsync()) { rows.Add((r.GetInt32(0), r.GetString(1))); } return rows; }
}
