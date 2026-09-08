using System.Globalization;
using System.Reflection;
using System.Text;
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
        string reconciliation;
        await using (IDeltaCanonicalTransaction tx = await target.BeginAsync(plan, schema, schema.Database, CancellationToken.None))
        {
            await tx.ApplyAsync(schema.Tables[0], update, updated, old, CancellationToken.None);
            await tx.ApplyAsync(schema.Tables[0], delete, null, deleted, CancellationToken.None);
            await tx.ApplyAsync(schema.Tables[0], insert, inserted, null, CancellationToken.None);
            reconciliation = await tx.ReconcileAsync(Evidence(schema, [updated, inserted]), CancellationToken.None);
            await tx.CommitAsync(hash, reconciliation, CancellationToken.None);
        }
        Assert.Equal([(1, "updated"), (3, "inserted")], await RowsAsync(cs));
        Assert.Equal(4L, await ScalarAsync(cs, "SELECT last_value FROM public.delta_items_id_seq"));
        Assert.Equal(1L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal"));
        Assert.Equal(reconciliation, await TextScalarAsync(cs, "SELECT reconciliation_sha256 FROM legacy_migration_internal.delta_journal"));
        await using IDeltaCanonicalTransaction replay = await target.BeginAsync(plan, schema, schema.Database, CancellationToken.None);
        Assert.Equal(DeltaExecutionDisposition.AlreadyCommitted, replay.Disposition);
        Assert.Equal(reconciliation, replay.ReconciliationSha256);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => replay.CommitAsync(hash, Hash('9'), CancellationToken.None));
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
        Assert.Equal(0L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal"));
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

    [Fact]
    public async Task StreamedTextInsert_IsConsumedAndFingerprintCheckedBeforeAtomicCommit()
    {
        (string cs, DatabaseSchemaPlan schema, PostgreSqlDeltaCanonicalTarget target) = await SetupAsync();
        byte[] expectedBytes = Encoding.UTF8.GetBytes("streamed text");
        var expected = new MigrationRow(new Dictionary<string, object?>
        {
            ["id"] = 3,
            ["value"] = new BufferedStreamingLob(StreamingLobKind.Text, expectedBytes),
        });
        CanonicalDeltaOperation insert = Operation(schema.Tables[0], [expected], []);
        var lob = new StreamingLob(StreamingLobKind.Text, expectedBytes.Length, async (destination, token) =>
            await destination.WriteAsync(expectedBytes, token));
        var streamed = new MigrationRow(new Dictionary<string, object?> { ["id"] = 3, ["value"] = lob });
        DeltaSynchronizationPlan plan = Plan(schema.Database, schema.Tables[0], [insert]);
        string hash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);

        await using (IDeltaCanonicalTransaction tx = await target.BeginAsync(plan, schema, schema.Database, CancellationToken.None))
        {
            await tx.ApplyAsync(schema.Tables[0], insert, streamed, null, CancellationToken.None);
            Assert.True(lob.IsConsumed);
            string reconciliation = await tx.ReconcileAsync(Evidence(schema, [Row(1, "old"), Row(2, "delete"), Row(3, "streamed text")]), CancellationToken.None);
            await tx.CommitAsync(hash, reconciliation, CancellationToken.None);
        }

        Assert.Equal([(1, "old"), (2, "delete"), (3, "streamed text")], await RowsAsync(cs));
        Assert.Equal(1L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal"));
    }

    private async Task<(string, DatabaseSchemaPlan, PostgreSqlDeltaCanonicalTarget)> SetupAsync()
    {
        string db = fixture.CanonicalDatabase;
        string cs = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = db }.ConnectionString;
        await using var connection = new NpgsqlConnection(cs); await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"""
            CREATE SCHEMA IF NOT EXISTS legacy_migration_internal;
            DROP TABLE IF EXISTS legacy_migration_internal.delta_journal; DROP TABLE IF EXISTS legacy_migration_internal.delta_fence; DROP TABLE IF EXISTS public.delta_items;
            CREATE TABLE public.delta_items(id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, value text NOT NULL); INSERT INTO public.delta_items VALUES (1,'old'),(2,'delete');
            CREATE TABLE legacy_migration_internal.delta_fence(database_name text PRIMARY KEY, schema_plan_sha256 text NOT NULL, target_schema_sha256 text NOT NULL, target_generation text NOT NULL, target_observation_sha256 text NOT NULL);
            CREATE TABLE legacy_migration_internal.delta_journal(plan_sha256 text PRIMARY KEY, plan_id uuid NOT NULL UNIQUE, source_cutoff_utc timestamptz NOT NULL, target_observation_sha256 text NOT NULL, operations_sha256 text NOT NULL, reconciliation_sha256 text NOT NULL, committed_at_utc timestamptz NOT NULL);
            """, connection); _ = await command.ExecuteNonQueryAsync();
        DatabaseSchemaPlan schema = new(db, "1", Hash('d'), Hash('b'), [Table()]);
        await using (NpgsqlTransaction schemaTransaction = await connection.BeginTransactionAsync())
        await using (var schemaInspector = new PostgreSqlWholeDatabaseTransaction(connection, schemaTransaction, ownsResources: false))
        {
            schema = schema with
            {
                TargetSchemaSha256 = await schemaInspector.InspectSchemaAsync(schema, CancellationToken.None),
            };
            await schemaTransaction.RollbackAsync();
        }
        await using var fence = new NpgsqlCommand("INSERT INTO legacy_migration_internal.delta_fence VALUES ($1,$2,$3,$4,$5);", connection);
        _ = fence.Parameters.AddWithValue(db);
        _ = fence.Parameters.AddWithValue(Hash('7'));
        _ = fence.Parameters.AddWithValue(schema.TargetSchemaSha256);
        _ = fence.Parameters.AddWithValue("generation-1");
        _ = fence.Parameters.AddWithValue(Hash('c'));
        _ = await fence.ExecuteNonQueryAsync();
        return (cs, schema, new PostgreSqlDeltaCanonicalTarget(new(cs, db, "generation-1")));
    }

    private static TableCopyPlan Table()
    {
        return new("dbo", "items", "public", "delta_items", ["id", "value"], ["id"])
        {
            ColumnTypes = new Dictionary<string, string> { ["id"] = "integer", ["value"] = "text" },
            PrimaryKey = new("pk_delta_items", ["id"]),
            Identities = [new("id", 1, 1, 3, true)],
        };
    }

    private static MigrationRow Row(int id, string value)
    {
        return new(new Dictionary<string, object?> { ["id"] = id, ["value"] = value });
    }

    [Fact]
    public async Task ReconciliationMismatch_RollsBackDmlAndDoesNotWriteCheckpoint()
    {
        (string cs, DatabaseSchemaPlan schema, PostgreSqlDeltaCanonicalTarget target) = await SetupAsync();
        MigrationRow inserted = Row(3, "inserted");
        CanonicalDeltaOperation insert = Operation(schema.Tables[0], [inserted], []);
        DeltaSynchronizationPlan plan = Plan(schema.Database, schema.Tables[0], [insert]);

        await using (IDeltaCanonicalTransaction tx = await target.BeginAsync(plan, schema, schema.Database, CancellationToken.None))
        {
            await tx.ApplyAsync(schema.Tables[0], insert, inserted, null, CancellationToken.None);
            MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                tx.ReconcileAsync(Evidence(schema, [Row(1, "old"), Row(2, "delete"), Row(3, "different")]), CancellationToken.None));
            Assert.Equal("shadow_reconciliation_failed", error.Code);
        }

        Assert.Equal([(1, "old"), (2, "delete")], await RowsAsync(cs));
        Assert.Equal(0L, await ScalarAsync(cs, "SELECT count(*) FROM legacy_migration_internal.delta_journal"));
        Assert.Equal(1L, await ScalarAsync(cs, "SELECT last_value FROM public.delta_items_id_seq"));
    }

    private static DatabaseReconciliationEvidence Evidence(DatabaseSchemaPlan schema, IReadOnlyList<MigrationRow> rows)
    {
        using var collector = new TableEvidenceCollector(schema.Tables[0]);
        foreach (MigrationRow row in rows)
        {
            collector.Append(row);
        }
        return new(schema.Database, schema.SourceSchemaSha256, schema.TargetSchemaSha256, [collector.Finish()])
        {
            SequenceNextValues = new Dictionary<string, long>(StringComparer.Ordinal)
            {
                ["public.delta_items.id"] = 4,
            },
        };
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
    private static async Task<string> TextScalarAsync(string cs, string sql) { await using var c = new NpgsqlConnection(cs); await c.OpenAsync(); await using var cmd = new NpgsqlCommand(sql, c); return Convert.ToString(await cmd.ExecuteScalarAsync(), CultureInfo.InvariantCulture)!; }
    private static async Task<List<(int, string)>> RowsAsync(string cs) { var rows = new List<(int, string)>(); await using var c = new NpgsqlConnection(cs); await c.OpenAsync(); await using var cmd = new NpgsqlCommand("SELECT id,value FROM public.delta_items ORDER BY id", c); await using var r = await cmd.ExecuteReaderAsync(); while (await r.ReadAsync()) { rows.Add((r.GetInt32(0), r.GetString(1))); } return rows; }
}
