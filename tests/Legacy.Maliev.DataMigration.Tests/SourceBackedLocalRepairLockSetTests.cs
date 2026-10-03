using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class SourceBackedLocalRepairLockSetTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GuardAndRollbackPreserveAllBigintSequenceParametersDependenciesAndState(bool isCalled)
    {
        await WithDatabase(async cs =>
        {
            await Execute(cs, $"SELECT setval('legacy_migration_internal.authority_seq',9007199254740993,{(isCalled ? "true" : "false")});");
            SourceBackedLocalRepairDatabasePreimage expected = await Read(cs);
            await using (var connection = new NpgsqlConnection(cs))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
                SourceBackedLocalRepairDatabasePreimage locked = await SourceBackedLocalRepairLockSet.AcquireAndVerifyAsync(connection, transaction, Schema(), expected, CancellationToken.None);
                SourceBackedLocalRepairPreimage.RequireMatches(expected, locked);
                Assert.Equal(9007199254740993L, Assert.Single(locked.Sequences).LastValue);
                Assert.Equal(isCalled, Assert.Single(locked.Sequences).IsCalled);
                Assert.Equal(7L, Assert.Single(locked.Sequences).Cache);
                await using (var locks = new NpgsqlCommand("SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND granted AND mode='ShareRowExclusiveLock';", connection, transaction))
                {
                    // All four signed tables, parameter catalog and the sequence itself.
                    Assert.Equal(6L, await locks.ExecuteScalarAsync());
                }
                await using (var mutate = new NpgsqlCommand("UPDATE legacy_migration_internal.effects SET value='rolled-back'; ALTER SEQUENCE legacy_migration_internal.authority_seq RESTART WITH 9007199254740995;", connection, transaction))
                {
                    _ = await mutate.ExecuteNonQueryAsync();
                }
                await transaction.RollbackAsync();
            }
            SourceBackedLocalRepairPreimage.RequireMatches(expected, await Read(cs));
            Assert.False(SourceBackedLocalRepairLockSet.AuthorizesExecution);
        });
    }

    [Theory]
    [InlineData("effect-writer")]
    [InlineData("nextval")]
    [InlineData("setval")]
    public async Task NewClientAfterGuardIsBlockedByRealRelationOrSequenceLock(string kind)
    {
        await WithDatabase(async cs =>
        {
            SourceBackedLocalRepairDatabasePreimage expected = await Read(cs);
            await using var guard = new NpgsqlConnection(cs);
            await guard.OpenAsync();
            await using NpgsqlTransaction transaction = await guard.BeginTransactionAsync(IsolationLevel.Serializable);
            _ = await SourceBackedLocalRepairLockSet.AcquireAndVerifyAsync(guard, transaction, Schema(), expected, CancellationToken.None);
            await using var writer = new NpgsqlConnection(cs);
            await writer.OpenAsync();
            string sql = kind switch
            {
                "effect-writer" => "UPDATE legacy_migration_internal.effects SET value='should-never-commit';",
                "nextval" => "SELECT nextval('legacy_migration_internal.authority_seq');",
                _ => "SELECT setval('legacy_migration_internal.authority_seq',9007199254740995,true);",
            };
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await using var command = new NpgsqlCommand(sql, writer);
            Task<int> pending = command.ExecuteNonQueryAsync(cancellation.Token);
            try
            {
                await AssertBlocked(writer.ProcessID, guard.ProcessID, cancellation.Token);
                Assert.False(pending.IsCompleted);
            }
            finally
            {
                await cancellation.CancelAsync();
                _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
                await writer.CloseAsync();
                await transaction.RollbackAsync();
            }
            await guard.CloseAsync();
            SourceBackedLocalRepairPreimage.RequireMatches(expected, await Read(cs));
        });
    }

    [Theory]
    [InlineData("cache")]
    [InlineData("rows")]
    [InlineData("sequence-state")]
    [InlineData("new-table")]
    public async Task ChangedPreimageFailsAndNeverResetsChangedCache(string mutation)
    {
        await WithDatabase(async cs =>
        {
            SourceBackedLocalRepairDatabasePreimage expected = await Read(cs);
            await Execute(cs, mutation switch
            {
                "cache" => "ALTER SEQUENCE legacy_migration_internal.authority_seq CACHE 9;",
                "rows" => "UPDATE legacy_migration_internal.effects SET value='changed';",
                "sequence-state" => "SELECT setval('legacy_migration_internal.authority_seq',9007199254740995,true);",
                _ => "CREATE TABLE legacy_migration_internal.new_effect(id bigint);",
            });
            SourceBackedLocalRepairDatabasePreimage changed = await Read(cs);
            await using (var connection = new NpgsqlConnection(cs))
            {
                await connection.OpenAsync();
                await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
                DeltaExecutionException failure = await Assert.ThrowsAsync<DeltaExecutionException>(() => SourceBackedLocalRepairLockSet.AcquireAndVerifyAsync(connection, transaction, Schema(), expected, CancellationToken.None));
                Assert.Equal("delta_source_repair_preimage_changed", failure.Code);
                if (mutation == "cache")
                {
                    await using var cache = new NpgsqlCommand("SELECT seqcache FROM pg_sequence WHERE seqrelid='legacy_migration_internal.authority_seq'::regclass;", connection, transaction);
                    Assert.Equal(9L, await cache.ExecuteScalarAsync());
                }
                await transaction.RollbackAsync();
            }
            SourceBackedLocalRepairPreimage.RequireMatches(changed, await Read(cs));
        });
    }

    [Fact]
    public async Task ExistingIdleClientIsRefusedBeforeSequenceDdl()
    {
        await WithDatabase(async cs =>
        {
            SourceBackedLocalRepairDatabasePreimage expected = await Read(cs);
            await using var existingClient = new NpgsqlConnection(cs);
            await existingClient.OpenAsync();
            await using var guard = new NpgsqlConnection(cs);
            await guard.OpenAsync();
            await using NpgsqlTransaction transaction = await guard.BeginTransactionAsync(IsolationLevel.Serializable);
            DeltaExecutionException failure = await Assert.ThrowsAsync<DeltaExecutionException>(() => SourceBackedLocalRepairLockSet.AcquireAndVerifyAsync(guard, transaction, Schema(), expected, CancellationToken.None));
            Assert.Equal("delta_source_repair_lock_clients_present", failure.Code);
            await transaction.RollbackAsync();
            await guard.CloseAsync();
            await existingClient.CloseAsync();
            SourceBackedLocalRepairPreimage.RequireMatches(expected, await Read(cs));
        });
    }

    [Theory]
    [InlineData(IsolationLevel.RepeatableRead)]
    [InlineData(IsolationLevel.ReadCommitted)]
    public async Task WrongIsolationFailsBeforeAnyMutationOrLock(IsolationLevel isolation)
    {
        await WithDatabase(async cs =>
        {
            SourceBackedLocalRepairDatabasePreimage expected = await Read(cs);
            await using var connection = new NpgsqlConnection(cs);
            await connection.OpenAsync();
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(isolation);
            DeltaExecutionException failure = await Assert.ThrowsAsync<DeltaExecutionException>(() => SourceBackedLocalRepairLockSet.AcquireAndVerifyAsync(connection, transaction, Schema(), expected, CancellationToken.None));
            Assert.Equal("delta_source_repair_lock_binding_invalid", failure.Code);
            await using var locks = new NpgsqlCommand("SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND granted AND mode='ShareRowExclusiveLock';", connection, transaction);
            Assert.Equal(0L, await locks.ExecuteScalarAsync());
            await transaction.RollbackAsync();
        });
    }

    [Theory]
    [InlineData("ordering")]
    [InlineData("duplicate")]
    [InlineData("hash")]
    [InlineData("cache")]
    public async Task InvalidExpectedShapeFailsBeforeLocks(string mutation)
    {
        await WithDatabase(async cs =>
        {
            SourceBackedLocalRepairDatabasePreimage expected = await Read(cs);
            expected = mutation switch
            {
                "ordering" => expected with { Relations = expected.Relations.Reverse().ToArray() },
                "duplicate" => expected with { Relations = [.. expected.Relations, expected.Relations[0]] },
                "hash" => expected with { CatalogObjectsSha256 = "invalid" },
                _ => expected with { Sequences = [expected.Sequences[0] with { Cache = 0 }] },
            };
            await using var connection = new NpgsqlConnection(cs);
            await connection.OpenAsync();
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
            DeltaExecutionException failure = await Assert.ThrowsAsync<DeltaExecutionException>(() => SourceBackedLocalRepairLockSet.AcquireAndVerifyAsync(connection, transaction, Schema(), expected, CancellationToken.None));
            Assert.Equal("delta_source_repair_lock_preimage_invalid", failure.Code);
            await using var locks = new NpgsqlCommand("SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND granted AND mode='ShareRowExclusiveLock';", connection, transaction);
            Assert.Equal(0L, await locks.ExecuteScalarAsync());
            await transaction.RollbackAsync();
        });
    }

    private async Task AssertBlocked(int writerPid, int guardPid, CancellationToken cancellationToken)
    {
        string cs = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Pooling = false }.ConnectionString;
        await using var observer = new NpgsqlConnection(cs);
        await observer.OpenAsync(cancellationToken);
        await using var query = new NpgsqlCommand("""
            SELECT EXISTS(SELECT 1 FROM pg_locks waiting JOIN pg_locks held
                ON held.database=waiting.database AND held.relation=waiting.relation
                WHERE waiting.pid=$1 AND NOT waiting.granted AND held.pid=$2 AND held.granted
                  AND held.mode='ShareRowExclusiveLock'
                  AND $2=ANY(pg_blocking_pids($1)));
            """, observer);
        _ = query.Parameters.AddWithValue(writerPid);
        _ = query.Parameters.AddWithValue(guardPid);
        while (await query.ExecuteScalarAsync(cancellationToken) is not true)
        {
            await Task.Delay(10, cancellationToken);
        }
    }

    private async Task WithDatabase(Func<string, Task> action)
    {
        await Execute(fixture.ConnectionString, "CREATE DATABASE \"ContactRequest\";");
        string cs = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = "ContactRequest", Pooling = false }.ConnectionString;
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
                CREATE SEQUENCE legacy_migration_internal.authority_seq AS bigint START 9007199254740993 CACHE 7;
                ALTER SEQUENCE legacy_migration_internal.authority_seq OWNED BY legacy_migration_internal.effects.id;
                """);
            await action(cs);
        }
        finally { await Execute(fixture.ConnectionString, "DROP DATABASE \"ContactRequest\" WITH (FORCE);"); }
    }

    private static DatabaseSchemaPlan Schema()
    {
        return new("ContactRequest", "1", new string('a', 64), new string('b', 64), []);
    }

    private static async Task<SourceBackedLocalRepairDatabasePreimage> Read(string cs)
    {
        await using var connection = new NpgsqlConnection(cs);
        await connection.OpenAsync();
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction)) { _ = await readOnly.ExecuteNonQueryAsync(); }
        SourceBackedLocalRepairDatabasePreimage value = await SourceBackedLocalRepairPreimage.InspectAsync(connection, transaction, Schema(), CancellationToken.None);
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
