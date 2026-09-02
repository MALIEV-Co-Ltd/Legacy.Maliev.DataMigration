using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlJournalTerminalAuthorityTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task FailedSchemaPreparation_IsNotCached()
    {
        string schema = $"terminal_{Guid.NewGuid():N}";
        await using var setup = new NpgsqlConnection(fixture.ControlConnectionString);
        await setup.OpenAsync();
        await using (var invalid = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"; CREATE VIEW \"{schema}\".migration_runs AS SELECT 1 AS invalid", setup)) { _ = await invalid.ExecuteNonQueryAsync(); }
        var journal = new PostgreSqlMigrationRunJournal(new(fixture.ControlConnectionString, schema));
        var identity = new MigrationRunIdentity(Guid.NewGuid(), new('a', 40), new('b', 64), new('c', 64), new('d', 64), "test");
        _ = await Assert.ThrowsAsync<PostgresException>(() => journal.TryBeginAsync(identity, default));
        await using (var repairFixture = new NpgsqlCommand($"DROP VIEW \"{schema}\".migration_runs", setup)) { _ = await repairFixture.ExecuteNonQueryAsync(); }
        Assert.Equal(MigrationRunStartStatus.Acquired, (await journal.TryBeginAsync(identity, default)).Status);
    }

    [Fact]
    public async Task CancelledSchemaPreparation_IsNotCached()
    {
        string schema = $"terminal_{Guid.NewGuid():N}";
        var preparer = new PostgreSqlMigrationRunJournal(new(fixture.ControlConnectionString, schema));
        var identity = new MigrationRunIdentity(Guid.NewGuid(), new('a', 40), new('b', 64), new('c', 64), new('d', 64), "test");
        _ = await preparer.TryBeginAsync(identity, default);
        await using var blocker = new NpgsqlConnection(fixture.ControlConnectionString);
        await blocker.OpenAsync();
        await using NpgsqlTransaction transaction = await blocker.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand($"SELECT 1 FROM \"{schema}\".migration_runs FOR UPDATE", blocker, transaction)) { _ = await hold.ExecuteScalarAsync(); }
        var journal = new PostgreSqlMigrationRunJournal(new(fixture.ControlConnectionString, schema));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<MigrationRunStartResult> attempt = journal.TryBeginAsync(identity, cancellation.Token);
        string query = await WaitForBlockedQueryAsync(fixture.ControlConnectionString, schema, cancellation.Token);
        Assert.Contains("ALTER TABLE", query, StringComparison.Ordinal);
        await cancellation.CancelAsync();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => attempt);
        await transaction.RollbackAsync();
        // Require schema preparation on the very same instance after its cancelled initialization.
        await using (var removeFixtureTable = new NpgsqlCommand($"DROP TABLE \"{schema}\".migration_database_checkpoints", blocker)) { _ = await removeFixtureTable.ExecuteNonQueryAsync(); }
        Assert.Equal(MigrationRunStartStatus.InProgress, (await journal.TryBeginAsync(identity, default)).Status);
        await using var exists = new NpgsqlCommand($"SELECT count(*) FROM \"{schema}\".migration_database_checkpoints", blocker);
        Assert.Equal(0L, await exists.ExecuteScalarAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Terminal_LeaseExpiresWhileWaitingOnUnchangedRow_RejectsPublication(bool completed)
    {
        string schema = $"terminal_{Guid.NewGuid():N}";
        var journal = new PostgreSqlMigrationRunJournal(new(fixture.ControlConnectionString, schema));
        var identity = new MigrationRunIdentity(Guid.NewGuid(), new('a', 40), new('b', 64), new('c', 64), new('d', 64), "test");
        MigrationRunLease lease = (await journal.TryBeginAsync(identity, default)).Lease!;
        await using var blocker = new NpgsqlConnection(fixture.ControlConnectionString);
        await blocker.OpenAsync();
        await using (var expire = new NpgsqlCommand($"UPDATE \"{schema}\".migration_runs SET lease_expires_at_utc = clock_timestamp() + interval '2 seconds'", blocker))
        {
            Assert.Equal(1, await expire.ExecuteNonQueryAsync());
        }
        await using NpgsqlTransaction transaction = await blocker.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand($"SELECT 1 FROM \"{schema}\".migration_runs FOR UPDATE", blocker, transaction))
        {
            _ = await hold.ExecuteScalarAsync();
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task waiting = completed
            ? journal.RecordCompletedAsync(lease, new(identity.RunId, identity.SourceCommitSha, identity.SchemaPlanSha256, identity.BackupManifestSha256,
                identity.RunnerDigestSha256, identity.TargetGeneration, DateTimeOffset.UtcNow, [], [], "test", null), timeout.Token)
            : journal.RecordFailedAsync(lease, new(identity.RunId, identity.SourceCommitSha, identity.SchemaPlanSha256, identity.BackupManifestSha256,
                identity.RunnerDigestSha256, identity.TargetGeneration, DateTimeOffset.UtcNow, "test", [], [], "test", null), timeout.Token);
        try
        {
            string query = await WaitForBlockedQueryAsync(fixture.ControlConnectionString, schema, timeout.Token);
            Assert.DoesNotContain("ALTER TABLE", query, StringComparison.Ordinal);
            await using var clock = new NpgsqlCommand($"SELECT clock_timestamp() >= lease_expires_at_utc FROM \"{schema}\".migration_runs", blocker, transaction);
            while (!(bool)(await clock.ExecuteScalarAsync(timeout.Token))!) { await Task.Delay(10, timeout.Token); }
        }
        finally { await transaction.CommitAsync(); }
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => waiting);
        await using var read = new NpgsqlCommand($"SELECT status || ':' || failure_receipts::text FROM \"{schema}\".migration_runs", blocker);
        Assert.Equal("in_progress:[]", await read.ExecuteScalarAsync());
        await using var receipt = new NpgsqlCommand($"SELECT receipt_signed_json FROM \"{schema}\".migration_runs", blocker);
        _ = Assert.IsType<DBNull>(await receipt.ExecuteScalarAsync());
    }

    [Fact]
    public async Task PreparedJournal_HeartbeatWaitsOnRowWithoutRepeatingSchemaDdl()
    {
        string schema = $"terminal_{Guid.NewGuid():N}";
        var journal = new PostgreSqlMigrationRunJournal(new(fixture.ControlConnectionString, schema));
        var identity = new MigrationRunIdentity(Guid.NewGuid(), new('a', 40), new('b', 64), new('c', 64), new('d', 64), "test");
        MigrationRunLease lease = (await journal.TryBeginAsync(identity, default)).Lease!;
        await using var blocker = new NpgsqlConnection(fixture.ControlConnectionString);
        await blocker.OpenAsync();
        await using NpgsqlTransaction transaction = await blocker.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand($"SELECT 1 FROM \"{schema}\".migration_runs FOR UPDATE", blocker, transaction))
        {
            _ = await hold.ExecuteScalarAsync();
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<MigrationRunLease> waiting = journal.HeartbeatAsync(lease, timeout.Token);
        try
        {
            string query = await WaitForBlockedQueryAsync(fixture.ControlConnectionString, schema, timeout.Token);
            Assert.DoesNotContain("ALTER TABLE", query, StringComparison.Ordinal);
            Assert.Contains("FOR UPDATE", query, StringComparison.Ordinal);
        }
        finally
        {
            await transaction.RollbackAsync();
            _ = await waiting;
        }
    }

    internal static async Task<string> WaitForBlockedQueryAsync(string connectionString, string schema, CancellationToken token)
    {
        await using var observer = new NpgsqlConnection(connectionString);
        await observer.OpenAsync(token);
        await using var command = new NpgsqlCommand("""
            SELECT query FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND datname = current_database()
            AND strpos(query, $1) > 0 AND wait_event_type = 'Lock' AND cardinality(pg_blocking_pids(pid)) > 0
            """, observer);
        _ = command.Parameters.AddWithValue(schema);
        while (true)
        {
            if (await command.ExecuteScalarAsync(token) is string query) { return query; }
            await Task.Delay(10, token);
        }
    }
}
