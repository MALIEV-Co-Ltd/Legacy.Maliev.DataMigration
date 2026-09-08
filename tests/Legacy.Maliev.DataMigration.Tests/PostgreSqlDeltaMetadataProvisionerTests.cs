using System.Data;
using System.Globalization;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlDeltaMetadataProvisionerTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task ProvisionDatabase_CreatesFenceAndReconciledJournalContract()
    {
        (string connectionString, DatabaseSchemaPlan schema, DeltaSynchronizationPlan plan) = CreateContract();
        await ResetMetadataAsync(connectionString);

        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        await PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(
            connection, transaction, plan, schema, CancellationToken.None);
        await transaction.CommitAsync();

        Assert.Equal(1L, await ScalarAsync(connectionString,
            "SELECT count(*) FROM legacy_migration_internal.delta_fence WHERE database_name='ContactRequest' AND schema_plan_sha256='" + Hash('7') + "' AND target_schema_sha256='" + Hash('b') + "' AND target_generation='generation-1' AND target_observation_sha256='" + Hash('c') + "';"));
        Assert.Equal("NO", await TextScalarAsync(connectionString, """
            SELECT is_nullable
            FROM information_schema.columns
            WHERE table_schema='legacy_migration_internal'
              AND table_name='delta_journal'
              AND column_name='reconciliation_sha256';
            """));
    }

    [Fact]
    public async Task ProvisionDatabase_UnreconciledLegacyJournal_FailsAndRollsBackFence()
    {
        (string connectionString, DatabaseSchemaPlan schema, DeltaSynchronizationPlan plan) = CreateContract();
        await ResetMetadataAsync(connectionString);
        await ExecuteAsync(connectionString, """
            CREATE SCHEMA legacy_migration_internal;
            CREATE TABLE legacy_migration_internal.delta_journal(
                plan_sha256 text PRIMARY KEY,
                plan_id uuid NOT NULL UNIQUE,
                source_cutoff_utc timestamptz NOT NULL,
                target_observation_sha256 text NOT NULL,
                operations_sha256 text NOT NULL,
                committed_at_utc timestamptz NOT NULL);
            INSERT INTO legacy_migration_internal.delta_journal
                (plan_sha256, plan_id, source_cutoff_utc, target_observation_sha256, operations_sha256, committed_at_utc)
            VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                '11111111-1111-1111-1111-111111111111', '2026-09-08T05:00:00Z',
                'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                '2026-09-08T05:01:00Z');
            """);

        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        DeltaExecutionException failure = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            PostgreSqlDeltaMetadataProvisioner.ProvisionDatabaseAsync(
                connection, transaction, plan, schema, CancellationToken.None));
        Assert.Equal("delta_metadata_legacy_journal_unreconciled", failure.Code);
        await transaction.RollbackAsync();

        Assert.Equal(0L, await ScalarAsync(connectionString,
            "SELECT count(*) FROM information_schema.tables WHERE table_schema='legacy_migration_internal' AND table_name='delta_fence';"));
        Assert.Equal(0L, await ScalarAsync(connectionString,
            "SELECT count(*) FROM information_schema.columns WHERE table_schema='legacy_migration_internal' AND table_name='delta_journal' AND column_name='reconciliation_sha256';"));
    }

    private (string ConnectionString, DatabaseSchemaPlan Schema, DeltaSynchronizationPlan Plan) CreateContract()
    {
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString)
        {
            Database = fixture.CanonicalDatabase,
            Pooling = false,
        }.ConnectionString;
        var table = new TableCopyPlan("dbo", "items", "public", "items", ["id"], ["id"]);
        var schema = new DatabaseSchemaPlan("ContactRequest", "1", Hash('a'), Hash('b'), [table]);
        var database = new DeltaDatabasePlan("ContactRequest", [new("public.items", 0, 0, 0, 0,
            DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([]), [])]);
        var plan = new DeltaSynchronizationPlan("1.1", Guid.NewGuid(), new string('1', 40),
            DateTimeOffset.Parse("2026-09-08T05:00:00Z", CultureInfo.InvariantCulture), Hash('d'), Hash('7'),
            Hash('e'), "local-aspire", "legacy-postgres-local", "generation-1", Hash('c'), Hash('f'),
            Hash('9'), DateTimeOffset.Parse("2026-09-08T05:01:00Z", CultureInfo.InvariantCulture), [database],
            "test", null)
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire, "legacy-postgres-local", Hash('8')),
        };
        return (connectionString, schema, plan);
    }

    private static async Task ResetMetadataAsync(string connectionString)
    {
        await ExecuteAsync(connectionString, "DROP SCHEMA IF EXISTS legacy_migration_internal CASCADE;");
    }

    private static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync();
    }

    private static async Task<long> ScalarAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return Convert.ToInt64(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
    }

    private static async Task<string> TextScalarAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return Convert.ToString(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture)!;
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }
}
