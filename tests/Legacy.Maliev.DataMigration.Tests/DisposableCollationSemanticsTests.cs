using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Characterizes synthetic PostgreSQL behavior; it makes no production-equivalence claim.</summary>
[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class DisposableCollationSemanticsTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task ExplicitIcuVersusInherited_ChangesEqualityCaseAccentAndOrdering()
    {
        await using var probe = await CollationProbe.CreateAsync(fixture.ConnectionString);
        await probe.ExecuteAsync($$"""
            CREATE TABLE {{probe.Schema}}.inherited ("Value" text NOT NULL);
            CREATE TABLE {{probe.Schema}}.explicit ("Value" text COLLATE {{probe.Collation}} NOT NULL);
            INSERT INTO {{probe.Schema}}.inherited ("Value") VALUES ('e'), ('E'), ('é'), ('item2'), ('item10'), ('z');
            INSERT INTO {{probe.Schema}}.explicit ("Value") VALUES ('e'), ('E'), ('é'), ('item2'), ('item10'), ('z');
            """);

        Assert.Equal(1L, await probe.ScalarAsync<long>($"SELECT count(*) FROM {probe.Schema}.inherited WHERE \"Value\" = 'E';"));
        Assert.Equal(3L, await probe.ScalarAsync<long>($"SELECT count(*) FROM {probe.Schema}.explicit WHERE \"Value\" = 'E';"));
        Assert.Equal(6L, await probe.ScalarAsync<long>($"SELECT count(DISTINCT \"Value\") FROM {probe.Schema}.inherited;"));
        Assert.Equal(4L, await probe.ScalarAsync<long>($"SELECT count(DISTINCT \"Value\") FROM {probe.Schema}.explicit;"));
        Assert.Equal("item10,item2", await probe.ScalarAsync<string>($$"""
            SELECT string_agg("Value", ',' ORDER BY "Value")
            FROM {{probe.Schema}}.inherited WHERE "Value" LIKE 'item%';
            """));
        Assert.Equal("item2,item10", await probe.ScalarAsync<string>($$"""
            SELECT string_agg("Value", ',' ORDER BY "Value")
            FROM {{probe.Schema}}.explicit WHERE "Value" LIKE 'item%';
            """));
    }

    [Fact]
    public async Task ChangingCollation_RequiresIndexCompatibilityAndMayRejectUniqueRebuild()
    {
        await using var probe = await CollationProbe.CreateAsync(fixture.ConnectionString);
        await probe.ExecuteAsync($$"""
            CREATE TABLE {{probe.Schema}}.search_values ("Value" text NOT NULL);
            INSERT INTO {{probe.Schema}}.search_values ("Value") VALUES ('item2'), ('item10');
            CREATE INDEX search_values_inherited_idx ON {{probe.Schema}}.search_values ("Value");
            CREATE TABLE {{probe.Schema}}.unique_values ("Value" text NOT NULL UNIQUE);
            INSERT INTO {{probe.Schema}}.unique_values ("Value") VALUES ('e'), ('é');
            """);

        string inheritedIndexCollation = await probe.IndexCollationAsync("search_values_inherited_idx");
        string explicitCollation = await probe.ScalarAsync<string>($"SELECT '{probe.Collation}'::regcollation::oid::text;");
        Assert.NotEqual(explicitCollation, inheritedIndexCollation);

        await probe.ExecuteAsync("SET enable_seqscan = off;");
        string before = await probe.ScalarAsync<string>($$"""
            EXPLAIN (FORMAT JSON, COSTS OFF)
            SELECT "Value" FROM {{probe.Schema}}.search_values
            ORDER BY "Value" COLLATE {{probe.Collation}} LIMIT 1;
            """);
        Assert.Contains("\"Sort\"", before, StringComparison.Ordinal);

        await probe.ExecuteAsync($$"""
            CREATE INDEX search_values_explicit_idx
            ON {{probe.Schema}}.search_values ("Value" COLLATE {{probe.Collation}});
            """);
        Assert.Equal(explicitCollation, await probe.IndexCollationAsync("search_values_explicit_idx"));
        string after = await probe.ScalarAsync<string>($$"""
            EXPLAIN (FORMAT JSON, COSTS OFF)
            SELECT "Value" FROM {{probe.Schema}}.search_values
            ORDER BY "Value" COLLATE {{probe.Collation}} LIMIT 1;
            """);
        Assert.DoesNotContain("\"Sort\"", after, StringComparison.Ordinal);
        Assert.Contains("Index", after, StringComparison.Ordinal);

        PostgresException collision = await Assert.ThrowsAsync<PostgresException>(() => probe.ExecuteAsync($$"""
            ALTER TABLE {{probe.Schema}}.unique_values
            ALTER COLUMN "Value" TYPE text COLLATE {{probe.Collation}};
            """));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, collision.SqlState);
        Assert.Equal(2L, await probe.ScalarAsync<long>($"SELECT count(*) FROM {probe.Schema}.unique_values;"));
    }

    private sealed class CollationProbe : IAsyncDisposable
    {
        private readonly NpgsqlConnection connection;

        private CollationProbe(NpgsqlConnection connection)
        {
            this.connection = connection;
            Schema = "collation_proof_" + Guid.NewGuid().ToString("N");
        }

        public string Schema { get; }
        public string Collation => Schema + ".case_accent_numeric";

        public static async Task<CollationProbe> CreateAsync(string connectionString)
        {
            var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            var probe = new CollationProbe(connection);
            try
            {
                await probe.ExecuteAsync($$"""
                    CREATE SCHEMA {{probe.Schema}};
                    CREATE COLLATION {{probe.Collation}}
                    (provider = icu, locale = 'und-u-kn-true-ks-level1', deterministic = false);
                    """);
                return probe;
            }
            catch
            {
                await connection.DisposeAsync();
                throw;
            }
        }

        public async Task ExecuteAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection);
            _ = await command.ExecuteNonQueryAsync();
        }

        public async Task<T> ScalarAsync<T>(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection);
            return Assert.IsType<T>(await command.ExecuteScalarAsync());
        }

        public Task<string> IndexCollationAsync(string indexName)
        {
            return ScalarAsync<string>($$"""
                SELECT i.indcollation[0]::text FROM pg_catalog.pg_index AS i
                WHERE i.indexrelid = '{{Schema}}.{{indexName}}'::regclass;
                """);
        }

        public async ValueTask DisposeAsync()
        {
            try { await ExecuteAsync($"DROP SCHEMA IF EXISTS {Schema} CASCADE;"); }
            finally { await connection.DisposeAsync(); }
        }
    }
}
