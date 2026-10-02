using System.Data;
using System.Globalization;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Internal lock and complete-preimage guard, never execution authority. Requires an externally
/// trusted maintenance window that prevents new clients and global/catalog DDL throughout the
/// caller-owned transaction. An entry session check cannot enforce that prerequisite.
/// </summary>
internal static class SourceBackedLocalRepairLockSet
{
    internal static bool AuthorizesExecution => false;

    internal static async Task<SourceBackedLocalRepairDatabasePreimage> AcquireAndVerifyAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, DatabaseSchemaPlan schema,
        SourceBackedLocalRepairDatabasePreimage expected, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(expected);
        expected = JsonSerializer.Deserialize<SourceBackedLocalRepairDatabasePreimage>(
            JsonSerializer.SerializeToUtf8Bytes(expected)) ?? throw Invalid("delta_source_repair_lock_preimage_invalid");
        RequireExpected(expected);
        if (transaction.Connection != connection || transaction.IsolationLevel != IsolationLevel.Serializable ||
            schema.Database != expected.Database || connection.Database != expected.Database)
        {
            throw Invalid("delta_source_repair_lock_binding_invalid");
        }
        foreach (SourceRepairRelationPreimage relation in expected.Relations)
        {
            await using var command = new NpgsqlCommand(
                $"LOCK TABLE ONLY {Qualified(relation.Schema, relation.Table)} IN SHARE ROW EXCLUSIVE MODE NOWAIT;",
                connection, transaction);
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        // Lock the sequence parameter catalog before the first SELECT establishes an MVCC
        // snapshot. Sequence allocation itself still needs the per-sequence DDL locks below.
        await using (var sequenceCatalog = new NpgsqlCommand(
            "LOCK TABLE pg_catalog.pg_sequence IN SHARE ROW EXCLUSIVE MODE NOWAIT;", connection, transaction))
        {
            _ = await sequenceCatalog.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        // Fail closed even for idle sessions: their cached sequence values and later writes
        // cannot be made safe by reading pg_stat_activity once or by advisory locks.
        await using (var clients = new NpgsqlCommand("""
            SELECT count(*) FROM pg_stat_activity
            WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend';
            """, connection, transaction))
        {
            if (Convert.ToInt64(await clients.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture) != 0)
            {
                throw Invalid("delta_source_repair_lock_clients_present");
            }
        }
        foreach (SourceRepairSequencePreimage sequence in expected.Sequences)
        {
            await using (var cache = new NpgsqlCommand("SELECT seqcache FROM pg_catalog.pg_sequence WHERE seqrelid=$1::regclass;", connection, transaction))
            {
                _ = cache.Parameters.AddWithValue(Qualified(sequence.Schema, sequence.Name));
                if (await cache.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not long observedCache ||
                    observedCache != sequence.Cache)
                {
                    throw Invalid("delta_source_repair_preimage_changed");
                }
            }
            // PostgreSQL 18 ALTER SEQUENCE blocks nextval/setval. Reapply the signed cache
            // value without RESTART, START, setval, type, owner or dependency changes.
            // The following complete inspection verifies every parameter and physical state.
            await using var command = new NpgsqlCommand(
                $"ALTER SEQUENCE {Qualified(sequence.Schema, sequence.Name)} CACHE {sequence.Cache.ToString(CultureInfo.InvariantCulture)};",
                connection, transaction);
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        SourceBackedLocalRepairDatabasePreimage observed = await SourceBackedLocalRepairPreimage
            .InspectAsync(connection, transaction, schema, cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairPreimage.RequireMatches(expected, observed);
        return observed;
    }

    private static void RequireExpected(SourceBackedLocalRepairDatabasePreimage? expected)
    {
        if (expected is null || !DatabaseInventory.ActiveDatabases.Contains(expected.Database, StringComparer.Ordinal) ||
            !Hash(expected.ObservedPhysicalSchemaSha256) || !Hash(expected.CatalogObjectsSha256) ||
            expected.Relations is null || expected.Sequences is null || expected.Relations.Count == 0 ||
            expected.Relations.Any(item => item is null || !Identifier(item.Schema) || !Identifier(item.Table) ||
                item.Rows < 0 || !Hash(item.RowMultisetSha256) || !Hash(item.CatalogSha256)) ||
            expected.Sequences.Any(item => item is null || !Identifier(item.Schema) || !Identifier(item.Name) ||
                item.Type is not ("bigint" or "integer" or "smallint") || item.Cache < 1 || item.Increment == 0 ||
                item.Minimum >= item.Maximum || item.Start < item.Minimum || item.Start > item.Maximum ||
                item.LastValue < item.Minimum || item.LastValue > item.Maximum || !Hash(item.CatalogSha256)) ||
            !OrderedUnique(expected.Relations.Select(item => (item.Schema, item.Table))) ||
            !OrderedUnique(expected.Sequences.Select(item => (item.Schema, item.Name))) ||
            expected.Relations.Select(item => (item.Schema, item.Table))
                .Intersect(expected.Sequences.Select(item => (item.Schema, item.Name))).Any())
        {
            throw Invalid("delta_source_repair_lock_preimage_invalid");
        }
    }

    private static bool OrderedUnique(IEnumerable<(string Schema, string Name)> values)
    {
        (string Schema, string Name)[] items = values.ToArray();
        return items.Distinct().Count() == items.Length && items.SequenceEqual(items
            .OrderBy(item => item.Schema, StringComparer.Ordinal).ThenBy(item => item.Name, StringComparer.Ordinal));
    }

    private static bool Identifier(string? value)
    {
        return !string.IsNullOrWhiteSpace(value) && !value.Contains('\0');
    }

    private static bool Hash(string? value)
    {
        return value is { Length: 64 } && value.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static string Qualified(string schema, string name)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(schema) + "." + PostgreSqlShadowTarget.QuoteIdentifier(name);
    }

    private static DeltaExecutionException Invalid(string code)
    {
        return new(code, "Source-backed repair requires a complete serializable preimage and independently maintained quiescence.");
    }
}
