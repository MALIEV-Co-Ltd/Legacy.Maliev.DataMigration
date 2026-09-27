using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Raw same-snapshot catalog inputs; never serialized in the production observation.</summary>
internal sealed record ProductionCollationMetadata(
    string Schema, string Table, string Column, string Provider, bool Deterministic,
    string CatalogSchema, int Encoding, int DatabaseEncoding, string? RecordedVersion, string? ActualVersion);

/// <summary>Reads only PostgreSQL catalog metadata for explicit column collations.</summary>
internal static class ProductionCollationMetadataInspector
{
    internal static async Task<IReadOnlyList<ProductionCollationMetadata>> InspectAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT n.nspname, c.relname, a.attname, coll.collprovider::text,
                   coll.collisdeterministic, coll_ns.nspname, coll.collencoding,
                   d.encoding, coll.collversion,
                   pg_catalog.pg_collation_actual_version(coll.oid)
            FROM pg_catalog.pg_attribute AS a
            INNER JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid
            INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
            INNER JOIN pg_catalog.pg_type AS t ON t.oid = a.atttypid
            LEFT JOIN pg_catalog.pg_collation AS coll ON coll.oid = a.attcollation
            LEFT JOIN pg_catalog.pg_namespace AS coll_ns ON coll_ns.oid = coll.collnamespace
            INNER JOIN pg_catalog.pg_database AS d ON d.datname = current_database()
            WHERE c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped
              AND a.attcollation <> t.typcollation
              AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'legacy_migration_internal')
              AND n.nspname NOT LIKE 'pg_toast%'
            ORDER BY n.nspname, c.relname, a.attnum;
            """;
        var result = new List<ProductionCollationMetadata>();
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (await reader.IsDBNullAsync(3, cancellationToken).ConfigureAwait(false) ||
                await reader.IsDBNullAsync(5, cancellationToken).ConfigureAwait(false))
            {
                throw new MigrationExecutionException("production_schema_collation_metadata_unreviewed",
                    "An explicit column collation has no complete catalog definition.");
            }
            result.Add(new(reader.GetString(0), reader.GetString(1), reader.GetString(2),
                reader.GetString(3), reader.GetBoolean(4), reader.GetString(5), reader.GetInt32(6),
                reader.GetInt32(7), await reader.IsDBNullAsync(8, cancellationToken).ConfigureAwait(false)
                    ? null : reader.GetString(8),
                await reader.IsDBNullAsync(9, cancellationToken).ConfigureAwait(false)
                    ? null : reader.GetString(9)));
        }
        return result;
    }
}
