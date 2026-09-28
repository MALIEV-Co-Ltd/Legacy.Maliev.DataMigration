using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Reads names and the complete physical schema from one read-only PostgreSQL snapshot.</summary>
public static class ProductionSchemaCatalogInspector
{
    /// <summary>Rejects stale, incomplete, or internally inconsistent source plans before target access.</summary>
    public static void ValidatePlan(FreshSchemaPlan schema, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(schema);
        if (schema.SchemaVersion != "2.0" || schema.CapturedAtUtc.Offset != TimeSpan.Zero ||
            nowUtc.Offset != TimeSpan.Zero || schema.CapturedAtUtc > nowUtc ||
            nowUtc - schema.CapturedAtUtc > TimeSpan.FromHours(2) ||
            schema.SourceCommitSha.Length != 40 || !schema.SourceCommitSha.All(char.IsAsciiHexDigit) ||
            !schema.Databases.Select(database => database.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            schema.Databases.Any(database => database.TargetSchemaSha256 !=
                PostgreSqlSchemaFingerprint.ComputeExpected(database)))
        {
            throw new MigrationExecutionException("delta_schema_catalog_boundary_invalid",
                "The catalog inspection requires a fresh exact-23 source plan.");
        }
    }

    /// <summary>Returns PII-free catalog evidence without reading application rows.</summary>
    public static async Task<ProductionSchemaObservation> InspectDatabaseAsync(
        DatabaseSchemaPlan database, string administrativeConnectionString, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(database);
        var builder = new NpgsqlConnectionStringBuilder(administrativeConnectionString)
        {
            Database = database.Database,
            Pooling = false,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        try
        {
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction))
            {
                _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            const string namesSql = """
                SELECT n.nspname, c.relname, a.attname
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                LEFT JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
                    AND a.attnum > 0 AND NOT a.attisdropped
                WHERE c.relkind IN ('r', 'p')
                    AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'legacy_migration_internal')
                    AND n.nspname NOT LIKE 'pg_toast%'
                ORDER BY n.nspname, c.relname, a.attnum;
                """;
            var names = new Dictionary<(string Schema, string Table), List<string>>();
            await using (var command = new NpgsqlCommand(namesSql, connection, transaction))
            await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
            {
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var key = (reader.GetString(0), reader.GetString(1));
                    if (!names.TryGetValue(key, out List<string>? columns))
                    {
                        columns = [];
                        names.Add(key, columns);
                    }
                    if (!await reader.IsDBNullAsync(2, cancellationToken).ConfigureAwait(false))
                    {
                        columns.Add(reader.GetString(2));
                    }
                }
            }
            (string fingerprint, IReadOnlyList<ProductionSchemaTableComponents> components,
                IReadOnlyList<PostgreSqlSchemaFingerprint.ColumnShape> columnShapes) =
                await inspector.InspectSchemaWithComponentsAsync(database, cancellationToken).ConfigureAwait(false);
            IReadOnlyList<ProductionCollationMetadata> collations =
                await ProductionCollationMetadataInspector.InspectAsync(connection, transaction, cancellationToken)
                    .ConfigureAwait(false);
            await inspector.RollbackAsync(cancellationToken).ConfigureAwait(false);
            var observation = new ProductionSchemaObservation(database.Database,
                [.. names.Select(item => new ObservedTargetTable(item.Key.Schema, item.Key.Table, item.Value))],
                fingerprint)
            { TableComponents = components };
            TableCopyPlan[] expected =
            [
                .. ApprovedSourceDispositionManifest.TargetTablesFor(database),
                .. ApprovedTargetExtensionManifest.TablesFor(database),
            ];
            return observation with
            {
                TableDiagnostics = ProductionSchemaComponentDiagnostics.Compare(expected, observation),
                ColumnDiagnostics = ProductionSchemaColumnDiagnostics.Compare(expected, observation, columnShapes,
                    collations),
            };
        }
        catch
        {
            try { await inspector.RollbackAsync(CancellationToken.None).ConfigureAwait(false); }
            catch (Exception failure) when (failure is NpgsqlException or InvalidOperationException)
            {
                // Retain the original inspection failure.
            }
            throw;
        }
    }
}
