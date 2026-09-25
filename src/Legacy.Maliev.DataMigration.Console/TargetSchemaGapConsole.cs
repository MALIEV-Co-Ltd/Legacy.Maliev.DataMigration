using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    private static async Task<object> InspectTargetSchemaGapsAsync(
        DeltaCommandConfiguration configuration,
        CancellationToken cancellationToken)
    {
        FreshSchemaPlan schema = await ReadProtectedJsonAsync<FreshSchemaPlan>(configuration.SchemaPlanPath,
            "delta_schema_plan_unprotected", cancellationToken).ConfigureAwait(false);
        if (!string.Equals(schema.SchemaVersion, "2.0", StringComparison.Ordinal) ||
            !schema.Databases.Select(database => database.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw new MigrationConsoleException("delta_schema_inventory_invalid",
                "The schema gap inspection requires a current exact-23 source schema plan.");
        }

        string target = await ReadProtectedTextAsync(configuration.TargetConnectionFile,
            "delta_target_connection_unprotected", cancellationToken).ConfigureAwait(false);
        await DefaultGuardedDeltaConsoleRuntime.VerifyTargetAuthorityAsync(
            target, configuration.TargetAuthority, cancellationToken).ConfigureAwait(false);
        var baseConnection = new NpgsqlConnectionStringBuilder(target) { Pooling = false };
        var gaps = new List<TargetSchemaGap>(schema.Databases.Count);
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            cancellationToken.ThrowIfCancellationRequested();
            gaps.Add(await TargetSchemaGapInspector.InspectDatabaseAsync(
                database, baseConnection.ConnectionString, cancellationToken).ConfigureAwait(false));
        }

        return new
        {
            schemaVersion = "1.0",
            inspectionKind = "names-only-not-reconciliation",
            sourceCommitSha = schema.SourceCommitSha,
            targetAuthority = configuration.TargetAuthority,
            observedAtUtc = DateTimeOffset.UtcNow,
            databases = gaps,
        };
    }
}

internal static class TargetSchemaGapInspector
{
    internal static async Task<TargetSchemaGap> InspectDatabaseAsync(
        DatabaseSchemaPlan database,
        string targetConnectionString,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(database);
        var builder = new NpgsqlConnectionStringBuilder(targetConnectionString)
        {
            Database = database.Database,
            Pooling = false,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(
            System.Data.IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction))
        {
            _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        const string metadataSql = """
                SELECT n.nspname, c.relname, a.attname
                FROM pg_catalog.pg_class AS c
                INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                LEFT JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
                    AND a.attnum > 0 AND NOT a.attisdropped
                WHERE c.relkind IN ('r', 'p')
                    AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'legacy_migration_internal')
                    AND n.nspname NOT LIKE 'pg_toast%'
                ORDER BY n.nspname, c.relname, a.attnum;
                """;
        await using var command = new NpgsqlCommand(metadataSql, connection, transaction);
        var observed = new Dictionary<(string Schema, string Table), List<string>>();
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var key = (reader.GetString(0), reader.GetString(1));
                if (!observed.TryGetValue(key, out List<string>? columns))
                {
                    columns = [];
                    observed.Add(key, columns);
                }
                if (!await reader.IsDBNullAsync(2, cancellationToken).ConfigureAwait(false))
                {
                    columns.Add(reader.GetString(2));
                }
            }
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return TargetSchemaGapAnalyzer.Analyze(database,
            [.. observed.Select(item => new ObservedTargetTable(item.Key.Schema, item.Key.Table, item.Value))]);
    }
}
