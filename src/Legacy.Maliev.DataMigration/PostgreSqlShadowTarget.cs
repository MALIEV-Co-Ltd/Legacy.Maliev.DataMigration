using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed record PostgreSqlShadowTargetOptions(string AdministrativeConnectionString);

public sealed partial class PostgreSqlShadowTarget : IPostgreSqlShadowTarget
{
    private const string OwnershipPrefix = "legacy-maliev-shadow:";
    private readonly string _administrativeConnectionString;

    public PostgreSqlShadowTarget(PostgreSqlShadowTargetOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.AdministrativeConnectionString))
        {
            throw new ArgumentException("A PostgreSQL administrative connection string is required.", nameof(options));
        }

        var builder = new NpgsqlConnectionStringBuilder(options.AdministrativeConnectionString);
        if (string.IsNullOrWhiteSpace(builder.Database))
        {
            builder.Database = "postgres";
        }

        _administrativeConnectionString = builder.ConnectionString;
    }

    public async Task<ShadowDatabase> CreateUniqueEmptyShadowAsync(
        string database,
        string shadowName,
        string ownerRunId,
        CancellationToken cancellationToken)
    {
        ValidateShadowIdentity(database, shadowName, ownerRunId);
        await using var connection = new NpgsqlConnection(_administrativeConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        string quotedName = QuoteIdentifier(shadowName);
        await using (var create = new NpgsqlCommand($"CREATE DATABASE {quotedName} TEMPLATE template0;", connection))
        {
            _ = await create.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        string ownership = OwnershipValue(database, ownerRunId);
        try
        {
            await using var comment = new NpgsqlCommand(
                $"COMMENT ON DATABASE {quotedName} IS {QuoteLiteral(ownership)};",
                connection);
            _ = await comment.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await using var cleanup = new NpgsqlCommand($"DROP DATABASE {quotedName} WITH (FORCE);", connection);
            _ = await cleanup.ExecuteNonQueryAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        return new ShadowDatabase(shadowName, ownerRunId, database);
    }

    public async Task<bool> IsEmptyAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        await AssertOwnershipAsync(shadow, cancellationToken).ConfigureAwait(false);
        await using NpgsqlConnection connection = CreateShadowConnection(shadow.Name);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        const string sql = """
            SELECT NOT EXISTS (
                SELECT 1
                FROM pg_catalog.pg_class AS c
                INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                WHERE c.relkind IN ('r', 'p')
                  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                  AND n.nspname NOT LIKE 'pg_toast%');
            """;
        await using var command = new NpgsqlCommand(sql, connection);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) ?? false);
    }

    public async Task<IPostgreSqlWholeDatabaseTransaction> BeginWholeDatabaseTransactionAsync(
        ShadowDatabase shadow,
        CancellationToken cancellationToken)
    {
        await AssertOwnershipAsync(shadow, cancellationToken).ConfigureAwait(false);
        NpgsqlConnection connection = CreateShadowConnection(shadow.Name);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            System.Data.IsolationLevel.Serializable,
            cancellationToken).ConfigureAwait(false);
        return new PostgreSqlWholeDatabaseTransaction(connection, transaction);
    }

    public async Task DeleteRunOwnedShadowAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        await AssertOwnershipAsync(shadow, cancellationToken).ConfigureAwait(false);
        await using var connection = new NpgsqlConnection(_administrativeConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand(
            $"DROP DATABASE {QuoteIdentifier(shadow.Name)} WITH (FORCE);",
            connection);
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task AssertOwnershipAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(shadow);
        ValidateShadowIdentity(shadow.Database, shadow.Name, shadow.OwnerRunId);
        await using var connection = new NpgsqlConnection(_administrativeConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        const string sql = "SELECT pg_catalog.shobj_description(oid, 'pg_database') FROM pg_catalog.pg_database WHERE datname = $1;";
        await using var command = new NpgsqlCommand(sql, connection);
        _ = command.Parameters.AddWithValue(shadow.Name);
        string? observed = (string?)await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (!string.Equals(observed, OwnershipValue(shadow.Database, shadow.OwnerRunId), StringComparison.Ordinal))
        {
            throw new MigrationExecutionException(
                "shadow_ownership_invalid",
                "The PostgreSQL database is not owned by this migration run.");
        }
    }

    private NpgsqlConnection CreateShadowConnection(string database)
    {
        var builder = new NpgsqlConnectionStringBuilder(_administrativeConnectionString) { Database = database };
        return new NpgsqlConnection(builder.ConnectionString);
    }

    private static void ValidateShadowIdentity(string database, string shadowName, string ownerRunId)
    {
        if (!ShadowName().IsMatch(shadowName) ||
            !Guid.TryParseExact(ownerRunId, "D", out _) ||
            string.IsNullOrWhiteSpace(database) || database.Contains('\0', StringComparison.Ordinal))
        {
            throw new MigrationExecutionException(
                "shadow_identity_invalid",
                "Only an exact run-owned legacy shadow database is permitted.");
        }
    }

    private static string OwnershipValue(string database, string ownerRunId)
    {
        return $"{OwnershipPrefix}{ownerRunId}:{database}";
    }

    internal static string QuoteIdentifier(string identifier)
    {
        return string.IsNullOrEmpty(identifier) || identifier.Contains('\0', StringComparison.Ordinal)
            ? throw new ArgumentException("PostgreSQL identifiers must be non-empty and contain no null bytes.", nameof(identifier))
            : $"\"{identifier.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
    }

    private static string QuoteLiteral(string value)
    {
        return $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";
    }

    [GeneratedRegex("^legacy_shadow_[a-z0-9_]+_[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ShadowName();
}

internal sealed class PostgreSqlWholeDatabaseTransaction(
    NpgsqlConnection connection,
    NpgsqlTransaction transaction) : IPostgreSqlWholeDatabaseTransaction
{
    private bool _completed;
    private bool _schemaInspected;
    private bool _inspectionStarted;
    private readonly HashSet<string> _expectedTableInspections = new(StringComparer.Ordinal);
    private readonly HashSet<string> _completedTableInspections = new(StringComparer.Ordinal);

    public async Task ApplySchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        _expectedTableInspections.Clear();
        foreach (TableCopyPlan table in plan.Tables)
        {
            _ = _expectedTableInspections.Add($"{table.TargetSchema}.{table.TargetTable}");
        }

        foreach (string schema in plan.Tables.Select(table => table.TargetSchema).Distinct(StringComparer.Ordinal))
        {
            await ExecuteAsync(
                $"CREATE SCHEMA IF NOT EXISTS {PostgreSqlShadowTarget.QuoteIdentifier(schema)};",
                cancellationToken).ConfigureAwait(false);
        }

        foreach (TableCopyPlan table in plan.Tables)
        {
            string columns = string.Join(", ", table.OrderedColumns.Select(column =>
            {
                string type = PostgreSqlTypePolicy.Validate(table.ColumnTypes[column]);
                string nullable = table.NullableColumns.Contains(column, StringComparer.Ordinal) ? string.Empty : " NOT NULL";
                string identity = table.IdentityColumns.Contains(column, StringComparer.Ordinal)
                    ? " GENERATED BY DEFAULT AS IDENTITY"
                    : string.Empty;
                return $"{PostgreSqlShadowTarget.QuoteIdentifier(column)} {type}{identity}{nullable}";
            }));
            await ExecuteAsync(
                $"CREATE TABLE {Qualified(table.TargetSchema, table.TargetTable)} ({columns});",
                cancellationToken).ConfigureAwait(false);
        }

        foreach (TableCopyPlan table in plan.Tables)
        {
            foreach (ForeignKeyCopyPlan foreignKey in table.ForeignKeys)
            {
                string columns = string.Join(", ", foreignKey.Columns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
                string referenced = string.Join(", ", foreignKey.ReferencedColumns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
                await ExecuteAsync(
                    $"ALTER TABLE {Qualified(table.TargetSchema, table.TargetTable)} " +
                    $"ADD CONSTRAINT {PostgreSqlShadowTarget.QuoteIdentifier(foreignKey.Name)} " +
                    $"FOREIGN KEY ({columns}) REFERENCES {Qualified(foreignKey.ReferencedSchema, foreignKey.ReferencedTable)} ({referenced}) DEFERRABLE INITIALLY DEFERRED;",
                    cancellationToken).ConfigureAwait(false);
            }
        }
    }

    public async Task<long> CopyBatchAsync(
        TableCopyPlan table,
        IReadOnlyList<MigrationRow> rows,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(rows);
        if (_inspectionStarted)
        {
            throw new MigrationExecutionException(
                "shadow_copy_after_inspection",
                "A shadow transaction cannot accept more rows after reconciliation inspection begins.");
        }

        string columns = string.Join(", ", table.OrderedColumns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        string sql = $"COPY {Qualified(table.TargetSchema, table.TargetTable)} ({columns}) FROM STDIN (FORMAT BINARY);";
        long count = 0;
        await using NpgsqlBinaryImporter importer = await connection.BeginBinaryImportAsync(sql, cancellationToken)
            .ConfigureAwait(false);
        foreach (MigrationRow row in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidateRow(table, row);
            await importer.StartRowAsync(cancellationToken).ConfigureAwait(false);
            foreach (string column in table.OrderedColumns)
            {
                object? value = NormalizeValue(row.Values[column], table.ColumnTypes[column]);
                if (value is null)
                {
                    await importer.WriteNullAsync(cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await importer.WriteAsync(value, PostgreSqlTypePolicy.Validate(table.ColumnTypes[column]), cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            count++;
        }

        _ = await importer.CompleteAsync(cancellationToken).ConfigureAwait(false);
        return count;
    }

    public async Task<string> InspectSchemaAsync(
        DatabaseSchemaPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        _inspectionStarted = true;
        List<PostgreSqlSchemaFingerprint.TableShape> tables = [];
        const string tableSql = """
            SELECT n.nspname, c.relname
            FROM pg_catalog.pg_class AS c
            INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p')
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND n.nspname NOT LIKE 'pg_toast%'
            ORDER BY n.nspname, c.relname;
            """;
        await using (var command = new NpgsqlCommand(tableSql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                tables.Add(new PostgreSqlSchemaFingerprint.TableShape(reader.GetString(0), reader.GetString(1)));
            }
        }

        List<PostgreSqlSchemaFingerprint.ColumnShape> columns = [];
        const string columnSql = """
            SELECT n.nspname, c.relname, a.attnum, a.attname,
                   pg_catalog.format_type(a.atttypid, a.atttypmod),
                   NOT a.attnotnull, a.attidentity <> ''
            FROM pg_catalog.pg_attribute AS a
            INNER JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid
            INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p')
              AND a.attnum > 0
              AND NOT a.attisdropped
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND n.nspname NOT LIKE 'pg_toast%'
            ORDER BY n.nspname, c.relname, a.attnum;
            """;
        await using (var command = new NpgsqlCommand(columnSql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                columns.Add(new PostgreSqlSchemaFingerprint.ColumnShape(
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetInt16(2),
                    reader.GetString(3),
                    PostgreSqlTypePolicy.Validate(reader.GetString(4)),
                    reader.GetBoolean(5),
                    reader.GetBoolean(6)));
            }
        }

        List<PostgreSqlSchemaFingerprint.ForeignKeyShape> foreignKeys = [];
        const string foreignKeySql = """
            SELECT child_ns.nspname, child.relname, constraint_row.conname,
                   ARRAY(
                       SELECT child_column.attname
                       FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
                       INNER JOIN pg_catalog.pg_attribute AS child_column
                           ON child_column.attrelid = child.oid AND child_column.attnum = key_column.attnum
                       ORDER BY key_column.ordinal),
                   referenced_ns.nspname, referenced.relname,
                   ARRAY(
                       SELECT referenced_column.attname
                       FROM unnest(constraint_row.confkey) WITH ORDINALITY AS key_column(attnum, ordinal)
                       INNER JOIN pg_catalog.pg_attribute AS referenced_column
                           ON referenced_column.attrelid = referenced.oid AND referenced_column.attnum = key_column.attnum
                       ORDER BY key_column.ordinal)
            FROM pg_catalog.pg_constraint AS constraint_row
            INNER JOIN pg_catalog.pg_class AS child ON child.oid = constraint_row.conrelid
            INNER JOIN pg_catalog.pg_namespace AS child_ns ON child_ns.oid = child.relnamespace
            INNER JOIN pg_catalog.pg_class AS referenced ON referenced.oid = constraint_row.confrelid
            INNER JOIN pg_catalog.pg_namespace AS referenced_ns ON referenced_ns.oid = referenced.relnamespace
            WHERE constraint_row.contype = 'f'
              AND child_ns.nspname NOT IN ('pg_catalog', 'information_schema')
            ORDER BY child_ns.nspname, child.relname, constraint_row.conname;
            """;
        await using (var command = new NpgsqlCommand(foreignKeySql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                foreignKeys.Add(new PostgreSqlSchemaFingerprint.ForeignKeyShape(
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetFieldValue<string[]>(3),
                    reader.GetString(4),
                    reader.GetString(5),
                    reader.GetFieldValue<string[]>(6)));
            }
        }

        _schemaInspected = true;
        return PostgreSqlSchemaFingerprint.Compute(tables, columns, foreignKeys);
    }

    public async Task<TableReconciliationEvidence> InspectTableAsync(
        TableCopyPlan table,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);
        _inspectionStarted = true;
        using var collector = new TableEvidenceCollector(table);
        string columns = string.Join(", ", table.OrderedColumns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        string ordering = string.Join(", ", table.OrderByColumns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        string readSql = $"SELECT {columns} FROM {Qualified(table.TargetSchema, table.TargetTable)} ORDER BY {ordering};";
        await using (var read = new NpgsqlCommand(readSql, connection, transaction))
        await using (NpgsqlDataReader reader = await read.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var values = new Dictionary<string, object?>(table.OrderedColumns.Count, StringComparer.Ordinal);
                for (var ordinal = 0; ordinal < table.OrderedColumns.Count; ordinal++)
                {
                    values.Add(table.OrderedColumns[ordinal], await reader.IsDBNullAsync(ordinal, cancellationToken)
                        .ConfigureAwait(false) ? null : reader.GetValue(ordinal));
                }

                collector.Append(new MigrationRow(values));
            }
        }

        TableReconciliationEvidence evidence = collector.Finish();
        var orphanCounts = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (ForeignKeyCopyPlan foreignKey in table.ForeignKeys.OrderBy(item => item.Name, StringComparer.Ordinal))
        {
            string join = string.Join(" AND ", foreignKey.Columns.Zip(
                foreignKey.ReferencedColumns,
                (column, referenced) => $"child.{PostgreSqlShadowTarget.QuoteIdentifier(column)} = parent.{PostgreSqlShadowTarget.QuoteIdentifier(referenced)}"));
            string required = string.Join(" AND ", foreignKey.Columns.Select(
                column => $"child.{PostgreSqlShadowTarget.QuoteIdentifier(column)} IS NOT NULL"));
            string sql = $"SELECT COUNT(*) FROM {Qualified(table.TargetSchema, table.TargetTable)} AS child " +
                $"LEFT JOIN {Qualified(foreignKey.ReferencedSchema, foreignKey.ReferencedTable)} AS parent ON {join} " +
                $"WHERE {required} AND parent.{PostgreSqlShadowTarget.QuoteIdentifier(foreignKey.ReferencedColumns[0])} IS NULL;";
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            orphanCounts.Add(
                foreignKey.Name,
                Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture));
        }

        foreach (string identityColumn in table.IdentityColumns)
        {
            await ReseedIdentityAsync(table, identityColumn, cancellationToken).ConfigureAwait(false);
        }

        _ = _completedTableInspections.Add($"{table.TargetSchema}.{table.TargetTable}");
        return evidence with
        {
            ForeignKeyOrphanCounts = new System.Collections.ObjectModel.ReadOnlyDictionary<string, long>(orphanCounts),
        };
    }

    public async Task CommitAsync(CancellationToken cancellationToken)
    {
        if (!_schemaInspected || !_completedTableInspections.SetEquals(_expectedTableInspections))
        {
            throw new MigrationExecutionException(
                "shadow_commit_without_reconciliation",
                "A shadow database cannot commit before successful reconciliation.");
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        _completed = true;
    }

    public async Task RollbackAsync(CancellationToken cancellationToken)
    {
        if (!_completed)
        {
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            _completed = true;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_completed)
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
        }

        await transaction.DisposeAsync().ConfigureAwait(false);
        await connection.DisposeAsync().ConfigureAwait(false);
    }

    private async Task ReseedIdentityAsync(
        TableCopyPlan table,
        string identityColumn,
        CancellationToken cancellationToken)
    {
        const string sequenceSql = "SELECT pg_get_serial_sequence($1, $2);";
        await using var sequence = new NpgsqlCommand(sequenceSql, connection, transaction);
        _ = sequence.Parameters.AddWithValue($"{table.TargetSchema}.{table.TargetTable}");
        _ = sequence.Parameters.AddWithValue(identityColumn);
        string? sequenceName = (string?)await sequence.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(sequenceName))
        {
            return;
        }

        string sql = $"SELECT setval($1::regclass, COALESCE((SELECT MAX({PostgreSqlShadowTarget.QuoteIdentifier(identityColumn)}) FROM {Qualified(table.TargetSchema, table.TargetTable)}), 1), EXISTS (SELECT 1 FROM {Qualified(table.TargetSchema, table.TargetTable)}));";
        await using var reseed = new NpgsqlCommand(sql, connection, transaction);
        _ = reseed.Parameters.AddWithValue(sequenceName);
        _ = await reseed.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task ExecuteAsync(string sql, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string Qualified(string schema, string table)
    {
        return $"{PostgreSqlShadowTarget.QuoteIdentifier(schema)}.{PostgreSqlShadowTarget.QuoteIdentifier(table)}";
    }

    private static void ValidateRow(TableCopyPlan table, MigrationRow row)
    {
        if (row.Values.Count != table.OrderedColumns.Count ||
            table.OrderedColumns.Any(column => !row.Values.ContainsKey(column)))
        {
            throw new MigrationExecutionException("row_shape_invalid", "A source row does not match its signed table plan.");
        }
    }

    private static object? NormalizeValue(object? value, string targetType)
    {
        return value is null or DBNull ? null : NormalizeNonNullValue(value, targetType);
    }

    private static object NormalizeNonNullValue(object value, string targetType)
    {
        return (PostgreSqlTypePolicy.Validate(targetType), value) switch
        {
            ("timestamp with time zone", DateTime dateTime) =>
                dateTime.Kind == DateTimeKind.Utc ? dateTime : dateTime.ToUniversalTime(),
            ("date", DateTime date) => DateOnly.FromDateTime(date),
            _ => value,
        };
    }
}

internal static class PostgreSqlSchemaFingerprint
{
    internal sealed record TableShape(string Schema, string Table);

    internal sealed record ColumnShape(
        string Schema,
        string Table,
        int Ordinal,
        string Column,
        string Type,
        bool Nullable,
        bool Identity);

    internal sealed record ForeignKeyShape(
        string Schema,
        string Table,
        string Name,
        IReadOnlyList<string> Columns,
        string ReferencedSchema,
        string ReferencedTable,
        IReadOnlyList<string> ReferencedColumns);

    internal static string ComputeExpected(DatabaseSchemaPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        List<TableShape> tables = [.. plan.Tables.Select(table => new TableShape(table.TargetSchema, table.TargetTable))];
        List<ColumnShape> columns = [.. plan.Tables.SelectMany(table => table.OrderedColumns.Select((column, ordinal) =>
            new ColumnShape(
                table.TargetSchema,
                table.TargetTable,
                ordinal + 1,
                column,
                PostgreSqlTypePolicy.Validate(table.ColumnTypes[column]),
                table.NullableColumns.Contains(column, StringComparer.Ordinal),
                table.IdentityColumns.Contains(column, StringComparer.Ordinal))))];
        List<ForeignKeyShape> foreignKeys = [.. plan.Tables.SelectMany(table => table.ForeignKeys.Select(foreignKey =>
            new ForeignKeyShape(
                table.TargetSchema,
                table.TargetTable,
                foreignKey.Name,
                foreignKey.Columns,
                foreignKey.ReferencedSchema,
                foreignKey.ReferencedTable,
                foreignKey.ReferencedColumns)))];
        return Compute(tables, columns, foreignKeys);
    }

    internal static string Compute(
        IEnumerable<TableShape> tables,
        IEnumerable<ColumnShape> columns,
        IEnumerable<ForeignKeyShape> foreignKeys)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            foreach (TableShape table in tables.OrderBy(item => item.Schema, StringComparer.Ordinal)
                .ThenBy(item => item.Table, StringComparer.Ordinal))
            {
                writer.Write((byte)'T');
                Write(writer, table.Schema);
                Write(writer, table.Table);
            }

            foreach (ColumnShape column in columns.OrderBy(item => item.Schema, StringComparer.Ordinal)
                .ThenBy(item => item.Table, StringComparer.Ordinal)
                .ThenBy(item => item.Ordinal))
            {
                writer.Write((byte)'C');
                Write(writer, column.Schema);
                Write(writer, column.Table);
                writer.Write(column.Ordinal);
                Write(writer, column.Column);
                Write(writer, column.Type);
                writer.Write(column.Nullable);
                writer.Write(column.Identity);
            }

            foreach (ForeignKeyShape foreignKey in foreignKeys.OrderBy(item => item.Schema, StringComparer.Ordinal)
                .ThenBy(item => item.Table, StringComparer.Ordinal)
                .ThenBy(item => item.Name, StringComparer.Ordinal))
            {
                writer.Write((byte)'F');
                Write(writer, foreignKey.Schema);
                Write(writer, foreignKey.Table);
                Write(writer, foreignKey.Name);
                Write(writer, foreignKey.Columns);
                Write(writer, foreignKey.ReferencedSchema);
                Write(writer, foreignKey.ReferencedTable);
                Write(writer, foreignKey.ReferencedColumns);
            }
        }

        return Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }

    private static void Write(BinaryWriter writer, IReadOnlyList<string> values)
    {
        writer.Write(values.Count);
        foreach (string value in values)
        {
            Write(writer, value);
        }
    }

    private static void Write(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value.Normalize(NormalizationForm.FormC));
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }
}

internal static partial class PostgreSqlTypePolicy
{
    internal static string Validate(string value)
    {
        string normalized = value.Trim().ToLowerInvariant();
        return !ApprovedType().IsMatch(normalized)
            ? throw new MigrationExecutionException("target_type_forbidden", $"PostgreSQL target type '{value}' is not approved.")
            : normalized;
    }

    [GeneratedRegex("^(smallint|integer|bigint|boolean|text|bytea|uuid|date|real|double precision|jsonb|timestamp (with|without) time zone|numeric\\([1-9][0-9]?,[0-9]{1,2}\\)|character varying\\([1-9][0-9]{0,6}\\)|character\\([1-9][0-9]{0,6}\\))$", RegexOptions.CultureInvariant)]
    private static partial Regex ApprovedType();
}
