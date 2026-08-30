using System.Globalization;
using System.Data;
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
        ShadowDatabase plannedShadow,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plannedShadow);
        ValidateShadowIdentity(plannedShadow);
        await using var connection = new NpgsqlConnection(_administrativeConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await AcquireShadowLockAsync(connection, plannedShadow.Name, cancellationToken).ConfigureAwait(false);
        try
        {
            string quotedName = QuoteIdentifier(plannedShadow.Name);
            await using (var create = new NpgsqlCommand($"CREATE DATABASE {quotedName} TEMPLATE template0;", connection))
            {
                _ = await create.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            string ownership = OwnershipValue(plannedShadow);
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

            return plannedShadow;
        }
        finally
        {
            await ReleaseShadowLockAsync(connection, plannedShadow.Name).ConfigureAwait(false);
        }
    }

    public Task<ShadowDatabase> CreateUniqueEmptyShadowAsync(
        string database,
        string shadowName,
        string ownerRunId,
        CancellationToken cancellationToken)
    {
        var planned = new ShadowDatabase(shadowName, ownerRunId, database)
        {
            OwnerAttempt = 1,
            FencingToken = Guid.NewGuid(),
        };
        return CreateUniqueEmptyShadowAsync(planned, cancellationToken);
    }

    public async Task<bool> IsEmptyAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        _ = await AssertOwnershipAsync(shadow, cancellationToken).ConfigureAwait(false);
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
        _ = await AssertOwnershipAsync(shadow, cancellationToken).ConfigureAwait(false);
        NpgsqlConnection connection = CreateShadowConnection(shadow.Name);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable,
            cancellationToken).ConfigureAwait(false);
        return new PostgreSqlWholeDatabaseTransaction(connection, transaction);
    }

    public async Task DeleteRunOwnedShadowAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(_administrativeConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await AcquireShadowLockAsync(connection, shadow.Name, cancellationToken).ConfigureAwait(false);
        try
        {
            if (!await AssertOwnershipAsync(connection, shadow, allowMissing: true, cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            await using var command = new NpgsqlCommand(
                $"DROP DATABASE {QuoteIdentifier(shadow.Name)} WITH (FORCE);",
                connection);
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await ReleaseShadowLockAsync(connection, shadow.Name).ConfigureAwait(false);
        }
    }

    private Task<bool> AssertOwnershipAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        return AssertOwnershipAsync(shadow, allowMissing: false, cancellationToken);
    }

    private async Task<bool> AssertOwnershipAsync(
        ShadowDatabase shadow,
        bool allowMissing,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(shadow);
        ValidateShadowIdentity(shadow);
        await using var connection = new NpgsqlConnection(_administrativeConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await AssertOwnershipAsync(connection, shadow, allowMissing, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> AssertOwnershipAsync(
        NpgsqlConnection connection,
        ShadowDatabase shadow,
        bool allowMissing,
        CancellationToken cancellationToken)
    {
        const string sql = "SELECT pg_catalog.shobj_description(oid, 'pg_database') FROM pg_catalog.pg_database WHERE datname = $1;";
        await using var command = new NpgsqlCommand(sql, connection);
        _ = command.Parameters.AddWithValue(shadow.Name);
        object? scalar = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (scalar is null && allowMissing)
        {
            return false;
        }

        string? observed = scalar as string;
        return string.Equals(observed, OwnershipValue(shadow), StringComparison.Ordinal)
            ? true
            : throw new MigrationExecutionException(
                "shadow_ownership_invalid",
                "The PostgreSQL database is not owned by this migration run.");
    }

    private NpgsqlConnection CreateShadowConnection(string database)
    {
        var builder = new NpgsqlConnectionStringBuilder(_administrativeConnectionString) { Database = database };
        return new NpgsqlConnection(builder.ConnectionString);
    }

    private static void ValidateShadowIdentity(ShadowDatabase shadow)
    {
        if (!ShadowName().IsMatch(shadow.Name) ||
            !Guid.TryParseExact(shadow.OwnerRunId, "D", out _) ||
            shadow.OwnerAttempt < 1 || shadow.FencingToken == Guid.Empty ||
            string.IsNullOrWhiteSpace(shadow.Database) || shadow.Database.Contains('\0', StringComparison.Ordinal))
        {
            throw new MigrationExecutionException(
                "shadow_identity_invalid",
                "Only an exact run-owned legacy shadow database is permitted.");
        }
    }

    private static string OwnershipValue(ShadowDatabase shadow)
    {
        return $"{OwnershipPrefix}{shadow.OwnerRunId}:{shadow.OwnerAttempt}:{shadow.FencingToken:N}:{shadow.Database}";
    }

    private static async Task AcquireShadowLockAsync(
        NpgsqlConnection connection,
        string shadowName,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended($1, 0));",
            connection);
        _ = command.Parameters.AddWithValue(shadowName);
        _ = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task ReleaseShadowLockAsync(NpgsqlConnection connection, string shadowName)
    {
        await using var command = new NpgsqlCommand(
            "SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended($1, 0));",
            connection);
        _ = command.Parameters.AddWithValue(shadowName);
        _ = await command.ExecuteScalarAsync(CancellationToken.None).ConfigureAwait(false);
    }

    internal static string QuoteIdentifier(string identifier)
    {
        return string.IsNullOrEmpty(identifier) || identifier.Contains('\0', StringComparison.Ordinal)
            ? throw new ArgumentException("PostgreSQL identifiers must be non-empty and contain no null bytes.", nameof(identifier))
            : $"\"{identifier.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
    }

    internal static string QuoteQualifiedIdentifier(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        string[] parts = identifier.Split('.', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return parts.Length is < 1 or > 2
            ? throw new MigrationExecutionException("target_sequence_evidence_invalid", "PostgreSQL returned an invalid sequence identifier.")
            : string.Join('.', parts.Select(part => QuoteIdentifier(part.Trim('"').Replace("\"\"", "\"", StringComparison.Ordinal))));
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
    private bool _schemaFinalized;
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
                string collation = table.Collations.TryGetValue(column, out string? collationName)
                    ? $" COLLATE {PostgreSqlShadowTarget.QuoteIdentifier(collationName)}"
                    : string.Empty;
                GeneratedColumnCopyPlan? generatedColumn = table.GeneratedColumns.SingleOrDefault(
                    item => string.Equals(item.Column, column, StringComparison.Ordinal));
                string generated = generatedColumn is null
                    ? string.Empty
                    : $" GENERATED ALWAYS AS ({generatedColumn.Expression}) STORED";
                IdentityCopyPlan? identityPlan = table.Identities.SingleOrDefault(
                    identity => string.Equals(identity.Column, column, StringComparison.Ordinal));
                string identity = identityPlan is null
                    ? string.Empty
                    : $" GENERATED BY DEFAULT AS IDENTITY (START WITH {identityPlan.SeedValue.ToString(CultureInfo.InvariantCulture)} INCREMENT BY {identityPlan.IncrementValue.ToString(CultureInfo.InvariantCulture)})";
                string defaultExpression = table.DefaultExpressions.TryGetValue(column, out string? expression)
                    ? $" DEFAULT {expression}"
                    : string.Empty;
                return $"{PostgreSqlShadowTarget.QuoteIdentifier(column)} {type}{collation}{generated}{identity}{defaultExpression}{nullable}";
            }));
            await ExecuteAsync(
                $"CREATE TABLE {Qualified(table.TargetSchema, table.TargetTable)} ({columns});",
                cancellationToken).ConfigureAwait(false);
        }

        foreach (TableCopyPlan table in plan.Tables)
        {
            if (table.PrimaryKey is not null)
            {
                await AddConstraintAsync(
                    table,
                    table.PrimaryKey.Name,
                    $"PRIMARY KEY ({QuotedColumns(table.PrimaryKey.Columns)})",
                    cancellationToken).ConfigureAwait(false);
            }

            foreach (UniqueConstraintCopyPlan unique in table.UniqueConstraints)
            {
                string nulls = unique.Columns.Intersect(table.NullableColumns, StringComparer.Ordinal).Any()
                    ? " NULLS NOT DISTINCT"
                    : string.Empty;
                await AddConstraintAsync(
                    table,
                    unique.Name,
                    $"UNIQUE{nulls} ({QuotedColumns(unique.Columns)})",
                    cancellationToken).ConfigureAwait(false);
            }

            foreach (CheckConstraintCopyPlan check in table.CheckConstraints)
            {
                await AddConstraintAsync(
                    table,
                    check.Name,
                    $"CHECK ({check.Expression})",
                    cancellationToken).ConfigureAwait(false);
            }

            foreach (IndexCopyPlan index in table.Indexes)
            {
                string unique = index.Unique ? "UNIQUE " : string.Empty;
                string nulls = index.Unique && index.Columns.Intersect(table.NullableColumns, StringComparer.Ordinal).Any()
                    ? " NULLS NOT DISTINCT"
                    : string.Empty;
                string keyColumns = string.Join(", ", index.Columns.Select(column =>
                    $"{PostgreSqlShadowTarget.QuoteIdentifier(column)}{(index.DescendingColumns.Contains(column, StringComparer.Ordinal) ? " DESC" : " ASC")}"));
                string include = index.IncludedColumns.Count == 0
                    ? string.Empty
                    : $" INCLUDE ({QuotedColumns(index.IncludedColumns)})";
                string filter = string.IsNullOrWhiteSpace(index.FilterPredicate)
                    ? string.Empty
                    : $" WHERE {index.FilterPredicate}";
                await ExecuteAsync(
                    $"CREATE {unique}INDEX {PostgreSqlShadowTarget.QuoteIdentifier(index.Name)} " +
                    $"ON {Qualified(table.TargetSchema, table.TargetTable)} ({keyColumns}){include}{nulls}{filter};",
                    cancellationToken).ConfigureAwait(false);
            }

        }
    }

    public async Task FinalizeSchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (_schemaFinalized || _inspectionStarted)
        {
            throw new MigrationExecutionException("shadow_schema_finalization_invalid", "The shadow schema can be finalized exactly once before inspection.");
        }

        foreach (TableCopyPlan table in plan.Tables)
        {
            foreach (IdentityCopyPlan identity in table.Identities)
            {
                await ReseedIdentityAsync(table, identity, cancellationToken).ConfigureAwait(false);
            }
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
                    $"FOREIGN KEY ({columns}) REFERENCES {Qualified(foreignKey.ReferencedSchema, foreignKey.ReferencedTable)} ({referenced}) " +
                    $"ON DELETE {ReferentialActionSql(foreignKey.OnDelete)} ON UPDATE {ReferentialActionSql(foreignKey.OnUpdate)} NOT DEFERRABLE NOT VALID; " +
                    $"ALTER TABLE {Qualified(table.TargetSchema, table.TargetTable)} VALIDATE CONSTRAINT {PostgreSqlShadowTarget.QuoteIdentifier(foreignKey.Name)};",
                    cancellationToken).ConfigureAwait(false);
            }
        }

        _schemaFinalized = true;
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

        string[] copyColumns = [.. table.OrderedColumns.Except(
            table.GeneratedColumns.Select(item => item.Column),
            StringComparer.Ordinal)];
        string columns = string.Join(", ", copyColumns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        string sql = $"COPY {Qualified(table.TargetSchema, table.TargetTable)} ({columns}) FROM STDIN (FORMAT BINARY);";
        long count = 0;
        await using (NpgsqlBinaryImporter importer = await connection.BeginBinaryImportAsync(sql, cancellationToken)
            .ConfigureAwait(false))
        {
            foreach (MigrationRow row in rows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ValidateRow(table, row);
                await importer.StartRowAsync(cancellationToken).ConfigureAwait(false);
                foreach (string column in copyColumns)
                {
                    object? rawValue = row.Values[column];
                    if (rawValue is StreamingLob lob)
                    {
                        ValidateStreamingBound(table, column, lob);
                        await using Stream stream = await lob.OpenReadAsync(cancellationToken).ConfigureAwait(false);
                        await importer.WriteAsync(
                            stream,
                            PostgreSqlTypePolicy.Validate(table.ColumnTypes[column]),
                            cancellationToken).ConfigureAwait(false);
                        if (!lob.IsConsumed)
                        {
                            throw new MigrationExecutionException(
                                "streaming_lob_incomplete",
                                "Npgsql did not consume the complete streamed value.");
                        }
                        continue;
                    }
                    object? value = NormalizeValue(rawValue, table.ColumnTypes[column]);
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
        }
        return count;
    }

    private static void ValidateStreamingBound(TableCopyPlan table, string column, StreamingLob lob)
    {
        long? observedBytes = table.SourceColumns.SingleOrDefault(item => item.Column == column)?.MaxObservedDataLength;
        long safeSourceLimit = lob.Kind == StreamingLobKind.Binary ? 1_000_000_000L : 500_000_000L;
        if (observedBytes is null || observedBytes < 0 || observedBytes > safeSourceLimit)
        {
            throw new MigrationExecutionException(
                "streaming_lob_target_limit_invalid",
                "The signed source maximum cannot be represented safely as one PostgreSQL varlena value.");
        }
        long expansionLimit = lob.Kind == StreamingLobKind.Binary
            ? observedBytes.Value
            : checked(observedBytes.Value * 2);
        if (lob.ExpectedByteLength is null || lob.ExpectedByteLength < 0 ||
            lob.ExpectedByteLength > 1_000_000_000L || lob.ExpectedByteLength > expansionLimit)
        {
            throw new MigrationExecutionException(
                "streaming_lob_target_limit_invalid",
                "The signed source maximum cannot be represented safely as one PostgreSQL varlena value.");
        }
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
                   NOT a.attnotnull, a.attidentity <> '',
                   CASE WHEN a.attgenerated = '' THEN COALESCE(pg_catalog.pg_get_expr(ad.adbin, ad.adrelid), '') ELSE '' END,
                   CASE WHEN a.attgenerated <> '' THEN COALESCE(pg_catalog.pg_get_expr(ad.adbin, ad.adrelid), '') ELSE '' END,
                   CASE WHEN a.attcollation = t.typcollation THEN '' ELSE COALESCE(coll.collname, '') END
            FROM pg_catalog.pg_attribute AS a
            INNER JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid
            INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
            INNER JOIN pg_catalog.pg_type AS t ON t.oid = a.atttypid
            LEFT JOIN pg_catalog.pg_attrdef AS ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
            LEFT JOIN pg_catalog.pg_collation AS coll ON coll.oid = a.attcollation
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
                    reader.GetBoolean(6),
                    NormalizeExpression(reader.GetString(7)),
                    NormalizeExpression(reader.GetString(8)),
                    reader.GetString(9)));
            }
        }

        List<PostgreSqlSchemaFingerprint.ConstraintShape> constraints = [];
        const string constraintSql = """
            SELECT n.nspname, c.relname, constraint_row.conname, constraint_row.contype,
                   ARRAY(
                       SELECT column_row.attname
                       FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key_column(attnum, ordinal)
                       INNER JOIN pg_catalog.pg_attribute AS column_row
                           ON column_row.attrelid = c.oid AND column_row.attnum = key_column.attnum
                       ORDER BY key_column.ordinal),
                   CASE WHEN constraint_row.contype = 'c'
                       THEN pg_catalog.pg_get_expr(constraint_row.conbin, constraint_row.conrelid)
                       ELSE '' END,
                   COALESCE(index_data.indnullsnotdistinct, false)
            FROM pg_catalog.pg_constraint AS constraint_row
            INNER JOIN pg_catalog.pg_class AS c ON c.oid = constraint_row.conrelid
            INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
            LEFT JOIN pg_catalog.pg_index AS index_data ON index_data.indexrelid = constraint_row.conindid
            WHERE constraint_row.contype IN ('p', 'u', 'c')
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
            ORDER BY n.nspname, c.relname, constraint_row.conname;
            """;
        await using (var command = new NpgsqlCommand(constraintSql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                constraints.Add(new PostgreSqlSchemaFingerprint.ConstraintShape(
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetChar(3),
                    reader.GetFieldValue<string[]>(4),
                    NormalizeExpression(reader.GetString(5)))
                {
                    NullsNotDistinct = reader.GetBoolean(6),
                });
            }
        }

        List<PostgreSqlSchemaFingerprint.IndexShape> indexes = [];
        const string indexSql = """
            SELECT n.nspname, table_row.relname, index_row.relname, index_data.indisunique,
                   ARRAY(
                       SELECT column_row.attname
                       FROM unnest(index_data.indkey) WITH ORDINALITY AS key_column(attnum, ordinal)
                       INNER JOIN pg_catalog.pg_attribute AS column_row
                           ON column_row.attrelid = table_row.oid AND column_row.attnum = key_column.attnum
                       WHERE key_column.ordinal <= index_data.indnkeyatts
                       ORDER BY key_column.ordinal),
                   ARRAY(
                       SELECT column_row.attname
                       FROM unnest(index_data.indkey) WITH ORDINALITY AS key_column(attnum, ordinal)
                       INNER JOIN pg_catalog.pg_attribute AS column_row
                           ON column_row.attrelid = table_row.oid AND column_row.attnum = key_column.attnum
                       WHERE key_column.ordinal > index_data.indnkeyatts
                       ORDER BY key_column.ordinal),
                   ARRAY(
                       SELECT key_column.ordinal::integer
                       FROM unnest(index_data.indoption) WITH ORDINALITY AS key_column(option_value, ordinal)
                       WHERE key_column.ordinal <= index_data.indnkeyatts AND (key_column.option_value & 1) = 1
                       ORDER BY key_column.ordinal),
                   COALESCE(pg_catalog.pg_get_expr(index_data.indpred, index_data.indrelid), ''),
                   index_data.indnullsnotdistinct
            FROM pg_catalog.pg_index AS index_data
            INNER JOIN pg_catalog.pg_class AS table_row ON table_row.oid = index_data.indrelid
            INNER JOIN pg_catalog.pg_namespace AS n ON n.oid = table_row.relnamespace
            INNER JOIN pg_catalog.pg_class AS index_row ON index_row.oid = index_data.indexrelid
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND n.nspname NOT LIKE 'pg_toast%'
              AND NOT EXISTS (
                  SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
                  WHERE constraint_row.conindid = index_data.indexrelid)
            ORDER BY n.nspname, table_row.relname, index_row.relname;
            """;
        await using (var command = new NpgsqlCommand(indexSql, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                indexes.Add(new PostgreSqlSchemaFingerprint.IndexShape(
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetBoolean(3),
                    reader.GetFieldValue<string[]>(4),
                    reader.GetFieldValue<string[]>(5),
                    reader.GetFieldValue<int[]>(6),
                    NormalizeExpression(reader.GetString(7)))
                {
                    NullsNotDistinct = reader.GetBoolean(8),
                });
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
                       ORDER BY key_column.ordinal),
                   constraint_row.confdeltype, constraint_row.confupdtype,
                   constraint_row.convalidated
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
                    reader.GetFieldValue<string[]>(6),
                    FromPostgreSqlAction(reader.GetChar(7)),
                    FromPostgreSqlAction(reader.GetChar(8)),
                    reader.GetBoolean(9)));
            }
        }

        _schemaInspected = true;
        return PostgreSqlSchemaFingerprint.Compute(tables, columns, constraints, indexes, foreignKeys);
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
        await using (NpgsqlDataReader reader = await read.ExecuteReaderAsync(CommandBehavior.SequentialAccess, cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var values = new Dictionary<string, object?>(table.OrderedColumns.Count, StringComparer.Ordinal);
                for (var ordinal = 0; ordinal < table.OrderedColumns.Count; ordinal++)
                {
                    string column = table.OrderedColumns[ordinal];
                    object? value;
                    if (await reader.IsDBNullAsync(ordinal, cancellationToken).ConfigureAwait(false))
                    {
                        value = null;
                    }
                    else if (table.SourceColumns.FirstOrDefault(item => item.Column == column)?.MaxObservedDataLength is not null &&
                        string.Equals(table.ColumnTypes[column], "bytea", StringComparison.Ordinal))
                    {
                        var lob = new StreamingLob(StreamingLobKind.Binary, async (destination, token) =>
                        {
                            await using Stream input = reader.GetStream(ordinal);
                            await input.CopyToAsync(destination, 64 * 1024, token).ConfigureAwait(false);
                        });
                        await lob.ConsumeAsync(Stream.Null, cancellationToken).ConfigureAwait(false);
                        value = lob;
                    }
                    else if (table.SourceColumns.FirstOrDefault(item => item.Column == column)?.MaxObservedDataLength is not null)
                    {
                        var lob = new StreamingLob(StreamingLobKind.Text, async (destination, token) =>
                        {
                            using TextReader input = reader.GetTextReader(ordinal);
                            await using var writer = new StreamWriter(destination, new UTF8Encoding(false, true), 32 * 1024, leaveOpen: true);
                            char[] buffer = new char[32 * 1024];
                            int readCount;
                            while ((readCount = await input.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false)) != 0)
                            {
                                await writer.WriteAsync(buffer.AsMemory(0, readCount), token).ConfigureAwait(false);
                            }
                            await writer.FlushAsync(token).ConfigureAwait(false);
                        });
                        await lob.ConsumeAsync(Stream.Null, cancellationToken).ConfigureAwait(false);
                        value = lob;
                    }
                    else
                    {
                        value = reader.GetValue(ordinal);
                    }
                    values.Add(column, value);
                }
                collector.Append(new MigrationRow(values));
            }
        }

        TableReconciliationEvidence evidence = collector.Finish();
        var orphanCounts = new Dictionary<string, long>(StringComparer.Ordinal);
        var relationshipCounts = new Dictionary<string, long>(StringComparer.Ordinal);
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
            string relationshipSql = $"SELECT COUNT(*) FROM {Qualified(table.TargetSchema, table.TargetTable)} AS child WHERE {required};";
            await using var relationshipCommand = new NpgsqlCommand(relationshipSql, connection, transaction);
            relationshipCounts.Add(
                foreignKey.Name,
                Convert.ToInt64(await relationshipCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture));
        }

        _ = _completedTableInspections.Add($"{table.TargetSchema}.{table.TargetTable}");
        return evidence with
        {
            ForeignKeyOrphanCounts = new System.Collections.ObjectModel.ReadOnlyDictionary<string, long>(orphanCounts),
            ForeignKeyRelationshipCounts = new System.Collections.ObjectModel.ReadOnlyDictionary<string, long>(relationshipCounts),
        };
    }

    public async Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(
        DatabaseSchemaPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var results = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (TableCopyPlan table in plan.Tables)
        {
            foreach (IdentityCopyPlan identity in table.Identities.OrderBy(item => item.Column, StringComparer.Ordinal))
            {
                const string sequenceSql = "SELECT pg_get_serial_sequence($1, $2);";
                await using var sequence = new NpgsqlCommand(sequenceSql, connection, transaction);
                _ = sequence.Parameters.AddWithValue($"{table.TargetSchema}.{table.TargetTable}");
                _ = sequence.Parameters.AddWithValue(identity.Column);
                string? sequenceName = (string?)await sequence.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(sequenceName))
                {
                    throw new MigrationExecutionException("target_sequence_evidence_missing", $"{plan.Database}.{table.TargetTable}.{identity.Column} sequence evidence is unavailable.");
                }

                string stateSql = $"SELECT last_value, is_called FROM {PostgreSqlShadowTarget.QuoteQualifiedIdentifier(sequenceName)};";
                await using var state = new NpgsqlCommand(stateSql, connection, transaction);
                await using NpgsqlDataReader reader = await state.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    throw new MigrationExecutionException("target_sequence_evidence_missing", $"{plan.Database}.{table.TargetTable}.{identity.Column} sequence evidence is unavailable.");
                }

                long lastValue = reader.GetInt64(0);
                bool isCalled = reader.GetBoolean(1);
                long next = isCalled ? checked(lastValue + identity.IncrementValue) : lastValue;
                results.Add($"{table.TargetSchema}.{table.TargetTable}.{identity.Column}", next);
            }
        }

        return new System.Collections.ObjectModel.ReadOnlyDictionary<string, long>(results);
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
            try
            {
                await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                // A failed COPY may dispose its transaction; disposal already guarantees rollback.
            }
            _completed = true;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_completed)
        {
            try
            {
                await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                // A failed COPY may dispose its transaction; disposal already guarantees rollback.
            }
            _completed = true;
        }

        await transaction.DisposeAsync().ConfigureAwait(false);
        await connection.DisposeAsync().ConfigureAwait(false);
    }

    private async Task ReseedIdentityAsync(
        TableCopyPlan table,
        IdentityCopyPlan identity,
        CancellationToken cancellationToken)
    {
        const string sequenceSql = "SELECT pg_get_serial_sequence($1, $2);";
        await using var sequence = new NpgsqlCommand(sequenceSql, connection, transaction);
        _ = sequence.Parameters.AddWithValue($"{table.TargetSchema}.{table.TargetTable}");
        _ = sequence.Parameters.AddWithValue(identity.Column);
        string? sequenceName = (string?)await sequence.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(sequenceName))
        {
            return;
        }

        const string sql = "SELECT setval($1::regclass, $2, $3);";
        await using var reseed = new NpgsqlCommand(sql, connection, transaction);
        _ = reseed.Parameters.AddWithValue(sequenceName);
        _ = reseed.Parameters.AddWithValue(identity.CurrentValue);
        _ = reseed.Parameters.AddWithValue(identity.IsCalled);
        _ = await reseed.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        const string definitionSql = "SELECT seqstart, seqincrement FROM pg_catalog.pg_sequence WHERE seqrelid = $1::regclass;";
        await using (var definition = new NpgsqlCommand(definitionSql, connection, transaction))
        {
            _ = definition.Parameters.AddWithValue(sequenceName);
            await using NpgsqlDataReader definitionReader = await definition.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await definitionReader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
                definitionReader.GetInt64(0) != identity.SeedValue ||
                definitionReader.GetInt64(1) != identity.IncrementValue)
            {
                throw new MigrationExecutionException("identity_definition_mismatch", $"Identity definition drifted for {table.TargetSchema}.{table.TargetTable}.{identity.Column}.");
            }
        }

        await using var verify = new NpgsqlCommand($"SELECT last_value, is_called FROM {sequenceName};", connection, transaction);
        await using NpgsqlDataReader reader = await verify.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
            reader.GetInt64(0) != identity.CurrentValue ||
            reader.GetBoolean(1) != identity.IsCalled)
        {
            throw new MigrationExecutionException("identity_state_mismatch", $"Identity state drifted for {table.TargetSchema}.{table.TargetTable}.{identity.Column}.");
        }
    }

    private static string ReferentialActionSql(ReferentialAction action)
    {
        return action switch
        {
            ReferentialAction.NoAction => "NO ACTION",
            ReferentialAction.Cascade => "CASCADE",
            ReferentialAction.SetNull => "SET NULL",
            ReferentialAction.SetDefault => "SET DEFAULT",
            ReferentialAction.Restrict => "RESTRICT",
            _ => throw new MigrationExecutionException("foreign_key_action_invalid", "The signed foreign key action is unsupported."),
        };
    }

    private static ReferentialAction FromPostgreSqlAction(char action)
    {
        return action switch
        {
            'a' => ReferentialAction.NoAction,
            'r' => ReferentialAction.Restrict,
            'c' => ReferentialAction.Cascade,
            'n' => ReferentialAction.SetNull,
            'd' => ReferentialAction.SetDefault,
            _ => throw new MigrationExecutionException("foreign_key_action_invalid", "PostgreSQL reported an unsupported foreign key action."),
        };
    }

    private async Task ExecuteAsync(string sql, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private Task AddConstraintAsync(
        TableCopyPlan table,
        string name,
        string definition,
        CancellationToken cancellationToken)
    {
        return ExecuteAsync(
            $"ALTER TABLE {Qualified(table.TargetSchema, table.TargetTable)} " +
            $"ADD CONSTRAINT {PostgreSqlShadowTarget.QuoteIdentifier(name)} {definition};",
            cancellationToken);
    }

    private static string QuotedColumns(IReadOnlyList<string> columns)
    {
        return string.Join(", ", columns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
    }

    private static string NormalizeExpression(string expression)
    {
        return SchemaExpressionCanonicalizer.Canonicalize(expression);
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
            ("timestamp with time zone", DateTime dateTime) when dateTime.Kind == DateTimeKind.Utc => dateTime,
            ("timestamp with time zone", DateTime) => throw new MigrationExecutionException(
                "source_temporal_kind_invalid",
                "A timestamp with time zone source value must carry an explicit UTC offset."),
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
        bool Identity,
        string DefaultExpression,
        string GeneratedExpression,
        string Collation);

    internal sealed record ConstraintShape(
        string Schema,
        string Table,
        string Name,
        char Kind,
        IReadOnlyList<string> Columns,
        string Expression)
    {
        public bool NullsNotDistinct { get; init; }
    }

    internal sealed record IndexShape(
        string Schema,
        string Table,
        string Name,
        bool Unique,
        IReadOnlyList<string> Columns,
        IReadOnlyList<string> IncludedColumns,
        IReadOnlyList<int> DescendingOrdinals,
        string FilterPredicate)
    {
        public bool NullsNotDistinct { get; init; }
    }

    internal sealed record ForeignKeyShape(
        string Schema,
        string Table,
        string Name,
        IReadOnlyList<string> Columns,
        string ReferencedSchema,
        string ReferencedTable,
        IReadOnlyList<string> ReferencedColumns,
        ReferentialAction OnDelete,
        ReferentialAction OnUpdate,
        bool Validated);

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
                table.Identities.Any(identity => string.Equals(identity.Column, column, StringComparison.Ordinal)),
                table.DefaultExpressions.GetValueOrDefault(column, string.Empty),
                table.GeneratedColumns.SingleOrDefault(item => string.Equals(item.Column, column, StringComparison.Ordinal))?.Expression ?? string.Empty,
                table.Collations.GetValueOrDefault(column, string.Empty))))];
        List<ConstraintShape> constraints = [.. plan.Tables.SelectMany(table =>
            (table.PrimaryKey is null
                ? Enumerable.Empty<ConstraintShape>()
                : [new ConstraintShape(
                    table.TargetSchema,
                    table.TargetTable,
                    table.PrimaryKey.Name,
                    'p',
                    table.PrimaryKey.Columns,
                    string.Empty)])
            .Concat(table.UniqueConstraints.Select(item => new ConstraintShape(
                table.TargetSchema,
                table.TargetTable,
                item.Name,
                'u',
                item.Columns,
                string.Empty)
            {
                NullsNotDistinct = item.Columns.Intersect(table.NullableColumns, StringComparer.Ordinal).Any(),
            }))
            .Concat(table.CheckConstraints.Select(item => new ConstraintShape(
                table.TargetSchema,
                table.TargetTable,
                item.Name,
                'c',
                item.Columns,
                item.Expression))))];
        List<IndexShape> indexes = [.. plan.Tables.SelectMany(table => table.Indexes.Select(index =>
            new IndexShape(
                table.TargetSchema,
                table.TargetTable,
                index.Name,
                index.Unique,
                index.Columns,
                index.IncludedColumns,
                [.. index.Columns.Select((column, ordinal) => (column, ordinal: ordinal + 1))
                    .Where(item => index.DescendingColumns.Contains(item.column, StringComparer.Ordinal))
                    .Select(item => item.ordinal)],
                index.FilterPredicate ?? string.Empty)
            {
                NullsNotDistinct = index.Unique && index.Columns.Intersect(table.NullableColumns, StringComparer.Ordinal).Any(),
            }))];
        List<ForeignKeyShape> foreignKeys = [.. plan.Tables.SelectMany(table => table.ForeignKeys.Select(foreignKey =>
            new ForeignKeyShape(
                table.TargetSchema,
                table.TargetTable,
                foreignKey.Name,
                foreignKey.Columns,
                foreignKey.ReferencedSchema,
                foreignKey.ReferencedTable,
                foreignKey.ReferencedColumns,
                foreignKey.OnDelete,
                foreignKey.OnUpdate,
                true)))];
        return Compute(tables, columns, constraints, indexes, foreignKeys);
    }

    internal static string Compute(
        IEnumerable<TableShape> tables,
        IEnumerable<ColumnShape> columns,
        IEnumerable<ConstraintShape> constraints,
        IEnumerable<IndexShape> indexes,
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
                Write(writer, NormalizeExpression(column.DefaultExpression));
                Write(writer, NormalizeExpression(column.GeneratedExpression));
                Write(writer, column.Collation);
            }

            foreach (ConstraintShape constraint in constraints.OrderBy(item => item.Schema, StringComparer.Ordinal)
                .ThenBy(item => item.Table, StringComparer.Ordinal)
                .ThenBy(item => item.Name, StringComparer.Ordinal))
            {
                writer.Write((byte)'K');
                Write(writer, constraint.Schema);
                Write(writer, constraint.Table);
                Write(writer, constraint.Name);
                writer.Write(constraint.Kind);
                Write(writer, constraint.Columns);
                Write(writer, NormalizeExpression(constraint.Expression));
                writer.Write(constraint.NullsNotDistinct);
            }

            foreach (IndexShape index in indexes.OrderBy(item => item.Schema, StringComparer.Ordinal)
                .ThenBy(item => item.Table, StringComparer.Ordinal)
                .ThenBy(item => item.Name, StringComparer.Ordinal))
            {
                writer.Write((byte)'I');
                Write(writer, index.Schema);
                Write(writer, index.Table);
                Write(writer, index.Name);
                writer.Write(index.Unique);
                writer.Write(index.NullsNotDistinct);
                Write(writer, index.Columns);
                Write(writer, index.IncludedColumns);
                writer.Write(index.DescendingOrdinals.Count);
                foreach (int ordinal in index.DescendingOrdinals)
                {
                    writer.Write(ordinal);
                }
                Write(writer, NormalizeExpression(index.FilterPredicate));
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
                writer.Write((int)foreignKey.OnDelete);
                writer.Write((int)foreignKey.OnUpdate);
                writer.Write(foreignKey.Validated);
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

    private static string NormalizeExpression(string expression)
    {
        return SchemaExpressionCanonicalizer.Canonicalize(expression);
    }
}

internal static class SchemaExpressionCanonicalizer
{
    internal static string Canonicalize(string expression)
    {
        string normalized = string.Join(' ', expression.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        while (HasSingleEnclosingParenthesisPair(normalized))
        {
            normalized = normalized[1..^1].Trim();
        }

        return normalized;
    }

    private static bool HasSingleEnclosingParenthesisPair(string value)
    {
        if (value.Length < 2 || value[0] != '(' || value[^1] != ')')
        {
            return false;
        }

        var depth = 0;
        var singleQuoted = false;
        var doubleQuoted = false;
        for (var index = 0; index < value.Length; index++)
        {
            char current = value[index];
            if (current == '\'' && !doubleQuoted)
            {
                if (singleQuoted && index + 1 < value.Length && value[index + 1] == '\'')
                {
                    index++;
                    continue;
                }

                singleQuoted = !singleQuoted;
                continue;
            }

            if (current == '"' && !singleQuoted)
            {
                if (doubleQuoted && index + 1 < value.Length && value[index + 1] == '"')
                {
                    index++;
                    continue;
                }

                doubleQuoted = !doubleQuoted;
                continue;
            }

            if (singleQuoted || doubleQuoted)
            {
                continue;
            }

            depth += current switch { '(' => 1, ')' => -1, _ => 0 };
            if (depth == 0 && index != value.Length - 1)
            {
                return false;
            }
        }

        return depth == 0 && !singleQuoted && !doubleQuoted;
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
