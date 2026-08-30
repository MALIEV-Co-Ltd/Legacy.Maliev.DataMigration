using System.Collections.Concurrent;
using System.Data;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Buffers.Binary;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration;

public sealed record SqlServerMigrationSourceOptions(string ConnectionString);

public sealed partial class SqlServerMigrationSource : IReadOnlySqlServerMigrationSource, IDatabaseSchemaPlanSource, IAsyncDisposable
{
    private readonly SqlServerMigrationSourceOptions _options;
    private readonly ConcurrentDictionary<string, SnapshotLease> _snapshots = new(StringComparer.Ordinal);

    public SqlServerMigrationSource(SqlServerMigrationSourceOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.ConnectionString))
        {
            throw new ArgumentException("A SQL Server source connection string is required.", nameof(options));
        }

        _options = options;
    }

    public async Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
    {
        string connectionString = CreateDatabaseConnectionString(_options, database);
        var connection = new SqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        SqlTransaction transaction;
        try
        {
            transaction = (SqlTransaction)await connection
                .BeginTransactionAsync(IsolationLevel.Snapshot, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        if (!_snapshots.TryAdd(database, new SnapshotLease(connection, transaction)))
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            await transaction.DisposeAsync().ConfigureAwait(false);
            await connection.DisposeAsync().ConfigureAwait(false);
            throw new MigrationExecutionException("source_snapshot_duplicate", $"A snapshot for {database} is already active.");
        }
    }

    public async Task<SourceSchemaEvidence> InspectSchemaAsync(
        string database,
        CancellationToken cancellationToken)
    {
        SnapshotLease lease = GetSnapshot(database);
        const string columnSql = """
            SELECT
                s.name AS schema_name,
                t.name AS table_name,
                c.column_id,
                c.name AS column_name,
                ty.name AS type_name,
                c.max_length,
                c.precision,
                c.scale,
                c.is_nullable,
                c.is_identity,
                identity_column.seed_value,
                identity_column.increment_value,
                identity_column.last_value,
                COALESCE(c.collation_name, N'') AS collation_name,
                COALESCE(dc.definition, N'') AS default_definition,
                COALESCE(cc.definition, N'') AS computed_definition
            FROM sys.tables AS t
            INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
            INNER JOIN sys.columns AS c ON c.object_id = t.object_id
            INNER JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
            LEFT JOIN sys.default_constraints AS dc ON dc.object_id = c.default_object_id
            LEFT JOIN sys.computed_columns AS cc ON cc.object_id = c.object_id AND cc.column_id = c.column_id
            LEFT JOIN sys.identity_columns AS identity_column
                ON identity_column.object_id = c.object_id AND identity_column.column_id = c.column_id
            WHERE t.is_ms_shipped = 0
            ORDER BY s.name, t.name, c.column_id;
            """;
        const string keyAndIndexSql = """
            SELECT
                s.name AS schema_name,
                t.name AS table_name,
                i.name AS index_name,
                i.is_primary_key,
                i.is_unique_constraint,
                i.is_unique,
                ic.key_ordinal,
                c.name AS column_name,
                ic.is_descending_key,
                ic.is_included_column,
                i.has_filter,
                COALESCE(i.filter_definition, N'') AS filter_definition
            FROM sys.indexes AS i
            INNER JOIN sys.tables AS t ON t.object_id = i.object_id
            INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
            INNER JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
            INNER JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
            WHERE t.is_ms_shipped = 0 AND i.is_hypothetical = 0
            ORDER BY s.name, t.name, i.name, ic.key_ordinal, ic.index_column_id;
            """;
        const string checkSql = """
            SELECT s.name, t.name, cc.name, cc.definition, cc.is_disabled, cc.is_not_trusted
            FROM sys.check_constraints AS cc
            INNER JOIN sys.tables AS t ON t.object_id = cc.parent_object_id
            INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
            WHERE t.is_ms_shipped = 0
            ORDER BY s.name, t.name, cc.name;
            """;
        const string foreignKeySql = """
            SELECT child_schema.name, child_table.name, foreign_key.name,
                   mapping.constraint_column_id, child_column.name,
                   referenced_schema.name, referenced_table.name, referenced_column.name,
                   foreign_key.delete_referential_action, foreign_key.update_referential_action,
                   foreign_key.is_disabled, foreign_key.is_not_trusted
            FROM sys.foreign_keys AS foreign_key
            INNER JOIN sys.tables AS child_table ON child_table.object_id = foreign_key.parent_object_id
            INNER JOIN sys.schemas AS child_schema ON child_schema.schema_id = child_table.schema_id
            INNER JOIN sys.tables AS referenced_table ON referenced_table.object_id = foreign_key.referenced_object_id
            INNER JOIN sys.schemas AS referenced_schema ON referenced_schema.schema_id = referenced_table.schema_id
            INNER JOIN sys.foreign_key_columns AS mapping ON mapping.constraint_object_id = foreign_key.object_id
            INNER JOIN sys.columns AS child_column
                ON child_column.object_id = mapping.parent_object_id AND child_column.column_id = mapping.parent_column_id
            INNER JOIN sys.columns AS referenced_column
                ON referenced_column.object_id = mapping.referenced_object_id AND referenced_column.column_id = mapping.referenced_column_id
            WHERE child_table.is_ms_shipped = 0
            ORDER BY child_schema.name, child_table.name, foreign_key.name, mapping.constraint_column_id;
            """;
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await AppendSchemaQueryAsync(hash, lease, "columns", columnSql, cancellationToken).ConfigureAwait(false);
        await AppendSchemaQueryAsync(hash, lease, "keys-indexes", keyAndIndexSql, cancellationToken).ConfigureAwait(false);
        await AppendSchemaQueryAsync(hash, lease, "checks", checkSql, cancellationToken).ConfigureAwait(false);
        await AppendSchemaQueryAsync(hash, lease, "foreign-keys", foreignKeySql, cancellationToken).ConfigureAwait(false);

        IReadOnlyList<SourceTableInventory> inventory = await ReadInventoryAsync(
            lease,
            cancellationToken).ConfigureAwait(false);
        return new SourceSchemaEvidence(
            database,
            Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant(),
            inventory);
    }

    private static async Task<IReadOnlyList<SourceTableInventory>> ReadInventoryAsync(
        SnapshotLease lease,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT s.name, t.name, c.column_id, c.name, type_schema.name, ty.name,
                   c.max_length, c.precision, c.scale, c.is_nullable, c.is_identity,
                   COALESCE(CONVERT(nvarchar(100), identity_column.seed_value), N''),
                   COALESCE(CONVERT(nvarchar(100), identity_column.increment_value), N''),
                   COALESCE(CONVERT(nvarchar(100), identity_column.last_value), N''),
                   COALESCE(c.collation_name, N''), COALESCE(dc.definition, N''),
                   COALESCE(cc.definition, N''), COALESCE(CONVERT(int, cc.is_persisted), 0),
                   c.is_ansi_padded, c.is_rowguidcol, c.is_sparse, c.is_column_set,
                   c.is_filestream, c.generated_always_type, COALESCE(c.encryption_type, 0),
                   COALESCE(c.encryption_algorithm_name, N''), c.is_hidden, c.is_masked
            FROM sys.tables AS t
            INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
            INNER JOIN sys.columns AS c ON c.object_id = t.object_id
            INNER JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
            INNER JOIN sys.schemas AS type_schema ON type_schema.schema_id = ty.schema_id
            LEFT JOIN sys.default_constraints AS dc ON dc.object_id = c.default_object_id
            LEFT JOIN sys.computed_columns AS cc ON cc.object_id = c.object_id AND cc.column_id = c.column_id
            LEFT JOIN sys.identity_columns AS identity_column
                ON identity_column.object_id = c.object_id AND identity_column.column_id = c.column_id
            WHERE t.is_ms_shipped = 0
            ORDER BY s.name, t.name, c.column_id;
            """;
        var rows = new List<InventoryRow>();
        await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
        await using (SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                string declaredType = FormatDeclaredType(reader.GetString(5), reader.GetInt16(6), reader.GetByte(7), reader.GetByte(8));
                using IncrementalHash metadataHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                foreach (int ordinal in Enumerable.Range(4, reader.FieldCount - 4))
                {
                    AppendHashValue(metadataHash, reader.IsDBNull(ordinal)
                        ? "<null>"
                        : Convert.ToString(reader.GetValue(ordinal), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
                }
                rows.Add(new InventoryRow(
                    reader.GetString(0), reader.GetString(1), reader.GetInt32(2), reader.GetString(3), declaredType,
                    Convert.ToHexString(metadataHash.GetHashAndReset()).ToLowerInvariant(),
                    IsLargeValueType(declaredType)));
            }
        }

        var lengths = new Dictionary<(string Schema, string Table, string Column), long>(new InventoryKeyComparer());
        foreach (InventoryRow row in rows.Where(item => item.IsLargeValue))
        {
            string lengthSql = $"SELECT COALESCE(MAX(CONVERT(bigint, DATALENGTH({QuoteIdentifier(row.Column)}))), 0) FROM {QuoteIdentifier(row.Schema)}.{QuoteIdentifier(row.Table)};";
            await using var lengthCommand = new SqlCommand(lengthSql, lease.Connection, lease.Transaction);
            lengths[(row.Schema, row.Table, row.Column)] = Convert.ToInt64(
                await lengthCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                System.Globalization.CultureInfo.InvariantCulture);
        }

        return [.. rows
            .GroupBy(row => (row.Schema, row.Table))
            .OrderBy(group => group.Key.Schema, StringComparer.Ordinal)
            .ThenBy(group => group.Key.Table, StringComparer.Ordinal)
            .Select(group => new SourceTableInventory(
                group.Key.Schema,
                group.Key.Table,
                [.. group.OrderBy(row => row.Ordinal).Select(row => new SourceColumnInventory(
                    row.Column,
                    row.DeclaredType,
                    row.MetadataSha256,
                    row.IsLargeValue ? lengths[(row.Schema, row.Table, row.Column)] : null))]))];
    }

    private static string FormatDeclaredType(string type, short maxLength, byte precision, byte scale)
    {
        string normalized = type.ToLowerInvariant();
        return normalized switch
        {
            "nvarchar" or "nchar" => $"{normalized}({(maxLength == -1 ? "max" : (maxLength / 2).ToString(System.Globalization.CultureInfo.InvariantCulture))})",
            "varchar" or "char" or "varbinary" or "binary" => $"{normalized}({(maxLength == -1 ? "max" : maxLength.ToString(System.Globalization.CultureInfo.InvariantCulture))})",
            "decimal" or "numeric" => $"{normalized}({precision.ToString(System.Globalization.CultureInfo.InvariantCulture)},{scale.ToString(System.Globalization.CultureInfo.InvariantCulture)})",
            "datetime2" or "datetimeoffset" or "time" => $"{normalized}({scale.ToString(System.Globalization.CultureInfo.InvariantCulture)})",
            _ => normalized,
        };
    }

    private static bool IsLargeValueType(string declaredType)
    {
        return declaredType is "nvarchar(max)" or "varchar(max)" or "varbinary(max)" or "text" or "ntext" or "image" or "xml";
    }

    private sealed record InventoryRow(
        string Schema, string Table, int Ordinal, string Column, string DeclaredType, string MetadataSha256, bool IsLargeValue);

    private sealed class InventoryKeyComparer : IEqualityComparer<(string Schema, string Table, string Column)>
    {
        public bool Equals((string Schema, string Table, string Column) x, (string Schema, string Table, string Column) y)
        {
            return string.Equals(x.Schema, y.Schema, StringComparison.Ordinal) &&
            string.Equals(x.Table, y.Table, StringComparison.Ordinal) &&
            string.Equals(x.Column, y.Column, StringComparison.Ordinal);
        }

        public int GetHashCode((string Schema, string Table, string Column) value)
        {
            return HashCode.Combine(StringComparer.Ordinal.GetHashCode(value.Schema), StringComparer.Ordinal.GetHashCode(value.Table), StringComparer.Ordinal.GetHashCode(value.Column));
        }
    }

    private static async Task AppendSchemaQueryAsync(
        IncrementalHash hash,
        SnapshotLease lease,
        string section,
        string sql,
        CancellationToken cancellationToken)
    {
        AppendHashValue(hash, section);
        await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
        await using SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
            {
                AppendHashValue(
                    hash,
                    reader.IsDBNull(ordinal)
                        ? "<null>"
                        : Convert.ToString(reader.GetValue(ordinal), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
            }
        }
    }

    private static void AppendHashValue(IncrementalHash hash, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value.Normalize(NormalizationForm.FormC));
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }

    public async IAsyncEnumerable<MigrationRow> ReadTableAsync(
        string database,
        TableCopyPlan table,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);
        SnapshotLease lease = GetSnapshot(database);
        bool hasLargeValues = table.OrderedColumns.Any(column => IsLargeValueType(table.SourceColumnTypes[column]));
        await using var command = new SqlCommand(
            hasLargeValues ? BuildStreamingReadTableCommand(table) : BuildReadTableCommand(table),
            lease.Connection,
            lease.Transaction)
        {
            CommandTimeout = 0,
        };
        await using SqlDataReader reader = await command.ExecuteReaderAsync(
            CommandBehavior.SequentialAccess,
            cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var values = new Dictionary<string, object?>(table.OrderedColumns.Count, StringComparer.Ordinal);
            string[] materializedColumns = [.. table.OrderedColumns.Where(column => !IsLargeValueType(table.SourceColumnTypes[column]))];
            for (var ordinal = 0; ordinal < materializedColumns.Length; ordinal++)
            {
                string column = materializedColumns[ordinal];
                string sourceType = table.SourceColumnTypes[column];
                object? value = await reader.IsDBNullAsync(ordinal, cancellationToken).ConfigureAwait(false)
                    ? null
                    : reader.GetValue(ordinal);
                values.Add(column, NormalizeSourceValue(value, sourceType, table.ColumnTypes[column]));
            }
            string[] streamedColumns = [.. table.OrderedColumns.Where(column => IsLargeValueType(table.SourceColumnTypes[column]))];
            for (var index = 0; index < streamedColumns.Length; index++)
            {
                string column = streamedColumns[index];
                int ordinal = materializedColumns.Length + index;
                if (await reader.IsDBNullAsync(ordinal, cancellationToken).ConfigureAwait(false))
                {
                    values.Add(column, null);
                }
                else
                {
                    long expectedByteLength = Convert.ToInt64(reader.GetValue(ordinal), System.Globalization.CultureInfo.InvariantCulture);
                    values.Add(column, CreateStreamingLob(lease, table, column, expectedByteLength, values));
                }
            }

            yield return new MigrationRow(values);
        }
    }

    public async Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(
        string database,
        TableCopyPlan table,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);
        SnapshotLease lease = GetSnapshot(database);
        var results = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (ForeignKeyCopyPlan foreignKey in table.ForeignKeys.OrderBy(item => item.Name, StringComparer.Ordinal))
        {
            ForeignKeyMetadata metadata = await ReadForeignKeyMetadataAsync(
                lease,
                table,
                foreignKey,
                cancellationToken).ConfigureAwait(false);
            string join = string.Join(" AND ", metadata.Columns.Zip(
                metadata.ReferencedColumns,
                (column, referenced) => $"child.{QuoteIdentifier(column)} = parent.{QuoteIdentifier(referenced)}"));
            string required = string.Join(" AND ", metadata.Columns.Select(
                column => $"child.{QuoteIdentifier(column)} IS NOT NULL"));
            string orphanSql = $"SELECT COUNT_BIG(*) FROM {QuoteIdentifier(table.SourceSchema)}.{QuoteIdentifier(table.SourceTable)} AS child " +
                $"LEFT JOIN {QuoteIdentifier(metadata.ReferencedSchema)}.{QuoteIdentifier(metadata.ReferencedTable)} AS parent ON {join} " +
                $"WHERE {required} AND parent.{QuoteIdentifier(metadata.ReferencedColumns[0])} IS NULL;";
            await using var command = new SqlCommand(orphanSql, lease.Connection, lease.Transaction);
            results.Add(
                foreignKey.Name,
                Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                    System.Globalization.CultureInfo.InvariantCulture));
        }

        return results;
    }

    public async Task<IReadOnlyDictionary<string, long>> InspectForeignKeyRelationshipsAsync(
        string database,
        TableCopyPlan table,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);
        SnapshotLease lease = GetSnapshot(database);
        var results = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (ForeignKeyCopyPlan foreignKey in table.ForeignKeys.OrderBy(item => item.Name, StringComparer.Ordinal))
        {
            ForeignKeyMetadata metadata = await ReadForeignKeyMetadataAsync(
                lease,
                table,
                foreignKey,
                cancellationToken).ConfigureAwait(false);
            string required = string.Join(" AND ", metadata.Columns.Select(
                column => $"child.{QuoteIdentifier(column)} IS NOT NULL"));
            string sql = $"SELECT COUNT_BIG(*) FROM {QuoteIdentifier(table.SourceSchema)}.{QuoteIdentifier(table.SourceTable)} AS child WHERE {required};";
            await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
            results.Add(
                foreignKey.Name,
                Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                    System.Globalization.CultureInfo.InvariantCulture));
        }

        return new System.Collections.ObjectModel.ReadOnlyDictionary<string, long>(results);
    }

    public async Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(
        string database,
        DatabaseSchemaPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        SnapshotLease lease = GetSnapshot(database);
        var results = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (TableCopyPlan table in plan.Tables)
        {
            foreach (IdentityCopyPlan identity in table.Identities.OrderBy(item => item.Column, StringComparer.Ordinal))
            {
                const string sql = "SELECT CONVERT(bigint, IDENT_CURRENT(@tableName)), CONVERT(bigint, IDENT_INCR(@tableName));";
                await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
                _ = command.Parameters.AddWithValue("@tableName", $"{table.SourceSchema}.{table.SourceTable}");
                await using SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(0) || reader.IsDBNull(1))
                {
                    throw new MigrationExecutionException("source_sequence_evidence_missing", $"{database}.{table.SourceTable}.{identity.Column} sequence evidence is unavailable.");
                }

                long current = reader.GetInt64(0);
                long increment = reader.GetInt64(1);
                long next = identity.IsCalled ? checked(current + increment) : current;
                results.Add($"{table.TargetSchema}.{table.TargetTable}.{identity.Column}", next);
            }
        }

        return new System.Collections.ObjectModel.ReadOnlyDictionary<string, long>(results);
    }

    public async Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
    {
        SnapshotLease lease = RemoveSnapshot(database);
        try
        {
            await lease.Transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await lease.DisposeAsync().ConfigureAwait(false);
        }
    }

    public async Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
    {
        if (!_snapshots.TryRemove(database, out SnapshotLease? lease))
        {
            return;
        }

        try
        {
            await lease.Transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await lease.DisposeAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (string database in _snapshots.Keys)
        {
            await RollbackDatabaseSnapshotAsync(database, CancellationToken.None).ConfigureAwait(false);
        }
    }

    internal static string CreateDatabaseConnectionString(
        SqlServerMigrationSourceOptions options,
        string database)
    {
        ArgumentNullException.ThrowIfNull(options);
        ValidateDatabaseName(database);
        var builder = new SqlConnectionStringBuilder(options.ConnectionString)
        {
            InitialCatalog = database,
            ApplicationIntent = ApplicationIntent.ReadOnly,
            MultipleActiveResultSets = true,
        };
        return builder.ConnectionString;
    }

    internal static string BuildReadTableCommand(TableCopyPlan table)
    {
        ArgumentNullException.ThrowIfNull(table);
        return table.OrderedColumns.Count == 0 || table.OrderByColumns.Count == 0
            ? throw new ArgumentException("A deterministic table read requires columns and ordering.", nameof(table))
            : $"SELECT {string.Join(", ", table.OrderedColumns.Select(QuoteIdentifier))} " +
            $"FROM {QuoteIdentifier(table.SourceSchema)}.{QuoteIdentifier(table.SourceTable)} " +
            $"ORDER BY {string.Join(", ", table.OrderByColumns.Select(QuoteIdentifier))};";
    }

    internal static object? NormalizeSourceValue(object? value, string sourceType)
    {
        return NormalizeSourceValue(value, sourceType, string.Empty);
    }

    private static string BuildStreamingReadTableCommand(TableCopyPlan table)
    {
        IReadOnlyList<string> keys = table.PrimaryKey?.Columns ?? table.OrderByColumns;
        if (keys.Count == 0 || keys.Any(column => IsLargeValueType(table.SourceColumnTypes[column])))
        {
            throw new MigrationExecutionException("streaming_lob_key_invalid", "A streamed value requires a materialized deterministic row key.");
        }
        string[] materialized = [.. table.OrderedColumns.Where(column => !IsLargeValueType(table.SourceColumnTypes[column]))];
        string[] lengthProbes = [.. table.OrderedColumns.Where(column => IsLargeValueType(table.SourceColumnTypes[column]))
            .Select(column => table.SourceColumnTypes[column] is "varbinary(max)" or "image"
                ? $"DATALENGTH({QuoteIdentifier(column)})"
                : $"DATALENGTH(CONVERT(varchar(max), {QuoteIdentifier(column)} COLLATE Latin1_General_100_BIN2_UTF8))")];
        return $"SELECT {string.Join(", ", materialized.Concat(lengthProbes))} " +
            $"FROM {QuoteIdentifier(table.SourceSchema)}.{QuoteIdentifier(table.SourceTable)} " +
            $"ORDER BY {string.Join(", ", table.OrderByColumns.Select(QuoteIdentifier))};";
    }

    private static StreamingLob CreateStreamingLob(
        SnapshotLease lease,
        TableCopyPlan table,
        string column,
        long expectedByteLength,
        Dictionary<string, object?> values)
    {
        IReadOnlyList<string> keys = table.PrimaryKey?.Columns ?? table.OrderByColumns;
        object?[] keyValues = [.. keys.Select(key => values[key])];
        string predicate = string.Join(" AND ", keys.Select((key, index) =>
            keyValues[index] is null or DBNull ? $"{QuoteIdentifier(key)} IS NULL" : $"{QuoteIdentifier(key)} = @key{index}"));
        string sql = $"SELECT {QuoteIdentifier(column)} FROM {QuoteIdentifier(table.SourceSchema)}.{QuoteIdentifier(table.SourceTable)} WHERE {predicate};";
        bool binary = table.SourceColumnTypes[column] is "varbinary(max)" or "image";
        return new StreamingLob(binary ? StreamingLobKind.Binary : StreamingLobKind.Text, expectedByteLength, async (destination, cancellationToken) =>
        {
            await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction) { CommandTimeout = 0 };
            for (var index = 0; index < keys.Count; index++)
            {
                if (keyValues[index] is not null and not DBNull)
                {
                    _ = command.Parameters.AddWithValue($"key{index}", keyValues[index]);
                }
            }
            await using SqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SequentialAccess, cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || await reader.IsDBNullAsync(0, cancellationToken).ConfigureAwait(false))
            {
                throw new MigrationExecutionException("streaming_lob_row_missing", "The deterministic source row for a streamed value is missing or null.");
            }
            if (binary)
            {
                await using Stream input = reader.GetStream(0);
                await input.CopyToAsync(destination, 64 * 1024, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                using TextReader input = reader.GetTextReader(0);
                await using var writer = new StreamWriter(destination, new UTF8Encoding(false, true), 32 * 1024, leaveOpen: true);
                char[] buffer = new char[32 * 1024];
                int read;
                while ((read = await input.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false)) != 0)
                {
                    await writer.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                }
                await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new MigrationExecutionException("streaming_lob_row_ambiguous", "The deterministic source key selected multiple rows.");
            }
        });
    }

    internal static object? NormalizeSourceValue(object? value, string sourceType, string targetType)
    {
        if (value is null or DBNull)
        {
            return null;
        }

        string normalizedType = sourceType.Split('(', 2)[0].Trim().ToLowerInvariant();
        return (normalizedType, targetType, value) switch
        {
            ("datetime2", "text", DateTime preciseDateTime) =>
                DateTime.SpecifyKind(preciseDateTime, DateTimeKind.Unspecified)
                    .ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff", System.Globalization.CultureInfo.InvariantCulture),
            ("datetimeoffset", "text", DateTimeOffset offset) =>
                offset.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffffzzz", System.Globalization.CultureInfo.InvariantCulture),
            ("datetime" or "datetime2" or "smalldatetime", _, DateTime dateTime) =>
                DateTime.SpecifyKind(dateTime, DateTimeKind.Unspecified),
            _ => value,
        };
    }

    private static string QuoteIdentifier(string identifier)
    {
        return string.IsNullOrEmpty(identifier) || identifier.Contains('\0', StringComparison.Ordinal)
            ? throw new ArgumentException("SQL Server identifiers must be non-empty and contain no null bytes.", nameof(identifier))
            : $"[{identifier.Replace("]", "]]", StringComparison.Ordinal)}]";
    }

    private static void ValidateDatabaseName(string database)
    {
        if (string.IsNullOrWhiteSpace(database) || !DatabaseName().IsMatch(database))
        {
            throw new ArgumentException("The SQL Server database name is not approved.", nameof(database));
        }
    }

    private SnapshotLease GetSnapshot(string database)
    {
        return _snapshots.TryGetValue(database, out SnapshotLease? lease)
            ? lease
            : throw new MigrationExecutionException("source_snapshot_missing", $"No active snapshot exists for {database}.");
    }

    private SnapshotLease RemoveSnapshot(string database)
    {
        return _snapshots.TryRemove(database, out SnapshotLease? lease)
            ? lease
            : throw new MigrationExecutionException("source_snapshot_missing", $"No active snapshot exists for {database}.");
    }

    private static async Task<ForeignKeyMetadata> ReadForeignKeyMetadataAsync(
        SnapshotLease lease,
        TableCopyPlan table,
        ForeignKeyCopyPlan foreignKey,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT
                referenced_schema.name,
                referenced_table.name,
                child_column.name,
                referenced_column.name,
                foreign_key.delete_referential_action,
                foreign_key.update_referential_action,
                foreign_key.is_disabled,
                foreign_key.is_not_trusted
            FROM sys.foreign_keys AS foreign_key
            INNER JOIN sys.tables AS child_table ON child_table.object_id = foreign_key.parent_object_id
            INNER JOIN sys.schemas AS child_schema ON child_schema.schema_id = child_table.schema_id
            INNER JOIN sys.tables AS referenced_table ON referenced_table.object_id = foreign_key.referenced_object_id
            INNER JOIN sys.schemas AS referenced_schema ON referenced_schema.schema_id = referenced_table.schema_id
            INNER JOIN sys.foreign_key_columns AS mapping ON mapping.constraint_object_id = foreign_key.object_id
            INNER JOIN sys.columns AS child_column
                ON child_column.object_id = mapping.parent_object_id
               AND child_column.column_id = mapping.parent_column_id
            INNER JOIN sys.columns AS referenced_column
                ON referenced_column.object_id = mapping.referenced_object_id
               AND referenced_column.column_id = mapping.referenced_column_id
            WHERE child_schema.name = @schema
              AND child_table.name = @table
              AND foreign_key.name = @foreignKey
            ORDER BY mapping.constraint_column_id;
            """;
        await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
        _ = command.Parameters.AddWithValue("@schema", table.SourceSchema);
        _ = command.Parameters.AddWithValue("@table", table.SourceTable);
        _ = command.Parameters.AddWithValue("@foreignKey", foreignKey.Name);
        await using SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        string? referencedSchema = null;
        string? referencedTable = null;
        List<string> columns = [];
        List<string> referencedColumns = [];
        int? deleteAction = null;
        int? updateAction = null;
        bool? disabled = null;
        bool? notTrusted = null;
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            referencedSchema ??= reader.GetString(0);
            referencedTable ??= reader.GetString(1);
            columns.Add(reader.GetString(2));
            referencedColumns.Add(reader.GetString(3));
            deleteAction ??= reader.GetByte(4);
            updateAction ??= reader.GetByte(5);
            disabled ??= reader.GetBoolean(6);
            notTrusted ??= reader.GetBoolean(7);
        }

        return ValidateObservedForeignKey(
            foreignKey,
            referencedSchema,
            referencedTable,
            columns,
            referencedColumns,
            deleteAction,
            updateAction,
            disabled,
            notTrusted);
    }

    internal static ForeignKeyMetadata ValidateObservedForeignKey(
        ForeignKeyCopyPlan foreignKey,
        string? referencedSchema,
        string? referencedTable,
        IReadOnlyList<string> columns,
        IReadOnlyList<string> referencedColumns,
        int? deleteAction = null,
        int? updateAction = null,
        bool? disabled = null,
        bool? notTrusted = null)
    {
        ArgumentNullException.ThrowIfNull(foreignKey);
        return referencedSchema is null ||
            referencedTable is null ||
            !string.Equals(
                referencedSchema,
                foreignKey.SourceReferencedSchema ?? foreignKey.ReferencedSchema,
                StringComparison.Ordinal) ||
            !string.Equals(
                referencedTable,
                foreignKey.SourceReferencedTable ?? foreignKey.ReferencedTable,
                StringComparison.Ordinal) ||
            !columns.SequenceEqual(foreignKey.Columns, StringComparer.Ordinal) ||
            !referencedColumns.SequenceEqual(
                foreignKey.SourceReferencedColumns ?? foreignKey.ReferencedColumns,
                StringComparer.Ordinal) ||
            (deleteAction is not null && FromSqlServerAction(deleteAction.Value) != foreignKey.OnDelete) ||
            (updateAction is not null && FromSqlServerAction(updateAction.Value) != foreignKey.OnUpdate) ||
            (disabled is not null && disabled.Value == foreignKey.SourceEnabled) ||
            (notTrusted is not null && notTrusted.Value == foreignKey.SourceTrusted)
            ? throw new MigrationExecutionException(
                "source_foreign_key_drift",
                $"The source foreign key {foreignKey.Name} does not match the signed schema plan.")
            : new ForeignKeyMetadata(
                referencedSchema,
                referencedTable,
                columns,
                referencedColumns,
                foreignKey.OnDelete,
                foreignKey.OnUpdate,
                foreignKey.SourceEnabled,
                foreignKey.SourceTrusted);
    }

    private static ReferentialAction FromSqlServerAction(int action)
    {
        return action switch
        {
            0 => ReferentialAction.NoAction,
            1 => ReferentialAction.Cascade,
            2 => ReferentialAction.SetNull,
            3 => ReferentialAction.SetDefault,
            _ => throw new MigrationExecutionException("source_foreign_key_drift", "SQL Server reported an unsupported foreign key action."),
        };
    }

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex DatabaseName();

    private sealed record SnapshotLease(SqlConnection Connection, SqlTransaction Transaction) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await Transaction.DisposeAsync().ConfigureAwait(false);
            await Connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    internal sealed record ForeignKeyMetadata(
        string ReferencedSchema,
        string ReferencedTable,
        IReadOnlyList<string> Columns,
        IReadOnlyList<string> ReferencedColumns,
        ReferentialAction OnDelete,
        ReferentialAction OnUpdate,
        bool Enabled,
        bool Trusted);
}
