using System.Collections.Concurrent;
using System.Data;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration;

public sealed record SqlServerMigrationSourceOptions(string ConnectionString);

public sealed partial class SqlServerMigrationSource : IReadOnlySqlServerMigrationSource, IAsyncDisposable
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
        const string sql = """
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
                COALESCE(dc.definition, N'') AS default_definition,
                COALESCE(cc.definition, N'') AS computed_definition
            FROM sys.tables AS t
            INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
            INNER JOIN sys.columns AS c ON c.object_id = t.object_id
            INNER JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
            LEFT JOIN sys.default_constraints AS dc ON dc.object_id = c.default_object_id
            LEFT JOIN sys.computed_columns AS cc ON cc.object_id = c.object_id AND cc.column_id = c.column_id
            WHERE t.is_ms_shipped = 0
            ORDER BY s.name, t.name, c.column_id;
            """;
        await using var command = new SqlCommand(sql, lease.Connection, lease.Transaction);
        await using SqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
            {
                string value = reader.IsDBNull(ordinal)
                    ? "<null>"
                    : Convert.ToString(reader.GetValue(ordinal), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
                byte[] bytes = Encoding.UTF8.GetBytes(value.Normalize(NormalizationForm.FormC));
                hash.AppendData(BitConverter.GetBytes(bytes.Length));
                hash.AppendData(bytes);
            }
        }

        return new SourceSchemaEvidence(database, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant());
    }

    public async IAsyncEnumerable<MigrationRow> ReadTableAsync(
        string database,
        TableCopyPlan table,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(table);
        SnapshotLease lease = GetSnapshot(database);
        await using var command = new SqlCommand(BuildReadTableCommand(table), lease.Connection, lease.Transaction)
        {
            CommandTimeout = 0,
        };
        await using SqlDataReader reader = await command.ExecuteReaderAsync(
            CommandBehavior.SequentialAccess,
            cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var values = new Dictionary<string, object?>(table.OrderedColumns.Count, StringComparer.Ordinal);
            for (var ordinal = 0; ordinal < table.OrderedColumns.Count; ordinal++)
            {
                values.Add(table.OrderedColumns[ordinal], await reader.IsDBNullAsync(ordinal, cancellationToken)
                    .ConfigureAwait(false) ? null : reader.GetValue(ordinal));
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
            MultipleActiveResultSets = false,
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
                referenced_column.name
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
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            referencedSchema ??= reader.GetString(0);
            referencedTable ??= reader.GetString(1);
            columns.Add(reader.GetString(2));
            referencedColumns.Add(reader.GetString(3));
        }

        return referencedSchema is null ||
            referencedTable is null ||
            !columns.SequenceEqual(foreignKey.Columns, StringComparer.Ordinal)
            ? throw new MigrationExecutionException(
                "source_foreign_key_drift",
                $"The source foreign key {foreignKey.Name} does not match the signed schema plan.")
            : new ForeignKeyMetadata(referencedSchema, referencedTable, columns, referencedColumns);
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

    private sealed record ForeignKeyMetadata(
        string ReferencedSchema,
        string ReferencedTable,
        IReadOnlyList<string> Columns,
        IReadOnlyList<string> ReferencedColumns);
}
