using System.Data;
using System.Runtime.CompilerServices;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public interface IDeltaOrderedRowSource
{
    IAsyncEnumerable<MigrationRow> ReadOrderedAsync(
        string database,
        TableCopyPlan table,
        CancellationToken cancellationToken);
}

/// <summary>Holds one immutable target row view across every table in a database plan.</summary>
public interface IDeltaDatabaseSnapshotRowSource : IDeltaOrderedRowSource
{
    Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);
    Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);
    Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken);
}

public sealed class SqlServerSnapshotDeltaRowSource(IReadOnlyMigrationSource source) : IDeltaOrderedRowSource
{
    public IAsyncEnumerable<MigrationRow> ReadOrderedAsync(
        string database,
        TableCopyPlan table,
        CancellationToken cancellationToken)
    {
        return source.ReadTableImmediatelyAsync(database, table, cancellationToken);
    }
}

public sealed record PostgreSqlDeltaRowSourceOptions(string AdministrativeConnectionString);

public sealed class PostgreSqlDeltaRowSource(PostgreSqlDeltaRowSourceOptions options) : IDeltaDatabaseSnapshotRowSource
{
    private readonly NpgsqlConnectionStringBuilder _settings = Validate(options);
    private NpgsqlConnection? _snapshotConnection;
    private NpgsqlTransaction? _snapshotTransaction;
    private string? _snapshotDatabase;

    public async Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(database);
        if (_snapshotConnection is not null)
        {
            throw new DeltaPlanningException("delta_target_snapshot_active",
                "A target database snapshot is already open.");
        }
        var connection = new NpgsqlConnection(ConnectionFor(database));
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
                IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
            try
            {
                await using var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction);
                _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                await using var establish = new NpgsqlCommand("SELECT pg_current_snapshot()::text;", connection, transaction);
                _ = await establish.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
                _snapshotConnection = connection;
                _snapshotTransaction = transaction;
                _snapshotDatabase = database;
            }
            catch
            {
                await transaction.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
    {
        return EndSnapshotAsync(database, commit: true, cancellationToken);
    }

    public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
    {
        return EndSnapshotAsync(database, commit: false, cancellationToken);
    }

    public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(
        string database,
        TableCopyPlan table,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(database);
        ArgumentNullException.ThrowIfNull(table);
        ValidateTable(table);
        if (_snapshotConnection is not null)
        {
            if (!string.Equals(_snapshotDatabase, database, StringComparison.Ordinal))
            {
                throw new DeltaPlanningException("delta_target_snapshot_database_invalid",
                    "The target row read is outside its active database snapshot.");
            }
            await foreach (MigrationRow row in ReadRowsAsync(_snapshotConnection, _snapshotTransaction!, table,
                cancellationToken).ConfigureAwait(false))
            {
                yield return row;
            }
            yield break;
        }
        await using var connection = new NpgsqlConnection(ConnectionFor(database));
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
        await foreach (MigrationRow row in ReadRowsAsync(connection, transaction, table,
            cancellationToken).ConfigureAwait(false))
        {
            yield return row;
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async IAsyncEnumerable<MigrationRow> ReadRowsAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, TableCopyPlan table,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        string columns = string.Join(", ", table.OrderedColumns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        string order = string.Join(", ", table.PrimaryKey!.Columns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        await using var command = new NpgsqlCommand(
            $"SELECT {columns} FROM {PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable)} ORDER BY {order};",
            connection,
            transaction);
        await using NpgsqlDataReader reader = await command
            .ExecuteReaderAsync(CommandBehavior.SequentialAccess, cancellationToken)
            .ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var values = new Dictionary<string, object?>(table.OrderedColumns.Count, StringComparer.Ordinal);
            for (var ordinal = 0; ordinal < table.OrderedColumns.Count; ordinal++)
            {
                string column = table.OrderedColumns[ordinal];
                values.Add(
                    column,
                    await reader.IsDBNullAsync(ordinal, cancellationToken).ConfigureAwait(false)
                        ? null
                        : ReadValue(reader, ordinal, table.SourceColumnTypes.TryGetValue(column, out string? sourceType)
                            ? sourceType : table.ColumnTypes[column]));
            }
            yield return new MigrationRow(values);
        }
    }

    private async Task EndSnapshotAsync(string database, bool commit, CancellationToken cancellationToken)
    {
        if (_snapshotConnection is null || _snapshotTransaction is null ||
            !string.Equals(_snapshotDatabase, database, StringComparison.Ordinal))
        {
            throw new DeltaPlanningException("delta_target_snapshot_database_invalid",
                "The target database snapshot is missing or belongs to another database.");
        }
        NpgsqlConnection connection = _snapshotConnection;
        NpgsqlTransaction transaction = _snapshotTransaction;
        _snapshotConnection = null;
        _snapshotTransaction = null;
        _snapshotDatabase = null;
        try
        {
            if (commit)
            {
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await transaction.DisposeAsync().ConfigureAwait(false);
            await connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    private string ConnectionFor(string database)
    {
        return new NpgsqlConnectionStringBuilder(_settings.ConnectionString)
        {
            Database = database,
            Pooling = false,
        }.ConnectionString;
    }

    private static NpgsqlConnectionStringBuilder Validate(PostgreSqlDeltaRowSourceOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.AdministrativeConnectionString))
        {
            throw new ArgumentException("A PostgreSQL administrative connection string is required.", nameof(options));
        }
        var builder = new NpgsqlConnectionStringBuilder(options.AdministrativeConnectionString);
        return string.IsNullOrWhiteSpace(builder.Host) || string.IsNullOrWhiteSpace(builder.Username)
            ? throw new ArgumentException("The PostgreSQL row-source endpoint is incomplete.", nameof(options))
            : builder;
    }

    private static void ValidateTable(TableCopyPlan table)
    {
        if (table.PrimaryKey is null || table.PrimaryKey.Columns.Count == 0 || table.OrderedColumns.Count == 0)
        {
            throw new DeltaPlanningException("delta_primary_key_required", "Ordered PostgreSQL delta reads require a primary key.");
        }
    }

    private static object ReadValue(NpgsqlDataReader reader, int ordinal, string sourceType)
    {
        if (!IsLargeValueType(sourceType))
        {
            return reader.GetValue(ordinal);
        }

        bool binary = sourceType is "varbinary(max)" or "image";
        byte[] bytes = binary
            ? reader.GetFieldValue<byte[]>(ordinal)
            : Encoding.UTF8.GetBytes(reader.GetString(ordinal));
        return new BufferedStreamingLob(
            binary ? StreamingLobKind.Binary : StreamingLobKind.Text,
            bytes);
    }

    private static bool IsLargeValueType(string declaredType)
    {
        return declaredType is "nvarchar(max)" or "varchar(max)" or "varbinary(max)" or
            "text" or "ntext" or "image" or "xml";
    }
}

public sealed class SqlServerSnapshotDeltaExecutionRowSource(IReadOnlyMigrationSource source) : IDeltaOrderedRowSource
{
    public IAsyncEnumerable<MigrationRow> ReadOrderedAsync(
        string database,
        TableCopyPlan table,
        CancellationToken cancellationToken)
    {
        return source.ReadTableForDeltaExecutionAsync(database, table, cancellationToken);
    }
}
