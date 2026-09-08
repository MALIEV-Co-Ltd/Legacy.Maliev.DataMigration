using System.Data;
using System.Runtime.CompilerServices;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public interface IDeltaOrderedRowSource
{
    IAsyncEnumerable<MigrationRow> ReadOrderedAsync(
        string database,
        TableCopyPlan table,
        CancellationToken cancellationToken);
}

public sealed class SqlServerSnapshotDeltaRowSource(SqlServerMigrationSource source) : IDeltaOrderedRowSource
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

public sealed class PostgreSqlDeltaRowSource(PostgreSqlDeltaRowSourceOptions options) : IDeltaOrderedRowSource
{
    private readonly NpgsqlConnectionStringBuilder _settings = Validate(options);

    public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(
        string database,
        TableCopyPlan table,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(database);
        ArgumentNullException.ThrowIfNull(table);
        ValidateTable(table);
        var builder = new NpgsqlConnectionStringBuilder(_settings.ConnectionString)
        {
            Database = database,
            Pooling = false,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection
            .BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken)
            .ConfigureAwait(false);
        string columns = string.Join(", ", table.OrderedColumns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        string order = string.Join(", ", table.PrimaryKey!.Columns.Select(PostgreSqlShadowTarget.QuoteIdentifier));
        await using var command = new NpgsqlCommand(
            $"SELECT {columns} FROM {PostgreSqlDeltaCanonicalTarget.Qualified(table.TargetSchema, table.TargetTable)} ORDER BY {order};",
            connection,
            transaction);
        await using (NpgsqlDataReader reader = await command
            .ExecuteReaderAsync(CommandBehavior.SequentialAccess, cancellationToken)
            .ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var values = new Dictionary<string, object?>(table.OrderedColumns.Count, StringComparer.Ordinal);
                for (var ordinal = 0; ordinal < table.OrderedColumns.Count; ordinal++)
                {
                    values.Add(
                        table.OrderedColumns[ordinal],
                        await reader.IsDBNullAsync(ordinal, cancellationToken).ConfigureAwait(false)
                            ? null
                            : reader.GetValue(ordinal));
                }
                yield return new MigrationRow(values);
            }
        }
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
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
}
