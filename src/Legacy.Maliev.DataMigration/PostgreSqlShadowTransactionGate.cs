using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal static class PostgreSqlShadowTransactionGate
{
    // The caller owns both resources only on success. A failed handoff always closes the
    // non-pooled physical connection, including an ambiguously acknowledged session lock.
    internal static async Task<NpgsqlTransaction> BeginAsync(
        NpgsqlConnection connection,
        string shadowName,
        bool readOnly,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        NpgsqlTransaction? transaction = null;
        try
        {
            await connection.OpenAsync(deadline.Token).ConfigureAwait(false);
            await ExecuteAsync("SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended($1, 0));").ConfigureAwait(false);
            // A lock SELECT inside Serializable would fix its snapshot BEFORE waiting.
            // Hold the session gate on this connection before creating the snapshot instead.
            transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, deadline.Token).ConfigureAwait(false);
            if (readOnly)
            {
                await using var readOnlyCommand = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction);
                _ = await readOnlyCommand.ExecuteNonQueryAsync(deadline.Token).ConfigureAwait(false);
            }
            await ExecuteAsync("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0));").ConfigureAwait(false);
            await ExecuteAsync("SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended($1, 0));").ConfigureAwait(false);
            return transaction;
        }
        catch (Exception primary)
        {
            await DisposeFailedAsync(connection, transaction, primary).ConfigureAwait(false);
            if (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested)
            {
                throw new MigrationExecutionException("shadow_settlement_timeout", "The target transaction did not settle within the bounded wait; its state was preserved.", primary);
            }
            throw;
        }

        async Task ExecuteAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            // The linked deadline is authoritative even when the configured wait exceeds
            // Npgsql's default command timeout. It is always bounded by the target options.
            command.CommandTimeout = 0;
            _ = command.Parameters.AddWithValue(shadowName);
            _ = await command.ExecuteScalarAsync(deadline.Token).ConfigureAwait(false);
        }
    }

    internal static async Task DisposeFailedAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, Exception primary)
    {
        List<Exception> failures = [primary];
        if (transaction is not null)
        {
            try { await transaction.DisposeAsync().ConfigureAwait(false); }
            catch (Exception cleanup) { failures.Add(cleanup); }
        }
        try { await connection.DisposeAsync().ConfigureAwait(false); }
        catch (Exception cleanup) { failures.Add(cleanup); }
        if (failures.Count > 1)
        {
            throw new AggregateException("Target operation failed; resource cleanup also failed.", failures);
        }
    }
}
