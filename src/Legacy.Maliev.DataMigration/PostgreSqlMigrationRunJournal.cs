using System.Text.Json;
using System.Text.RegularExpressions;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed record PostgreSqlMigrationRunJournalOptions(
    string ConnectionString,
    string Schema = "legacy_migration_control");

public sealed partial class PostgreSqlMigrationRunJournal : IMigrationRunJournal
{
    private readonly string _connectionString;
    private readonly string _schema;
    private readonly string _table;

    public PostgreSqlMigrationRunJournal(PostgreSqlMigrationRunJournalOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.ConnectionString) || !SchemaName().IsMatch(options.Schema))
        {
            throw new ArgumentException("A connection string and safe journal schema are required.", nameof(options));
        }

        _connectionString = options.ConnectionString;
        _schema = PostgreSqlShadowTarget.QuoteIdentifier(options.Schema);
        _table = $"{_schema}.{PostgreSqlShadowTarget.QuoteIdentifier("migration_runs")}";
    }

    public async Task<MigrationRunStartResult> TryBeginAsync(
        MigrationRunIdentity identity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            System.Data.IsolationLevel.Serializable,
            cancellationToken).ConfigureAwait(false);
        await EnsureSchemaAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        await using (var insert = new NpgsqlCommand($"""
            INSERT INTO {_table} (
                run_id, source_commit_sha, schema_plan_sha256, backup_manifest_sha256,
                runner_digest_sha256, target_generation, status, receipt_json, updated_at_utc)
            VALUES ($1, $2, $3, $4, $5, $6, 'in_progress', NULL, now())
            ON CONFLICT (run_id) DO NOTHING;
            """, connection, transaction))
        {
            AddIdentityParameters(insert, identity);
            int inserted = await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            if (inserted == 1)
            {
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return new MigrationRunStartResult(MigrationRunStartStatus.Acquired, null);
            }
        }

        JournalRow observed = await ReadForUpdateAsync(
            connection,
            transaction,
            identity.RunId,
            cancellationToken).ConfigureAwait(false);
        if (observed.Identity != identity)
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new MigrationRunStartResult(MigrationRunStartStatus.Conflict, observed.Receipt);
        }

        if (string.Equals(observed.Status, "completed", StringComparison.Ordinal))
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new MigrationRunStartResult(MigrationRunStartStatus.AlreadyCompleted, observed.Receipt);
        }

        if (string.Equals(observed.Status, "failed", StringComparison.Ordinal))
        {
            await using var retry = new NpgsqlCommand(
                $"UPDATE {_table} SET status = 'in_progress', receipt_json = NULL, updated_at_utc = now() WHERE run_id = $1 AND status = 'failed';",
                connection,
                transaction);
            _ = retry.Parameters.AddWithValue(identity.RunId);
            if (await retry.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            {
                throw new MigrationExecutionException("run_journal_invalid", "The failed journal lease could not be reacquired.");
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new MigrationRunStartResult(MigrationRunStartStatus.Acquired, null);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new MigrationRunStartResult(MigrationRunStartStatus.InProgress, null);
    }

    public async Task RecordCompletedAsync(
        MigrationExecutionReceipt receipt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        MigrationRunIdentity identity = MigrationRunIdentity.FromReceipt(receipt);
        await UpdateStatusAsync(
            identity,
            "completed",
            JsonSerializer.Serialize(receipt),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task RecordFailedAsync(
        MigrationFailureReceipt receipt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        var identity = new MigrationRunIdentity(
            receipt.RunId,
            receipt.SourceCommitSha,
            receipt.SchemaPlanSha256,
            receipt.BackupManifestSha256,
            receipt.RunnerDigestSha256,
            receipt.TargetGeneration);
        await UpdateStatusAsync(
            identity,
            "failed",
            JsonSerializer.Serialize(receipt),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task UpdateStatusAsync(
        MigrationRunIdentity identity,
        string status,
        string receiptJson,
        CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await EnsureSchemaAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand($"""
            UPDATE {_table}
            SET status = $7,
                receipt_json = $8::jsonb,
                failure_receipts = CASE
                    WHEN $7 = 'failed' THEN failure_receipts || jsonb_build_array($8::jsonb)
                    ELSE failure_receipts
                END,
                updated_at_utc = now()
            WHERE run_id = $1
              AND source_commit_sha = $2
              AND schema_plan_sha256 = $3
              AND backup_manifest_sha256 = $4
              AND runner_digest_sha256 = $5
              AND target_generation = $6
              AND status = 'in_progress';
            """, connection, transaction);
        AddIdentityParameters(command, identity);
        _ = command.Parameters.AddWithValue(status);
        _ = command.Parameters.AddWithValue(receiptJson);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
        {
            throw new MigrationExecutionException(
                "run_journal_completion_conflict",
                "The journal refused completion for a missing or mismatched lease.");
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task EnsureSchemaAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        string sql = $"""
            CREATE SCHEMA IF NOT EXISTS {_schema};
            CREATE TABLE IF NOT EXISTS {_table} (
                run_id uuid PRIMARY KEY,
                source_commit_sha text NOT NULL,
                schema_plan_sha256 text NOT NULL,
                backup_manifest_sha256 text NOT NULL,
                runner_digest_sha256 text NOT NULL,
                target_generation text NOT NULL,
                status text NOT NULL CHECK (status IN ('in_progress', 'completed', 'failed')),
                receipt_json jsonb NULL,
                failure_receipts jsonb NOT NULL DEFAULT '[]'::jsonb,
                updated_at_utc timestamp with time zone NOT NULL
            );
            ALTER TABLE {_table}
                ADD COLUMN IF NOT EXISTS failure_receipts jsonb NOT NULL DEFAULT '[]'::jsonb;
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<JournalRow> ReadForUpdateAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        Guid runId,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand($"""
            SELECT source_commit_sha, schema_plan_sha256, backup_manifest_sha256,
                   runner_digest_sha256, target_generation, status, receipt_json::text
            FROM {_table}
            WHERE run_id = $1
            FOR UPDATE;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(runId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new MigrationExecutionException("run_journal_invalid", "The journal lease disappeared during acquisition.");
        }

        var identity = new MigrationRunIdentity(
            runId,
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4));
        string status = reader.GetString(5);
        MigrationExecutionReceipt? receipt = reader.IsDBNull(6) || !string.Equals(status, "completed", StringComparison.Ordinal)
            ? null
            : JsonSerializer.Deserialize<MigrationExecutionReceipt>(reader.GetString(6));
        return new JournalRow(identity, status, receipt);
    }

    private static void AddIdentityParameters(NpgsqlCommand command, MigrationRunIdentity identity)
    {
        _ = command.Parameters.AddWithValue(identity.RunId);
        _ = command.Parameters.AddWithValue(identity.SourceCommitSha);
        _ = command.Parameters.AddWithValue(identity.SchemaPlanSha256);
        _ = command.Parameters.AddWithValue(identity.BackupManifestSha256);
        _ = command.Parameters.AddWithValue(identity.RunnerDigestSha256);
        _ = command.Parameters.AddWithValue(identity.TargetGeneration);
    }

    [GeneratedRegex("^[a-z][a-z0-9_]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex SchemaName();

    private sealed record JournalRow(
        MigrationRunIdentity Identity,
        string Status,
        MigrationExecutionReceipt? Receipt);
}
