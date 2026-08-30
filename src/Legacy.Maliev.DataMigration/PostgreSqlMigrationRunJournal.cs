using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.RegularExpressions;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed record PostgreSqlMigrationRunJournalOptions(
    string ConnectionString,
    string Schema = "legacy_migration_control",
    string? LeaseOwner = null,
    TimeSpan? LeaseDuration = null,
    TimeProvider? TimeProvider = null,
    string? ExpectedControlRole = null);

public sealed partial class PostgreSqlMigrationRunJournal : IMigrationRunJournal
{
    private static readonly TimeSpan DefaultLeaseDuration = TimeSpan.FromMinutes(5);
    private static readonly SemaphoreSlim SchemaGate = new(1, 1);
    private readonly string _connectionString;
    private readonly string _schema;
    private readonly string _table;
    private readonly string _shadowTable;
    private readonly string _leaseOwner;
    private readonly TimeSpan _leaseDuration;
    private readonly TimeProvider _timeProvider;
    private readonly string _expectedControlRole;
    private readonly ConcurrentDictionary<Guid, MigrationRunLease> _leases = new();

    public PostgreSqlMigrationRunJournal(PostgreSqlMigrationRunJournalOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.ConnectionString) || !SchemaName().IsMatch(options.Schema))
        {
            throw new ArgumentException("A connection string and safe journal schema are required.", nameof(options));
        }

        var connection = new NpgsqlConnectionStringBuilder(options.ConnectionString);
        if (!string.Equals(connection.Database, PostgreSqlMigrationRuntimeBoundaryValidator.ControlDatabase, StringComparison.Ordinal))
        {
            throw new ArgumentException("The journal connection must target the dedicated migration-control database.", nameof(options));
        }

        string owner = options.LeaseOwner ?? $"{Environment.MachineName}:{Environment.ProcessId}:{Guid.NewGuid():N}";
        TimeSpan duration = options.LeaseDuration ?? DefaultLeaseDuration;
        if (string.IsNullOrWhiteSpace(owner) || owner.Length > 200 || owner.Contains('\0', StringComparison.Ordinal) ||
            duration < TimeSpan.FromSeconds(10) || duration > TimeSpan.FromHours(1))
        {
            throw new ArgumentException("A safe lease owner and a lease duration between 10 seconds and one hour are required.", nameof(options));
        }

        _connectionString = options.ConnectionString;
        _schema = PostgreSqlShadowTarget.QuoteIdentifier(options.Schema);
        _table = $"{_schema}.{PostgreSqlShadowTarget.QuoteIdentifier("migration_runs")}";
        _shadowTable = $"{_schema}.{PostgreSqlShadowTarget.QuoteIdentifier("migration_run_shadows")}";
        _leaseOwner = owner;
        _leaseDuration = duration;
        _timeProvider = options.TimeProvider ?? TimeProvider.System;
        _expectedControlRole = options.ExpectedControlRole ?? connection.Username ??
            throw new ArgumentException("The expected migration-control role is required.", nameof(options));
    }

    public async Task<MigrationRunStartResult> TryBeginAsync(MigrationRunIdentity identity, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        DateTimeOffset now = _timeProvider.GetUtcNow();
        DateTimeOffset expires = now.Add(_leaseDuration);
        Guid fencingToken = Guid.NewGuid();
        await using NpgsqlConnection connection = await OpenValidatedConnectionAsync(cancellationToken).ConfigureAwait(false);
        await EnsureSchemaWithoutTransactionAsync(connection, cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            System.Data.IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await using (var insert = new NpgsqlCommand($"""
            INSERT INTO {_table} (
                run_id, source_commit_sha, schema_plan_sha256, backup_manifest_sha256,
                runner_digest_sha256, target_generation, status, receipt_json,
                lease_owner, lease_attempt, fencing_token, heartbeat_at_utc, lease_expires_at_utc, updated_at_utc)
            VALUES ($1, $2, $3, $4, $5, $6, 'in_progress', NULL, $7, 1, $8, $9, $10, $9)
            ON CONFLICT (run_id) DO NOTHING;
            """, connection, transaction))
        {
            AddIdentityParameters(insert, identity);
            _ = insert.Parameters.AddWithValue(_leaseOwner);
            _ = insert.Parameters.AddWithValue(fencingToken);
            _ = insert.Parameters.AddWithValue(now);
            _ = insert.Parameters.AddWithValue(expires);
            if (await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 1)
            {
                MigrationRunLease lease = TrackLease(identity, 1, expires, fencingToken);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                return new(MigrationRunStartStatus.Acquired, null, lease, []);
            }
        }

        JournalRow observed = await ReadForUpdateAsync(connection, transaction, identity.RunId, cancellationToken).ConfigureAwait(false);
        if (observed.Identity != identity)
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new(MigrationRunStartStatus.Conflict, observed.Receipt);
        }

        if (string.Equals(observed.Status, "completed", StringComparison.Ordinal))
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new(MigrationRunStartStatus.AlreadyCompleted, observed.Receipt);
        }

        bool liveLease = string.Equals(observed.Status, "in_progress", StringComparison.Ordinal) &&
            observed.LeaseExpiresAtUtc is not null && observed.LeaseExpiresAtUtc > now;
        if (liveLease)
        {
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new(MigrationRunStartStatus.InProgress, null);
        }

        int nextAttempt = checked(observed.LeaseAttempt + 1);
        await using (var retry = new NpgsqlCommand($"""
            UPDATE {_table}
            SET status = 'in_progress', receipt_json = NULL, lease_owner = $2,
                lease_attempt = $3, heartbeat_at_utc = $4, lease_expires_at_utc = $5,
                fencing_token = $6, updated_at_utc = $4
            WHERE run_id = $1 AND status IN ('failed', 'in_progress');
            """, connection, transaction))
        {
            _ = retry.Parameters.AddWithValue(identity.RunId);
            _ = retry.Parameters.AddWithValue(_leaseOwner);
            _ = retry.Parameters.AddWithValue(nextAttempt);
            _ = retry.Parameters.AddWithValue(now);
            _ = retry.Parameters.AddWithValue(expires);
            _ = retry.Parameters.AddWithValue(fencingToken);
            if (await retry.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            {
                throw new MigrationExecutionException("run_journal_invalid", "The expired or failed journal lease could not be reacquired.");
            }
        }

        IReadOnlyList<ShadowDatabase> pending = await ReadPendingShadowsAsync(
            connection, transaction, identity.RunId, cancellationToken).ConfigureAwait(false);
        MigrationRunLease acquired = TrackLease(identity, nextAttempt, expires, fencingToken);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new(MigrationRunStartStatus.Acquired, null, acquired, pending);
    }

    public async Task<MigrationRunLease> HeartbeatAsync(MigrationRunLease lease, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lease);
        DateTimeOffset now = _timeProvider.GetUtcNow();
        DateTimeOffset expires = now.Add(_leaseDuration);
        await using NpgsqlConnection connection = await OpenValidatedConnectionAsync(cancellationToken).ConfigureAwait(false);
        await EnsureSchemaWithoutTransactionAsync(connection, cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand($"""
            UPDATE {_table}
            SET heartbeat_at_utc = $4, lease_expires_at_utc = $5, updated_at_utc = $4
            WHERE run_id = $1 AND lease_owner = $2 AND lease_attempt = $3 AND fencing_token = $6
              AND status = 'in_progress' AND lease_expires_at_utc > $4;
            """, connection);
        _ = command.Parameters.AddWithValue(lease.Identity.RunId);
        _ = command.Parameters.AddWithValue(lease.Owner);
        _ = command.Parameters.AddWithValue(lease.Attempt);
        _ = command.Parameters.AddWithValue(now);
        _ = command.Parameters.AddWithValue(expires);
        _ = command.Parameters.AddWithValue(lease.FencingToken);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
        {
            throw LeaseLost();
        }

        MigrationRunLease renewed = lease with { ExpiresAtUtc = expires };
        _leases[lease.Identity.RunId] = renewed;
        return renewed;
    }

    public async Task RegisterShadowAsync(MigrationRunLease lease, ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(shadow);
        if (!string.Equals(shadow.OwnerRunId, lease.Identity.RunId.ToString("D"), StringComparison.Ordinal) ||
            shadow.OwnerAttempt != lease.Attempt || shadow.FencingToken != lease.FencingToken)
        {
            throw new MigrationExecutionException("shadow_ownership_invalid", "The shadow inventory does not belong to this migration run.");
        }

        await using NpgsqlConnection connection = await OpenValidatedConnectionAsync(cancellationToken).ConfigureAwait(false);
        await EnsureSchemaWithoutTransactionAsync(connection, cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await AssertLiveOwnedLeaseAsync(connection, transaction, lease, cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand($"""
            INSERT INTO {_shadowTable} (
                run_id, shadow_name, owner_run_id, source_database, cleanup_status,
                owner_attempt, fencing_token, cleanup_attempts, last_error_code, updated_at_utc)
            VALUES ($1, $2, $3, $4, 'pending', $5, $6, 0, NULL, $7)
            ON CONFLICT (run_id, shadow_name) DO UPDATE
            SET owner_run_id = EXCLUDED.owner_run_id,
                source_database = EXCLUDED.source_database,
                owner_attempt = EXCLUDED.owner_attempt,
                fencing_token = EXCLUDED.fencing_token,
                cleanup_status = 'pending',
                last_error_code = NULL,
                updated_at_utc = EXCLUDED.updated_at_utc
            WHERE {_shadowTable}.cleanup_status = 'deleted' OR
                  ({_shadowTable}.owner_attempt = EXCLUDED.owner_attempt AND {_shadowTable}.fencing_token = EXCLUDED.fencing_token);
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(lease.Identity.RunId);
        _ = command.Parameters.AddWithValue(shadow.Name);
        _ = command.Parameters.AddWithValue(shadow.OwnerRunId);
        _ = command.Parameters.AddWithValue(shadow.Database);
        _ = command.Parameters.AddWithValue(shadow.OwnerAttempt);
        _ = command.Parameters.AddWithValue(shadow.FencingToken);
        _ = command.Parameters.AddWithValue(_timeProvider.GetUtcNow());
        _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ShadowDatabase>> GetPendingShadowsAsync(MigrationRunLease lease, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lease);
        await using NpgsqlConnection connection = await OpenValidatedConnectionAsync(cancellationToken).ConfigureAwait(false);
        await EnsureSchemaWithoutTransactionAsync(connection, cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await AssertLiveOwnedLeaseAsync(connection, transaction, lease, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ShadowDatabase> pending = await ReadPendingShadowsAsync(
            connection, transaction, lease.Identity.RunId, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return pending;
    }

    public async Task RecordShadowCleanupAsync(MigrationRunLease lease, ShadowCleanupOutcome outcome, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(outcome);
        await using NpgsqlConnection connection = await OpenValidatedConnectionAsync(cancellationToken).ConfigureAwait(false);
        await EnsureSchemaWithoutTransactionAsync(connection, cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await AssertLiveOwnedLeaseAsync(connection, transaction, lease, cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand($"""
            UPDATE {_shadowTable}
            SET cleanup_status = $3, cleanup_attempts = cleanup_attempts + 1,
                last_error_code = $4, updated_at_utc = $5
            WHERE run_id = $1 AND shadow_name = $2 AND owner_attempt = $6 AND fencing_token = $7
              AND cleanup_status <> 'deleted';
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(lease.Identity.RunId);
        _ = command.Parameters.AddWithValue(outcome.ShadowName);
        _ = command.Parameters.AddWithValue(outcome.Deleted ? "deleted" : "failed");
        _ = command.Parameters.AddWithValue((object?)outcome.ErrorCode ?? DBNull.Value);
        _ = command.Parameters.AddWithValue(_timeProvider.GetUtcNow());
        _ = command.Parameters.AddWithValue(outcome.OwnerAttempt);
        _ = command.Parameters.AddWithValue(outcome.FencingToken);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
        {
            throw new MigrationExecutionException("shadow_inventory_invalid", "The journal refused an unknown or already-deleted shadow cleanup result.");
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task RecordCompletedAsync(MigrationExecutionReceipt receipt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        return RecordCompletedAsync(CurrentLease(receipt.RunId), receipt, cancellationToken);
    }

    public Task RecordCompletedAsync(MigrationRunLease lease, MigrationExecutionReceipt receipt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        return UpdateStatusAsync(lease, MigrationRunIdentity.FromReceipt(receipt), "completed", JsonSerializer.Serialize(receipt), cancellationToken);
    }

    public Task RecordFailedAsync(MigrationFailureReceipt receipt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        return RecordFailedAsync(CurrentLease(receipt.RunId), receipt, cancellationToken);
    }

    public Task RecordFailedAsync(MigrationRunLease lease, MigrationFailureReceipt receipt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        var identity = new MigrationRunIdentity(receipt.RunId, receipt.SourceCommitSha, receipt.SchemaPlanSha256,
            receipt.BackupManifestSha256, receipt.RunnerDigestSha256, receipt.TargetGeneration);
        return UpdateStatusAsync(lease, identity, "failed", JsonSerializer.Serialize(receipt), cancellationToken);
    }

    private async Task UpdateStatusAsync(MigrationRunLease lease, MigrationRunIdentity identity, string status, string receiptJson, CancellationToken cancellationToken)
    {
        if (lease.Identity != identity)
        {
            throw LeaseLost();
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        await using NpgsqlConnection connection = await OpenValidatedConnectionAsync(cancellationToken).ConfigureAwait(false);
        await EnsureSchemaWithoutTransactionAsync(connection, cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand($"""
            UPDATE {_table}
            SET status = $9, receipt_json = $10::jsonb,
                failure_receipts = CASE WHEN $9 = 'failed'
                    THEN failure_receipts || jsonb_build_array($10::jsonb) ELSE failure_receipts END,
                lease_expires_at_utc = $11, updated_at_utc = $11
            WHERE run_id = $1 AND source_commit_sha = $2 AND schema_plan_sha256 = $3
              AND backup_manifest_sha256 = $4 AND runner_digest_sha256 = $5
              AND target_generation = $6 AND lease_owner = $7 AND lease_attempt = $8
              AND fencing_token = $12 AND status = 'in_progress' AND lease_expires_at_utc > $11;
            """, connection, transaction);
        AddIdentityParameters(command, identity);
        _ = command.Parameters.AddWithValue(lease.Owner);
        _ = command.Parameters.AddWithValue(lease.Attempt);
        _ = command.Parameters.AddWithValue(status);
        _ = command.Parameters.AddWithValue(receiptJson);
        _ = command.Parameters.AddWithValue(now);
        _ = command.Parameters.AddWithValue(lease.FencingToken);
        if (await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
        {
            throw new MigrationExecutionException("run_journal_completion_conflict", "The journal refused completion for a missing, expired, or mismatched lease.");
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        _ = _leases.TryRemove(identity.RunId, out _);
    }

    private async Task EnsureSchemaWithoutTransactionAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await SchemaGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var command = new NpgsqlCommand(BuildSchemaSql(), connection);
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = SchemaGate.Release();
        }
    }

    private async Task<NpgsqlConnection> OpenValidatedConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = new NpgsqlConnection(_connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await PostgreSqlMigrationRuntimeBoundaryValidator.ValidateOperationalControlConnectionAsync(
                connection, _expectedControlRole, cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private string BuildSchemaSql()
    {
        return $"""
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
            lease_owner text NULL,
            lease_attempt integer NOT NULL DEFAULT 0,
            fencing_token uuid NULL,
            heartbeat_at_utc timestamp with time zone NULL,
            lease_expires_at_utc timestamp with time zone NULL,
            updated_at_utc timestamp with time zone NOT NULL
        );
        ALTER TABLE {_table} ADD COLUMN IF NOT EXISTS failure_receipts jsonb NOT NULL DEFAULT '[]'::jsonb;
        ALTER TABLE {_table} ADD COLUMN IF NOT EXISTS lease_owner text NULL;
        ALTER TABLE {_table} ADD COLUMN IF NOT EXISTS lease_attempt integer NOT NULL DEFAULT 0;
        ALTER TABLE {_table} ADD COLUMN IF NOT EXISTS fencing_token uuid NULL;
        ALTER TABLE {_table} ADD COLUMN IF NOT EXISTS heartbeat_at_utc timestamp with time zone NULL;
        ALTER TABLE {_table} ADD COLUMN IF NOT EXISTS lease_expires_at_utc timestamp with time zone NULL;
        CREATE TABLE IF NOT EXISTS {_shadowTable} (
            run_id uuid NOT NULL REFERENCES {_table}(run_id) ON DELETE CASCADE,
            shadow_name text NOT NULL,
            owner_run_id text NOT NULL,
            source_database text NOT NULL,
            cleanup_status text NOT NULL CHECK (cleanup_status IN ('pending', 'failed', 'deleted')),
            owner_attempt integer NOT NULL,
            fencing_token uuid NOT NULL,
            cleanup_attempts integer NOT NULL DEFAULT 0,
            last_error_code text NULL,
            updated_at_utc timestamp with time zone NOT NULL,
            PRIMARY KEY (run_id, shadow_name)
        );
        ALTER TABLE {_shadowTable} ADD COLUMN IF NOT EXISTS owner_attempt integer NULL;
        ALTER TABLE {_shadowTable} ADD COLUMN IF NOT EXISTS fencing_token uuid NULL;
        """;
    }

    private async Task<JournalRow> ReadForUpdateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid runId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand($"""
            SELECT source_commit_sha, schema_plan_sha256, backup_manifest_sha256,
                   runner_digest_sha256, target_generation, status, receipt_json::text,
                   lease_attempt, lease_expires_at_utc
            FROM {_table} WHERE run_id = $1 FOR UPDATE;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(runId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new MigrationExecutionException("run_journal_invalid", "The journal lease disappeared during acquisition.");
        }

        var identity = new MigrationRunIdentity(runId, reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4));
        string status = reader.GetString(5);
        MigrationExecutionReceipt? receipt = reader.IsDBNull(6) || !string.Equals(status, "completed", StringComparison.Ordinal)
            ? null
            : JsonSerializer.Deserialize<MigrationExecutionReceipt>(reader.GetString(6));
        return new(identity, status, receipt, reader.GetInt32(7), reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8));
    }

    private async Task AssertLiveOwnedLeaseAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, MigrationRunLease lease, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand($"""
            SELECT 1 FROM {_table}
            WHERE run_id = $1 AND lease_owner = $2 AND lease_attempt = $3 AND fencing_token = $5
              AND status = 'in_progress' AND lease_expires_at_utc > $4 FOR UPDATE;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(lease.Identity.RunId);
        _ = command.Parameters.AddWithValue(lease.Owner);
        _ = command.Parameters.AddWithValue(lease.Attempt);
        _ = command.Parameters.AddWithValue(_timeProvider.GetUtcNow());
        _ = command.Parameters.AddWithValue(lease.FencingToken);
        if (await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is null)
        {
            throw LeaseLost();
        }
    }

    private async Task<IReadOnlyList<ShadowDatabase>> ReadPendingShadowsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid runId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand($"""
            SELECT shadow_name, owner_run_id, source_database, owner_attempt, fencing_token FROM {_shadowTable}
            WHERE run_id = $1 AND cleanup_status <> 'deleted' ORDER BY shadow_name;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(runId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        List<ShadowDatabase> shadows = [];
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (reader.IsDBNull(3) || reader.IsDBNull(4))
            {
                throw new MigrationExecutionException("shadow_inventory_invalid", "A legacy shadow inventory row is missing its fencing identity.");
            }

            shadows.Add(new(reader.GetString(0), reader.GetString(1), reader.GetString(2))
            {
                OwnerAttempt = reader.GetInt32(3),
                FencingToken = reader.GetGuid(4),
            });
        }

        return shadows;
    }

    private MigrationRunLease TrackLease(MigrationRunIdentity identity, int attempt, DateTimeOffset expires, Guid fencingToken)
    {
        var lease = new MigrationRunLease(identity, _leaseOwner, attempt, expires) { FencingToken = fencingToken };
        _leases[identity.RunId] = lease;
        return lease;
    }

    private MigrationRunLease CurrentLease(Guid runId)
    {
        return _leases.TryGetValue(runId, out MigrationRunLease? lease) ? lease : throw LeaseLost();
    }

    private static MigrationExecutionException LeaseLost()
    {
        return new("run_lease_lost", "The migration lease is expired, missing, or owned by another runner attempt.");
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
        MigrationExecutionReceipt? Receipt,
        int LeaseAttempt,
        DateTimeOffset? LeaseExpiresAtUtc);
}
