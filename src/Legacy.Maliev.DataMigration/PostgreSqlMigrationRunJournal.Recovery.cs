using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed partial class PostgreSqlMigrationRunJournal
{
    public async Task<MigrationRunLease> AcquireInitialAsync(InitialMigrationAdmission admission, RestoredSourceObservation source,
        LocalExecutionBinding localBinding, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(admission);
        RecoveryAuthorityVerifier verifier = RecoveryVerifier();
        MigrationRunIdentity identity = admission.Payload.Identity;
        Guid fence = Guid.NewGuid();
        await using NpgsqlConnection connection = await OpenValidatedConnectionAsync(cancellationToken).ConfigureAwait(false);
        await EnsureSchemaWithoutTransactionAsync(connection, cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        // An inserted row remains invisible until both current-clock gates and first lease succeed.
        await using (var insert = new NpgsqlCommand($"""
            INSERT INTO {_table} (run_id, source_commit_sha, schema_plan_sha256, backup_manifest_sha256,
                runner_digest_sha256, target_generation, status, lease_owner, lease_attempt, fencing_token,
                admission_signed_json, updated_at_utc)
            VALUES ($1, $2, $3, $4, $5, $6, 'in_progress', $7, 1, $8, $9, clock_timestamp())
            ON CONFLICT (run_id) DO NOTHING;
            """, connection, transaction))
        {
            AddIdentityParameters(insert, identity);
            _ = insert.Parameters.AddWithValue(_leaseOwner);
            _ = insert.Parameters.AddWithValue(fence);
            _ = insert.Parameters.AddWithValue(admission.ExactJson);
            if (await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            {
                throw new MigrationExecutionException("initial_admission_conflict", "Initial admission cannot adopt or replace any existing run.");
            }
        }
        _ = await ReadForUpdateAsync(connection, transaction, identity.RunId, cancellationToken).ConfigureAwait(false);
        DateTimeOffset now = await ReadServerTimeAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        verifier.ValidateInitialAcquisition(admission, source, localBinding, now);
        DateTimeOffset expires = now.Add(_leaseDuration);
        await SetRecoveryLeaseAsync(connection, transaction, identity.RunId, 1, fence, now, expires, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return TrackLease(identity, 1, expires, fence);
    }

    public async Task<RecoveryJournalSnapshot> ReadRecoverySnapshotAsync(MigrationRunIdentity identity, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        _ = RecoveryVerifier();
        await using NpgsqlConnection connection = await OpenValidatedConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY", connection, transaction))
        {
            _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        try
        {
            RecoveryJournalSnapshot snapshot = await ReadRecoveryStateAsync(connection, transaction, identity.RunId, cancellationToken).ConfigureAwait(false);
            if (snapshot.Baseline.Identity != identity) { throw new MigrationExecutionException("run_identity_conflict", "The requested immutable run identity differs from the journal."); }
            ValidateRecoverySnapshot(snapshot);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return snapshot;
        }
        catch (PostgresException exception) when (exception.SqlState is PostgresErrorCodes.UndefinedTable or PostgresErrorCodes.UndefinedColumn or PostgresErrorCodes.InvalidSchemaName)
        {
            throw NotAdmitted(exception);
        }
    }

    public async Task<MigrationRunLease> AcquireResumeAsync(SourceContinuityAttestation continuity, ResumeAuthorizationReceipt authorization,
        RestoredSourceObservation source, LocalExecutionBinding localBinding, FreshRunnerObservation runner,
        FreshTargetObservation target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        RecoveryAuthorityVerifier verifier = RecoveryVerifier();
        MigrationRunIdentity identity = authorization.Payload.Identity;
        await using NpgsqlConnection connection = await OpenValidatedConnectionAsync(cancellationToken).ConfigureAwait(false);
        await EnsureSchemaWithoutTransactionAsync(connection, cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        JournalRow row = await ReadForUpdateAsync(connection, transaction, identity.RunId, cancellationToken).ConfigureAwait(false);
        if (row.AdmissionJson is null) { throw NotAdmitted(); }
        RecoveryJournalSnapshot snapshot = await ReadRecoveryStateAsync(connection, transaction, identity.RunId, cancellationToken).ConfigureAwait(false);
        // This clock is read AFTER the row lock and all baseline reads; no preflight result grants mutation authority.
        DateTimeOffset now = await ReadServerTimeAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        if (row.Status == "in_progress" && row.LeaseExpiresAtUtc > now)
        {
            throw new MigrationExecutionException("run_lease_live", "A live lease cannot be displaced by a resume authorization.");
        }
        verifier.ValidateResume(snapshot.Admission, continuity, authorization, snapshot.Baseline, source, localBinding, runner, target, now);
        await using (var consume = new NpgsqlCommand($"""
            INSERT INTO {_resumeTable} (run_id, nonce, authorization_signed_json, continuity_signed_json, baseline_sha256, consumed_at_utc)
            VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (run_id, nonce) DO NOTHING;
            """, connection, transaction))
        {
            _ = consume.Parameters.AddWithValue(identity.RunId);
            _ = consume.Parameters.AddWithValue(authorization.Payload.Nonce);
            _ = consume.Parameters.AddWithValue(authorization.ExactJson);
            _ = consume.Parameters.AddWithValue(continuity.ExactJson);
            _ = consume.Parameters.AddWithValue(snapshot.Baseline.ComputeSha256());
            _ = consume.Parameters.AddWithValue(now);
            if (await consume.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            {
                throw new MigrationExecutionException("resume_nonce_reused", "The resume authorization nonce has already been consumed.");
            }
        }
        int attempt = checked(row.LeaseAttempt + 1);
        Guid fence = Guid.NewGuid();
        DateTimeOffset expires = now.Add(_leaseDuration);
        await SetRecoveryLeaseAsync(connection, transaction, identity.RunId, attempt, fence, now, expires, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return TrackLease(identity, attempt, expires, fence);
    }

    private async Task SetRecoveryLeaseAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid runId, int attempt,
        Guid fence, DateTimeOffset now, DateTimeOffset expires, CancellationToken token)
    {
        await using var command = new NpgsqlCommand($"""
            UPDATE {_table} SET status = 'in_progress', receipt_json = NULL, receipt_signed_json = NULL,
                lease_owner = $2, lease_attempt = $3, fencing_token = $4, heartbeat_at_utc = $5,
                lease_expires_at_utc = $6, updated_at_utc = $5 WHERE run_id = $1;
            """, connection, transaction);
        _ = command.Parameters.AddWithValue(runId);
        _ = command.Parameters.AddWithValue(_leaseOwner);
        _ = command.Parameters.AddWithValue(attempt);
        _ = command.Parameters.AddWithValue(fence);
        _ = command.Parameters.AddWithValue(now);
        _ = command.Parameters.AddWithValue(expires);
        if (await command.ExecuteNonQueryAsync(token).ConfigureAwait(false) != 1) { throw LeaseLost(); }
    }

    private async Task<RecoveryJournalSnapshot> ReadRecoveryStateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid runId, CancellationToken token)
    {
        RecoveryJournalBaseline baseline;
        InitialMigrationAdmission admission;
        DateTimeOffset? expiry;
        await using (var command = new NpgsqlCommand($"""
            SELECT source_commit_sha, schema_plan_sha256, backup_manifest_sha256, runner_digest_sha256, target_generation,
                status, lease_owner, lease_attempt, fencing_token, receipt_signed_json, failure_receipts::text,
                admission_signed_json, lease_expires_at_utc FROM {_table} WHERE run_id = $1;
            """, connection, transaction))
        {
            _ = command.Parameters.AddWithValue(runId);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            if (!await reader.ReadAsync(token).ConfigureAwait(false) || reader.IsDBNull(11)) { throw NotAdmitted(); }
            admission = InitialMigrationAdmission.Parse(reader.GetString(11));
            baseline = new(new(runId, reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4)),
                admission.ComputeSha256(), reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6), reader.GetInt32(7),
                reader.IsDBNull(8) ? null : reader.GetGuid(8), reader.IsDBNull(9) ? null : reader.GetString(9), reader.GetString(10), [], []);
            expiry = reader.IsDBNull(12) ? null : reader.GetFieldValue<DateTimeOffset>(12);
        }
        // Planning must detect an incomplete recovery schema without creating or repairing it.
        // Consumption history is checked independently by its run-scoped unique nonce constraint.
        await using (var schema = new NpgsqlCommand($"""
            SELECT nonce, authorization_signed_json, continuity_signed_json, baseline_sha256, consumed_at_utc
            FROM {_resumeTable} WHERE run_id = $1 AND FALSE;
            """, connection, transaction))
        {
            _ = schema.Parameters.AddWithValue(runId);
            _ = await schema.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }
        var shadows = ImmutableArray.CreateBuilder<RecoveryShadowState>();
        await using (var command = new NpgsqlCommand($"""
            SELECT shadow_name, owner_run_id, source_database, owner_attempt, fencing_token, cleanup_status, cleanup_attempts, last_error_code
            FROM {_shadowTable} WHERE run_id = $1 ORDER BY shadow_name;
            """, connection, transaction))
        {
            _ = command.Parameters.AddWithValue(runId);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                if (reader.IsDBNull(3) || reader.IsDBNull(4)) { throw new MigrationExecutionException("shadow_inventory_invalid", "Registered shadow ownership is incomplete."); }
                shadows.Add(new(new(reader.GetString(0), reader.GetString(1), reader.GetString(2))
                { OwnerAttempt = reader.GetInt32(3), FencingToken = reader.GetGuid(4) }, reader.GetString(5), reader.GetInt32(6), reader.IsDBNull(7) ? null : reader.GetString(7)));
            }
        }
        var checkpoints = ImmutableArray.CreateBuilder<RecoveryCheckpointState>();
        await using (var command = new NpgsqlCommand($"SELECT source_database, checkpoint_json FROM {_checkpointTable} WHERE run_id = $1 ORDER BY source_database", connection, transaction))
        {
            _ = command.Parameters.AddWithValue(runId);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            while (await reader.ReadAsync(token).ConfigureAwait(false)) { checkpoints.Add(new(reader.GetString(0), reader.GetString(1))); }
        }
        DateTimeOffset now = await ReadServerTimeAsync(connection, transaction, token).ConfigureAwait(false);
        return new(admission, baseline with { Shadows = shadows.ToImmutable(), Checkpoints = checkpoints.ToImmutable() }, now, expiry);
    }

    private void ValidateRecoverySnapshot(RecoveryJournalSnapshot snapshot)
    {
        if (snapshot.Baseline.Status == "completed")
        {
            ValidateAdmittedCompletion(snapshot, snapshot.Baseline.TerminalReceiptSignedJson);
        }
        else
        {
            _ = RecoveryVerifier().GetPermittedOperations(snapshot.Admission, snapshot.Baseline, snapshot.ObservedAtUtc);
        }
    }

    private async Task ValidateAdmittedStateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid runId, CancellationToken token)
    {
        JournalRow row = await ReadForUpdateAsync(connection, transaction, runId, token).ConfigureAwait(false);
        if (row.AdmissionJson is not null)
        {
            ValidateRecoverySnapshot(await ReadRecoveryStateAsync(connection, transaction, runId, token).ConfigureAwait(false));
        }
    }

    private void ValidateAdmittedCompletion(RecoveryJournalSnapshot snapshot, string? receiptJson)
    {
        // Reuse the authenticated checkpoint/ownership checks, without granting operations or a lease
        // for a completed run. The persisted status itself remains unchanged in the returned baseline.
        _ = RecoveryVerifier().GetPermittedOperations(snapshot.Admission, snapshot.Baseline with { Status = "in_progress" }, snapshot.ObservedAtUtc);
        try
        {
            MigrationExecutionReceipt? receipt = receiptJson is null ? null : JsonSerializer.Deserialize<MigrationExecutionReceipt>(receiptJson);
            CompletionRequire(receipt is not null && receipt.Databases is not null && receipt.Reconciliation is not null &&
                receipt.Databases.All(item => item is not null) && receipt.Reconciliation.All(item => item is not null), "Exact signed completion evidence is missing.");
            CompletionRequire(MigrationRunIdentity.FromReceipt(receipt!) == snapshot.Baseline.Identity &&
                receipt!.AttestationKeyId == _recoveryOptions!.Roles.ExecutionKeyId && receipt.AttestationSignature is not null &&
                _recoveryOptions.TrustStore.Verify(receipt.AttestationKeyId, MigrationEvidenceAttestation.CreatePayload(receipt), Convert.FromBase64String(receipt.AttestationSignature)),
                "Completion identity, execution signing role or signature is invalid.");
            string[] expected = DatabaseInventory.ActiveDatabases.ToArray();
            CompletionRequire(snapshot.Baseline.Checkpoints.Length == expected.Length && receipt!.Databases.Count == expected.Length && receipt.Reconciliation.Count == expected.Length &&
                receipt.Databases.Select(item => item.Database).Order(StringComparer.Ordinal).SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal) &&
                receipt.Reconciliation.Select(item => item.Database).Order(StringComparer.Ordinal).SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal),
                "Completion requires full exact persisted checkpoint and receipt coverage.");
            CompletionRequire(receipt!.CompletedAtUtc.Offset == TimeSpan.Zero && receipt.CompletedAtUtc >= snapshot.Admission.Payload.AdmittedAtUtc &&
                receipt.CompletedAtUtc <= snapshot.ObservedAtUtc, "Completion time is invalid.");
            foreach (RecoveryCheckpointState item in snapshot.Baseline.Checkpoints)
            {
                DatabaseMigrationCheckpoint checkpoint = JsonSerializer.Deserialize<DatabaseMigrationCheckpoint>(item.SignedCheckpointJson)!;
                MigratedShadowDatabase database = receipt!.Databases.Single(value => value.Database == item.Database);
                DatabaseReconciliationEvidence reconciliation = receipt.Reconciliation.Single(value => value.Database == item.Database);
                CompletionRequire(database == checkpoint.Database && receipt.CompletedAtUtc >= checkpoint.CommittedAtUtc &&
                    JsonElement.DeepEquals(JsonSerializer.SerializeToElement(reconciliation), JsonSerializer.SerializeToElement(checkpoint.Reconciliation)),
                    "Completion evidence differs from its persisted signed checkpoint.");
            }
        }
        catch (Exception exception) when (exception is JsonException or FormatException or InvalidOperationException)
        {
            throw new MigrationExecutionException("completed_receipt_invalid", "Completion evidence is malformed or mismatched.", exception);
        }
    }

    private static void CompletionRequire([DoesNotReturnIf(false)] bool valid, string message)
    {
        if (!valid) { throw new MigrationExecutionException("completed_receipt_invalid", message); }
    }

    private RecoveryAuthorityVerifier RecoveryVerifier()
    {
        return _recoveryVerifier ??
        throw new MigrationExecutionException("recovery_verifier_required", "Explicit recovery signing roles, runner policy and trust must be configured.");
    }

    private static MigrationExecutionException NotAdmitted(Exception? inner = null)
    {
        return new("run_not_admitted", "The journal has no immutable admission or required recovery schema; historical runs cannot be adopted.", inner);
    }
}
