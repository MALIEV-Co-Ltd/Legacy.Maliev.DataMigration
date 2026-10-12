using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthRepairReceipt(string Kind, Guid OperationId, string Database,
    string OperationSha256, string BeforeSha256, string? AfterSha256, string AuthorizationSha256,
    string PreviousReceiptSha256, CurrentAppOwnedCommitClassification Classification, DateTimeOffset ObservedAtUtc,
    string KeyId, string? Signature);

/// <summary>Fixed Auth collation component; no history copying, session deletion, role provisioning or Console authority.</summary>
internal static class PostgreSqlCurrentAuthRepair
{
    internal static async Task<CurrentAuthRepairReceipt> ExecuteAsync(string connectionString, CurrentAuthNativeObservation expectedBefore,
        CurrentAuthRepairPermit permit, P256MigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust,
        CurrentAuthRepairSigningPins pins, CancellationToken ct)
    {
        try { return await ExecuteCoreAsync(connectionString, expectedBefore, permit, signer, trust, pins, ct).ConfigureAwait(false); }
        finally { permit.Stop(); }
    }

    private static async Task<CurrentAuthRepairReceipt> ExecuteCoreAsync(string connectionString, CurrentAuthNativeObservation expectedBefore,
        CurrentAuthRepairPermit permit, P256MigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust,
        CurrentAuthRepairSigningPins pins, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(15)); CancellationToken ct = deadline.Token;
        CurrentAuthRepairScope scope = permit.Scope;
        expectedBefore = new(CurrentAuthRepairPermit.CopySnapshot(expectedBefore.Snapshot), expectedBefore.CopyTuples(), expectedBefore.CopyStorage(), expectedBefore.CopyExpressions());
        CurrentAuthNativePreservation.RequireBefore(expectedBefore);
        string beforeHash = expectedBefore.Snapshot.Sha256;
        if (expectedBefore.Snapshot.Database != "Auth" || beforeHash != scope.BeforeDatabaseSha256["Auth"] || pins != permit.SigningPins || signer.KeyId != pins.ReceiptKeyId ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.ReceiptKeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint)
        { permit.Stop(); throw CurrentAuthRepairPermit.Invalid(); }
        byte[] probe = [.. "Legacy.Maliev.CurrentAuth.ReceiptKeyProbe.v1\0"u8, .. scope.OperationId.ToByteArray()];
        if (!trust.Verify(signer.KeyId, probe, signer.Sign(probe))) { permit.Stop(); throw CurrentAuthRepairPermit.Invalid(); }
        var settings = new NpgsqlConnectionStringBuilder(connectionString)
        { Database = "Auth", Pooling = false, IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 };
        if (settings.Host != "127.0.0.1" || settings.Port is < 1 or > 65535 || settings.Username != scope.Maintenance.Role ||
            string.IsNullOrWhiteSpace(settings.Password) || !string.IsNullOrEmpty(settings.Options))
        { permit.Stop(); throw CurrentAuthRepairPermit.Invalid(); }
        bool commitStarted = false, acknowledged = false, rollbackAcknowledged = false;
        string? afterHash = null; var chain = new CurrentAuthRetainedReceiptChain(); NpgsqlTransaction? transaction = null;
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        // Atomically claim the single execution before entering its failure publisher.
        // A stopped, reserved or concurrently reused permit owns no new receipt chain.
        await permit.StartAsync(ct).ConfigureAwait(false);
        try
        {
            await permit.RequireFleetAsync(scope.BeforeDatabaseSha256, ct).ConfigureAwait(false);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using (var preflight = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false))
            {
                await ReadOnlyAsync(connection, preflight, ct).ConfigureAwait(false);
                await RequireInstalledPolicyAsync(connection, preflight, scope, ct).ConfigureAwait(false);
                CurrentAuthNativeObservation current = await CurrentAuthNativePreservation.CaptureAsync(connection, preflight, ct).ConfigureAwait(false);
                CurrentAuthNativePreservation.RequireBefore(current);
                if (current.Snapshot.Sha256 != beforeHash) { throw CurrentAuthRepairPermit.Invalid(); }
                await preflight.RollbackAsync(ct).ConfigureAwait(false);
            }
            transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
            await CurrentAppOwnedRepairPreservation.LockAsync(connection, transaction, expectedBefore.Snapshot, ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            CurrentAuthNativeObservation locked = await CurrentAuthNativePreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
            CurrentAuthNativePreservation.RequireBefore(locked);
            if (locked.Snapshot.Sha256 != beforeHash) { throw CurrentAuthRepairPermit.Invalid(); }
            // Only the immutable owner's sixteen exact same-type operands. No user SQL is accepted.
            CurrentAuthCollationOperand[] operands = ApprovedCurrentAuthSchema.CollationOperands();
            if (operands.Length != 16) { throw CurrentAuthRepairPermit.Invalid(); }
            foreach (CurrentAuthCollationOperand operand in operands)
            {
                string sql = $"ALTER TABLE \"public\".{Quote(operand.Table)} ALTER COLUMN {Quote(operand.Column)} TYPE {operand.PostgreSqlType} COLLATE \"C\";";
                await using var ddl = new NpgsqlCommand(sql, connection, transaction);
                _ = await ddl.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }
            CurrentAuthNativeObservation after = await CurrentAuthNativePreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
            CurrentAuthNativePreservation.RequirePreserved(locked, after); afterHash = after.Snapshot.Sha256;
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            CurrentAuthRepairReceipt prepared = Sign(CurrentAppOwnedCommitClassification.Prepared);
            await RetainAsync(prepared, "prepared", ct).ConfigureAwait(false);
            chain.RecordRetained(prepared, scope, permit.AuthorizationSha256, trust, pins, DateTimeOffset.UtcNow);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            commitStarted = true; await transaction.CommitAsync(ct).ConfigureAwait(false); acknowledged = true;
            await transaction.DisposeAsync().ConfigureAwait(false); transaction = null;
            await connection.CloseAsync().ConfigureAwait(false);
            // A separate backend independently observes committed bytes and every retained native tuple.
            await using (var readbackConnection = new NpgsqlConnection(settings.ConnectionString))
            {
                await readbackConnection.OpenAsync(ct).ConfigureAwait(false);
                await using var readback = await readbackConnection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                await ReadOnlyAsync(readbackConnection, readback, ct).ConfigureAwait(false);
                await RequireInstalledPolicyAsync(readbackConnection, readback, scope, ct).ConfigureAwait(false);
                CurrentAuthNativeObservation observed = await CurrentAuthNativePreservation.CaptureAsync(readbackConnection, readback, ct).ConfigureAwait(false);
                CurrentAuthNativePreservation.RequirePreserved(locked, observed);
                if (observed.Snapshot.Sha256 != afterHash) { throw CurrentAuthRepairPermit.Invalid(); }
                await readback.RollbackAsync(ct).ConfigureAwait(false);
            }
            await permit.RequireAsync(ct).ConfigureAwait(false);
            var advanced = scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal); advanced["Auth"] = afterHash;
            await permit.RequireFleetAsync(advanced, ct).ConfigureAwait(false);
            CurrentAuthRepairReceipt terminal = Sign(CurrentAppOwnedCommitClassification.CommittedAndReadback);
            await RetainAsync(terminal, "committed-readback", ct).ConfigureAwait(false);
            // Advance only after durable terminal publication returns; a later fleet failure links this exact terminal.
            chain.RecordRetained(terminal, scope, permit.AuthorizationSha256, trust, pins, DateTimeOffset.UtcNow);
            await permit.RequireAsync(ct).ConfigureAwait(false); await permit.RequireFleetAsync(advanced, ct).ConfigureAwait(false);
            return terminal;
        }
        catch (Exception original)
        {
            permit.Stop(); using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            if (!commitStarted && transaction is not null)
            {
                try { await transaction.RollbackAsync(cleanup.Token).ConfigureAwait(false); rollbackAcknowledged = true; }
                catch (Exception failure) when (failure is NpgsqlException or InvalidOperationException or OperationCanceledException) { }
            }
            CurrentAppOwnedCommitClassification classification = commitStarted || acknowledged ? CurrentAppOwnedCommitClassification.Uncertain :
                rollbackAcknowledged ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.FailedBeforeCommit;
            try { await RetainAsync(Sign(classification), "failed-or-uncertain", cleanup.Token).ConfigureAwait(false); }
            catch (Exception evidenceFailure) { throw new AggregateException(original, evidenceFailure); }
            throw;
        }
        finally { permit.Stop(); if (transaction is not null) { await transaction.DisposeAsync().ConfigureAwait(false); } }
        CurrentAuthRepairReceipt Sign(CurrentAppOwnedCommitClassification classification)
        {
            var unsigned = new CurrentAuthRepairReceipt("current-auth-repair-receipt-v1", scope.OperationId, "Auth", scope.OperationSha256, beforeHash, afterHash, permit.AuthorizationSha256, chain.PreviousSha256, classification, DateTimeOffset.UtcNow, signer.KeyId, null);
            var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(ReceiptPayload(unsigned))) };
            RequireReceipt(signed, scope, permit.AuthorizationSha256, trust, pins, chain.PreviousSha256, DateTimeOffset.UtcNow); return signed;
        }
        Task RetainAsync(CurrentAuthRepairReceipt receipt, string suffix, CancellationToken token)
        {
            return permit.Environment.RetainNewEvidenceAsync($"{scope.OperationId:D}-Auth-{suffix}.json", JsonSerializer.SerializeToUtf8Bytes(receipt), token);
        }
    }
    internal static byte[] ReceiptPayload(CurrentAuthRepairReceipt receipt)
    {
        return [.. "Legacy.Maliev.CurrentAuth.Receipt.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(receipt with { Signature = null })];
    }

    internal static void RequireReceipt(CurrentAuthRepairReceipt receipt, CurrentAuthRepairScope scope, string authorizationSha256, IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins,
        string expectedPreviousSha256, DateTimeOffset nowUtc)
    {
        if (receipt.Kind != "current-auth-repair-receipt-v1" || receipt.OperationId != scope.OperationId || receipt.Database != "Auth" || receipt.OperationSha256 != scope.OperationSha256 ||
            receipt.BeforeSha256 != scope.BeforeDatabaseSha256["Auth"] || receipt.AuthorizationSha256 != authorizationSha256 || !CurrentAuthRepairPermit.HashShape(authorizationSha256) ||
            !CurrentAuthRepairPermit.HashShape(receipt.PreviousReceiptSha256) || receipt.PreviousReceiptSha256 != expectedPreviousSha256 || !CurrentAuthRepairPermit.HashShape(expectedPreviousSha256) || (receipt.AfterSha256 is not null && !CurrentAuthRepairPermit.HashShape(receipt.AfterSha256)) ||
            (receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback && receipt.AfterSha256 is null) ||
            !Enum.IsDefined(receipt.Classification) || receipt.ObservedAtUtc.Offset != TimeSpan.Zero || nowUtc.Offset != TimeSpan.Zero || receipt.ObservedAtUtc > nowUtc ||
            nowUtc - receipt.ObservedAtUtc > TimeSpan.FromMinutes(15) || receipt.ObservedAtUtc < scope.Maintenance.IssuedAtUtc ||
            (receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback && receipt.ObservedAtUtc >= scope.Maintenance.ExpiresAtUtc) || receipt.KeyId != pins.ReceiptKeyId || string.IsNullOrWhiteSpace(receipt.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(receipt.KeyId, out string actual) || actual != pins.ReceiptFingerprint) { throw CurrentAuthRepairPermit.Invalid(); }
        try { if (!trust.Verify(receipt.KeyId, ReceiptPayload(receipt), Convert.FromBase64String(receipt.Signature))) { throw CurrentAuthRepairPermit.Invalid(); } }
        catch (FormatException) { throw CurrentAuthRepairPermit.Invalid(); }
    }
    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static async Task ReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    { await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction); _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    internal static async Task RequireInstalledPolicyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CurrentAuthRepairScope scope, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),
              pg_postmaster_start_time(),pg_conf_load_time(),current_user,
              encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex'),
              (SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text,'UTF8')),'hex') FROM pg_hba_file_rules h),
              (SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL),
              (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()),
              (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D'),
              rolvaliduntil,shobj_description(r.oid,'pg_authid'),rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
              (SELECT count(*) FROM pg_auth_members WHERE member=r.oid),
              (SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=r.oid),
              (SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),current_setting('hba_file'),NOT pg_is_in_recovery()
            FROM pg_control_system(),pg_roles r WHERE rolname=current_user;
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        CurrentAppOwnedMaintenancePin m = scope.Maintenance;
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
            reader.GetString(0) != scope.Target.SystemIdentifierSha256 ||
            reader.GetFieldValue<DateTimeOffset>(1) != m.Postmaster || reader.GetFieldValue<DateTimeOffset>(2) != m.ConfigLoaded ||
            reader.GetString(3) != m.Role || reader.GetString(4) != m.HbaSha256 || reader.GetString(5) != m.HbaRulesSha256 ||
            reader.GetInt64(6) != 0 || reader.GetInt64(7) != 0 || reader.GetInt64(8) != 0 || reader.GetInt64(9) != 0 ||
            reader.GetFieldValue<DateTimeOffset>(10) != m.ExpiresAtUtc || reader.GetString(11) != m.RoleComment ||
            !reader.GetBoolean(12) || !reader.GetBoolean(13) || reader.GetBoolean(14) || reader.GetBoolean(15) ||
            reader.GetBoolean(16) || reader.GetBoolean(17) || reader.GetInt64(18) != 0 || !reader.GetBoolean(19) || reader.GetInt64(20) != 0 ||
            reader.GetString(21) != m.HbaPath || !reader.GetBoolean(22) || DateTimeOffset.UtcNow >= m.ExpiresAtUtc)
        { throw CurrentAuthRepairPermit.Invalid(); }
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw CurrentAuthRepairPermit.Invalid(); }
        await reader.DisposeAsync().ConfigureAwait(false);
        string owner = scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire ? "legacy_local" : "postgres";
        await using (var ownership = new NpgsqlCommand("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid=c.relowner AND r.rolname=@owner);", connection, transaction))
        {
            _ = ownership.Parameters.AddWithValue("owner", owner);
            if (Convert.ToInt64(await ownership.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) != 0) { throw CurrentAuthRepairPermit.Invalid(); }
        }
        await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, transaction, scope.Maintenance.Role,
            scope.Target.Kind, cancellationToken).ConfigureAwait(false);
    }
}

// Receipt metadata only, never execution authority. Advance only after the real custody publication acknowledges.
internal sealed class CurrentAuthRetainedReceiptChain
{
    private int _phase;
    private string? _preparedAfterSha256;
    internal string PreviousSha256 { get; private set; } = new('0', 64);
    internal void RecordRetained(CurrentAuthRepairReceipt receipt, CurrentAuthRepairScope scope, string authorizationSha256,
        IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins, DateTimeOffset nowUtc)
    {
        PostgreSqlCurrentAuthRepair.RequireReceipt(receipt, scope, authorizationSha256, trust, pins, PreviousSha256, nowUtc);
        CurrentAppOwnedCommitClassification expected = _phase == 0 ? CurrentAppOwnedCommitClassification.Prepared : CurrentAppOwnedCommitClassification.CommittedAndReadback;
        if (_phase >= 2 || receipt.Classification != expected || receipt.PreviousReceiptSha256 != PreviousSha256 ||
            (_phase == 1 && receipt.AfterSha256 != _preparedAfterSha256))
        { throw CurrentAuthRepairPermit.Invalid(); }
        if (_phase == 0) { _preparedAfterSha256 = receipt.AfterSha256; }
        PreviousSha256 = CurrentAuthRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(receipt)); _phase++;
    }
}
