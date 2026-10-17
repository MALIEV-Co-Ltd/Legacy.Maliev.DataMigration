using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentCustomerSequenceRepairReceipt(string Kind, Guid OperationId, string Database,
    string OperationSha256, string BeforeSha256, string? AfterSha256, string AuthorizationSha256,
    string PreviousReceiptSha256, CurrentAppOwnedCommitClassification Classification, DateTimeOffset ObservedAtUtc,
    string KeyId, string? Signature);

// Disposable evidence hook only. No serialized callback or persistent execution authority.
internal interface ICurrentCustomerSequenceCandidateProofObserver
{
    Task RetainActualCandidateAsync(CurrentCustomerSequenceObservation before, CurrentCustomerSequenceObservation candidate, CancellationToken ct);
}

/// <summary>Fixed Customer sequence START definition component; no allocation reset, row deletion, role provisioning or Console authority.</summary>
internal static class PostgreSqlCurrentCustomerSequenceRepair
{
    internal static async Task<CurrentCustomerSequenceRepairReceipt> ExecuteAsync(string connectionString, CurrentCustomerSequenceObservation expectedBefore,
        CurrentCustomerSequenceRepairPermit permit, P256MigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust,
        CurrentCustomerSequenceRepairSigningPins pins, CancellationToken ct)
    {
        try { return await ExecuteCoreAsync(connectionString, expectedBefore, permit, signer, trust, pins, ct).ConfigureAwait(false); }
        finally { permit.Stop(); }
    }

    private static async Task<CurrentCustomerSequenceRepairReceipt> ExecuteCoreAsync(string connectionString, CurrentCustomerSequenceObservation expectedBefore,
        CurrentCustomerSequenceRepairPermit permit, P256MigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust,
        CurrentCustomerSequenceRepairSigningPins pins, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(15)); CancellationToken ct = deadline.Token;
        CurrentCustomerSequenceRepairScope scope = permit.Scope;
        expectedBefore = new(expectedBefore.State with { }, CurrentCustomerSequenceRepairPermit.CopySnapshot(expectedBefore.Snapshot));
        string owner = CurrentRepairOperandOwnerProfile.ExpectedOwnerName(CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, scope.Target);
        CurrentCustomerSequenceRepairPermit.RequireNativePreimage(expectedBefore, scope, DateTimeOffset.UtcNow);
        string beforeHash = expectedBefore.Snapshot.Sha256;
        if (expectedBefore.Snapshot.Database != "Customer" || beforeHash != scope.BeforeDatabaseSha256["Customer"] || pins != permit.SigningPins || signer.KeyId != pins.ReceiptKeyId ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.ReceiptKeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint)
        { permit.Stop(); throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        byte[] probe = [.. "Legacy.Maliev.CurrentCustomerSequence.ReceiptKeyProbe.v1\0"u8, .. scope.OperationId.ToByteArray()];
        if (!trust.Verify(signer.KeyId, probe, signer.Sign(probe))) { permit.Stop(); throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var settings = new NpgsqlConnectionStringBuilder(connectionString)
        { Database = "Customer", Pooling = false, IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 };
        if (settings.Host != "127.0.0.1" || settings.Port is < 1 or > 65535 || settings.Username != scope.Maintenance.Role ||
            string.IsNullOrWhiteSpace(settings.Password) || !string.IsNullOrEmpty(settings.Options))
        { permit.Stop(); throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        bool commitStarted = false, acknowledged = false, rollbackAcknowledged = false;
        string? afterHash = null; var chain = new CurrentCustomerSequenceRetainedReceiptChain(); NpgsqlTransaction? transaction = null;
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        try
        {
            await permit.StartAsync(ct).ConfigureAwait(false);
            await permit.RequireFleetAsync(scope.BeforeDatabaseSha256, ct).ConfigureAwait(false);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using (var preflight = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false))
            {
                await ReadOnlyAsync(connection, preflight, ct).ConfigureAwait(false);
                await RequireInstalledPolicyAsync(connection, preflight, scope, ct).ConfigureAwait(false);
                CurrentCustomerSequenceObservation current = await CurrentCustomerSequenceNativeObservation.CaptureAsync(connection, preflight, ct).ConfigureAwait(false);
                CurrentCustomerSequenceRepairPermit.RequireNativePreimage(current, scope, DateTimeOffset.UtcNow);
                _ = await CurrentCustomerSequenceNativeObservation.RequireOperandOwnerAsync(connection, preflight, scope, current, ct).ConfigureAwait(false);
                if (current.Snapshot.Sha256 != beforeHash) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                await preflight.RollbackAsync(ct).ConfigureAwait(false);
            }
            transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
            await CurrentAppOwnedRepairPreservation.LockAsync(connection, transaction, expectedBefore.Snapshot, ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            CurrentCustomerSequenceObservation locked = await CurrentCustomerSequenceNativeObservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
            CurrentCustomerSequenceRepairPermit.RequireNativePreimage(locked, scope, DateTimeOffset.UtcNow);
            string ownerClosure = await CurrentCustomerSequenceNativeObservation.RequireOperandOwnerAsync(connection, transaction, scope, locked, ct).ConfigureAwait(false);
            if (locked.Snapshot.Sha256 != beforeHash) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            // Exact reviewed definition only. Never restart/setval/nextval or allocate/reset values.
            await using (var ddl = new NpgsqlCommand(ApprovedCurrentCustomerSequenceDefinition.CandidateSql, connection, transaction))
            { _ = await ddl.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            CurrentCustomerSequenceObservation after = await CurrentCustomerSequenceNativeObservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
            ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(locked, after, owner);
            if (await CurrentCustomerSequenceNativeObservation.RequireOperandOwnerAsync(connection, transaction, scope, after, ct).ConfigureAwait(false) != ownerClosure) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            afterHash = after.Snapshot.Sha256;
            if (permit.Environment is ICurrentCustomerSequenceCandidateProofObserver observer)
            {
                if (scope.ProofAdmission is not (CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap or CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap) ||
                    !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) ||
                    DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                await observer.RetainActualCandidateAsync(locked, after, ct).ConfigureAwait(false);
            }
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            CurrentCustomerSequenceRepairReceipt prepared = Sign(CurrentAppOwnedCommitClassification.Prepared);
            await RetainAsync(prepared, "prepared", ct).ConfigureAwait(false);
            chain.RecordRetained(prepared, scope, permit.AuthorizationSha256, trust, pins, DateTimeOffset.UtcNow);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            if (permit.Environment is ICurrentCustomerSequenceClosedCommitObserver commitObserver)
            {
                if (scope.ProofAdmission != CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap || scope.ClosedConsoleSeed is null)
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                CurrentCustomerSequenceClosedBootstrap.RequireBinding(scope.ClosedConsoleSeed, scope);
                await commitObserver.ArmImmediatelyBeforeCommitAsync(ct).ConfigureAwait(false);
            }
            commitStarted = true; await transaction.CommitAsync(ct).ConfigureAwait(false); acknowledged = true;
            await transaction.DisposeAsync().ConfigureAwait(false); transaction = null;
            await connection.CloseAsync().ConfigureAwait(false);
            // A separate backend independently observes committed bytes and every retained native tuple/allocation state.
            await using (var readbackConnection = new NpgsqlConnection(settings.ConnectionString))
            {
                await readbackConnection.OpenAsync(ct).ConfigureAwait(false);
                await using var readback = await readbackConnection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                await ReadOnlyAsync(readbackConnection, readback, ct).ConfigureAwait(false);
                await RequireInstalledPolicyAsync(readbackConnection, readback, scope, ct).ConfigureAwait(false);
                CurrentCustomerSequenceObservation observed = await CurrentCustomerSequenceNativeObservation.CaptureAsync(readbackConnection, readback, ct).ConfigureAwait(false);
                ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(locked, observed, owner);
                if (await CurrentCustomerSequenceNativeObservation.RequireOperandOwnerAsync(readbackConnection, readback, scope, observed, ct).ConfigureAwait(false) != ownerClosure) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                if (observed.Snapshot.Sha256 != afterHash) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                await readback.RollbackAsync(ct).ConfigureAwait(false);
            }
            await permit.RequireAsync(ct).ConfigureAwait(false);
            var advanced = scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal); advanced["Customer"] = afterHash;
            await permit.RequireFleetAsync(advanced, ct).ConfigureAwait(false);
            CurrentCustomerSequenceRepairReceipt terminal = Sign(CurrentAppOwnedCommitClassification.CommittedAndReadback);
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
        CurrentCustomerSequenceRepairReceipt Sign(CurrentAppOwnedCommitClassification classification)
        {
            var unsigned = new CurrentCustomerSequenceRepairReceipt("current-customer-sequence-repair-receipt-v1", scope.OperationId, "Customer", scope.OperationSha256, beforeHash, afterHash, permit.AuthorizationSha256, chain.PreviousSha256, classification, DateTimeOffset.UtcNow, signer.KeyId, null);
            var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(ReceiptPayload(unsigned))) };
            RequireReceipt(signed, scope, permit.AuthorizationSha256, trust, pins, chain.PreviousSha256, DateTimeOffset.UtcNow); return signed;
        }
        Task RetainAsync(CurrentCustomerSequenceRepairReceipt receipt, string suffix, CancellationToken token)
        {
            return permit.Environment.RetainNewEvidenceAsync($"{scope.OperationId:D}-Customer-{suffix}.json", JsonSerializer.SerializeToUtf8Bytes(receipt), token);
        }
    }
    internal static byte[] ReceiptPayload(CurrentCustomerSequenceRepairReceipt receipt)
    {
        return [.. "Legacy.Maliev.CurrentCustomerSequence.Receipt.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(receipt with { Signature = null })];
    }

    internal static void RequireReceipt(CurrentCustomerSequenceRepairReceipt receipt, CurrentCustomerSequenceRepairScope scope, string authorizationSha256, IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins,
        string expectedPreviousSha256, DateTimeOffset nowUtc)
    {
        if (receipt.Kind != "current-customer-sequence-repair-receipt-v1" || receipt.OperationId != scope.OperationId || receipt.Database != "Customer" || receipt.OperationSha256 != scope.OperationSha256 ||
            receipt.BeforeSha256 != scope.BeforeDatabaseSha256["Customer"] || receipt.AuthorizationSha256 != authorizationSha256 || !CurrentCustomerSequenceRepairPermit.HashShape(authorizationSha256) ||
            !CurrentCustomerSequenceRepairPermit.HashShape(receipt.PreviousReceiptSha256) || receipt.PreviousReceiptSha256 != expectedPreviousSha256 || !CurrentCustomerSequenceRepairPermit.HashShape(expectedPreviousSha256) || (receipt.AfterSha256 is not null && !CurrentCustomerSequenceRepairPermit.HashShape(receipt.AfterSha256)) ||
            (receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback && receipt.AfterSha256 is null) ||
            !Enum.IsDefined(receipt.Classification) || receipt.ObservedAtUtc.Offset != TimeSpan.Zero || nowUtc.Offset != TimeSpan.Zero || receipt.ObservedAtUtc > nowUtc ||
            nowUtc - receipt.ObservedAtUtc > TimeSpan.FromMinutes(15) || receipt.ObservedAtUtc < scope.Maintenance.IssuedAtUtc ||
            (receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback && receipt.ObservedAtUtc >= scope.Maintenance.ExpiresAtUtc) || receipt.KeyId != pins.ReceiptKeyId || string.IsNullOrWhiteSpace(receipt.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(receipt.KeyId, out string actual) || actual != pins.ReceiptFingerprint) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        try { if (!trust.Verify(receipt.KeyId, ReceiptPayload(receipt), Convert.FromBase64String(receipt.Signature))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
        catch (FormatException) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    private static async Task ReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    { await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction); _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    internal static async Task RequireInstalledPolicyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CurrentCustomerSequenceRepairScope scope, CancellationToken cancellationToken)
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
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        await reader.DisposeAsync().ConfigureAwait(false);
        // Exact Customer operand ownership is bound at every native capture; other fleet owners stay untouched.
        await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, transaction, scope.Maintenance.Role,
            scope.Target.Kind, cancellationToken).ConfigureAwait(false);
    }
}

// Receipt metadata only, never execution authority. Advance only after the real custody publication acknowledges.
internal sealed class CurrentCustomerSequenceRetainedReceiptChain
{
    private int _phase;
    private string? _preparedAfterSha256;
    internal string PreviousSha256 { get; private set; } = new('0', 64);
    internal void RecordRetained(CurrentCustomerSequenceRepairReceipt receipt, CurrentCustomerSequenceRepairScope scope, string authorizationSha256,
        IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins, DateTimeOffset nowUtc)
    {
        PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(receipt, scope, authorizationSha256, trust, pins, PreviousSha256, nowUtc);
        CurrentAppOwnedCommitClassification expected = _phase == 0 ? CurrentAppOwnedCommitClassification.Prepared : CurrentAppOwnedCommitClassification.CommittedAndReadback;
        if (_phase >= 2 || receipt.Classification != expected || receipt.PreviousReceiptSha256 != PreviousSha256 ||
            (_phase == 1 && receipt.AfterSha256 != _preparedAfterSha256))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        if (_phase == 0) { _preparedAfterSha256 = receipt.AfterSha256; }
        PreviousSha256 = CurrentCustomerSequenceRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(receipt)); _phase++;
    }
}
