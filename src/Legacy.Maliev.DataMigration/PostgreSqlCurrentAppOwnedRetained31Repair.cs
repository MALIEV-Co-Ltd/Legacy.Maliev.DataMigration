using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAppOwnedRetained31Receipt(string Kind, Guid OperationId, string Database,
    string ContractSha256, string OperationSha256, string BeforeSha256, string? AfterSha256,
    string AuthorizationSha256, string PreviousReceiptSha256, CurrentAppOwnedCommitClassification Classification,
    DateTimeOffset ObservedAtUtc, string KeyId, string? Signature);

/// <summary>Native fixed retained31 executor. Requires a separately reserved, fresh typed permit.</summary>
internal static class PostgreSqlCurrentAppOwnedRetained31Repair
{
    internal static async Task<CurrentAppOwnedRetained31Receipt> ExecuteDatabaseAsync(string connectionString, string database,
        FreshSchemaPlan beforeSchema, FreshSchemaPlan afterSchema, CurrentAppOwnedDatabaseSnapshot expectedBefore,
        CurrentAppOwnedRetained31Permit permit, P256MigrationEvidenceSigner receiptSigner,
        IReceiptAttestationTrustStore trust, CurrentAppOwnedRetained31SigningPins pins, string previousReceiptSha256, CancellationToken ct)
    {
        CurrentAppOwnedRetained31Scope scope = permit.Scope;
        beforeSchema = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(beforeSchema))!;
        afterSchema = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(afterSchema))!;
        // Immutable facts can be shared; copy array membership before validating its exact hash.
        expectedBefore = expectedBefore with { Catalog = expectedBefore.Catalog.ToArray(), Relations = expectedBefore.Relations.ToArray(), Sequences = expectedBefore.Sequences.ToArray() };
        CurrentAppOwnedRetained31Contract contract = CurrentAppOwnedRetained31Contract.Create(beforeSchema, afterSchema, scope.SourceCommitSha, DateTimeOffset.UtcNow);
        if (scope.Operation != CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations || scope.ContractSha256 != contract.ComputeSha256() ||
            expectedBefore.Database != database || !CurrentAppOwnedRepairManifest.Databases(scope.Operation).Contains(database, StringComparer.Ordinal) ||
            !scope.BeforeDatabaseSha256.TryGetValue(database, out string? beforeHash) || beforeHash != CurrentAppOwnedSnapshotSerialization.Sha256(expectedBefore) ||
            receiptSigner.KeyId != pins.ReceiptKeyId || !CurrentAppOwnedRepairPermit.HashShape(previousReceiptSha256) ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.ReceiptKeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint)
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        byte[] keyProbe = [.. "Legacy.Maliev.CurrentAppOwnedRetained31.ReceiptKeyProbe.v1\0"u8, .. scope.OperationId.ToByteArray()];
        if (!trust.Verify(receiptSigner.KeyId, keyProbe, receiptSigner.Sign(keyProbe))) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        var builder = new NpgsqlConnectionStringBuilder(connectionString)
        { Database = database, Pooling = false, IncludeErrorDetail = false, Timeout = 10, CommandTimeout = 30 };
        if (builder.Host != "127.0.0.1" || builder.Username != scope.Maintenance.Role || string.IsNullOrWhiteSpace(builder.Password) ||
            !string.IsNullOrEmpty(builder.Options)) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        await permit.ClaimDatabaseAsync(database, previousReceiptSha256, ct).ConfigureAwait(false);
        bool commitStarted = false, acknowledged = false, rollbackAcknowledged = false;
        string? afterHash = null;
        NpgsqlTransaction? transaction = null;
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        try
        {
            await RequireGlobalAsync(permit, ct).ConfigureAwait(false);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using (var preflight = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false))
            {
                await ReadOnlyAsync(connection, preflight, ct).ConfigureAwait(false);
                await RequireInstalledPolicyAsync(connection, preflight, scope, ct).ConfigureAwait(false);
                CurrentAppOwnedRetained31Observation before = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, preflight, ct).ConfigureAwait(false);
                if (CurrentAppOwnedSnapshotSerialization.Sha256(before.Snapshot) != beforeHash) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                CurrentAppOwnedRetained31Preservation.RequireBefore(before, beforeSchema, afterSchema, DateTimeOffset.UtcNow);
                await preflight.RollbackAsync(ct).ConfigureAwait(false);
            }
            transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
            await CurrentAppOwnedRepairPreservation.LockAsync(connection, transaction, expectedBefore, ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
            CurrentAppOwnedRetained31Observation lockedBefore = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
            if (CurrentAppOwnedSnapshotSerialization.Sha256(lockedBefore.Snapshot) != beforeHash) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            CurrentAppOwnedRetained31Preservation.RequireBefore(lockedBefore, beforeSchema, afterSchema, DateTimeOffset.UtcNow);
            await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
            DatabaseSchemaPlan oldPhysical = contract.BeforeForDatabase(database), finalPhysical = contract.AfterForDatabase(database);
            if (await inspector.InspectSchemaAsync(oldPhysical, ct).ConfigureAwait(false) != oldPhysical.TargetSchemaSha256)
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            await using (var ddl = new NpgsqlCommand(CurrentAppOwnedRepairManifest.CollationSql(database), connection, transaction))
            { _ = await ddl.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            if (await inspector.InspectSchemaAsync(finalPhysical, ct).ConfigureAwait(false) != finalPhysical.TargetSchemaSha256)
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            CurrentAppOwnedRetained31Observation preparedAfter = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
            CurrentAppOwnedRetained31Preservation.RequirePreserved(lockedBefore, preparedAfter, beforeSchema, afterSchema, DateTimeOffset.UtcNow);
            afterHash = CurrentAppOwnedSnapshotSerialization.Sha256(preparedAfter.Snapshot);
            await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            CurrentAppOwnedRetained31Receipt prepared = Sign(CurrentAppOwnedCommitClassification.Prepared);
            await RetainAsync(prepared, "prepared", ct).ConfigureAwait(false);
            previousReceiptSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(prepared);
            // Prepared authentic after evidence is durable AFTER transactional DDL and BEFORE COMMIT.
            await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            commitStarted = true;
            await transaction.CommitAsync(ct).ConfigureAwait(false);
            acknowledged = true;
            await transaction.DisposeAsync().ConfigureAwait(false); transaction = null;
            await using (var readback = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false))
            {
                await ReadOnlyAsync(connection, readback, ct).ConfigureAwait(false);
                await RequireInstalledPolicyAsync(connection, readback, scope, ct).ConfigureAwait(false);
                if ((await InspectHashAsync(connection, readback, ct).ConfigureAwait(false)) != afterHash)
                { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                await using var finalInspector = new PostgreSqlWholeDatabaseTransaction(connection, readback, ownsResources: false);
                if (await finalInspector.InspectSchemaAsync(finalPhysical, ct).ConfigureAwait(false) != finalPhysical.TargetSchemaSha256)
                { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                await readback.RollbackAsync(ct).ConfigureAwait(false);
            }
            await connection.CloseAsync().ConfigureAwait(false);
            await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
            // The closed environment re-observes/authenticates prepared-after on a second native connection.
            await permit.Environment.ObserveCommittedDatabaseAsync(prepared, ct).ConfigureAwait(false);
            await RequireGlobalAsync(permit, ct).ConfigureAwait(false);
            CurrentAppOwnedRetained31Receipt committed = Sign(CurrentAppOwnedCommitClassification.CommittedAndReadback);
            await RetainAsync(committed, "committed-readback", ct).ConfigureAwait(false);
            await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
            permit.CompleteDatabase(database, CurrentAppOwnedSnapshotSerialization.Sha256(committed));
            return committed;
        }
        catch (Exception original)
        {
            permit.Stop();
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            if (!commitStarted && transaction is not null)
            {
                try { await transaction.RollbackAsync(cleanup.Token).ConfigureAwait(false); rollbackAcknowledged = true; }
                catch (Exception failure) when (failure is NpgsqlException or InvalidOperationException or OperationCanceledException) { }
            }
            CurrentAppOwnedCommitClassification classification = commitStarted || acknowledged
                ? CurrentAppOwnedCommitClassification.Uncertain
                : rollbackAcknowledged ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.FailedBeforeCommit;
            try { await RetainAsync(Sign(classification), "failed-or-uncertain", cleanup.Token).ConfigureAwait(false); }
            catch (Exception evidenceFailure) { throw new AggregateException(original, evidenceFailure); }
            throw;
        }
        finally { if (transaction is not null) { await transaction.DisposeAsync().ConfigureAwait(false); } }

        CurrentAppOwnedRetained31Receipt Sign(CurrentAppOwnedCommitClassification classification)
        {
            var unsigned = new CurrentAppOwnedRetained31Receipt("current-app-owned-retained31-receipt-v1", scope.OperationId, database,
                scope.ContractSha256, scope.OperationSha256, beforeHash, afterHash, permit.AuthorizationSha256, previousReceiptSha256,
                classification, DateTimeOffset.UtcNow, receiptSigner.KeyId, null);
            var signed = unsigned with { Signature = Convert.ToBase64String(receiptSigner.Sign(Payload(unsigned))) };
            RequireReceipt(signed, scope, permit.AuthorizationSha256, trust, pins);
            return signed;
        }
        Task RetainAsync(CurrentAppOwnedRetained31Receipt receipt, string suffix, CancellationToken token)
        {
            return permit.Environment.RetainNewEvidenceAsync($"{scope.OperationId:D}-{database}-{suffix}.json", JsonSerializer.SerializeToUtf8Bytes(receipt), token);
        }
    }

    internal static byte[] Payload(CurrentAppOwnedRetained31Receipt receipt)
    {
        return [.. "Legacy.Maliev.CurrentAppOwnedRetained31.Receipt.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(receipt with { Signature = null })];
    }

    internal static void RequireReceipt(CurrentAppOwnedRetained31Receipt receipt, CurrentAppOwnedRetained31Scope scope,
        string authorizationSha256, IReceiptAttestationTrustStore trust, CurrentAppOwnedRetained31SigningPins pins)
    {
        if (receipt.Kind != "current-app-owned-retained31-receipt-v1" || receipt.OperationId != scope.OperationId ||
            !CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations).Contains(receipt.Database, StringComparer.Ordinal) ||
            receipt.ContractSha256 != scope.ContractSha256 || receipt.OperationSha256 != scope.OperationSha256 ||
            receipt.BeforeSha256 != scope.BeforeDatabaseSha256[receipt.Database] || receipt.AuthorizationSha256 != authorizationSha256 ||
            !CurrentAppOwnedRepairPermit.HashShape(receipt.PreviousReceiptSha256) || receipt.ObservedAtUtc.Offset != TimeSpan.Zero ||
            !Enum.IsDefined(receipt.Classification) || (receipt.AfterSha256 is not null && !CurrentAppOwnedRepairPermit.HashShape(receipt.AfterSha256)) ||
            ((receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback) && receipt.AfterSha256 is null) ||
            receipt.KeyId != pins.ReceiptKeyId || string.IsNullOrWhiteSpace(receipt.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(receipt.KeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint)
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        try { if (!trust.Verify(receipt.KeyId, Payload(receipt), Convert.FromBase64String(receipt.Signature))) { throw CurrentAppOwnedRetained31Permit.Invalid(); } }
        catch (FormatException) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
    }

    private static async Task RequireGlobalAsync(CurrentAppOwnedRetained31Permit permit, CancellationToken ct)
    {
        await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
        if (await permit.Environment.InspectGlobalPreservationAsync(ct).ConfigureAwait(false) != permit.Scope.GlobalPreservationSha256)
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
    }

    private static async Task ReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction);
        _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task<string> InspectHashAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        return CurrentAppOwnedSnapshotSerialization.Sha256(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false));
    }

    internal static async Task RequireInstalledPolicyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CurrentAppOwnedRetained31Scope scope, CancellationToken ct)
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
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        CurrentAppOwnedMaintenancePin m = scope.Maintenance;
        if (!await reader.ReadAsync(ct).ConfigureAwait(false) || reader.GetString(0) != scope.Target.SystemIdentifierSha256 ||
            reader.GetFieldValue<DateTimeOffset>(1) != m.Postmaster || reader.GetFieldValue<DateTimeOffset>(2) != m.ConfigLoaded ||
            reader.GetString(3) != m.Role || reader.GetString(4) != m.HbaSha256 || reader.GetString(5) != m.HbaRulesSha256 ||
            reader.GetInt64(6) != 0 || reader.GetInt64(7) != 0 || reader.GetInt64(8) != 0 || reader.GetInt64(9) != 0 ||
            reader.GetFieldValue<DateTimeOffset>(10) != m.ExpiresAtUtc || reader.GetString(11) != m.RoleComment ||
            !reader.GetBoolean(12) || !reader.GetBoolean(13) || reader.GetBoolean(14) || reader.GetBoolean(15) ||
            reader.GetBoolean(16) || reader.GetBoolean(17) || reader.GetInt64(18) != 0 || !reader.GetBoolean(19) || reader.GetInt64(20) != 0 ||
            reader.GetString(21) != m.HbaPath || !reader.GetBoolean(22) || DateTimeOffset.UtcNow >= m.ExpiresAtUtc)
        { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
        await reader.DisposeAsync().ConfigureAwait(false);
        await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, transaction, m.Role, scope.Target.Kind, ct).ConfigureAwait(false);
    }
}
