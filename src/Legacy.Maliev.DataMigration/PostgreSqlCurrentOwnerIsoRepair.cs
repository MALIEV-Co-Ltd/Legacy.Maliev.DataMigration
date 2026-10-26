using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentOwnerIsoRepairReceipt(string Kind, Guid OperationId, string Database,
    string ContractSha256, string OperationSha256, string BeforeSha256, string? AfterSha256,
    string AuthorizationSha256, string PreviousReceiptSha256, CurrentAppOwnedCommitClassification Classification,
    DateTimeOffset ObservedAtUtc, string KeyId, string? Signature);

/// <summary>Native fixed owner ISO executor. Requires a separately reserved, fresh typed permit.</summary>
internal static class PostgreSqlCurrentOwnerIsoRepair
{
    private static readonly string[] OrderedDatabases = ["Country", "Material"];
    internal static string[] Databases()
    {
        return OrderedDatabases.ToArray();
    }

    internal const string Sql = """
        SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='20s';
        LOCK TABLE public."Country" IN ACCESS EXCLUSIVE MODE;
        ALTER TABLE public."Country" ALTER COLUMN "ISO2" TYPE varchar(2) COLLATE public.legacy_ci_as
            USING rpad("ISO2"::text,2,' ');
        ALTER TABLE public."Country" ALTER COLUMN "ISO3" TYPE varchar(3) COLLATE public.legacy_ci_as
            USING rpad("ISO3"::text,3,' ');
        """;
    internal static string OperationSha256 => CurrentAppOwnedRepairPermit.Hash(
        [.. "Legacy.Maliev.CurrentOwnerIsoRepair.FixedSql.v1\0"u8, .. System.Text.Encoding.UTF8.GetBytes(Sql)]);

    internal static async Task<IReadOnlyList<CurrentOwnerIsoRepairReceipt>> ExecuteFleetAsync(
        string connectionString, FreshSchemaPlan source, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline, CurrentOwnerIsoRepairPermit permit,
        P256MigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust, CurrentOwnerIsoRepairSigningPins pins,
        CancellationToken ct)
    {
        try
        {
            // Freeze membership while sharing only immutable fact records; never clone a whole fleet JSON blob.
            CurrentAppOwnedDatabaseSnapshot[] held = baseline.Select(snapshot => snapshot with
            {
                Catalog = snapshot.Catalog.ToArray(),
                Relations = snapshot.Relations.ToArray(),
                Sequences = snapshot.Sequences.ToArray(),
            }).ToArray();
            CurrentOwnerIsoRepairScope scope = permit.Scope;
            if (held.Length != scope.BeforeDatabaseSha256.Count || held.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != held.Length ||
                !held.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
                held.Any(x => CurrentAppOwnedSnapshotSerialization.Sha256(x) != scope.BeforeDatabaseSha256[x.Database]) ||
                CurrentAppOwnedSnapshotSerialization.Sha256(held) != scope.GlobalPreservationSha256)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            source = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(source))!;
            owners = JsonSerializer.Deserialize<CurrentOwnerIsoSourceObservation[]>(JsonSerializer.SerializeToUtf8Bytes(owners))!;
            await permit.BeginExecutionAsync(ct).ConfigureAwait(false);
            var receipts = new List<CurrentOwnerIsoRepairReceipt>();
            string previous = new('0', 64);
            foreach (string database in OrderedDatabases)
            {
                CurrentOwnerIsoRepairReceipt terminal = await ExecuteDatabaseCoreAsync(connectionString, database,
                    source, owners, held.Single(x => x.Database == database), permit, signer, trust, pins, previous, ct).ConfigureAwait(false);
                receipts.Add(terminal); previous = CurrentAppOwnedSnapshotSerialization.Sha256(terminal);
            }
            permit.Stop();
            return receipts.AsReadOnly();
        }
        catch { permit.Stop(); throw; }
    }

    private static async Task<CurrentOwnerIsoRepairReceipt> ExecuteDatabaseCoreAsync(string connectionString, string database,
        FreshSchemaPlan beforeSchema, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, CurrentAppOwnedDatabaseSnapshot expectedBefore,
        CurrentOwnerIsoRepairPermit permit, P256MigrationEvidenceSigner receiptSigner,
        IReceiptAttestationTrustStore trust, CurrentOwnerIsoRepairSigningPins pins, string previousReceiptSha256, CancellationToken ct)
    {
        CurrentOwnerIsoRepairScope scope = permit.Scope;
        beforeSchema = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(beforeSchema))!;
        owners = JsonSerializer.Deserialize<CurrentOwnerIsoSourceObservation[]>(JsonSerializer.SerializeToUtf8Bytes(owners))!;
        // Immutable facts can be shared; copy array membership before validating its exact hash.
        expectedBefore = expectedBefore with { Catalog = expectedBefore.Catalog.ToArray(), Relations = expectedBefore.Relations.ToArray(), Sequences = expectedBefore.Sequences.ToArray() };
        ApprovedCurrentOwnerIsoOverlay contract = ApprovedCurrentOwnerIsoOverlay.Create(beforeSchema, scope.SourceCommitSha, scope.Operation, owners, DateTimeOffset.UtcNow);
        if (scope.Operation != CurrentOwnerIsoSelection.LiteralWidthV1 || scope.ContractSha256 != contract.ComputeSha256() ||
            scope.OperationSha256 != OperationSha256 || scope.BeforeSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(beforeSchema) ||
            scope.OwnerSourcesSha256 != CurrentAppOwnedSnapshotSerialization.Sha256(owners) ||
            expectedBefore.Database != database || !Databases().Contains(database, StringComparer.Ordinal) ||
            !scope.BeforeDatabaseSha256.TryGetValue(database, out string? beforeHash) || beforeHash != CurrentAppOwnedSnapshotSerialization.Sha256(expectedBefore) ||
            receiptSigner.KeyId != pins.ReceiptKeyId || !CurrentAppOwnedRepairPermit.HashShape(previousReceiptSha256) ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.ReceiptKeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint)
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        byte[] keyProbe = [.. "Legacy.Maliev.CurrentOwnerIsoRepair.ReceiptKeyProbe.v1\0"u8, .. scope.OperationId.ToByteArray()];
        if (!trust.Verify(receiptSigner.KeyId, keyProbe, receiptSigner.Sign(keyProbe))) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        var builder = new NpgsqlConnectionStringBuilder(connectionString)
        { Database = database, Pooling = false, IncludeErrorDetail = false, Timeout = 10, CommandTimeout = 30 };
        if (builder.Host != "127.0.0.1" || builder.Username != scope.Maintenance.Role || string.IsNullOrWhiteSpace(builder.Password) ||
            !string.IsNullOrEmpty(builder.Options)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
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
                CurrentOwnerIsoNativeObservation before = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, preflight, contract, false, ct).ConfigureAwait(false);
                if (CurrentAppOwnedSnapshotSerialization.Sha256(before.Snapshot) != beforeHash) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                CurrentOwnerIsoNativePreservation.RequireBefore(before, contract);
                _ = await CurrentOwnerIsoNativePreservation.RequireOperandOwnerAsync(connection, preflight, scope, before, ct).ConfigureAwait(false);
                await preflight.RollbackAsync(ct).ConfigureAwait(false);
            }
            transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
            await CurrentAppOwnedRepairPreservation.LockAsync(connection, transaction, expectedBefore, ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
            CurrentOwnerIsoNativeObservation lockedBefore = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, transaction, contract, false, ct).ConfigureAwait(false);
            if (CurrentAppOwnedSnapshotSerialization.Sha256(lockedBefore.Snapshot) != beforeHash) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            CurrentOwnerIsoNativePreservation.RequireBefore(lockedBefore, contract);
            string ownerClosure = await CurrentOwnerIsoNativePreservation.RequireOperandOwnerAsync(connection, transaction, scope, lockedBefore, ct).ConfigureAwait(false);
            await using (var ddl = new NpgsqlCommand(Sql, connection, transaction))
            { _ = await ddl.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            CurrentOwnerIsoNativeObservation preparedAfter = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, transaction, contract, true, ct).ConfigureAwait(false);
            CurrentOwnerIsoNativePreservation.RequirePreserved(lockedBefore, preparedAfter, contract);
            if (await CurrentOwnerIsoNativePreservation.RequireOperandOwnerAsync(connection, transaction, scope, preparedAfter, ct).ConfigureAwait(false) != ownerClosure) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            await CurrentOwnerIsoNativeProofObservation.RecordAsync(permit, contract, lockedBefore, preparedAfter, ct).ConfigureAwait(false);
            afterHash = CurrentAppOwnedSnapshotSerialization.Sha256(preparedAfter.Snapshot);
            await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, ct).ConfigureAwait(false);
            CurrentOwnerIsoRepairReceipt prepared = Sign(CurrentAppOwnedCommitClassification.Prepared);
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
                CurrentOwnerIsoNativeObservation observedAfter = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, readback, contract, true, ct).ConfigureAwait(false);
                CurrentOwnerIsoNativePreservation.RequirePreserved(lockedBefore, observedAfter, contract);
                if (await CurrentOwnerIsoNativePreservation.RequireOperandOwnerAsync(connection, readback, scope, observedAfter, ct).ConfigureAwait(false) != ownerClosure) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                if (CurrentAppOwnedSnapshotSerialization.Sha256(observedAfter.Snapshot) != afterHash)
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                await readback.RollbackAsync(ct).ConfigureAwait(false);
            }
            await connection.CloseAsync().ConfigureAwait(false);
            await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
            // The closed environment re-observes/authenticates prepared-after on a second native connection.
            await permit.Environment.ObserveCommittedDatabaseAsync(prepared, ct).ConfigureAwait(false);
            await RequireGlobalAsync(permit, ct).ConfigureAwait(false);
            CurrentOwnerIsoRepairReceipt committed = Sign(CurrentAppOwnedCommitClassification.CommittedAndReadback);
            await RetainAsync(committed, "committed-readback", ct).ConfigureAwait(false);
            previousReceiptSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(committed);
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

        CurrentOwnerIsoRepairReceipt Sign(CurrentAppOwnedCommitClassification classification)
        {
            var unsigned = new CurrentOwnerIsoRepairReceipt("current-owner-iso-receipt-v1", scope.OperationId, database,
                scope.ContractSha256, scope.OperationSha256, beforeHash, afterHash, permit.AuthorizationSha256, previousReceiptSha256,
                classification, DateTimeOffset.UtcNow, receiptSigner.KeyId, null);
            var signed = unsigned with { Signature = Convert.ToBase64String(receiptSigner.Sign(Payload(unsigned))) };
            RequireReceipt(signed, scope, permit.AuthorizationSha256, trust, pins);
            return signed;
        }
        Task RetainAsync(CurrentOwnerIsoRepairReceipt receipt, string suffix, CancellationToken token)
        {
            return permit.Environment.RetainNewEvidenceAsync($"{scope.OperationId:D}-{database}-{suffix}.json", JsonSerializer.SerializeToUtf8Bytes(receipt), token);
        }
    }

    internal static byte[] Payload(CurrentOwnerIsoRepairReceipt receipt)
    {
        return [.. "Legacy.Maliev.CurrentOwnerIsoRepair.Receipt.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(receipt with { Signature = null })];
    }

    internal static void RequireReceipt(CurrentOwnerIsoRepairReceipt receipt, CurrentOwnerIsoRepairScope scope,
        string authorizationSha256, IReceiptAttestationTrustStore trust, CurrentOwnerIsoRepairSigningPins pins)
    {
        if (receipt.Kind != "current-owner-iso-receipt-v1" || receipt.OperationId != scope.OperationId ||
            !Databases().Contains(receipt.Database, StringComparer.Ordinal) ||
            receipt.ContractSha256 != scope.ContractSha256 || receipt.OperationSha256 != scope.OperationSha256 ||
            receipt.BeforeSha256 != scope.BeforeDatabaseSha256[receipt.Database] || receipt.AuthorizationSha256 != authorizationSha256 ||
            !CurrentAppOwnedRepairPermit.HashShape(receipt.PreviousReceiptSha256) || receipt.ObservedAtUtc.Offset != TimeSpan.Zero ||
            receipt.ObservedAtUtc < scope.Maintenance.IssuedAtUtc ||
            !Enum.IsDefined(receipt.Classification) || (receipt.AfterSha256 is not null && !CurrentAppOwnedRepairPermit.HashShape(receipt.AfterSha256)) ||
            ((receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback) && receipt.AfterSha256 is null) ||
            receipt.KeyId != pins.ReceiptKeyId || string.IsNullOrWhiteSpace(receipt.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(receipt.KeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint)
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        try { if (!trust.Verify(receipt.KeyId, Payload(receipt), Convert.FromBase64String(receipt.Signature))) { throw CurrentOwnerIsoRepairPermit.Invalid(); } }
        catch (FormatException) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }

    private static async Task RequireGlobalAsync(CurrentOwnerIsoRepairPermit permit, CancellationToken ct)
    {
        await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
        if (await permit.Environment.InspectGlobalPreservationAsync(ct).ConfigureAwait(false) != permit.Scope.GlobalPreservationSha256)
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        await permit.RequireExecutionAsync(ct).ConfigureAwait(false);
    }

    private static async Task ReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction);
        _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    internal static async Task RequireInstalledPolicyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CurrentOwnerIsoRepairScope scope, CancellationToken ct)
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
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        await reader.DisposeAsync().ConfigureAwait(false);
        await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, transaction, m.Role, scope.Target.Kind, ct).ConfigureAwait(false);
    }
}
