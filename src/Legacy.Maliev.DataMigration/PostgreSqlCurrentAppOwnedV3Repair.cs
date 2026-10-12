using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;


internal sealed record CurrentAppOwnedV3RepairReceipt(string Kind, Guid OperationId, string Database,
    string OperationSha256, string BeforeSha256, string? AfterSha256, string AuthorizationSha256,
    string PreviousReceiptSha256, CurrentAppOwnedCommitClassification Classification,
    DateTimeOffset ObservedAtUtc, string KeyId, string? Signature);

/// <summary>Distinct fixed V2 to V3 additive execution. Never accepts eight or retained31 permission.</summary>
internal static class PostgreSqlCurrentAppOwnedV3Repair
{
    private static readonly string[] OrderedDatabases = ["Invoice", "PurchaseOrder", "Quotation"];
    internal static async Task<IReadOnlyList<CurrentAppOwnedV3RepairReceipt>> ExecuteFleetAsync(
        string connectionString, FreshSchemaPlan beforeSchema, FreshSchemaPlan afterSchema,
        IReadOnlyList<V3AdditiveObservation> repairPreimages, CurrentAppOwnedV3RepairPermit permit,
        P256MigrationEvidenceSigner receiptSigner, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRepairSigningPins pins, CancellationToken ct)
    {
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromMinutes(15)); ct = deadline.Token;
            beforeSchema = Clone(beforeSchema); afterSchema = Clone(afterSchema);
            // Clone each collection explicitly: IReadOnlySet is not a JSON deserialization contract.
            V3AdditiveObservation[] preimages = repairPreimages.Select(x => x with
            {
                Snapshot = CurrentAppOwnedV3RepairPermit.CopySnapshot(x.Snapshot),
                AddedCatalogKeys = new HashSet<string>(x.AddedCatalogKeys, StringComparer.Ordinal),
                NewObjectClosure = new HashSet<string>(x.NewObjectClosure, StringComparer.Ordinal),
            }).ToArray();
            CurrentAppOwnedV3RepairScope scope = permit.Scope;
            CurrentAppOwnedV3AdditiveContract contract = CurrentAppOwnedV3AdditiveContract.Create(beforeSchema, afterSchema, scope.SourceCommitSha, DateTimeOffset.UtcNow);
            byte[] signerProbe = [.. "Legacy.Maliev.CurrentAppOwnedV3.ReceiptKeyProbe.v1\0"u8, .. scope.OperationId.ToByteArray()];
            if (JsonSerializer.Serialize(pins) != JsonSerializer.Serialize(permit.SigningPins) ||
                !trust.Verify(receiptSigner.KeyId, signerProbe, receiptSigner.Sign(signerProbe)) ||
                scope.OperationSha256 != contract.ComputeSha256() ||
                scope.BeforeSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(beforeSchema) ||
                scope.AfterSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(afterSchema) ||
                !preimages.Select(x => x.Snapshot.Database).Order(StringComparer.Ordinal)
                    .SequenceEqual(OrderedDatabases, StringComparer.Ordinal) ||
                preimages.Any(x => CurrentAppOwnedSnapshotSerialization.Sha256(x.Snapshot) != scope.BeforeDatabaseSha256[x.Snapshot.Database] ||
                    x.AddedCatalogKeys.Count != 0 || x.NewObjectClosure.Count != 0) ||
                receiptSigner.KeyId != pins.ReceiptKeyId || !trust.TryGetPublicKeyFingerprintSha256(receiptSigner.KeyId, out string fingerprint) ||
                fingerprint != pins.ReceiptFingerprint)
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            var endpoint = new NpgsqlConnectionStringBuilder(connectionString);
            if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 ||
                endpoint.Username != scope.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password) ||
                !string.IsNullOrEmpty(endpoint.Options)) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            await permit.StartAsync(ct).ConfigureAwait(false);
            var expectedFleet = scope.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
            var receipts = new List<CurrentAppOwnedV3RepairReceipt>();
            string previous = new('0', 64);
            foreach (string database in OrderedDatabases)
            {
                // Any exception, including uncertain COMMIT or evidence publication, exits this loop.
                // No connection is opened for the next database; reservation prevents operation replay.
                CurrentAppOwnedV3RepairReceipt receipt = await ExecuteDatabaseAsync(connectionString, database, beforeSchema, afterSchema,
                    preimages.Single(x => x.Snapshot.Database == database), expectedFleet, permit,
                    receiptSigner, trust, pins, previous, ct).ConfigureAwait(false);
                receipts.Add(receipt);
                expectedFleet[database] = receipt.AfterSha256 ?? throw CurrentAppOwnedV3RepairPermit.Invalid();
                previous = CurrentAppOwnedV3RepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(receipt));
            }
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await permit.RequireFleetAsync(expectedFleet, ct).ConfigureAwait(false);
            return receipts.AsReadOnly();
        }
        catch { permit.Stop(); throw; }
        finally { permit.Stop(); }
    }

    private static T Clone<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw CurrentAppOwnedV3RepairPermit.Invalid();
    }
    private static async Task<CurrentAppOwnedV3RepairReceipt> ExecuteDatabaseAsync(
        string connectionString, string database, FreshSchemaPlan beforeSchema, FreshSchemaPlan afterSchema,
        V3AdditiveObservation expectedObservation, IReadOnlyDictionary<string, string> expectedFleet, CurrentAppOwnedV3RepairPermit permit,
        P256MigrationEvidenceSigner receiptSigner, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRepairSigningPins pins, string previousReceiptSha256, CancellationToken cancellationToken)
    {
        CurrentAppOwnedV3RepairScope scope = permit.Scope;
        CurrentAppOwnedV3AdditiveContract contract = CurrentAppOwnedV3AdditiveContract.Create(beforeSchema, afterSchema, scope.SourceCommitSha, DateTimeOffset.UtcNow);
        CurrentAppOwnedDatabaseSnapshot expectedBefore = expectedObservation.Snapshot;
        if (scope.Operation != CurrentAppOwnedV3RepairOperation.AppendFourNullableColumnsAndCreateThreeTables || scope.OperationSha256 != contract.ComputeSha256() || expectedBefore.Database != database ||
            !scope.BeforeDatabaseSha256.TryGetValue(database, out string? beforeHash) || beforeHash != CurrentAppOwnedSnapshotSerialization.Sha256(expectedBefore) ||
            receiptSigner.KeyId != pins.ReceiptKeyId || !CurrentAppOwnedV3RepairPermit.HashShape(previousReceiptSha256))
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
        await permit.RequireFleetAsync(expectedFleet, cancellationToken).ConfigureAwait(false);
        var builder = new NpgsqlConnectionStringBuilder(connectionString) { Database = database, Pooling = false, IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        bool commitStarted = false, commitAcknowledged = false, rollbackAcknowledged = false;
        string? afterHash = null;
        try
        {
            await CurrentAppOwnedRepairPreservation.LockAsync(connection, transaction, expectedBefore, cancellationToken).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, cancellationToken).ConfigureAwait(false);
            await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
            string owner = scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire ? "legacy_local" : "postgres";
            V3AdditiveObservation observed = await CurrentAppOwnedV3AdditivePreservation.CaptureAsync(connection, transaction,
                beforeSchema, afterSchema, scope.SourceCommitSha, false, DateTimeOffset.UtcNow, cancellationToken, owner).ConfigureAwait(false);
            if (CurrentAppOwnedSnapshotSerialization.Sha256(observed.Snapshot) != beforeHash ||
                JsonSerializer.Serialize(observed.InvoiceProjection) != JsonSerializer.Serialize(expectedObservation.InvoiceProjection) ||
                observed.InvoiceClassKey != expectedObservation.InvoiceClassKey ||
                observed.InvoiceClassNormalizedSha256 != expectedObservation.InvoiceClassNormalizedSha256)
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            if (database == "Invoice")
            {
                await using var ddl = new NpgsqlCommand("""
                    ALTER TABLE public."InvoiceCreationAdmission" ADD COLUMN "OriginIssuer" character varying(512) COLLATE "C" NULL;
                    ALTER TABLE public."InvoiceCreationAdmission" ADD COLUMN "FinancialResultJson" text COLLATE "C" NULL;
                    ALTER TABLE public."InvoiceCreationAdmission" ADD COLUMN "FinancialOwnershipJson" text COLLATE "C" NULL;
                    ALTER TABLE public."InvoiceCreationAdmission" ADD COLUMN "EmployeeCompletionJson" text COLLATE "C" NULL;
                    """, connection, transaction);
                _ = await ddl.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                // Only the three exact manifest tables, not every app-owned extension.
                DatabaseSchemaPlan additions = contract.AfterForDatabase(database) with
                {
                    Tables = contract.CreateTables().Where(x => x.Database == database).Select(x => x.Table).ToArray(),
                    TargetExtensionProfile = null,
                    SourceDispositionProfile = null,
                    SourceTableDispositions = [],
                };
                await using var creator = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                await creator.ApplySchemaAsync(additions, cancellationToken).ConfigureAwait(false);
                await creator.FinalizeSchemaAsync(additions, cancellationToken).ConfigureAwait(false);
                foreach (TableCopyPlan table in additions.Tables)
                {
                    await using var changeOwner = new NpgsqlCommand(
                        $"ALTER TABLE public.{PostgreSqlShadowTarget.QuoteIdentifier(table.TargetTable)} OWNER TO {PostgreSqlShadowTarget.QuoteIdentifier(owner)};",
                        connection, transaction);
                    _ = await changeOwner.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            V3AdditiveObservation final = await CurrentAppOwnedV3AdditivePreservation.CaptureAsync(connection, transaction,
                beforeSchema, afterSchema, scope.SourceCommitSha, true, DateTimeOffset.UtcNow, cancellationToken, owner).ConfigureAwait(false);
            CurrentAppOwnedV3AdditivePreservation.RequirePreserved(observed, final);
            CurrentAppOwnedDatabaseSnapshot after = final.Snapshot;
            afterHash = CurrentAppOwnedSnapshotSerialization.Sha256(after);
            await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, cancellationToken).ConfigureAwait(false);
            CurrentAppOwnedV3RepairReceipt prepared = Sign(CurrentAppOwnedCommitClassification.Prepared);
            await permit.Environment.RetainNewEvidenceAsync($"{scope.OperationId:D}-{database}-prepared.json",
                JsonSerializer.SerializeToUtf8Bytes(prepared), cancellationToken).ConfigureAwait(false);
            previousReceiptSha256 = CurrentAppOwnedV3RepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(prepared));
            // Real protected-main/custody/authorization/policy rechecks AFTER durable prepared publication.
            await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, cancellationToken).ConfigureAwait(false);
            commitStarted = true;
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            commitAcknowledged = true;
            await using (var readback = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false))
            {
                await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, readback))
                { _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false); }
                await RequireInstalledPolicyAsync(connection, readback, scope, cancellationToken).ConfigureAwait(false);
                V3AdditiveObservation readbackObservation = await CurrentAppOwnedV3AdditivePreservation.CaptureAsync(connection, readback,
                    beforeSchema, afterSchema, scope.SourceCommitSha, true, DateTimeOffset.UtcNow, cancellationToken, owner).ConfigureAwait(false);
                CurrentAppOwnedV3AdditivePreservation.RequirePreserved(observed, readbackObservation);
                if (CurrentAppOwnedSnapshotSerialization.Sha256(readbackObservation.Snapshot) != afterHash)
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
                await readback.RollbackAsync(cancellationToken).ConfigureAwait(false);
            }
            // Global preservation uses an independent operator connection and its
            // zero-other-client fence. Retire this backend before that observation.
            await connection.CloseAsync().ConfigureAwait(false);
            await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
            var advancedFleet = expectedFleet.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
            advancedFleet[database] = afterHash;
            await permit.RequireFleetAsync(advancedFleet, cancellationToken).ConfigureAwait(false);
            CurrentAppOwnedV3RepairReceipt committed = Sign(CurrentAppOwnedCommitClassification.CommittedAndReadback);
            await permit.Environment.RetainNewEvidenceAsync($"{scope.OperationId:D}-{database}-committed-readback.json",
                JsonSerializer.SerializeToUtf8Bytes(committed), cancellationToken).ConfigureAwait(false);
            return committed;
        }
        catch
        {
            permit.Stop();
            using var failureDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            if (!commitStarted)
            {
                try { await transaction.RollbackAsync(failureDeadline.Token).ConfigureAwait(false); rollbackAcknowledged = true; }
                catch (Exception rollbackFailure) when (rollbackFailure is NpgsqlException or OperationCanceledException) { rollbackAcknowledged = false; }
            }
            CurrentAppOwnedV3RepairReceipt failure = Sign(ClassifyFailure(commitStarted, commitAcknowledged, rollbackAcknowledged));
            await permit.Environment.RetainNewEvidenceAsync($"{scope.OperationId:D}-{database}-failed-or-uncertain.json",
                JsonSerializer.SerializeToUtf8Bytes(failure), failureDeadline.Token).ConfigureAwait(false);
            throw;
        }

        CurrentAppOwnedV3RepairReceipt Sign(CurrentAppOwnedCommitClassification classification)
        {
            var unsigned = new CurrentAppOwnedV3RepairReceipt("current-app-owned-v3-receipt-v1", scope.OperationId, database,
                scope.OperationSha256, beforeHash, afterHash, permit.AuthorizationSha256, previousReceiptSha256,
                classification, DateTimeOffset.UtcNow, receiptSigner.KeyId, null);
            byte[] payload = [.. "Legacy.Maliev.CurrentAppOwnedV3.Receipt.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(unsigned)];
            byte[] signature = receiptSigner.Sign(payload);
            return !trust.TryGetPublicKeyFingerprintSha256(receiptSigner.KeyId, out string actual) || actual != pins.ReceiptFingerprint ||
                !trust.Verify(receiptSigner.KeyId, payload, signature)
                ? throw CurrentAppOwnedV3RepairPermit.Invalid()
                : (unsigned with { Signature = Convert.ToBase64String(signature) });
        }
    }

    internal static void RequireReceipt(CurrentAppOwnedV3RepairReceipt receipt, CurrentAppOwnedV3RepairScope scope,
        string authorizationSha256, IReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins)
    {
        if (receipt.Kind != "current-app-owned-v3-receipt-v1" || receipt.OperationId != scope.OperationId ||
            receipt.OperationSha256 != scope.OperationSha256 || receipt.AuthorizationSha256 != authorizationSha256 ||
            !new[] { "Invoice", "PurchaseOrder", "Quotation" }.Contains(receipt.Database, StringComparer.Ordinal) ||
            !scope.BeforeDatabaseSha256.TryGetValue(receipt.Database, out string? before) || receipt.BeforeSha256 != before ||
            !CurrentAppOwnedV3RepairPermit.HashShape(authorizationSha256) || !CurrentAppOwnedV3RepairPermit.HashShape(receipt.PreviousReceiptSha256) ||
            (receipt.AfterSha256 is not null && !CurrentAppOwnedV3RepairPermit.HashShape(receipt.AfterSha256)) ||
            (receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback && receipt.AfterSha256 is null) ||
            !Enum.IsDefined(receipt.Classification) || receipt.ObservedAtUtc.Offset != TimeSpan.Zero ||
            receipt.KeyId != pins.ReceiptKeyId || string.IsNullOrWhiteSpace(receipt.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(receipt.KeyId, out string actual) || actual != pins.ReceiptFingerprint)
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        try
        {
            byte[] payload = [.. "Legacy.Maliev.CurrentAppOwnedV3.Receipt.v1\0"u8,
                .. JsonSerializer.SerializeToUtf8Bytes(receipt with { Signature = null })];
            if (!trust.Verify(receipt.KeyId, payload, Convert.FromBase64String(receipt.Signature)))
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        }
        catch (FormatException) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
    }
    internal static CurrentAppOwnedCommitClassification ClassifyFailure(bool commitStarted, bool commitAcknowledged, bool rollbackAcknowledged)
    {
        return commitStarted || commitAcknowledged ? CurrentAppOwnedCommitClassification.Uncertain :
        rollbackAcknowledged ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.FailedBeforeCommit;
    }

    internal static async Task RequireInstalledPolicyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CurrentAppOwnedV3RepairScope scope, CancellationToken cancellationToken)
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
        { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
        await reader.DisposeAsync().ConfigureAwait(false);
        await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, transaction, scope.Maintenance.Role,
            scope.Target.Kind, cancellationToken).ConfigureAwait(false);
    }
}
