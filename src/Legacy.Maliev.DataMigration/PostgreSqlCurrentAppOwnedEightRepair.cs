using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal enum CurrentAppOwnedCommitClassification { Prepared, CommittedAndReadback, RolledBackBeforeCommit, FailedBeforeCommit, Uncertain }
internal sealed record CurrentAppOwnedRepairReceipt(string Kind, Guid OperationId, string Database,
    string OperationSha256, string BeforeSha256, string? AfterSha256, string AuthorizationSha256,
    string PreviousReceiptSha256, CurrentAppOwnedCommitClassification Classification,
    DateTimeOffset ObservedAtUtc, string KeyId, string? Signature);

/// <summary>Actual fixed eight-table create-only path. Does not admit the unproven retained31 operation.</summary>
internal static class PostgreSqlCurrentAppOwnedEightRepair
{
    internal static async Task<CurrentAppOwnedRepairReceipt> ExecuteDatabaseAsync(
        string connectionString, string database, FreshSchemaPlan beforeSchema, FreshSchemaPlan afterSchema,
        CurrentAppOwnedDatabaseSnapshot expectedBefore, CurrentAppOwnedRepairPermit permit,
        P256MigrationEvidenceSigner receiptSigner, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRepairSigningPins pins, string previousReceiptSha256, CancellationToken cancellationToken)
    {
        CurrentAppOwnedRepairScope scope = permit.Scope;
        CurrentAppOwnedRepairManifest.RequireSchemaPair(beforeSchema, afterSchema, DateTimeOffset.UtcNow);
        if (scope.Operation != CurrentAppOwnedRepairOperation.CreateEightTables || expectedBefore.Database != database ||
            !scope.BeforeDatabaseSha256.TryGetValue(database, out string? beforeHash) || beforeHash != expectedBefore.Sha256 ||
            receiptSigner.KeyId != pins.ReceiptKeyId || !CurrentAppOwnedRepairPermit.HashShape(previousReceiptSha256))
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
        await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
        if (await permit.Environment.InspectGlobalPreservationAsync(cancellationToken).ConfigureAwait(false) != scope.GlobalPreservationSha256)
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
        var builder = new NpgsqlConnectionStringBuilder(connectionString) { Database = database, Pooling = false, IncludeErrorDetail = false };
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
            CurrentAppOwnedDatabaseSnapshot observed = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            if (observed.Sha256 != beforeHash) { throw CurrentAppOwnedRepairPermit.Invalid(); }
            string[] names = CurrentAppOwnedRepairManifest.NewTables(database);
            string[] present = [.. observed.Relations.Where(x => x.Schema == "public" && names.Contains(x.Name, StringComparer.Ordinal)).Select(x => x.Name)];
            CurrentAppOwnedCreationState state = CurrentAppOwnedRepairPreflight.ClassifyInventory(database, present);
            DatabaseSchemaPlan expectedPhysical = (state == CurrentAppOwnedCreationState.MissingExactSet ? beforeSchema : afterSchema)
                .Databases.Single(x => x.Database == database);
            await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
            if (await inspector.InspectSchemaAsync(expectedPhysical, cancellationToken).ConfigureAwait(false) != expectedPhysical.TargetSchemaSha256)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            string owner = scope.Target.Kind == DeltaTargetAuthorityKind.LocalAspire ? "legacy_local" : "postgres";
            if (state == CurrentAppOwnedCreationState.MissingExactSet)
            {
                await using (var ddl = new NpgsqlCommand(CurrentAppOwnedRepairManifest.CreateEightSql(database), connection, transaction))
                { _ = await ddl.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false); }
                foreach (string name in names)
                {
                    await using var changeOwner = new NpgsqlCommand(
                        $"ALTER TABLE public.{PostgreSqlShadowTarget.QuoteIdentifier(name)} OWNER TO {PostgreSqlShadowTarget.QuoteIdentifier(owner)};",
                        connection, transaction);
                    _ = await changeOwner.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            DatabaseSchemaPlan finalSchema = afterSchema.Databases.Single(x => x.Database == database);
            if (await inspector.InspectSchemaAsync(finalSchema, cancellationToken).ConfigureAwait(false) != finalSchema.TargetSchemaSha256)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            IReadOnlySet<string> newObjects = await CurrentAppOwnedRepairPreservation.ObserveNewObjectClosureAsync(
                connection, transaction, database, owner, cancellationToken).ConfigureAwait(false);
            CurrentAppOwnedDatabaseSnapshot after = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            CurrentAppOwnedRepairPreservation.RequirePreserved(expectedBefore, after, newObjects,
                state == CurrentAppOwnedCreationState.MissingExactSet ? names : []);
            afterHash = after.Sha256;
            await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
            await RequireInstalledPolicyAsync(connection, transaction, scope, cancellationToken).ConfigureAwait(false);
            CurrentAppOwnedRepairReceipt prepared = Sign(CurrentAppOwnedCommitClassification.Prepared);
            await permit.Environment.RetainNewEvidenceAsync($"{scope.OperationId:D}-{database}-prepared.json",
                JsonSerializer.SerializeToUtf8Bytes(prepared), cancellationToken).ConfigureAwait(false);
            previousReceiptSha256 = CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(prepared));
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
                if ((await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, readback, cancellationToken).ConfigureAwait(false)).Sha256 != afterHash)
                { throw CurrentAppOwnedRepairPermit.Invalid(); }
                await readback.RollbackAsync(cancellationToken).ConfigureAwait(false);
            }
            // Global preservation uses an independent operator connection and its
            // zero-other-client fence. Retire this backend before that observation.
            await connection.CloseAsync().ConfigureAwait(false);
            await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
            if (await permit.Environment.InspectGlobalPreservationAsync(cancellationToken).ConfigureAwait(false) != scope.GlobalPreservationSha256)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            CurrentAppOwnedRepairReceipt committed = Sign(CurrentAppOwnedCommitClassification.CommittedAndReadback);
            await permit.Environment.RetainNewEvidenceAsync($"{scope.OperationId:D}-{database}-committed-readback.json",
                JsonSerializer.SerializeToUtf8Bytes(committed), cancellationToken).ConfigureAwait(false);
            return committed;
        }
        catch
        {
            if (!commitStarted)
            {
                try { await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false); rollbackAcknowledged = true; }
                catch (NpgsqlException) { rollbackAcknowledged = false; }
            }
            CurrentAppOwnedRepairReceipt failure = Sign(ClassifyFailure(commitStarted, commitAcknowledged, rollbackAcknowledged));
            await permit.Environment.RetainNewEvidenceAsync($"{scope.OperationId:D}-{database}-failed-or-uncertain.json",
                JsonSerializer.SerializeToUtf8Bytes(failure), CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        CurrentAppOwnedRepairReceipt Sign(CurrentAppOwnedCommitClassification classification)
        {
            var unsigned = new CurrentAppOwnedRepairReceipt("current-app-owned-eight-receipt-v1", scope.OperationId, database,
                scope.OperationSha256, beforeHash, afterHash, permit.AuthorizationSha256, previousReceiptSha256,
                classification, DateTimeOffset.UtcNow, receiptSigner.KeyId, null);
            byte[] payload = [.. "Legacy.Maliev.CurrentAppOwnedEight.Receipt.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(unsigned)];
            byte[] signature = receiptSigner.Sign(payload);
            return !trust.TryGetPublicKeyFingerprintSha256(receiptSigner.KeyId, out string actual) || actual != pins.ReceiptFingerprint ||
                !trust.Verify(receiptSigner.KeyId, payload, signature)
                ? throw CurrentAppOwnedRepairPermit.Invalid()
                : (unsigned with { Signature = Convert.ToBase64String(signature) });
        }
    }

    internal static CurrentAppOwnedCommitClassification ClassifyFailure(bool commitStarted, bool commitAcknowledged, bool rollbackAcknowledged)
    {
        return commitStarted || commitAcknowledged ? CurrentAppOwnedCommitClassification.Uncertain :
        rollbackAcknowledged ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.FailedBeforeCommit;
    }

    internal static async Task RequireInstalledPolicyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CurrentAppOwnedRepairScope scope, CancellationToken cancellationToken)
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
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw CurrentAppOwnedRepairPermit.Invalid(); }
    }
}
