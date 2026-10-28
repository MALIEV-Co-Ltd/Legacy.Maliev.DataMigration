using System.Data;
using Npgsql;
using NpgsqlTypes;

namespace Legacy.Maliev.DataMigration;

/// <summary>Unrouted guarded fixed CAS preparation. No restore, replacement or historical adoption.</summary>
internal static class PostgreSqlCurrentAuthLocalSessionArchive
{
    internal static async Task<CurrentAuthArchiveReceipt> ExecuteAsync(string localOperatorConnection,
        CurrentAuthLocalSessionArchivePermit permit, P256MigrationEvidenceSigner signer, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromMinutes(8)); ct = deadline.Token;
        permit.RequireEvidenceSigner(signer);
        CurrentAuthArchiveScope scope = permit.Scope;
        var endpoint = new NpgsqlConnectionStringBuilder(localOperatorConnection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Database != "Auth" ||
            endpoint.Username != scope.LocalObservationPolicy.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password) ||
            !string.IsNullOrEmpty(endpoint.Options)) { permit.Stop(); throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        endpoint.Pooling = false; endpoint.IncludeErrorDetail = false; endpoint.Timeout = 5; endpoint.CommandTimeout = 30;
        CurrentAuthLocalSessionArchiveObservation? before = null;
        CurrentAuthArchiveRecoveryManifest? recovery = null;
        NpgsqlConnection? connection = null; NpgsqlTransaction? transaction = null;
        string previous = new('0', 64); string? afterHash = null;
        bool commitStarted = false, committed = false, rollbackAcknowledged = false, reserved = false;
        try
        {
            before = await permit.RequireOriginalFleetsAsync(ct).ConfigureAwait(false);
            await permit.ReserveAsync(ct).ConfigureAwait(false); reserved = true;
            // Fresh post-reservation complete target captures close review-to-reserve drift.
            before = await permit.RequireOriginalFleetsAsync(ct).ConfigureAwait(false);
            connection = new NpgsqlConnection(endpoint.ConnectionString); await connection.OpenAsync(ct).ConfigureAwait(false);
            transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
            await PolicyAsync(ct).ConfigureAwait(false);
            await using (var locks = new NpgsqlCommand("""
                SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s';
                LOCK TABLE public."__EFMigrationsHistory",public.google_identity_nonces,
                  public.identity_action_tokens,public.refresh_sessions IN ACCESS EXCLUSIVE MODE;
                """, connection, transaction)) { _ = await locks.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            CurrentAuthLocalSessionArchiveObservation locked = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection,
                transaction, scope.LocalObservationPolicy.RunBindingSha256, ct).ConfigureAwait(false);
            CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(locked, before);
            recovery = await CurrentAuthLocalSessionArchiveCrypto.WriteAndVerifyAsync(permit.Environment.RecoveryStorage, scope,
                permit.AuthorizationSha256, locked.Sessions, ct).ConfigureAwait(false);
            await permit.RetainRecoveryManifestAsync(recovery, signer, ct).ConfigureAwait(false);
            await permit.RequireAsync(ct).ConfigureAwait(false); await PolicyAsync(ct).ConfigureAwait(false);
            await CurrentAuthLocalSessionArchiveCrypto.VerifyAsync(permit.Environment.RecoveryStorage, scope, recovery, locked.Sessions, ct).ConfigureAwait(false);
            CurrentAuthLocalSessionArchiveObservation justBefore = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection,
                transaction, scope.LocalObservationPolicy.RunBindingSha256, ct).ConfigureAwait(false);
            CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(justBefore, locked);
            await using (var delete = new NpgsqlCommand("DELETE FROM public.refresh_sessions WHERE \"Id\"=ANY(@ids) RETURNING " +
                CurrentAuthLocalSessionArchiveObservation.Fields + ";", connection, transaction))
            {
                _ = delete.Parameters.AddWithValue("ids", NpgsqlDbType.Array | NpgsqlDbType.Uuid, locked.Sessions.Select(x => x.Id).ToArray());
                CurrentAuthArchiveSession[] returned = await CurrentAuthLocalSessionArchiveObservation.ReadRowsAsync(delete, ct).ConfigureAwait(false);
                CurrentAuthLocalSessionArchivePolicy.RequireRows(returned, locked.Sessions);
            }
            CurrentAuthLocalSessionArchiveObservation after = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection,
                transaction, scope.LocalObservationPolicy.RunBindingSha256, ct).ConfigureAwait(false);
            CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(locked, after); afterHash = after.Native.Snapshot.Sha256;
            await PolicyAsync(ct).ConfigureAwait(false);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            // Actual encrypted copies + recovery key are independently held/decrypted once
            // more before durable prepared publication and COMMIT.
            await CurrentAuthLocalSessionArchiveCrypto.VerifyAsync(permit.Environment.RecoveryStorage, scope, recovery, locked.Sessions, ct).ConfigureAwait(false);
            previous = await permit.RetainAsync(Receipt(CurrentAppOwnedCommitClassification.Prepared), signer, ct).ConfigureAwait(false);
            await PolicyAsync(ct).ConfigureAwait(false); await permit.RequireAsync(ct).ConfigureAwait(false); await PolicyAsync(ct).ConfigureAwait(false);
            commitStarted = true; await transaction.CommitAsync(ct).ConfigureAwait(false); committed = true;
            await transaction.DisposeAsync().ConfigureAwait(false); transaction = null;
            await connection.DisposeAsync().ConfigureAwait(false); connection = null;
            // The first writer backend is retired before independent readback and fleet capture.
            await permit.RequireAsync(ct).ConfigureAwait(false);
            await using (var readback = new NpgsqlConnection(endpoint.ConnectionString))
            {
                await readback.OpenAsync(ct).ConfigureAwait(false);
                await using var tx = await readback.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", readback, tx))
                { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
                await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(readback, tx, scope.LocalObservationPolicy, ct).ConfigureAwait(false);
                CurrentAuthLocalSessionArchiveObservation observed = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(readback, tx,
                    scope.LocalObservationPolicy.RunBindingSha256, ct).ConfigureAwait(false);
                CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(locked, observed);
                if (observed.Native.Snapshot.Sha256 != afterHash) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                await tx.RollbackAsync(ct).ConfigureAwait(false);
            }
            CurrentAuthArchiveFleet local = await permit.Environment.CaptureLocalFleetAsync(scope, ct).ConfigureAwait(false);
            CurrentAuthArchiveFleet production = await permit.Environment.CaptureProductionFleetAsync(scope, ct).ConfigureAwait(false);
            CurrentAuthLocalSessionArchivePolicy.RequireFleet(local, scope.LocalObservationPolicy, DateTimeOffset.UtcNow, allowEmptyLocalSessions: true);
            CurrentAuthLocalSessionArchivePolicy.RequireFleet(production, scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
            CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(locked, local.Auth);
            if (local.Auth.Native.Snapshot.Sha256 != afterHash || CurrentAuthLocalSessionArchivePolicy.RequireComparison(local.Auth, production.Auth) != scope.ApplicationComparisonSha256)
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            await CurrentAuthLocalSessionArchiveCrypto.VerifyAsync(permit.Environment.RecoveryStorage, scope, recovery, locked.Sessions, ct).ConfigureAwait(false);
            await permit.RequireAsync(ct).ConfigureAwait(false);
            CurrentAuthArchiveReceipt terminal = Receipt(CurrentAppOwnedCommitClassification.CommittedAndReadback);
            previous = await permit.RetainAsync(terminal, signer, ct).ConfigureAwait(false);
            // Any post-retention failure links this terminal hash, never the old prepared hash.
            await permit.RequireAsync(ct).ConfigureAwait(false); return terminal;
        }
        catch (Exception original)
        {
            permit.Stop(); using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            if (!commitStarted && transaction is not null)
            {
                try { await transaction.RollbackAsync(cleanup.Token).ConfigureAwait(false); rollbackAcknowledged = true; }
                catch (Exception failure) when (failure is NpgsqlException or InvalidOperationException or OperationCanceledException) { }
            }
            if (reserved)
            {
                CurrentAppOwnedCommitClassification outcome = commitStarted || committed ? CurrentAppOwnedCommitClassification.Uncertain :
                    rollbackAcknowledged ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.FailedBeforeCommit;
                try { _ = await permit.RetainAsync(Receipt(outcome), signer, cleanup.Token).ConfigureAwait(false); }
                catch (Exception retentionFailure) { throw new AggregateException(original, retentionFailure); }
            }
            throw;
        }
        finally
        {
            permit.Stop();
            try { if (transaction is not null) { await transaction.DisposeAsync().ConfigureAwait(false); } }
            finally { if (connection is not null) { await connection.DisposeAsync().ConfigureAwait(false); } }
        }
        CurrentAuthArchiveReceipt Receipt(CurrentAppOwnedCommitClassification outcome)
        {
            return new(scope.OperationId,
            permit.AuthorizationSha256, previous, scope.LocalObservationPolicy.BeforeDatabaseSha256["Auth"], afterHash,
            recovery is null ? new string('0', 64) : CurrentAuthLocalSessionArchivePolicy.Hash(recovery), outcome, DateTimeOffset.UtcNow);
        }

        Task PolicyAsync(CancellationToken token)
        {
            return PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(connection, transaction, scope.LocalObservationPolicy, token);
        }
    }
}
