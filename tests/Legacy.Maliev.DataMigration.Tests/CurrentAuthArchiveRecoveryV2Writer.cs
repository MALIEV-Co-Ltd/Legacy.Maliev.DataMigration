using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;
using NpgsqlTypes;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    // No constructor, endpoint, row argument or SQL operation is exposed outside this actual owned pair.
    private sealed class RecoveryRestoreCapability
    {
        private readonly CurrentAuthArchiveGenuineOwnedPair _pair;
        private readonly CurrentAuthArchiveRestoreScopeV2 _scope;
        private readonly CurrentAuthArchiveClaim _review, _authorization;
        private readonly CurrentAuthArchiveFleet _empty, _comparison;
        private readonly CurrentAuthArchiveRecoveryV2Storage _storage;
        private readonly byte[] _recovered;
        private int _used;
        private RecoveryRestoreCapability(CurrentAuthArchiveGenuineOwnedPair pair, CurrentAuthArchiveRestoreScopeV2 scope,
            CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization, CurrentAuthArchiveFleet empty,
            CurrentAuthArchiveFleet comparison, CurrentAuthArchiveRecoveryV2Storage storage, byte[] recovered)
        { _pair = pair; _scope = scope; _review = review; _authorization = authorization; _empty = empty; _comparison = comparison; _storage = storage; _recovered = recovered; }
        internal static RecoveryRestoreCapability CreateOwned(CurrentAuthArchiveGenuineOwnedPair pair, CurrentAuthArchiveRestoreScopeV2 scope,
            CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization, CurrentAuthArchiveFleet empty,
            CurrentAuthArchiveFleet comparison, CurrentAuthArchiveRecoveryV2Storage storage, byte[] recovered)
        {
            return pair._restoreStarted != 1 || !pair._executionEnvironmentClosed || pair._environment is not null || (pair._recoveryCapture is null && pair._recoveryFinal6Capture is null) ||
                pair._recoveryV2Case is null || pair._recoveryAudienceClaim is null || pair._disposed || empty.Auth.Sessions.Count != 0 ||
                scope.FirstDomain != (pair._recoveryV2Case == CurrentAuthArchiveRecoveryV2Case.FirstOnly) ||
                scope.AudienceSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(pair._recoveryAudienceClaim) ||
                scope.EmptyAuthSha256 != empty.Auth.Native.Snapshot.Sha256 || scope.EmptyNativeSha256 != CurrentAuthArchiveRecoveryV2Preservation.NativeSha(empty.Auth.Native) ||
                scope.EmptyFleetSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(empty.Databases) || scope.ComparisonFleetSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(comparison.Databases) ||
                scope.UnavailableDomainSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(storage.Unavailable) ||
                CurrentAuthLocalSessionArchivePolicy.HashBytes(recovered) != scope.OriginalRowsSha256
                ? throw Invalid()
                : new(pair, scope, review, authorization, empty, comparison, storage, recovered);
        }
        private async Task RequireAsync(CancellationToken ct)
        {
            CurrentAuthArchiveRecoveryV2Preservation.RequireScope(_scope, _pair.Scope, DateTimeOffset.UtcNow);
            await _pair.RequireRecoveryCustodyAsync(ct); await _storage.RequireCustodyAsync(ct);
            var capture = _pair.RecoveryActualSource;
            if (_scope.SourceFullSha256 != capture.FullPlanSha256 || _scope.SourceDefinitionSha256 != capture.DefinitionSha256 || _scope.SourceIdentitySha256 != capture.SourceIdentitySha256) { throw Invalid(); }
            var reviewed = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRestoreScopeV2>(_review, CurrentAuthArchiveRecoveryV2.ReviewDomain,
                _pair._inputs.Pins.ReviewKeyId, _pair._inputs.Pins.ReviewFingerprint, _pair._inputs.TrustStore);
            var permission = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(_authorization, CurrentAuthArchiveRecoveryV2.AuthorizationDomain,
                _pair._inputs.Pins.AuthorizationKeyId, _pair._inputs.Pins.AuthorizationFingerprint, _pair._inputs.TrustStore);
            if (reviewed != _scope || permission.OperationId != _scope.OperationId || permission.ReviewSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(_review) ||
                permission.IssuedAtUtc != _scope.CapturedAtUtc || permission.ExpiresAtUtc != _scope.ExpiresAtUtc) { throw Invalid(); }
        }
        internal async Task ExecuteAsync(CancellationToken ct)
        {
            if (Interlocked.CompareExchange(ref _used, 1, 0) != 0) { throw Invalid(); }
            await RequireAsync(ct);
            var rows = JsonSerializer.Deserialize<CurrentAuthArchiveSession[]>(_recovered) ?? throw Invalid();
            byte[] canonical = CurrentAuthLocalSessionArchivePolicy.EncodeRows(rows);
            try { if (rows.Length != _scope.OriginalRows || !canonical.AsSpan().SequenceEqual(_recovered)) { throw Invalid(); } }
            finally { CryptographicOperations.ZeroMemory(canonical); }
            using var signer = _pair.DualSigner(_pair._inputs.Pins.EvidenceKeyId, CurrentAuthArchiveGenuineDualInputContract.EvidenceKeyName, _pair._inputs.Pins.EvidenceFingerprint);
            string authorization = CurrentAuthLocalSessionArchivePolicy.Hash(_authorization), previous = new('0', 64);
            bool commitStarted = false, committed = false, rollbackAcknowledged = false;
            NpgsqlConnection? connection = null; NpgsqlTransaction? transaction = null; string? afterHash = null;
            var reserved = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2Journal.ReservationDomain,
                new CurrentAuthArchiveRestoreReservationV2(_scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(_scope), authorization), signer);
            await _pair.RecoveryValueAsync("restore-reservation", reserved, ct);
            try
            {
                connection = _pair.RecoveryConnection(false, "Auth"); await connection.OpenAsync(ct);
                transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
                await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(connection, transaction, _pair.Scope.LocalObservationPolicy, ct);
                await using (var locks = new NpgsqlCommand("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s'; LOCK TABLE public.\"__EFMigrationsHistory\",public.google_identity_nonces,public.identity_action_tokens,public.refresh_sessions IN ACCESS EXCLUSIVE MODE;", connection, transaction))
                { _ = await locks.ExecuteNonQueryAsync(ct); }
                var locked = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, transaction, _pair.Scope.LocalObservationPolicy.RunBindingSha256, ct);
                CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(locked, _empty.Auth);
                if (locked.Sessions.Count != 0 || CurrentAuthArchiveRecoveryV2Preservation.NativeSha(locked.Native) != _scope.EmptyNativeSha256) { throw Invalid(); }
                await RequireAsync(ct);
                foreach (var row in rows)
                {
                    await using var insert = new NpgsqlCommand("INSERT INTO public.refresh_sessions (" + CurrentAuthLocalSessionArchiveObservation.Fields + ") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11);", connection, transaction);
                    Add(NpgsqlDbType.Uuid, row.Id); Add(NpgsqlDbType.Uuid, row.FamilyId); Add(NpgsqlDbType.Text, row.IdentityId); Add(NpgsqlDbType.Integer, row.IdentityKind);
                    Add(NpgsqlDbType.Text, row.SecurityStamp); Add(NpgsqlDbType.Text, row.TokenHash); Add(NpgsqlDbType.TimestampTz, row.CreatedAt); Add(NpgsqlDbType.TimestampTz, row.ExpiresAt);
                    Add(NpgsqlDbType.TimestampTz, row.RotatedAt); Add(NpgsqlDbType.TimestampTz, row.RevokedAt); Add(NpgsqlDbType.Uuid, row.ReplacedById);
                    if (await insert.ExecuteNonQueryAsync(ct) != 1) { throw Invalid(); }
                    void Add(NpgsqlDbType type, object? value)
                    {
                        _ = insert.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = type, Value = value ?? DBNull.Value });
                    }
                }
                var candidate = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, transaction, _pair.Scope.LocalObservationPolicy.RunBindingSha256, ct);
                byte[] bytes = CurrentAuthLocalSessionArchivePolicy.EncodeRows(candidate.Sessions);
                try { if (!bytes.AsSpan().SequenceEqual(_recovered)) { throw Invalid(); } } finally { CryptographicOperations.ZeroMemory(bytes); }
                // Exact definitions, private rows, sequence tuples and index storage remain bound to the original pre-delete observation.
                CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(candidate, locked);
                afterHash = candidate.Native.Snapshot.Sha256;
                await RequireAsync(ct); await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(connection, transaction, _pair.Scope.LocalObservationPolicy, ct);
                var prepared = Receipt(CurrentAppOwnedCommitClassification.Prepared);
                var preparedClaim = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2.ReceiptDomain, prepared, signer);
                await _pair.RecoveryValueAsync("restore-prepared", preparedClaim, ct); previous = CurrentAuthLocalSessionArchivePolicy.Hash(preparedClaim);
                await RequireAsync(ct); commitStarted = true; await transaction.CommitAsync(ct); committed = true;
                await transaction.DisposeAsync(); transaction = null; await connection.DisposeAsync(); connection = null;
                var after = await _pair.CaptureRecoveryFleetAsync(false, ct); var comparisonAfter = await _pair.CaptureRecoveryFleetAsync(true, ct);
                // The original before observation is retained by the fixed operation, never supplied by the caller.
                var original = _pair._recoveryOriginal ?? throw Invalid();
                CurrentAuthArchiveRecoveryV2Preservation.RequireRestored(original, _empty, after, _comparison, comparisonAfter, _pair.Scope);
                if (after.Auth.Native.Snapshot.Sha256 != afterHash) { throw Invalid(); }
                await RequireAsync(ct); await _pair.RecoveryFleetAsync("restored", after, ct); await _pair.RecoveryFleetAsync("comparison-restored", comparisonAfter, ct);
                await _pair.RecoveryValueAsync("other-domain-unavailable-after", _storage.ObserveUnavailable(), ct);
                var terminal = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2.ReceiptDomain, Receipt(CurrentAppOwnedCommitClassification.CommittedAndReadback), signer);
                await _pair.RecoveryValueAsync("restore-committed-readback", terminal, ct);
                previous = CurrentAuthLocalSessionArchivePolicy.Hash(terminal);
                CurrentAuthArchiveRecoveryV2Journal.Require(_scope, _pair.Scope, _review, _authorization, reserved, preparedClaim, terminal,
                    _pair._inputs.Pins, _pair._inputs.TrustStore, DateTimeOffset.UtcNow);
            }
            catch (Exception actual)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                if (!commitStarted && transaction is not null)
                { try { await transaction.RollbackAsync(cleanup.Token); rollbackAcknowledged = true; } catch (Exception failure) when (failure is NpgsqlException or InvalidOperationException or OperationCanceledException) { } }
                var outcome = commitStarted || committed ? CurrentAppOwnedCommitClassification.Uncertain : rollbackAcknowledged ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.FailedBeforeCommit;
                try
                {
                    await _pair.RecoveryValueAsync("restore-failed-or-uncertain", CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2.ReceiptDomain, Receipt(outcome), signer), cleanup.Token);
                    await _pair.RecoveryValueAsync("restore-actual-failure", new { Type = actual.GetType().FullName, (actual as PostgresException)?.SqlState, ObservedAtUtc = DateTimeOffset.UtcNow }, cleanup.Token);
                }
                catch (Exception retention) { throw new AggregateException(actual, retention); }
                throw;
            }
            finally
            { try { if (transaction is not null) { await transaction.DisposeAsync(); } } finally { if (connection is not null) { await connection.DisposeAsync(); } } }
            CurrentAuthArchiveRestoreReceiptV2 Receipt(CurrentAppOwnedCommitClassification outcome)
            {
                return new(_scope.OperationId, authorization, previous,
                _scope.SetupManifestSha256, _scope.EmptyAuthSha256, afterHash, _scope.OriginalRowsSha256, outcome, DateTimeOffset.UtcNow);
            }
        }
    }
    private CurrentAuthArchiveFleet? _recoveryOriginal;
}
