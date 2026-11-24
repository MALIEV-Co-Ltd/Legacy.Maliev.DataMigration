using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed partial class CurrentAuthLocalSessionArchivePermit
{
    internal sealed partial class GenuineExecutionCapability
    {
        private async Task<CurrentAuthArchiveGenuineExecutionMethodResult> ExecuteCommitAckLostAsync(CancellationToken ct)
        {
            CurrentAuthLocalSessionArchivePermit? permit = null; CommitWriterLease? transport = null; Exception? primary = null;
            try
            {
                await RequireAsync(ct);
                if (_binding.Case != CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost || Interlocked.CompareExchange(ref _state, 1, 0) != 0) { throw Invalid(); }
                await (_reserve.Invoke(_issuer, [_id, ct]) as Task ?? throw Invalid()); await RequireAsync(ct);
                var owned = _binding.Owned;
                var scope = Claims(_binding.Claims.Review, _binding.Claims.Authorization, owned.Trust, owned.Pins, DateTimeOffset.UtcNow);
                if (CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(owned.Scope)) { throw Invalid(); }
                permit = new(_binding.Claims.Review, _binding.Claims.Authorization, scope, owned.Trust, owned.Pins, owned.Environment, TimeProvider.System);
                string direct = await Invoke<string>(_issuer, Fixed(_issuer.GetType(), "ReadExecutionConnectionAsync", typeof(Task<string>),
                    [typeof(Guid), typeof(CancellationToken)]), [_id, ct]);
                using var signer = await Invoke<P256MigrationEvidenceSigner>(_issuer, Fixed(_issuer.GetType(), "CreateExecutionSignerAsync", typeof(Task<P256MigrationEvidenceSigner>),
                    [typeof(Guid), typeof(CancellationToken)]), [_id, ct]);
                permit.RequireEvidenceSigner(signer); DateTimeOffset began = DateTimeOffset.UtcNow;
                transport = await CommitWriterLease.CreateOwnedAsync(this, permit, ct);
                var before = await owned.Environment.CaptureLocalFleetAsync(scope, ct);
                var comparison = await owned.Environment.CaptureProductionFleetAsync(scope, ct);
                CurrentAuthLocalSessionArchivePolicy.RequireFleet(before, scope.LocalObservationPolicy, DateTimeOffset.UtcNow);
                CurrentAuthLocalSessionArchivePolicy.RequireFleet(comparison, scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
                Exception actual;
                try { _ = await PostgreSqlCurrentAuthLocalSessionArchive.ExecuteGenuineCommitAckAsync(direct, permit, signer, transport, ct); throw Invalid(); }
                catch (Exception failure) when (failure is NpgsqlException or IOException) { actual = failure; }
                DateTimeOffset failed = DateTimeOffset.UtcNow;
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                var proxy = await transport.CloseAsync(cleanup.Token);
                CurrentAuthArchiveGenuineCommitFacts.RequireSettled(proxy, scope, permit.AuthorizationSha256);
                if (proxy.CreatedAtUtc < began || proxy.DroppedAtUtc > failed || !ReferenceEquals(proxy.Environment, owned.Environment)) { throw Invalid(); }
                RequireBinding(_issuer, _binding);
                var facts = new CurrentAuthArchiveGenuineCommitFailureFacts(_binding.Case, _binding.Claims, actual.GetType().FullName ?? throw Invalid(), before, comparison, began, failed, proxy);
                var retained = await Invoke<CurrentAuthArchiveGenuineDualArtifacts>(_issuer, Fixed(_issuer.GetType(), "RetainCommitFailureAsync",
                    typeof(Task<CurrentAuthArchiveGenuineDualArtifacts>), [typeof(Guid), typeof(CurrentAuthArchiveGenuineCommitFailureFacts), typeof(CancellationToken)]), [_id, facts, ct]);
                return retained.BeganAtUtc != began || retained.EndedAtUtc < failed || retained.EndedAtUtc > DateTimeOffset.UtcNow
                    ? throw Invalid()
                    : new(1, began, DateTimeOffset.UtcNow, retained);
            }
            catch (Exception failure) { primary = failure; throw; }
            finally
            {
                try { if (transport is not null) { await transport.DisposeAsync(); } }
                catch (Exception cleanup) when (primary is not null) { primary.Data["commit_transport_cleanup_failure"] = cleanup.GetType().Name; }
                finally { permit?.Stop(); _ = Interlocked.Exchange(ref _state, 2); }
            }
        }
    }
}
