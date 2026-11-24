using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed partial class CurrentAuthLocalSessionArchivePermit
{
    internal sealed partial class GenuineExecutionCapability
    {
        private async Task<CurrentAuthArchiveGenuineExecutionMethodResult> ExecutePublicationFailureAsync(CancellationToken ct)
        {
            CurrentAuthLocalSessionArchivePermit? permit = null;
            try
            {
                await RequireAsync(ct);
                if (!CurrentAuthArchiveGenuinePublicationFault.IsCase(_binding.Case) || Interlocked.CompareExchange(ref _state, 1, 0) != 0) { throw Invalid(); }
                await (_reserve.Invoke(_issuer, [_id, ct]) as Task ?? throw Invalid()); await RequireAsync(ct);
                var owned = _binding.Owned;
                var scope = Claims(_binding.Claims.Review, _binding.Claims.Authorization, owned.Trust, owned.Pins, DateTimeOffset.UtcNow);
                if (CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(owned.Scope)) { throw Invalid(); }
                permit = new(_binding.Claims.Review, _binding.Claims.Authorization, scope, owned.Trust, owned.Pins, owned.Environment, TimeProvider.System);
                string connection = await Invoke<string>(_issuer, Fixed(_issuer.GetType(), "ReadExecutionConnectionAsync", typeof(Task<string>),
                    [typeof(Guid), typeof(CancellationToken)]), [_id, ct]);
                using var signer = await Invoke<P256MigrationEvidenceSigner>(_issuer, Fixed(_issuer.GetType(), "CreateExecutionSignerAsync", typeof(Task<P256MigrationEvidenceSigner>),
                    [typeof(Guid), typeof(CancellationToken)]), [_id, ct]);
                var endpoint = new NpgsqlConnectionStringBuilder(connection);
                if (endpoint.Host != "127.0.0.1" || endpoint.Database != "Auth" || endpoint.Port is < 1 or > 65535 || endpoint.Pooling ||
                    endpoint.Username != scope.LocalObservationPolicy.Maintenance.Role || string.IsNullOrWhiteSpace(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options)) { throw Invalid(); }
                permit.RequireEvidenceSigner(signer); await RequireAsync(ct);
                DateTimeOffset began = DateTimeOffset.UtcNow;
                var local = await owned.Environment.CaptureLocalFleetAsync(scope, ct);
                var comparison = await owned.Environment.CaptureProductionFleetAsync(scope, ct);
                CurrentAuthLocalSessionArchivePolicy.RequireFleet(local, scope.LocalObservationPolicy, DateTimeOffset.UtcNow);
                CurrentAuthLocalSessionArchivePolicy.RequireFleet(comparison, scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
                Exception actual;
                try
                {
                    _ = await PostgreSqlCurrentAuthLocalSessionArchive.ExecuteAsync(connection, permit, signer, ct);
                    throw Invalid();
                }
                catch (Exception failure) when (failure is IOException or UnauthorizedAccessException) { actual = failure; }
                // No stopped Env is re-admitted. Only the fixed typed receiver may perform the separately fenced read-only observation.
                RequireBinding(_issuer, _binding);
                var facts = new CurrentAuthArchiveGenuinePublicationFailureFacts(_binding.Case, _binding.Claims,
                    actual.GetType().FullName ?? throw Invalid(), actual.HResult, local, comparison, began, DateTimeOffset.UtcNow);
                var retained = await Invoke<CurrentAuthArchiveGenuineDualArtifacts>(_issuer, Fixed(_issuer.GetType(), "RetainPublicationFailureAsync",
                    typeof(Task<CurrentAuthArchiveGenuineDualArtifacts>), [typeof(Guid), typeof(CurrentAuthArchiveGenuinePublicationFailureFacts), typeof(CancellationToken)]), [_id, facts, ct]);
                return retained.BeganAtUtc != began || retained.EndedAtUtc < facts.FailedAtUtc || retained.EndedAtUtc > DateTimeOffset.UtcNow
                    ? throw Invalid()
                    : new(1, began, DateTimeOffset.UtcNow, retained);
            }
            finally { permit?.Stop(); _ = Interlocked.Exchange(ref _state, 2); }
        }
    }
}
