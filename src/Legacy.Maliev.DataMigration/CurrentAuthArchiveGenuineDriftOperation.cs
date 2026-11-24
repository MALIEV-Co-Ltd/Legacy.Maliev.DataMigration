using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed partial class CurrentAuthLocalSessionArchivePermit
{
    internal sealed partial class GenuineExecutionCapability
    {
        private async Task<CurrentAuthArchiveGenuineExecutionMethodResult> ExecuteDriftAsync(CancellationToken ct)
        {
            CurrentAuthLocalSessionArchivePermit? permit = null;
            try
            {
                await RequireAsync(ct);
                if (!CurrentAuthArchiveGenuineDrift.IsCase(_binding.Case) || Interlocked.CompareExchange(ref _state, 1, 0) != 0) { throw Invalid(); }
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
                var applied = await Invoke<CurrentAuthArchiveGenuineDriftApplied>(_issuer, Fixed(_issuer.GetType(), "ApplyDriftAsync", typeof(Task<CurrentAuthArchiveGenuineDriftApplied>),
                    [typeof(Guid), typeof(CancellationToken)]), [_id, ct]);
                CurrentAuthArchiveGenuineDrift.RequireApplied(scope, applied, DateTimeOffset.UtcNow);
                MigrationExecutionException? actual = null;
                try
                {
                    _ = await PostgreSqlCurrentAuthLocalSessionArchive.ExecuteAsync(connection, permit, signer, ct);
                }
                catch (MigrationExecutionException failure) when (failure.Code == "current_auth_local_archive_invalid") { actual = failure; }
                if (actual is null) { throw Invalid(); }
                var facts = new CurrentAuthArchiveGenuineDriftFailure(_binding.Case, _binding.Claims, applied,
                    actual.GetType().FullName ?? throw Invalid(), actual.Code, actual.HResult, began, DateTimeOffset.UtcNow);
                // No reset or failed-Env observer is allowed: the fixed receiver uses ordinary read-only methods.
                var artifacts = await Invoke<CurrentAuthArchiveGenuineDualArtifacts>(_issuer, Fixed(_issuer.GetType(), "RetainDriftFailureAsync", typeof(Task<CurrentAuthArchiveGenuineDualArtifacts>),
                    [typeof(Guid), typeof(CurrentAuthArchiveGenuineDriftFailure), typeof(CancellationToken)]), [_id, facts, ct]);
                return artifacts.BeganAtUtc != began || artifacts.EndedAtUtc < facts.FailedAtUtc || artifacts.EndedAtUtc > DateTimeOffset.UtcNow
                    ? throw Invalid()
                    : new(1, began, DateTimeOffset.UtcNow, artifacts);
            }
            finally { permit?.Stop(); _ = Interlocked.Exchange(ref _state, 2); }
        }
    }
}
