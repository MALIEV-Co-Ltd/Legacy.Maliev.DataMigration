using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair : ICurrentAuthArchiveGenuineOwnedLease
{
    internal static async Task<ICurrentAuthArchiveGenuineOwnedLease> OpenLeaseAsync(CurrentAuthArchiveGenuineHostConfiguration request, CancellationToken ct)
    {
        return await CreateAsync(request, ct);
    }

    async Task<CurrentAuthArchiveGenuineAttestation> ICurrentAuthArchiveGenuineOwnedLease.AttestAsync(bool requireBaseline, CancellationToken ct)
    {
        if (requireBaseline) { await RequireAsync(ct); }
        else
        {
            if (_disposed || _first is null || _second is null || _firstAuthority is null || _secondAuthority is null || _environment is null ||
                _scope is null || DateTimeOffset.UtcNow >= _scope.ExpiresAtUtc) { throw Invalid(); }
            using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct, _lease.Token, _first.Token, _second.Token);
            _bundle.Require(); await _inputs.RequireAsync(lease.Token);
            await _first.RequireHealthyHeldAsync(_firstAuthority, lease.Token);
            await _second.RequireHealthyHeldAsync(_secondAuthority, lease.Token);
            // Ownership/policy liveness remains mandatory after reservation. The
            // executor separately checks phase-specific fleets after its deletes.
            await _environment.RequireAcceptedSourceOwnerCustodyAndTargetsAsync(Scope, lease.Token);
            _bundle.Require();
        }
        return _environment is null
            ? throw Invalid()
            : new("helper", "dual-durable-readback", Scope, Subject, _inputs.Source,
            typeof(CurrentAuthArchiveGenuineOwnedPair).Assembly.Location, typeof(MigrationConsole).Assembly.Location,
            typeof(CurrentAuthLocalSessionArchivePermit).Assembly.Location, _inputs.Pins, _inputs.TrustStore, _environment);
    }
}
