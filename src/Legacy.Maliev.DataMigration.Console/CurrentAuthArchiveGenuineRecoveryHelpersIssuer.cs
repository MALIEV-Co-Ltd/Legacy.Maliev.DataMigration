namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveGenuineIssuer
{
    internal async Task<CurrentAuthArchiveGenuineProviderMethodResult> ExecuteRecoveryHelperAsync(CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, CancellationToken ct)
    {
        var capability = await CurrentAuthArchiveGenuineCapability.AuthenticateConsoleOwnedIssuerAsync(this, ct);
        try
        {
            var claims = await _lease.PrepareRecoveryHelperClaimsAsync(helperCase, ct);
            return await capability.ExecuteRecoveryHelperAsync(claims, helperCase, ct);
        }
        finally { capability.Stop(); }
    }

    internal async Task<CurrentAuthArchiveGenuineRecoveryHelpersOutcome> ExecuteRecoveryHelperFaultAsync(Guid capabilityId,
        CurrentAuthArchiveGenuineRecoveryHelpersRequest request, CancellationToken ct)
    {
        var held = await RequireOwnedCapabilityAsync(capabilityId, requireBaseline: false, ct);
        return CurrentAuthLocalSessionArchivePolicy.Hash(request.Scope) != CurrentAuthLocalSessionArchivePolicy.Hash(held.Scope)
            ? throw Invalid()
            : await _lease.ExecuteRecoveryHelperFaultAsync(request, ct);
    }

    internal async Task<CurrentAuthArchiveGenuineDualArtifacts> RetainRecoveryHelperFactsAsync(Guid capabilityId,
        CurrentAuthArchiveGenuineRecoveryHelpersFacts facts, CancellationToken ct)
    {
        var held = await RequireOwnedCapabilityAsync(capabilityId, requireBaseline: false, ct);
        return CurrentAuthLocalSessionArchivePolicy.Hash(facts.Preservation.Scope) != CurrentAuthLocalSessionArchivePolicy.Hash(held.Scope)
            ? throw Invalid()
            : await _lease.RetainRecoveryHelperFactsAsync(facts, ct);
    }
}
