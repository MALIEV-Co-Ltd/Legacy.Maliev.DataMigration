namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveGenuineIssuer
{
    internal async Task<CurrentAuthArchiveGenuineDualArtifacts> ExecuteDualDurableReadbackAsync(CancellationToken ct)
    {
        return (await ExecuteDualDurableReadbackMethodAsync(ct)).Artifacts;
    }

    internal async Task<CurrentAuthArchiveGenuineProviderMethodResult> ExecuteDualDurableReadbackMethodAsync(CancellationToken ct)
    {
        var capability = await CurrentAuthArchiveGenuineCapability.AuthenticateConsoleOwnedIssuerAsync(this, ct);
        try
        {
            // These are issued for the actual already observed scope; all three
            // fixed role keys remain inside the held protected parent custody.
            var claims = await _lease.PrepareDualHelperClaimsAsync(ct);
            return await capability.ExecuteDualDurableReadbackMethodAsync(claims, ct);
        }
        finally { capability.Stop(); }
    }

    internal async Task<CurrentAuthArchiveGenuineDualArtifacts> RetainDualHelperFactsAsync(Guid capabilityId,
        CurrentAuthArchiveGenuineDualFacts facts, CancellationToken ct)
    {
        var held = await RequireOwnedCapabilityAsync(capabilityId, requireBaseline: false, ct);
        return CurrentAuthLocalSessionArchivePolicy.Hash(facts.Scope) != CurrentAuthLocalSessionArchivePolicy.Hash(held.Scope)
            ? throw CurrentAuthArchiveGenuineHost.Invalid("dual_helper_scope")
            : await _lease.RetainDualHelperFactsAsync(facts, ct);
    }
}
