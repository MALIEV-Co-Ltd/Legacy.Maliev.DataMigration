namespace Legacy.Maliev.DataMigration;

internal sealed partial class CurrentAuthArchiveGenuineCapability
{
    internal async Task<CurrentAuthArchiveGenuineDualArtifacts> ExecuteDualDurableReadbackAsync(
        CurrentAuthArchiveGenuineHelperClaims claims, CancellationToken ct)
    {
        return (await ExecuteDualDurableReadbackMethodAsync(claims, ct)).Artifacts;
    }

    internal async Task<CurrentAuthArchiveGenuineProviderMethodResult> ExecuteDualDurableReadbackMethodAsync(
        CurrentAuthArchiveGenuineHelperClaims claims, CancellationToken ct)
    {
        var scope = CurrentAuthLocalSessionArchivePermit.RequireGenuineDualHelperClaims(claims, _binding.Trust, _binding.Pins, DateTimeOffset.UtcNow);
        if (CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(_binding.Scope)) { throw Invalid(); }
        await RequireAsync(ct);
        await ReserveOnceAsync(ct);
        DateTimeOffset began = DateTimeOffset.UtcNow;
        var environment = _binding.Environment;
        await environment.RequireAcceptedSourceOwnerCustodyAndTargetsAsync(scope, ct);
        var localBefore = await environment.CaptureLocalFleetAsync(scope, ct);
        var comparisonBefore = await environment.CaptureProductionFleetAsync(scope, ct);
        RequireOriginal(localBefore, comparisonBefore);
        var manifest = await CurrentAuthLocalSessionArchiveCrypto.WriteAndVerifyAsync(environment.RecoveryStorage,
            scope, CurrentAuthLocalSessionArchivePolicy.Hash(claims.Authorization), localBefore.Auth.Sessions, ct);
        await CurrentAuthLocalSessionArchiveCrypto.VerifyAsync(environment.RecoveryStorage, scope, manifest, localBefore.Auth.Sessions, ct);
        var localAfter = await environment.CaptureLocalFleetAsync(scope, ct);
        var comparisonAfter = await environment.CaptureProductionFleetAsync(scope, ct);
        RequireOriginal(localAfter, comparisonAfter);
        await RequireAsync(ct);
        var facts = new CurrentAuthArchiveGenuineDualFacts(scope, claims, manifest,
            localBefore, localAfter, comparisonBefore, comparisonAfter, began);
        // Fixed compiled receiver on the exact issuer already authenticated by
        // this capability. No receiver, reflection name or callback is supplied.
        var receiver = FixedMethod(_issuer.GetType(), "RetainDualHelperFactsAsync", typeof(Task<CurrentAuthArchiveGenuineDualArtifacts>),
            [typeof(Guid), typeof(CurrentAuthArchiveGenuineDualFacts), typeof(CancellationToken)]);
        var pending = receiver.Invoke(_issuer, [_capabilityId, facts, ct]) as Task<CurrentAuthArchiveGenuineDualArtifacts> ?? throw Invalid();
        var retained = await pending.ConfigureAwait(false);
        await RequireAsync(ct);
        return retained.BeganAtUtc != began || retained.EndedAtUtc > DateTimeOffset.UtcNow || retained.EndedAtUtc < began
            ? throw Invalid()
            : new(0, began, DateTimeOffset.UtcNow, retained);
        void RequireOriginal(CurrentAuthArchiveFleet local, CurrentAuthArchiveFleet comparison)
        {
            CurrentAuthLocalSessionArchivePolicy.RequireFleet(local, scope.LocalObservationPolicy, DateTimeOffset.UtcNow);
            CurrentAuthLocalSessionArchivePolicy.RequireFleet(comparison, scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
        }
    }
}
