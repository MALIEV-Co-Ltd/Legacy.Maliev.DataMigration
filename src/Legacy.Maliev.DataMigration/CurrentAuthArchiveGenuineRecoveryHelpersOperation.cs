namespace Legacy.Maliev.DataMigration;

internal sealed partial class CurrentAuthArchiveGenuineCapability
{
    internal async Task<CurrentAuthArchiveGenuineProviderMethodResult> ExecuteRecoveryHelperAsync(CurrentAuthArchiveGenuineHelperClaims claims,
        CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, CancellationToken ct)
    {
        var scope = CurrentAuthLocalSessionArchivePermit.RequireGenuineRecoveryHelperClaims(claims, _binding.Trust, _binding.Pins, helperCase, DateTimeOffset.UtcNow);
        if (CurrentAuthLocalSessionArchivePolicy.Hash(scope) != CurrentAuthLocalSessionArchivePolicy.Hash(_binding.Scope) ||
            _binding.CaseId != CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(helperCase)) { throw Invalid(); }
        await RequireAsync(ct); await ReserveOnceAsync(ct);
        DateTimeOffset began = DateTimeOffset.UtcNow;
        var environment = _binding.Environment;
        var localBefore = await environment.CaptureLocalFleetAsync(scope, ct);
        var comparisonBefore = await environment.CaptureProductionFleetAsync(scope, ct);
        RequireOriginal(localBefore, comparisonBefore);
        var execute = FixedMethod(_issuer.GetType(), "ExecuteRecoveryHelperFaultAsync", typeof(Task<CurrentAuthArchiveGenuineRecoveryHelpersOutcome>),
            [typeof(Guid), typeof(CurrentAuthArchiveGenuineRecoveryHelpersRequest), typeof(CancellationToken)]);
        var request = new CurrentAuthArchiveGenuineRecoveryHelpersRequest(scope, claims, localBefore.Auth.Sessions, began);
        var pending = execute.Invoke(_issuer, [_capabilityId, request, ct]) as Task<CurrentAuthArchiveGenuineRecoveryHelpersOutcome> ?? throw Invalid();
        var outcome = await pending.ConfigureAwait(false);
        int observedCode = CurrentAuthArchiveGenuineRecoveryHelpers.RequireObservedOutcome(outcome, scope, helperCase,
            CurrentAuthLocalSessionArchivePolicy.Hash(claims.Authorization), began);
        var localAfter = await environment.CaptureLocalFleetAsync(scope, ct);
        var comparisonAfter = await environment.CaptureProductionFleetAsync(scope, ct);
        RequireOriginal(localAfter, comparisonAfter); await RequireAsync(ct);
        var preserve = new CurrentAuthArchiveGenuineDualFacts(scope, claims, outcome.Manifest, localBefore, localAfter,
            comparisonBefore, comparisonAfter, began);
        var receiver = FixedMethod(_issuer.GetType(), "RetainRecoveryHelperFactsAsync", typeof(Task<CurrentAuthArchiveGenuineDualArtifacts>),
            [typeof(Guid), typeof(CurrentAuthArchiveGenuineRecoveryHelpersFacts), typeof(CancellationToken)]);
        var retained = receiver.Invoke(_issuer, [_capabilityId, new CurrentAuthArchiveGenuineRecoveryHelpersFacts(preserve, outcome), ct])
            as Task<CurrentAuthArchiveGenuineDualArtifacts> ?? throw Invalid();
        var artifacts = await retained.ConfigureAwait(false);
        await RequireAsync(ct);
        return new(observedCode, began, DateTimeOffset.UtcNow, artifacts);

        void RequireOriginal(CurrentAuthArchiveFleet local, CurrentAuthArchiveFleet comparison)
        {
            CurrentAuthLocalSessionArchivePolicy.RequireFleet(local, scope.LocalObservationPolicy, DateTimeOffset.UtcNow);
            CurrentAuthLocalSessionArchivePolicy.RequireFleet(comparison, scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
        }
    }
}
