namespace Legacy.Maliev.DataMigration.Console;

// The interface grants no authority. The issuer accepts only the exact sealed
// lease type loaded from its qualified, held and seed-bound Tests image.
internal interface ICurrentAuthArchiveGenuineOwnedLease : IAsyncDisposable
{
    Task<CurrentAuthArchiveGenuineAttestation> AttestAsync(bool requireBaseline, CancellationToken ct);
    Task<CurrentAuthArchiveGenuineHelperClaims> PrepareDualHelperClaimsAsync(CancellationToken ct);
    Task<CurrentAuthArchiveGenuineDualArtifacts> RetainDualHelperFactsAsync(CurrentAuthArchiveGenuineDualFacts facts, CancellationToken ct);
    Task<CurrentAuthArchiveGenuineHelperClaims> PrepareRecoveryHelperClaimsAsync(CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, CancellationToken ct);
    Task<CurrentAuthArchiveGenuineRecoveryHelpersOutcome> ExecuteRecoveryHelperFaultAsync(CurrentAuthArchiveGenuineRecoveryHelpersRequest request, CancellationToken ct);
    Task<CurrentAuthArchiveGenuineDualArtifacts> RetainRecoveryHelperFactsAsync(CurrentAuthArchiveGenuineRecoveryHelpersFacts facts, CancellationToken ct);
}
