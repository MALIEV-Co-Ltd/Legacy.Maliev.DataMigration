namespace Legacy.Maliev.DataMigration.Console;

internal static partial class CurrentAuthLocalSessionArchiveDeviceProcess
{
    // Read-only contexts only. These unknown markers remain rejected by every V1 serialized scope/admission path.
    internal const CurrentAuthArchiveProofAdmission IntendedObservationMode = (CurrentAuthArchiveProofAdmission)4;
    private const CurrentAuthArchiveProofAdmission PersistentV2ObservationMode = (CurrentAuthArchiveProofAdmission)3;
    internal static async Task<CurrentAuthArchiveDeviceProof> ObserveVersionedContextAsync(CurrentAuthArchiveScope scope,
        string firstRoot, string secondRoot, CurrentAppOwnedRepairCustody firstFiles, CurrentAppOwnedRepairCustody secondFiles, CancellationToken ct)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        RequireVersionedDeviceContext(scope, now);
        var request = new CurrentAuthArchiveDevicePreflightRequest("Legacy.Maliev.CurrentAuth.ArchiveDevicePreflight.v1", scope.OperationId,
            scope.LocalObservationPolicy.SourceCommitSha, scope.LocalObservationPolicy.RunBindingSha256, scope.ProductionObservationPolicy.RunBindingSha256,
            scope.LocalObservationPolicy.TargetObservationSha256, scope.ProductionObservationPolicy.TargetObservationSha256,
            scope.Paths, firstRoot, secondRoot, now, scope.ExpiresAtUtc < now.AddMinutes(1) ? scope.ExpiresAtUtc : now.AddMinutes(1));
        return await ObservePreflightAsync(request, firstFiles, secondFiles, ct);
    }
    internal static void RequireVersionedDeviceContext(CurrentAuthArchiveScope scope, DateTimeOffset now)
    {
        if (scope.ProofAdmission is not (IntendedObservationMode or PersistentV2ObservationMode) || scope.ComponentSubject is not null ||
            scope.CapturedAtUtc.Offset != TimeSpan.Zero || scope.ExpiresAtUtc.Offset != TimeSpan.Zero || scope.CapturedAtUtc > now ||
            scope.ExpiresAtUtc <= now || scope.ExpiresAtUtc <= scope.CapturedAtUtc || scope.ExpiresAtUtc - scope.CapturedAtUtc > TimeSpan.FromMinutes(2))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        CurrentAuthLocalSessionArchiveEnvironment.RequireObservationPolicies(scope, now);
    }
}
