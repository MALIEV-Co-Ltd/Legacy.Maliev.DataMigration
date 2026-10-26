namespace Legacy.Maliev.DataMigration;

/// <summary>Observation only. The sink never receives native connections, transactions or keys.</summary>
internal interface ICurrentOwnerIsoNativeProofObserver
{
    Task ObserveCandidateAsync(CurrentOwnerIsoNativeObservation locked,
        CurrentOwnerIsoNativeObservation candidate, CancellationToken ct);
}

internal static class CurrentOwnerIsoNativeProofObservation
{
    internal static Task RecordAsync(CurrentOwnerIsoRepairPermit permit, ApprovedCurrentOwnerIsoOverlay contract,
        CurrentOwnerIsoNativeObservation locked, CurrentOwnerIsoNativeObservation candidate, CancellationToken ct)
    {
        if (permit.Environment is not ICurrentOwnerIsoNativeProofObserver sink) { return Task.CompletedTask; }
        var scope = permit.Scope;
        if (scope.ProofAdmission is not (CurrentOwnerIsoProofAdmission.DisposableNativeBootstrap or CurrentOwnerIsoProofAdmission.DisposableNativeComponent or CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap) ||
            scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) ||
            DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        CurrentOwnerIsoNativePreservation.RequirePreserved(locked, candidate, contract);
        return sink.ObserveCandidateAsync(Copy(locked), Copy(candidate), ct);
    }
    private static CurrentOwnerIsoNativeObservation Copy(CurrentOwnerIsoNativeObservation x)
    {
        return new(x.Snapshot, x.OverlaySha256, x.Selected, x.LiteralRows, x.CopyCatalog(), x.CopyStorage(), x.SnapshotXmin);
    }
}
