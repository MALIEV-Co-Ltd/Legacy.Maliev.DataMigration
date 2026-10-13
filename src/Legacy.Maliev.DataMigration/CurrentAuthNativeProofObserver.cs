namespace Legacy.Maliev.DataMigration;

/// <summary>Read-only disposable component evidence sink. Never receives a connection, transaction or signing key.</summary>
internal interface ICurrentAuthNativeProofObserver
{
    Task ObserveCandidateAsync(CurrentAuthNativeObservation locked, CurrentAuthNativeObservation candidate, CancellationToken ct);
}

internal static class CurrentAuthNativeProofObservation
{
    internal static Task CaptureCandidateAsync(CurrentAuthRepairPermit permit, CurrentAuthNativeObservation locked,
        CurrentAuthNativeObservation candidate, CancellationToken ct)
    {
        if (permit.Environment is not ICurrentAuthNativeProofObserver observer) { return Task.CompletedTask; }
        // A production or persistent scope cannot activate the test observation route.
        if (permit.Scope.ProofAdmission is not (CurrentAuthProofAdmission.DisposableNativeBootstrap or CurrentAuthProofAdmission.DisposableNativeComponent or CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap) ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(permit.Scope.Target))
        { throw CurrentAuthRepairPermit.Invalid(); }
        CurrentAuthNativePreservation.RequirePreserved(locked, candidate);
        return observer.ObserveCandidateAsync(Copy(locked), Copy(candidate), ct);
    }

    private static CurrentAuthNativeObservation Copy(CurrentAuthNativeObservation value) =>
        new(CurrentAuthRepairPermit.CopySnapshot(value.Snapshot), value.CopyTuples(), value.CopyStorage(), value.CopyExpressions());
}
