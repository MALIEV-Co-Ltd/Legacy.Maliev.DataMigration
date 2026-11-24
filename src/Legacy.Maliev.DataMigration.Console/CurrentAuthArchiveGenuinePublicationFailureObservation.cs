namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveGenuineFailureObservation(CurrentAuthArchiveFleet Local,
    CurrentAuthArchiveFleet Comparison, CurrentAuthArchiveGenuineDualNativeEvidence Native, CurrentAuthArchiveGenuineSlotWitness Witness);

internal sealed partial class CurrentAuthLocalSessionArchiveEnvironment
{
    private readonly CurrentAuthArchiveGenuineExecutionIssuer.SlotDenial? _genuineDenial;

    internal CurrentAuthLocalSessionArchiveEnvironment(CurrentAppOwnedRepairCustody localFiles, CurrentAppOwnedRepairCustody productionFiles,
        WindowsLocalRunAuthority localAuthority, WindowsLocalRunAuthority productionAuthority, CurrentAuthArchiveScope scope,
        FreshSchemaPlan source, CurrentAppOwnedRepairTargetPins localTarget, CurrentAppOwnedRepairTargetPins productionTarget,
        string localConnection, string productionConnection, string localOrdinary, string productionOrdinary,
        CurrentAuthArchiveDeviceProof devices, IReceiptAttestationTrustStore trust, CurrentAuthArchivePins pins, string authorization,
        CurrentAuthArchiveGenuineExecutionIssuer.SlotDenial denial, ICurrentAuthArchiveGenuineExecutionLease owner)
        : this(localFiles, productionFiles, localAuthority, productionAuthority, scope, source, localTarget, productionTarget,
            localConnection, productionConnection, localOrdinary, productionOrdinary, devices, trust, pins, authorization)
    {
        try
        {
            denial.BindFinalEnvironment(owner, this, scope, authorization, localFiles, localAuthority, productionAuthority);
            _genuineDenial = denial;
            _publication.Dispose();
            _publication = new(localFiles, localAuthority, productionAuthority, scope.OperationId, denial);
        }
        catch (Exception primary)
        {
            try { _publication.Dispose(); } catch (Exception cleanup) { primary.Data["denial_publication_cleanup"] = cleanup.GetType().Name; }
            try { _storage.Dispose(); } catch (Exception cleanup) { primary.Data["denial_storage_cleanup"] = cleanup.GetType().Name; }
            try { _cloud?.Dispose(); } catch (Exception cleanup) { primary.Data["denial_cloud_cleanup"] = cleanup.GetType().Name; }
            try { _gate.Dispose(); } catch (Exception cleanup) { primary.Data["denial_gate_cleanup"] = cleanup.GetType().Name; }
            throw;
        }
    }

    // This token parameter is private and never supplied by any ordinary execution method.
    private void RequireObservationCustody(CurrentAuthArchiveGenuineExecutionIssuer.SlotDenial? observation, OwnedCommitProxy? proxy)
    {
        if (observation is null && proxy is null) { RequireHealthy(); return; }
        if (observation is not null && proxy is not null) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        if (proxy is not null)
        {
            if (!_failed || !_reserved || _genuineDenial is not null || !ReferenceEquals(_ownedCommitProxy, proxy) ||
                !_publication.IsAcknowledged($"{_scope.OperationId:D}-Auth-session-archive-failed-or-uncertain.json")) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            _ = proxy.RequirePostFailure();
            CurrentAuthArchiveCapacity.Require(admission: false); _localFiles.Require(); _productionFiles.Require(); RequireInventory(); return;
        }
        if (!_failed || !_reserved || !ReferenceEquals(_genuineDenial, observation) ||
            !_publication.IsAcknowledged($"{_scope.OperationId:D}-Auth-session-archive-failed-or-uncertain.json"))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        _ = observation!.RequirePostFailure(this, _scope, _authorization, _localAuthority, _productionAuthority);
        CurrentAuthArchiveCapacity.Require(admission: false); _localFiles.Require(); _productionFiles.Require(); RequireInventory();
    }

    internal async Task<CurrentAuthArchiveGenuineFailureObservation> ObserveGenuinePublicationFailureAsync(
        CurrentAuthArchiveGenuineExecutionIssuer.SlotDenial observation, CurrentAuthArchiveProofArtifact localHba,
        CurrentAuthArchiveProofArtifact localRules, CurrentAuthArchiveProofArtifact comparisonHba, CurrentAuthArchiveProofArtifact comparisonRules,
        CancellationToken ct)
    {
        RequireObservationCustody(observation, null);
        await RequireAcceptedCoreAsync(_scope, observation, null, ct);
        var local = await CaptureCoreAsync(_scope, true, observation, null, ct);
        var comparison = await CaptureCoreAsync(_scope, false, observation, null, ct);
        var native = await CaptureNativeCoreAsync(_scope, localHba, localRules, comparisonHba, comparisonRules, observation, null, ct);
        RequireObservationCustody(observation, null);
        return new(local, comparison, native, observation.RequirePostFailure(this, _scope, _authorization, _localAuthority, _productionAuthority));
    }
}
