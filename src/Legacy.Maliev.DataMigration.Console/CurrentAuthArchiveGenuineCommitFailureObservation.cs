namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveGenuineCommitFailureObservation(CurrentAuthArchiveFleet Local, CurrentAuthArchiveFleet Comparison,
    CurrentAuthArchiveGenuineDualNativeEvidence Native, CurrentAuthArchiveGenuineCommitProxyInfo Proxy, byte[] Created, byte[] Disposed);
internal sealed partial class CurrentAuthLocalSessionArchiveEnvironment
{
    internal async Task<CurrentAuthArchiveGenuineCommitFailureObservation> ObserveGenuineCommitFailureAsync(OwnedCommitProxy proxy,
        CurrentAuthArchiveProofArtifact localHba, CurrentAuthArchiveProofArtifact localRules, CurrentAuthArchiveProofArtifact comparisonHba,
        CurrentAuthArchiveProofArtifact comparisonRules, CancellationToken ct)
    {
        RequireObservationCustody(null, proxy); await RequireAcceptedCoreAsync(_scope, null, proxy, ct);
        var local = await CaptureCoreAsync(_scope, true, null, proxy, ct); var comparison = await CaptureCoreAsync(_scope, false, null, proxy, ct);
        var native = await CaptureNativeCoreAsync(_scope, localHba, localRules, comparisonHba, comparisonRules, null, proxy, ct);
        RequireObservationCustody(null, proxy);
        byte[] Read(string phase)
        {
            return _localFiles.Read(Path.Combine(_localAuthority.Binding.ArtifactRootCanonicalPath,
            $"genuine-commit-proxy-{_scope.OperationId:N}-{phase}.json"), sharedReader: true, maximumBytes: 65536);
        }

        return new(local, comparison, native, proxy.RequirePostFailure(), Read("created"), Read("disposed"));
    }
}
