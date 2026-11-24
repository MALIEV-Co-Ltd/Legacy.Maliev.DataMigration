namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveRecoveryV2Input(string Kind, CurrentAuthArchiveGenuineHostConfiguration Request,
    CurrentAuthArchiveProofArtifact Audience, CurrentAuthArchiveProofArtifact CaseBinding, CurrentAuthArchiveProofArtifact SourceCredential);
internal static class CurrentAuthArchiveRecoveryV2InputContract
{
    internal static void Require(CurrentAuthArchiveRecoveryV2Input input, CurrentAuthArchiveRecoveryV2Case expected)
    {
        string id = CurrentAuthArchiveRecoveryV2.CaseId(expected);
        if (input is null || input.Kind != "current-auth-archive-recovery-input-v2" || input.Request is null || input.Request.Phase != "recovery" ||
            input.Request.CaseId != id || input.Audience is null || input.CaseBinding is null || input.SourceCredential is null) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        CurrentAuthArchiveGenuineHost.RequireInput(input.Request);
        string root = Path.GetDirectoryName(input.Request.Inputs.ParentBinding.Path)!;
        foreach (var artifact in new[] { input.Audience, input.CaseBinding, input.SourceCredential })
        { if (!Path.IsPathFullyQualified(artifact.Path) || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(artifact.Path), root) || !CurrentAuthRepairPermit.HashShape(artifact.Sha256)) { throw CurrentAuthArchiveRecoveryV2.Invalid(); } }
    }
}

internal interface ICurrentAuthArchiveRecoveryV2Lease : IAsyncDisposable
{
    Task<CurrentAuthArchiveGenuineExecutionAttestation> AttestExecutionAsync(bool baseline, CancellationToken ct);
    Task<string> ReadExecutionConnectionAsync(CancellationToken ct);
    Task<P256MigrationEvidenceSigner> CreateExecutionSignerAsync(CancellationToken ct);
    Task<CurrentAuthArchiveGenuineDualArtifacts> CompleteRecoveryAsync(CurrentAuthArchiveGenuineExecutionFacts setup, CancellationToken ct);
}
