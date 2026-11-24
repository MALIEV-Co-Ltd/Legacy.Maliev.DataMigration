namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveGenuineExecutionInput(string Kind, CurrentAuthArchiveGenuineHostConfiguration Request);

internal static class CurrentAuthArchiveGenuineExecutionInputContract
{
    internal const string Kind = "current-auth-archive-genuine-execution13-input-v1";
    internal static void Require(CurrentAuthArchiveGenuineExecutionInput input, CurrentAuthArchiveGenuineExecutionCase expected)
    {
        CurrentAuthArchiveGenuineExecutionCases.RequireImplemented(expected);
        var (Phase, CaseId) = CurrentAuthArchiveGenuineExecutionCases.Identity(expected);
        if (input is null || input.Kind != Kind || input.Request is null || input.Request.Phase != Phase || input.Request.CaseId != CaseId)
        { throw CurrentAuthArchiveGenuineExecutionCases.Invalid(); }
        CurrentAuthArchiveGenuineHost.RequireInput(input.Request);
    }
}

// Only the exact sealed qualified Tests lease can implement the issuer's runtime handoff.
// This interface alone grants no authority; no serialized target or implementation is admitted.
internal interface ICurrentAuthArchiveGenuineExecutionLease : IAsyncDisposable
{
    Task<CurrentAuthArchiveGenuineExecutionAttestation> AttestExecutionAsync(bool baseline, CancellationToken ct);
    Task<string> ReadExecutionConnectionAsync(CancellationToken ct);
    Task<P256MigrationEvidenceSigner> CreateExecutionSignerAsync(CancellationToken ct);
    Task<CurrentAuthArchiveGenuineDualArtifacts> RetainExecutionAsync(CurrentAuthArchiveGenuineExecutionFacts facts, CancellationToken ct);
    Task BindPublicationDenialAsync(CurrentAuthArchiveGenuineExecutionIssuer.SlotDenial denial, CancellationToken ct);
    Task<CurrentAuthArchiveGenuineDualArtifacts> RetainPublicationFailureAsync(CurrentAuthArchiveGenuinePublicationFailureFacts facts, CancellationToken ct);
    Task<CurrentAuthArchiveGenuineDriftApplied> ApplyDriftAsync(CancellationToken ct);
    Task<CurrentAuthArchiveGenuineDualArtifacts> RetainDriftFailureAsync(CurrentAuthArchiveGenuineDriftFailure facts, CancellationToken ct);
    Task<CurrentAuthArchiveGenuineCommitProxyInfo> OpenCommitProxyAsync(CurrentAuthArchiveGenuineExecutionIssuer.CommitProxyFactory factory, CancellationToken ct);
    Task<CurrentAuthArchiveGenuineCommitProxyInfo> ReadCommitProxyAsync(CancellationToken ct);
    Task ArmCommitProxyAsync(int backendPid, CancellationToken ct);
    Task<CurrentAuthArchiveGenuineCommitProxyInfo> CloseCommitProxyAsync(CancellationToken ct);
    Task<CurrentAuthArchiveGenuineDualArtifacts> RetainCommitFailureAsync(CurrentAuthArchiveGenuineCommitFailureFacts facts, CancellationToken ct);
}
