namespace Legacy.Maliev.DataMigration.Console;

internal sealed class CurrentReviewedCapture
{
    private readonly CurrentAuthArchiveProofAudienceV2 _audience;
    internal CurrentAuthArchiveRecoverySourceEvidence Evidence { get; }
    private CurrentReviewedCapture(CurrentAuthArchiveRecoverySourceEvidence evidence, CurrentAuthArchiveProofAudienceV2 audience)
    { Evidence = evidence; _audience = audience; }
    internal static async Task<CurrentReviewedCapture> CaptureAsync(string protectedSourceConnection, CurrentAuthArchiveProofAudienceV2 audience, CancellationToken ct)
    {
        var evidence = await CurrentAuthArchiveRecoverySourceCapture.CaptureAsync(protectedSourceConnection, audience.SourceIdentitySha256, audience.AcceptedCommitSha, ct);
        var result = new CurrentReviewedCapture(evidence, audience); await result.RequireAsync(ct); return result;
    }
    internal async Task RequireAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != _audience.AcceptedCommitSha || DateTimeOffset.UtcNow >= _audience.ExpiresAtUtc) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        CurrentAuthArchiveRecoveryV2.RequireSource(Evidence, _audience.AcceptedCommitSha, _audience.SourceIdentitySha256, _audience.SourceDefinitionSha256, DateTimeOffset.UtcNow);
    }
}
