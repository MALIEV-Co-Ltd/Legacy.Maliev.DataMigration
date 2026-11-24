using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    private CurrentAuthLocalSessionArchiveEnvironment.OwnedCommitProxy? _commitProxy;
    async Task<CurrentAuthArchiveGenuineCommitProxyInfo> ICurrentAuthArchiveGenuineExecutionLease.OpenCommitProxyAsync(
        CurrentAuthArchiveGenuineExecutionIssuer.CommitProxyFactory factory, CancellationToken ct)
    {
        await RequireExecutionLiveAsync(false, ct);
        if (_executionCase != CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost || _commitProxy is not null || _environment is null || _publicationDenial is not null)
        { throw Invalid(); }
        _commitProxy = await _environment.OpenOwnedCommitProxyAsync(factory, ct); return _commitProxy.Observe();
    }
    async Task<CurrentAuthArchiveGenuineCommitProxyInfo> ICurrentAuthArchiveGenuineExecutionLease.ReadCommitProxyAsync(CancellationToken ct)
    { await RequireExecutionLiveAsync(false, ct); return (_commitProxy ?? throw Invalid()).Observe(); }
    async Task ICurrentAuthArchiveGenuineExecutionLease.ArmCommitProxyAsync(int backendPid, CancellationToken ct)
    { await RequireExecutionLiveAsync(false, ct); (_commitProxy ?? throw Invalid()).Arm(backendPid); }
    async Task<CurrentAuthArchiveGenuineCommitProxyInfo> ICurrentAuthArchiveGenuineExecutionLease.CloseCommitProxyAsync(CancellationToken ct)
    {
        if (_commitProxy is null) { throw Invalid(); }
        await _commitProxy.DisposeAsync(); ct.ThrowIfCancellationRequested(); return _commitProxy.Observe();
    }
    async Task<CurrentAuthArchiveGenuineDualArtifacts> ICurrentAuthArchiveGenuineExecutionLease.RetainCommitFailureAsync(
        CurrentAuthArchiveGenuineCommitFailureFacts failure, CancellationToken ct)
    {
        if (_disposed || _executionEnvironmentClosed || _environment is null || _executionClaims is null || failure.Claims != _executionClaims ||
            _executionCase != CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost || failure.Case != _executionCase || _commitProxy is null ||
            _first is null || _second is null || _firstAuthority is null || _secondAuthority is null || _firstPolicy is null || _secondPolicy is null ||
            failure.BeganAtUtc > failure.FailedAtUtc || failure.FailedAtUtc > DateTimeOffset.UtcNow || !ReferenceEquals(failure.Proxy.Environment, _environment)) { throw Invalid(); }
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct, _lease.Token, _first.Token, _second.Token);
        _bundle.Require(); await _inputs.RequireAsync(lease.Token);
        await _first.RequireHealthyHeldAsync(_firstAuthority, lease.Token); await _second.RequireHealthyHeldAsync(_secondAuthority, lease.Token);
        var observed = await _environment.ObserveGenuineCommitFailureAsync(_commitProxy, _firstPolicy.HbaFile, _firstPolicy.RawRules,
            _secondPolicy.HbaFile, _secondPolicy.RawRules, lease.Token);
        if (CurrentAuthLocalSessionArchivePolicy.Hash(observed.Proxy) != CurrentAuthLocalSessionArchivePolicy.Hash(failure.Proxy) ||
            observed.Proxy.DroppedAtUtc < failure.BeganAtUtc || observed.Proxy.DroppedAtUtc > failure.FailedAtUtc || observed.Proxy.ClosedAtUtc < failure.FailedAtUtc) { throw Invalid(); }
        var facts = new CurrentAuthArchiveGenuineExecutionFacts(failure.Case, failure.Claims, null, failure.LocalBefore, observed.Local,
            failure.ComparisonBefore, observed.Comparison, failure.BeganAtUtc, DateTimeOffset.UtcNow);
        return await RetainExecutionCoreAsync(facts, null, null, failure, observed, lease.Token);
    }

    internal static CurrentAuthArchiveReceipt[] RequireCommitFailureJournal(IReadOnlyDictionary<string, byte[]> journal, CurrentAuthArchiveScope scope,
        CurrentAuthArchiveGenuineExecutionFacts facts, CurrentAuthArchiveGenuineCommitFailureFacts failure,
        CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust)
    {
        string auth = CurrentAuthLocalSessionArchivePolicy.Hash(facts.Claims.Authorization);
        CurrentAuthArchiveGenuineCommitFacts.RequireSettled(failure.Proxy, scope, auth);
        if (scope.ComponentSubject?.Seed.CaseId != "commit-ack-lost" || facts.Case != CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost || failure.Case != facts.Case || facts.Claims != failure.Claims ||
            journal.Count != 4 || !journal.ContainsKey("operation-start") || !journal.ContainsKey("recovery-manifest") ||
            !journal.ContainsKey("prepared") || !journal.ContainsKey("failed-or-uncertain") || failure.Proxy.DroppedAtUtc > failure.FailedAtUtc) { throw Invalid(); }
        using var reservation = JsonDocument.Parse(journal["operation-start"]);
        if (reservation.RootElement.GetProperty("Domain").GetString() != "current-auth-session-archive-reservation-v1" ||
            reservation.RootElement.GetProperty("OperationId").GetGuid() != scope.OperationId || reservation.RootElement.GetProperty("AuthorizationSha256").GetString() != auth) { throw Invalid(); }
        var manifest = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRecoveryManifest>(
            MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(journal["recovery-manifest"]), CurrentAuthLocalSessionArchivePolicy.RecoveryDomain,
            pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
        if (manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(scope) || manifest.AuthorizationSha256 != auth) { throw Invalid(); }
        var receipts = new List<CurrentAuthArchiveReceipt>(); string previous = new('0', 64);
        foreach (string name in TerminalFailureReceiptSlots)
        {
            var claim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(journal[name]);
            var receipt = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveReceipt>(claim, CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
            if (receipt.Classification != (name == "prepared" ? CurrentAppOwnedCommitClassification.Prepared : CurrentAppOwnedCommitClassification.Uncertain) ||
                receipt.OperationId != scope.OperationId || receipt.AuthorizationSha256 != auth || receipt.PreviousSha256 != previous ||
                receipt.BeforeAuthSha256 != facts.LocalBefore.Auth.Native.Snapshot.Sha256 || receipt.AfterAuthSha256 != facts.LocalAfter.Auth.Native.Snapshot.Sha256 ||
                receipt.RecoveryManifestSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(manifest) || receipt.ObservedAtUtc < facts.BeganAtUtc ||
                receipt.ObservedAtUtc > failure.FailedAtUtc || (receipts.Count != 0 && receipt.ObservedAtUtc < receipts[^1].ObservedAtUtc) ||
                receipt.ObservedAtUtc.Offset != TimeSpan.Zero || (name == "prepared" && receipt.ObservedAtUtc > failure.Proxy.ArmedAtUtc) ||
                (name == "failed-or-uncertain" && receipt.ObservedAtUtc < failure.Proxy.DroppedAtUtc)) { throw Invalid(); }
            previous = CurrentAuthLocalSessionArchivePolicy.Hash(claim); receipts.Add(receipt);
        }
        return receipts.ToArray();
    }
}
