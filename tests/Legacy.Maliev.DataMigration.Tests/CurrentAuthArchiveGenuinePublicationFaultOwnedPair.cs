using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    private CurrentAuthArchiveGenuineExecutionIssuer.SlotDenial? _publicationDenial;
    private static readonly string[] PreparedFailureReceiptSlots = ["failed-or-uncertain"];
    private static readonly string[] TerminalFailureReceiptSlots = ["prepared", "failed-or-uncertain"];

    async Task ICurrentAuthArchiveGenuineExecutionLease.BindPublicationDenialAsync(CurrentAuthArchiveGenuineExecutionIssuer.SlotDenial denial, CancellationToken ct)
    {
        await RequireExecutionLiveAsync(true, ct);
        if (_publicationDenial is not null || _executionClaims is null || _executionCase != denial.Case || _environment is null ||
            _firstFiles is null || _secondFiles is null || _firstAuthority is null || _secondAuthority is null ||
            _firstPolicy is null || _secondPolicy is null || _dualDeviceProof is null) { throw Invalid(); }
        var native = await _environment.CaptureDualHelperNativeEvidenceAsync(Scope, _firstPolicy.HbaFile, _firstPolicy.RawRules,
            _secondPolicy.HbaFile, _secondPolicy.RawRules, ct);
        var old = _environment; _environment = null; old.Dispose();
        _environment = new(_firstFiles, _secondFiles, _firstAuthority, _secondAuthority, Scope, _inputs.Source, native.LocalTarget, native.ComparisonTarget,
            Connection(_firstFiles, _firstPolicy.OperatorConnectionPath), Connection(_secondFiles, _secondPolicy.OperatorConnectionPath),
            Connection(_firstFiles, _firstPolicy.OrdinaryConnectionPath), Connection(_secondFiles, _secondPolicy.OrdinaryConnectionPath),
            _dualDeviceProof, _inputs.TrustStore, _inputs.Pins, CurrentAuthLocalSessionArchivePolicy.Hash(_executionClaims.Authorization), denial, this);
        _publicationDenial = denial;
        await RequireExecutionLiveAsync(true, ct);
        static string Connection(CurrentAppOwnedRepairCustody files, string path)
        {
            return Encoding.UTF8.GetString(files.Read(path, maximumBytes: 65536));
        }
    }

    async Task<CurrentAuthArchiveGenuineDualArtifacts> ICurrentAuthArchiveGenuineExecutionLease.RetainPublicationFailureAsync(
        CurrentAuthArchiveGenuinePublicationFailureFacts failure, CancellationToken ct)
    {
        if (_disposed || _executionEnvironmentClosed || _environment is null || _publicationDenial is null || _executionClaims is null ||
            _executionCase != failure.Case || failure.Claims != _executionClaims || _first is null || _second is null ||
            _firstAuthority is null || _secondAuthority is null || _firstPolicy is null || _secondPolicy is null ||
            failure.ActualExceptionType is not ("System.IO.IOException" or "System.UnauthorizedAccessException") ||
            failure.BeganAtUtc.Offset != TimeSpan.Zero || failure.FailedAtUtc.Offset != TimeSpan.Zero ||
            failure.FailedAtUtc < failure.BeganAtUtc || failure.FailedAtUtc > DateTimeOffset.UtcNow || DateTimeOffset.UtcNow >= Scope.ExpiresAtUtc)
        { throw Invalid(); }
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct, _lease.Token, _first.Token, _second.Token);
        _bundle.Require(); await _inputs.RequireAsync(lease.Token);
        await _first.RequireHealthyHeldAsync(_firstAuthority, lease.Token);
        await _second.RequireHealthyHeldAsync(_secondAuthority, lease.Token);
        var observation = await _environment.ObserveGenuinePublicationFailureAsync(_publicationDenial, _firstPolicy.HbaFile, _firstPolicy.RawRules,
            _secondPolicy.HbaFile, _secondPolicy.RawRules, lease.Token);
        CurrentAuthArchiveGenuinePublicationFault.RequireWitness(observation.Witness, Scope, CurrentAuthLocalSessionArchivePolicy.Hash(failure.Claims.Authorization),
            failure.Case, failure.BeganAtUtc, DateTimeOffset.UtcNow);
        if (observation.Witness.NativeCreateError != (failure.ActualHResult & 0xffff) || observation.Witness.FailedAtUtc > failure.FailedAtUtc) { throw Invalid(); }
        _bundle.Require();
        var facts = new CurrentAuthArchiveGenuineExecutionFacts(failure.Case, failure.Claims, null,
            failure.LocalBefore, observation.Local, failure.ComparisonBefore, observation.Comparison, failure.BeganAtUtc, DateTimeOffset.UtcNow);
        return await RetainExecutionCoreAsync(facts, failure, observation, lease.Token);
    }

    internal static CurrentAuthArchiveReceipt[] RequireFailureJournal(IReadOnlyDictionary<string, byte[]> journal,
        CurrentAuthArchiveScope scope, CurrentAuthArchiveGenuineExecutionFacts facts, CurrentAuthArchiveGenuinePublicationFailureFacts failure,
        CurrentAuthArchiveGenuineSlotWitness witness, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust)
    {
        bool preparedFault = facts.Case == CurrentAuthArchiveGenuineExecutionCase.PreparedPublication;
        if (!CurrentAuthArchiveGenuinePublicationFault.IsCase(facts.Case) || failure.Case != facts.Case || failure.Claims != facts.Claims ||
            journal.Count != (preparedFault ? 3 : 4) || !journal.ContainsKey("operation-start") || !journal.ContainsKey("recovery-manifest") ||
            !journal.ContainsKey("failed-or-uncertain") || journal.ContainsKey("committed-readback") || journal.ContainsKey("prepared") == preparedFault)
        { throw Invalid(); }
        string auth = CurrentAuthLocalSessionArchivePolicy.Hash(facts.Claims.Authorization);
        CurrentAuthArchiveGenuinePublicationFault.RequireWitness(witness, scope, auth, facts.Case, facts.BeganAtUtc, facts.ReturnedAtUtc);
        if (witness.NativeCreateError != (failure.ActualHResult & 0xffff) || witness.FailedAtUtc > failure.FailedAtUtc) { throw Invalid(); }
        using var reservation = JsonDocument.Parse(journal["operation-start"]);
        if (reservation.RootElement.GetProperty("Domain").GetString() != "current-auth-session-archive-reservation-v1" ||
            reservation.RootElement.GetProperty("OperationId").GetGuid() != scope.OperationId ||
            reservation.RootElement.GetProperty("AuthorizationSha256").GetString() != auth) { throw Invalid(); }
        var manifest = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRecoveryManifest>(
            MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(journal["recovery-manifest"]), CurrentAuthLocalSessionArchivePolicy.RecoveryDomain,
            pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
        if (manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(scope) || manifest.AuthorizationSha256 != auth) { throw Invalid(); }
        var before = facts.LocalBefore.Auth.Native.Snapshot;
        var deleted = before with
        {
            Relations = before.Relations.Select(relation => relation.Schema == "public" && relation.Name == "refresh_sessions"
            ? relation with { Rows = 0, RowSha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes([]) } : relation).ToArray()
        };
        CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before, deleted);
        var receipts = new List<CurrentAuthArchiveReceipt>(); string previous = new('0', 64);
        foreach (string slot in preparedFault ? PreparedFailureReceiptSlots : TerminalFailureReceiptSlots)
        {
            var claim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(journal[slot]);
            var receipt = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveReceipt>(claim, CurrentAuthLocalSessionArchivePolicy.ReceiptDomain,
                pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
            bool classification = slot == "prepared" ? receipt.Classification == CurrentAppOwnedCommitClassification.Prepared : preparedFault
                ? receipt.Classification is CurrentAppOwnedCommitClassification.FailedBeforeCommit or CurrentAppOwnedCommitClassification.RolledBackBeforeCommit
                : receipt.Classification == CurrentAppOwnedCommitClassification.Uncertain;
            if (!classification || receipt.OperationId != scope.OperationId || receipt.AuthorizationSha256 != auth || receipt.PreviousSha256 != previous ||
                receipt.BeforeAuthSha256 != before.Sha256 || receipt.AfterAuthSha256 != deleted.Sha256 ||
                receipt.RecoveryManifestSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(manifest) || receipt.ObservedAtUtc.Offset != TimeSpan.Zero ||
                receipt.ObservedAtUtc < facts.BeganAtUtc || receipt.ObservedAtUtc > failure.FailedAtUtc ||
                (receipts.Count != 0 && receipt.ObservedAtUtc < receipts[^1].ObservedAtUtc)) { throw Invalid(); }
            previous = CurrentAuthLocalSessionArchivePolicy.Hash(claim); receipts.Add(receipt);
        }
        return receipts.ToArray();
    }
}
