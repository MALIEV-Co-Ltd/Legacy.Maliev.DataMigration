using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveFinal6CaseReadback
{
    private async Task RequireFamilyAsync(CurrentAuthArchiveGenuineCase identity, CancellationToken ct)
    {
        if (identity.Phase == "recovery") { await RequireRecoveryV2Async(ct); return; }
        bool preflight = Run.Generated.Case is CurrentAuthArchiveProofCaseV2.HostUnprobed or CurrentAuthArchiveProofCaseV2.LocalTrust;
        var before = await FleetAsync("local-before", preflight, ct); var after = await FleetAsync("local-after", preflight, ct);
        var comparisonBefore = await FleetAsync("comparison-before", preflight, ct); var comparisonAfter = await FleetAsync("comparison-after", preflight, ct);
        before.RequireWindow(Scope.LocalObservationPolicy, false, Method.StartedAtUtc, Method.ReturnedAtUtc, true);
        after.RequireWindow(Scope.LocalObservationPolicy, false, Method.StartedAtUtc, Method.ReturnedAtUtc, false);
        comparisonBefore.RequireWindow(Scope.ProductionObservationPolicy, true, Method.StartedAtUtc, Method.ReturnedAtUtc, true);
        comparisonAfter.RequireWindow(Scope.ProductionObservationPolicy, true, Method.StartedAtUtc, Method.ReturnedAtUtc, false);
        if (preflight) { RequirePreflightV2(before, after, comparisonBefore, comparisonAfter); return; }
        RequireOrdinaryClaims(); RequireNativeOwnershipAndPolicyV2(false);
        bool drift = Run.Generated.Case is CurrentAuthArchiveProofCaseV2.CasDrift or CurrentAuthArchiveProofCaseV2.JournalDrift or CurrentAuthArchiveProofCaseV2.SequenceDrift or CurrentAuthArchiveProofCaseV2.ComparisonDrift;
        if (drift) { await RequireDriftV2Async(before, after, comparisonBefore, comparisonAfter, ct); return; }
        CurrentAuthArchiveRetainedFleetV2.RequireExact(comparisonBefore, comparisonAfter);
        var scenario = Value<CurrentAuthArchiveProofScenario>("scenario");
        if (identity.Phase == "helper")
        {
            CurrentAuthArchiveRetainedFleetV2.RequireExact(before, after);
            if (_stage.GetProperty("Receipts").GetArrayLength() != 0) { throw Invalid(); }
            CurrentAuthArchiveProofReader.RequireEffects(identity.CaseId, scenario, [], before.Native.Snapshot, after.Native.Snapshot);
            RequireNativeOriginalJournalV2([], false);
            var manifest = Verify<CurrentAuthArchiveRecoveryManifest>("recovery-manifest", CurrentAuthLocalSessionArchivePolicy.RecoveryDomain);
            if (Run.Generated.Case != CurrentAuthArchiveProofCaseV2.Dual)
            {
                var outcome = Value<CurrentAuthArchiveGenuineRecoveryHelpersOutcome>("recovery-outcome");
                if (CurrentAuthArchiveGenuineRecoveryHelpers.RequireObservedOutcome(outcome, Scope, CurrentAuthArchiveGeneratedCasesV2.Helper(Run.Generated.Case),
                    CurrentAuthLocalSessionArchivePolicy.Hash(Value<CurrentAuthArchiveClaim>("authorization")), Method.StartedAtUtc) != Method.ReturnCode)
                { throw Invalid(); }
            }
            VerifyCryptoCopies(manifest, before.Sessions, identity.CaseId, ct);
        }
        else
        {
            if (Run.Generated.Case == CurrentAuthArchiveProofCaseV2.PreparedPublication) { CurrentAuthArchiveRetainedFleetV2.RequireExact(before, after); }
            else { CurrentAuthArchiveRetainedFleetV2.RequireDeletedOnly(before, after); }
            var attempted = Run.Generated.Case == CurrentAuthArchiveProofCaseV2.PreparedPublication
                ? before.Native.Snapshot with
                {
                    Relations = before.Native.Snapshot.Relations.Select(item => item.Schema == "public" && item.Name == "refresh_sessions"
                    ? item with { Rows = 0, RowSha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes([]) } : item).ToArray()
                }
                : after.Native.Snapshot;
            CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before.Native.Snapshot, attempted);
            var receipts = RequireOriginalJournal(before.Native.Snapshot.Sha256, attempted.Sha256);
            CurrentAuthArchiveProofReader.RequireEffects(identity.CaseId, scenario, receipts, before.Native.Snapshot, after.Native.Snapshot);
            VerifyCryptoCopies(Verify<CurrentAuthArchiveRecoveryManifest>("recovery-manifest", CurrentAuthLocalSessionArchivePolicy.RecoveryDomain), before.Sessions, "both", ct);
            if (Run.Generated.Case is CurrentAuthArchiveProofCaseV2.PreparedPublication or CurrentAuthArchiveProofCaseV2.TerminalPublication)
            {
                CurrentAuthArchiveGenuinePublicationFault.RequireWitness(Value<CurrentAuthArchiveGenuineSlotWitness>("slot-witness"), Scope,
                    CurrentAuthLocalSessionArchivePolicy.Hash(Value<CurrentAuthArchiveClaim>("authorization")), CurrentAuthArchiveGeneratedCasesV2.Execution(Run.Generated.Case), Method.StartedAtUtc, Method.ReturnedAtUtc);
                using var failure = JsonDocument.Parse(Bytes("publication-failure"));
                if (failure.RootElement.GetProperty("ActualExceptionType").GetString() is not ("System.IO.IOException" or "Legacy.Maliev.DataMigration.MigrationExecutionException")) { throw Invalid(); }
                var witness = Value<CurrentAuthArchiveGenuineSlotWitness>("slot-witness");
                if ((failure.RootElement.GetProperty("ActualHResult").GetInt32() & 0xffff) != witness.NativeCreateError ||
                    failure.RootElement.GetProperty("FailedAtUtc").GetDateTimeOffset() < witness.FailedAtUtc) { throw Invalid(); }
            }
            if (Run.Generated.Case == CurrentAuthArchiveProofCaseV2.CommitAckLost)
            {
                using var failure = JsonDocument.Parse(Bytes("commit-failure"));
                var proxy = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineCommitProxyInfo>(JsonSerializer.SerializeToUtf8Bytes(failure.RootElement.GetProperty("Proxy")));
                CurrentAuthArchiveGenuineCommitFacts.RequireSettled(proxy, Scope, CurrentAuthLocalSessionArchivePolicy.Hash(Value<CurrentAuthArchiveClaim>("authorization")));
                var provider = Artifact<JsonElement>(new(Run.ProviderProcess.Path, Run.ProviderProcess.Sha256));
                if (proxy.DroppedAtUtc > Method.ReturnedAtUtc || proxy.OwnerImageSha256 != provider.GetProperty("ExecutableSha256").GetString() ||
                    proxy.OwnerPid != provider.GetProperty("ProcessId").GetInt32() || proxy.OwnerStartedAtUtc != provider.GetProperty("ProcessStartTimeUtc").GetDateTimeOffset()) { throw Invalid(); }
                _ = Bytes("proxy-created"); _ = Bytes("proxy-disposed");
            }
        }
    }

    private async Task<CurrentAuthArchiveRetainedFleetV2> FleetAsync(string name, bool legacy, CancellationToken ct)
    {
        var databases = await CurrentAuthArchiveStreamedBaselineV2.ReadAsync(_roots.For(_artifacts[name].Path), _artifacts[name], ct);
        var catalogs = Value<CurrentAuthArchiveFleetCatalogs>(name + "-catalogs");
        var sessions = Value<CurrentAuthArchiveSession[]>(name + "-sessions");
        CurrentAuthArchiveNativeCommitmentV2 native;
        if (legacy)
        {
            using var raw = JsonDocument.Parse(Bytes(name + "-native"));
            native = CurrentAuthArchiveRetainedFleetV2.ParseLegacyCommitment(raw.RootElement, databases.Single(item => item.Database == "Auth"));
        }
        else { native = Value<CurrentAuthArchiveNativeCommitmentV2>(name + "-native-v2"); }
        return new(databases, catalogs, sessions, native);
    }
    private T Verify<T>(string name, string domain)
    {
        return CurrentAuthLocalSessionArchivePolicy.Verify<T>(Value<CurrentAuthArchiveClaim>(name), domain,
        _pins.EvidenceKeyId, _pins.EvidenceFingerprint, _trust);
    }

    private void RequireOrdinaryClaims()
    {
        var review = Value<CurrentAuthArchiveClaim>(Run.Generated.Case is CurrentAuthArchiveProofCaseV2.FirstRestore or CurrentAuthArchiveProofCaseV2.SecondRestore ? "setup-review" : "review");
        var authorization = Value<CurrentAuthArchiveClaim>(Run.Generated.Case is CurrentAuthArchiveProofCaseV2.FirstRestore or CurrentAuthArchiveProofCaseV2.SecondRestore ? "setup-authorization" : "authorization");
        var reviewed = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveScope>(review, CurrentAuthLocalSessionArchivePolicy.ReviewDomain, _pins.ReviewKeyId, _pins.ReviewFingerprint, _trust);
        var allowed = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(authorization, CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, _pins.AuthorizationKeyId, _pins.AuthorizationFingerprint, _trust);
        if (CurrentAuthLocalSessionArchivePolicy.Hash(reviewed) != CurrentAuthLocalSessionArchivePolicy.Hash(Scope) || allowed.OperationId != Scope.OperationId ||
            allowed.ReviewSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(review) || allowed.IssuedAtUtc > Method.StartedAtUtc || allowed.ExpiresAtUtc <= Method.StartedAtUtc) { throw Invalid(); }
    }
    private CurrentAuthArchiveReceipt[] RequireOriginalJournal(string before, string after)
    {
        string authorization = CurrentAuthLocalSessionArchivePolicy.Hash(Value<CurrentAuthArchiveClaim>("authorization"));
        using var reservation = JsonDocument.Parse(Bytes("operation-start", 65536));
        if (reservation.RootElement.GetProperty("Domain").GetString() != "current-auth-session-archive-reservation-v1" ||
            reservation.RootElement.GetProperty("OperationId").GetGuid() != Scope.OperationId || reservation.RootElement.GetProperty("AuthorizationSha256").GetString() != authorization) { throw Invalid(); }
        var manifest = Verify<CurrentAuthArchiveRecoveryManifest>("recovery-manifest", CurrentAuthLocalSessionArchivePolicy.RecoveryDomain);
        if (manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(Scope) || manifest.AuthorizationSha256 != authorization) { throw Invalid(); }
        var refs = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineArtifact[]>(JsonSerializer.SerializeToUtf8Bytes(_stage.GetProperty("Receipts")));
        var receipts = new List<CurrentAuthArchiveReceipt>(); string previous = new('0', 64); DateTimeOffset observed = Method.StartedAtUtc;
        foreach (var artifact in refs)
        {
            var claim = Artifact<CurrentAuthArchiveClaim>(artifact);
            var receipt = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveReceipt>(claim, CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, _pins.EvidenceKeyId, _pins.EvidenceFingerprint, _trust);
            if (receipt.OperationId != Scope.OperationId || receipt.AuthorizationSha256 != authorization || receipt.PreviousSha256 != previous ||
                receipt.BeforeAuthSha256 != before || receipt.AfterAuthSha256 != after || receipt.RecoveryManifestSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(manifest) ||
                receipt.ObservedAtUtc.Offset != TimeSpan.Zero || receipt.ObservedAtUtc < observed || receipt.ObservedAtUtc > Method.ReturnedAtUtc) { throw Invalid(); }
            observed = receipt.ObservedAtUtc; previous = CurrentAuthLocalSessionArchivePolicy.Hash(claim); receipts.Add(receipt);
        }
        string[] slots = Run.Generated.Case == CurrentAuthArchiveProofCaseV2.PreparedPublication ? ["operation-start", "recovery-manifest", "failed-or-uncertain"] :
            Run.Generated.Case is CurrentAuthArchiveProofCaseV2.TerminalPublication or CurrentAuthArchiveProofCaseV2.CommitAckLost ?
            ["operation-start", "recovery-manifest", "prepared", "failed-or-uncertain"] : ["operation-start", "recovery-manifest", "prepared", "committed-readback"];
        RequireNativeOriginalJournalV2(slots, false);
        return receipts.ToArray();
    }
    private async Task RequireDriftV2Async(CurrentAuthArchiveRetainedFleetV2 before, CurrentAuthArchiveRetainedFleetV2 after,
        CurrentAuthArchiveRetainedFleetV2 comparisonBefore, CurrentAuthArchiveRetainedFleetV2 comparisonAfter, CancellationToken ct)
    {
        var localFault = await FleetAsync("local-fault", false, ct); var comparisonFault = await FleetAsync("comparison-fault", false, ct);
        localFault.RequireWindow(Scope.LocalObservationPolicy, false, Method.StartedAtUtc, Method.ReturnedAtUtc, false);
        comparisonFault.RequireWindow(Scope.ProductionObservationPolicy, true, Method.StartedAtUtc, Method.ReturnedAtUtc, false);
        var mutation = Value<CurrentAuthArchiveGenuineDriftMutation>("mutation");
        var selected = CurrentAuthArchiveGeneratedCasesV2.Execution(Run.Generated.Case);
        if (mutation.Case != selected) { throw Invalid(); }
        CurrentAuthArchiveGenuineDrift.RequireMutation(mutation);
        var original = CurrentAuthArchiveGenuineDrift.Comparison(selected) ? comparisonBefore : before;
        var fault = CurrentAuthArchiveGenuineDrift.Comparison(selected) ? comparisonFault : localFault;
        CurrentAuthArchiveGenuineDrift.RequireControlledChange(selected, original.Native.Snapshot, fault.Native.Snapshot);
        if (!original.Databases.Select(item => item.Database).SequenceEqual(fault.Databases.Select(item => item.Database), StringComparer.Ordinal) ||
            original.Databases.Where(item => item.Database != "Auth").Any(item => item.Sha256 != fault.Databases.Single(other => other.Database == item.Database).Sha256)) { throw Invalid(); }
        CurrentAuthArchiveNativeCommitmentV2.RequireSameAuxiliary(original.Native, fault.Native);
        CurrentAuthArchiveRetainedFleetV2.RequireExact(CurrentAuthArchiveGenuineDrift.Comparison(selected) ? before : comparisonBefore,
            CurrentAuthArchiveGenuineDrift.Comparison(selected) ? localFault : comparisonFault);
        CurrentAuthArchiveRetainedFleetV2.RequireExact(localFault, after); CurrentAuthArchiveRetainedFleetV2.RequireExact(comparisonFault, comparisonAfter);
        if (selected == CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift) { CurrentAuthArchiveProofReader.RequireCasFaultRows(before.Sessions, localFault.Sessions); }
        RequireSlotAbsenceV2(false);
        RequireNativeOriginalJournalV2([], false);
        CurrentAuthArchiveProofReader.RequireEffects(CurrentAuthArchiveGeneratedCasesV2.Identity(Run.Generated.Case).CaseId,
            Value<CurrentAuthArchiveProofScenario>("scenario"), [], localFault.Native.Snapshot, after.Native.Snapshot);
    }
    private void RequireSlotAbsenceV2(bool preflight)
    {
        using var absence = JsonDocument.Parse(Bytes("archive-slot-absence", 65536)); var value = absence.RootElement;
        if (value.GetProperty("OperationId").GetGuid() != Scope.OperationId || !value.GetProperty("ReservationAbsent").GetBoolean() ||
            !value.GetProperty(preflight ? "ReceiptSlotsAbsent" : "ReceiptsAbsent").GetBoolean() || !value.GetProperty("RecoveryFilesAbsent").GetBoolean() ||
            value.GetProperty("ObservedAtUtc").GetDateTimeOffset() > Method.ReturnedAtUtc ||
            (_stage.TryGetProperty("Receipts", out var receipts) && receipts.GetArrayLength() != 0)) { throw Invalid(); }
    }
}
