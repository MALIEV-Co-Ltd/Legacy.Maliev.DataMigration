using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveCaseReadbackV2
{
    private async Task RequireRecoveryV2Async(CancellationToken ct)
    {
        RequireOrdinaryClaims(); RequireNativeOwnershipAndPolicyV2(true);
        var original = await RecoveryFleetAsync("original"); var empty = await RecoveryFleetAsync("setup-empty");
        var comparisonOriginal = await RecoveryFleetAsync("comparison-original"); var comparisonSetup = await RecoveryFleetAsync("comparison-setup");
        var currentEmpty = await RecoveryFleetAsync("restore-empty-preimage"); var currentComparison = await RecoveryFleetAsync("restore-comparison-preimage");
        var restored = await RecoveryFleetAsync("restored"); var comparisonRestored = await RecoveryFleetAsync("comparison-restored");
        original.RequireWindow(Scope.LocalObservationPolicy, false, Method.StartedAtUtc, Method.ReturnedAtUtc, true);
        comparisonOriginal.RequireWindow(Scope.ProductionObservationPolicy, true, Method.StartedAtUtc, Method.ReturnedAtUtc, true);
        foreach (var item in new[] { empty, currentEmpty, restored }) { item.RequireWindow(Scope.LocalObservationPolicy, false, Method.StartedAtUtc, Method.ReturnedAtUtc, false); }
        foreach (var item in new[] { comparisonSetup, currentComparison, comparisonRestored }) { item.RequireWindow(Scope.ProductionObservationPolicy, true, Method.StartedAtUtc, Method.ReturnedAtUtc, false); }
        CurrentAuthArchiveRetainedFleetV2.RequireDeletedOnly(original, empty); CurrentAuthArchiveRetainedFleetV2.RequireExact(empty, currentEmpty);
        CurrentAuthArchiveRetainedFleetV2.RequireExact(original, restored); CurrentAuthArchiveRetainedFleetV2.RequireExact(comparisonOriginal, comparisonSetup);
        CurrentAuthArchiveRetainedFleetV2.RequireExact(comparisonOriginal, currentComparison); CurrentAuthArchiveRetainedFleetV2.RequireExact(comparisonOriginal, comparisonRestored);
        string[] slots = ["operation-start", "recovery-manifest", "prepared", "committed-readback"];
        if (!_stage.GetProperty("SetupJournalSlots").EnumerateArray().Select(item => item.GetString()).SequenceEqual(slots, StringComparer.Ordinal)) { throw Invalid(); }
        var claims = new CurrentAuthArchiveGenuineHelperClaims(Value<CurrentAuthArchiveClaim>("setup-review"), Value<CurrentAuthArchiveClaim>("setup-authorization"));
        string authorization = CurrentAuthLocalSessionArchivePolicy.Hash(claims.Authorization);
        var manifest = Verify<CurrentAuthArchiveRecoveryManifest>("setup-recovery-manifest", CurrentAuthLocalSessionArchivePolicy.RecoveryDomain);
        if (manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(Scope) || manifest.AuthorizationSha256 != authorization) { throw Invalid(); }
        using (var reservation = JsonDocument.Parse(Bytes("setup-operation-start", 65536)))
        {
            if (reservation.RootElement.GetProperty("Domain").GetString() != "current-auth-session-archive-reservation-v1" || reservation.RootElement.GetProperty("OperationId").GetGuid() != Scope.OperationId ||
                reservation.RootElement.GetProperty("AuthorizationSha256").GetString() != authorization) { throw Invalid(); }
        }
        var preparedClaim = Value<CurrentAuthArchiveClaim>("setup-prepared"); var terminalClaim = Value<CurrentAuthArchiveClaim>("setup-committed-readback");
        var prepared = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveReceipt>(preparedClaim, CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, _pins.EvidenceKeyId, _pins.EvidenceFingerprint, _trust);
        var terminal = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveReceipt>(terminalClaim, CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, _pins.EvidenceKeyId, _pins.EvidenceFingerprint, _trust);
        if (prepared.Classification != CurrentAppOwnedCommitClassification.Prepared || terminal.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback ||
            prepared.PreviousSha256 != new string('0', 64) || terminal.PreviousSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(preparedClaim) || prepared.ObservedAtUtc > terminal.ObservedAtUtc ||
            new[] { prepared, terminal }.Any(receipt => receipt.OperationId != Scope.OperationId || receipt.AuthorizationSha256 != authorization ||
                receipt.BeforeAuthSha256 != original.Native.Snapshot.Sha256 || receipt.AfterAuthSha256 != empty.Native.Snapshot.Sha256 || receipt.RecoveryManifestSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(manifest) ||
                receipt.ObservedAtUtc < Method.StartedAtUtc || receipt.ObservedAtUtc > Method.ReturnedAtUtc)) { throw Invalid(); }
        RequireNativeOriginalJournalV2(slots, true);
        var restore = Value<CurrentAuthArchiveRestoreScopeV2>("restore-scope");
        var restoreTerminal = Value<CurrentAuthArchiveClaim>("restore-committed-readback");
        var receipt = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRestoreReceiptV2>(restoreTerminal, CurrentAuthArchiveRecoveryV2.ReceiptDomain, _pins.EvidenceKeyId, _pins.EvidenceFingerprint, _trust);
        CurrentAuthArchiveRecoveryV2Journal.Require(restore, Scope, Value<CurrentAuthArchiveClaim>("restore-review"), Value<CurrentAuthArchiveClaim>("restore-authorization"),
            Value<CurrentAuthArchiveClaim>("restore-reservation"), Value<CurrentAuthArchiveClaim>("restore-prepared"), restoreTerminal, _pins, _trust, receipt.ObservedAtUtc);
        var currentSource = Value<CurrentAuthArchiveRecoverySourceEvidence>("current-source-capture");
        CurrentAuthArchiveRecoveryV2.RequireSource(currentSource, Source.Plan.SourceCommitSha, Source.SourceIdentitySha256, Source.DefinitionSha256, restore.CapturedAtUtc);
        if (currentSource.BeganAtUtc < terminal.ObservedAtUtc || restore.SourceFullSha256 != currentSource.FullPlanSha256 || restore.EmptyAuthSha256 != currentEmpty.Native.Snapshot.Sha256 ||
            restore.EmptyNativeSha256 != currentEmpty.Native.NativeSha256 || restore.EmptyFleetSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(currentEmpty.Databases) ||
            restore.ComparisonFleetSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(currentComparison.Databases) || restore.SetupManifestSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(manifest) ||
            restore.SetupJournalsSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(slots.Order(StringComparer.Ordinal).Select(slot => new { Key = slot, _artifacts["setup-" + slot].Sha256 })) ||
            restore.FirstDomain != (Run.Generated.Case == CurrentAuthArchiveProofCaseV2.FirstRestore) || receipt.ObservedAtUtc > Method.ReturnedAtUtc ||
            _artifacts.ContainsKey("restore-failed-or-uncertain") || !_stage.GetProperty("RestoreCompleted").GetBoolean()) { throw Invalid(); }
        var originals = Value<CurrentAuthArchiveRecoveryOriginalFile[]>("original-file-identities");
        string[] paths = [Scope.Paths.FirstCiphertext, Scope.Paths.RecoveryPrivateKey, Scope.Paths.SecondCiphertext, Scope.Paths.SecondRecoveryPrivateKey];
        if (originals.Length != 4 || !originals.Select(file => file.Path).Order(StringComparer.Ordinal).SequenceEqual(paths.Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw Invalid(); }
        // Only original-file identities and commitments survive cleanup. Retaining alternate readable
        // copies of either recovery domain would invalidate the runtime unavailability experiment.
        if (originals.Any(file => file.Length <= 0 || file.Sha256.Length != 64 || file.Sha256.Any(character => !Uri.IsHexDigit(character))) ||
            originals.Single(file => file.Path == Scope.Paths.FirstCiphertext).Sha256 != manifest.FirstCiphertextSha256 ||
            originals.Single(file => file.Path == Scope.Paths.SecondCiphertext).Sha256 != manifest.SecondCiphertextSha256 ||
            _artifacts.Keys.Any(name => name.StartsWith("original-domain-file-", StringComparison.Ordinal))) { throw Invalid(); }
        string cipher = restore.FirstDomain ? Scope.Paths.FirstCiphertext : Scope.Paths.SecondCiphertext;
        string key = restore.FirstDomain ? Scope.Paths.RecoveryPrivateKey : Scope.Paths.SecondRecoveryPrivateKey;
        if (restore.SelectedCipherIdentity != originals.Single(file => file.Path == cipher).Identity || restore.SelectedKeyIdentity != originals.Single(file => file.Path == key).Identity ||
            restore.SelectedCipherSha256 != originals.Single(file => file.Path == cipher).Sha256 || restore.SelectedKeySha256 != originals.Single(file => file.Path == key).Sha256) { throw Invalid(); }
        var unavailableBefore = Value<CurrentAuthArchiveRecoveryUnavailableFile[]>("other-domain-unavailable-before");
        var unavailableAfter = Value<CurrentAuthArchiveRecoveryUnavailableFile[]>("other-domain-unavailable-after");
        string[] unavailablePaths = restore.FirstDomain ? [Scope.Paths.SecondCiphertext, Scope.Paths.SecondRecoveryPrivateKey] : [Scope.Paths.FirstCiphertext, Scope.Paths.RecoveryPrivateKey];
        foreach (var unavailable in new[] { unavailableBefore, unavailableAfter })
        {
            if (unavailable.Length != 2 || !unavailable.Select(file => file.Path).Order(StringComparer.Ordinal).SequenceEqual(unavailablePaths.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
                unavailable.Any(file => file.NativeError != 32 || file.Identity != originals.Single(originalFile => originalFile.Path == file.Path).Identity ||
                    file.Sha256 != originals.Single(originalFile => originalFile.Path == file.Path).Sha256 || file.ObservedAtUtc < terminal.ObservedAtUtc || file.ObservedAtUtc > Method.ReturnedAtUtc)) { throw Invalid(); }
        }
        if (restore.UnavailableDomainSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(unavailableBefore) ||
            unavailableBefore.Max(file => file.ObservedAtUtc) > restore.CapturedAtUtc || unavailableAfter.Min(file => file.ObservedAtUtc) < restored.Catalogs.After.EndedAtUtc) { throw Invalid(); }
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(CurrentAuthLocalSessionArchivePolicy.EncodeRows(restored.Sessions)) != Scope.DeleteSetSha256 ||
            restored.Sessions.Length != Scope.DeleteCount) { throw Invalid(); }

        async Task<CurrentAuthArchiveRetainedFleetV2> RecoveryFleetAsync(string name)
        {
            var databases = await CurrentAuthArchiveStreamedBaselineV2.ReadAsync(_roots.For(_artifacts[name + "-databases"].Path), _artifacts[name + "-databases"], ct);
            using var native = JsonDocument.Parse(Bytes(name + "-native"));
            return new(databases, Value<CurrentAuthArchiveFleetCatalogs>(name + "-catalogs"), Value<CurrentAuthArchiveSession[]>(name + "-sessions"),
                CurrentAuthArchiveRetainedFleetV2.ParseLegacyCommitment(native.RootElement, databases.Single(item => item.Database == "Auth")));
        }
    }
}
