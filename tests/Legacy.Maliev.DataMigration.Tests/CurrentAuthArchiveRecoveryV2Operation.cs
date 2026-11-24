using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    private readonly Dictionary<string, CurrentAuthArchiveGenuineArtifact> _recoveryArtifacts = new(StringComparer.Ordinal);

    async Task<CurrentAuthArchiveGenuineDualArtifacts> ICurrentAuthArchiveRecoveryV2Lease.CompleteRecoveryAsync(CurrentAuthArchiveGenuineExecutionFacts setup, CancellationToken ct)
    {
        if (Interlocked.CompareExchange(ref _restoreStarted, 1, 0) != 0 || _recoveryV2Case is not { } selected || _recoveryAudience is null ||
            _recoveryAudienceClaim is null || _recoveryCaseClaim is null || _recoverySourceConnection is null || _recoveryV2Input is null || _executionClaims != setup.Claims ||
            setup.Case != CurrentAuthArchiveRecoveryV2.SetupCase(selected) || _environment is null || _firstFiles is null || _secondFiles is null ||
            _firstAuthority is null || _secondAuthority is null || _first is null || _second is null || _firstPolicy is null || _secondPolicy is null || _dualDeviceProof is null) { throw Invalid(); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, _lease.Token, _first.Token, _second.Token); ct = deadline.Token;
        await RequireRecoveryLiveAsync(false, ct); _environment.RequireTerminal(setup.Terminal ?? throw Invalid());
        CurrentAuthArchiveRecoveryV2Preservation.RequireSetup(setup, Scope);
        _recoveryOriginal = setup.LocalBefore;
        var localEmpty = await _environment.CaptureLocalFleetAsync(Scope, ct);
        var comparisonEmpty = await _environment.CaptureProductionFleetAsync(Scope, ct);
        RequireRecoveryFleetEqual(setup.LocalAfter, localEmpty); RequireRecoveryFleetEqual(setup.ComparisonAfter, comparisonEmpty);
        var native = await _environment.CaptureDualHelperNativeEvidenceAsync(Scope, _firstPolicy.HbaFile, _firstPolicy.RawRules, _secondPolicy.HbaFile, _secondPolicy.RawRules, ct);
        var localHba = await RecoveryProofCopyAsync("local-hba", _firstFiles, _firstPolicy.HbaFile, ct);
        var localRules = await RecoveryProofCopyAsync("local-rules", _firstFiles, _firstPolicy.RawRules, ct);
        var comparisonHba = await RecoveryProofCopyAsync("comparison-hba", _secondFiles, _secondPolicy.HbaFile, ct);
        var comparisonRules = await RecoveryProofCopyAsync("comparison-rules", _secondFiles, _secondPolicy.RawRules, ct);
        native = native with { LocalPolicy = native.LocalPolicy with { HbaFile = localHba, RawRules = localRules }, ComparisonPolicy = native.ComparisonPolicy with { HbaFile = comparisonHba, RawRules = comparisonRules } };
        await RecoveryValueAsync("scope", Scope, ct); await RecoveryValueAsync("original-source", _inputs.Source, ct);
        await RecoveryValueAsync("setup-review", setup.Claims.Review, ct); await RecoveryValueAsync("setup-authorization", setup.Claims.Authorization, ct);
        await RecoveryValueAsync("audience", _recoveryAudienceClaim, ct); await RecoveryValueAsync("case-binding", _recoveryCaseClaim, ct);
        await RecoveryValueAsync("setup-native-policy", native, ct); await RecoveryValueAsync("original-device", _dualDeviceProof, ct);
        await RecoveryFleetAsync("original", setup.LocalBefore, ct); await RecoveryFleetAsync("setup-empty", localEmpty, ct);
        await RecoveryFleetAsync("comparison-original", setup.ComparisonBefore, ct); await RecoveryFleetAsync("comparison-setup", comparisonEmpty, ct);
        string[] setupSlots = ["operation-start", "recovery-manifest", "prepared", "committed-readback"];
        var journals = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        string journalPrefix = Scope.OperationId.ToString("D") + "-";
        string[] expectedFiles = setupSlots.Select(name => journalPrefix + "Auth-session-archive-" + name + ".json").Order(StringComparer.Ordinal).ToArray();
        string[] actualFiles = Directory.EnumerateFileSystemEntries(_first.Root).Select(Path.GetFileName).Where(name => name is not null && name.StartsWith(journalPrefix, StringComparison.OrdinalIgnoreCase)).Select(name => name!).Order(StringComparer.Ordinal).ToArray();
        if (!actualFiles.SequenceEqual(expectedFiles, StringComparer.Ordinal) || Directory.EnumerateFileSystemEntries(_second.Root).Select(Path.GetFileName).Any(name => name is not null && name.StartsWith(journalPrefix, StringComparison.OrdinalIgnoreCase))) { throw Invalid(); }
        foreach (string slot in setupSlots)
        {
            string path = Path.Combine(_first.Root, journalPrefix + "Auth-session-archive-" + slot + ".json");
            byte[] bytes = _firstFiles.Read(path, sharedReader: true, maximumBytes: 65536); journals.Add(slot, bytes);
            _ = await RecoveryBytesAsync("setup-" + slot, bytes, ct);
        }
        _ = RequireExecutionJournal(journals, Scope, setup.Claims, setup.Terminal, setup.LocalBefore.Auth.Native.Snapshot.Sha256,
            localEmpty.Auth.Native.Snapshot.Sha256, setup.BeganAtUtc, setup.ReturnedAtUtc, _inputs.Pins, _inputs.TrustStore);
        var manifest = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRecoveryManifest>(MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(journals["recovery-manifest"]),
            CurrentAuthLocalSessionArchivePolicy.RecoveryDomain, _inputs.Pins.EvidenceKeyId, _inputs.Pins.EvidenceFingerprint, _inputs.TrustStore);
        await CurrentAuthLocalSessionArchiveCrypto.VerifyAsync(_environment.RecoveryStorage, Scope, manifest, setup.LocalBefore.Auth.Sessions, ct);
        string[] paths = [Scope.Paths.FirstCiphertext, Scope.Paths.RecoveryPrivateKey, Scope.Paths.SecondCiphertext, Scope.Paths.SecondRecoveryPrivateKey];
        var originals = new List<CurrentAuthArchiveRecoveryOriginalFile>();
        for (int index = 0; index < paths.Length; index++)
        {
            string path = paths[index]; var files = index < 2 ? _firstFiles : _secondFiles;
            byte[] bytes = files.Read(path, sharedReader: true, maximumBytes: index % 2 == 0 ? 12 * 1024 * 1024 : 65536);
            try
            {
                using var held = SecureLocalFile.OpenReadShared(path);
                if (!SecureLocalFile.HandleResolvesToApprovedPath(held, path) || held.Length != bytes.Length) { throw Invalid(); }
                string hash = CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes);
                if (Convert.ToHexStringLower(SHA256.HashData(held)) != hash) { throw Invalid(); }
                originals.Add(new(path, SecureLocalFile.GetHandleIdentity(held), hash, bytes.Length));
                // Retain identity/hash/length only; never copy either recovery domain into control custody.
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        await RecoveryValueAsync("original-file-identities", originals, ct);
        // Release every old read handle, including custody's retained reads. Root authorities remain held throughout.
        _executionEnvironmentClosed = true; var old = _environment; _environment = null; old.Dispose();
        _firstFiles.Dispose(); _secondFiles.Dispose(); _firstFiles = new(_firstAuthority); _secondFiles = new(_secondAuthority);
        _recoveryCapture = await CurrentReviewedCapture.CaptureAsync(_recoverySourceConnection, _recoveryAudience, ct);
        await RecoveryValueAsync("current-source-capture", _recoveryCapture.Evidence, ct);
        using var storage = new CurrentAuthArchiveRecoveryV2Storage(_firstAuthority, _secondAuthority, Scope, _dualDeviceProof, selected, originals);
        await storage.RequireCustodyAsync(ct); await RecoveryValueAsync("other-domain-unavailable-before", storage.Unavailable, ct);
        byte[] recovered = await CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, Scope, manifest, selected == CurrentAuthArchiveRecoveryV2Case.FirstOnly, ct);
        try
        {
            var currentEmpty = await CaptureRecoveryFleetAsync(false, ct); var currentComparison = await CaptureRecoveryFleetAsync(true, ct);
            RequireRecoveryFleetEqual(localEmpty, currentEmpty); RequireRecoveryFleetEqual(comparisonEmpty, currentComparison);
            await RecoveryFleetAsync("restore-empty-preimage", currentEmpty, ct); await RecoveryFleetAsync("restore-comparison-preimage", currentComparison, ct);
            string selectedCipher = selected == CurrentAuthArchiveRecoveryV2Case.FirstOnly ? Scope.Paths.FirstCiphertext : Scope.Paths.SecondCiphertext;
            string selectedKey = selected == CurrentAuthArchiveRecoveryV2Case.FirstOnly ? Scope.Paths.RecoveryPrivateKey : Scope.Paths.SecondRecoveryPrivateKey;
            var cipher = originals.Single(item => item.Path == selectedCipher); var key = originals.Single(item => item.Path == selectedKey);
            DateTimeOffset captured = DateTimeOffset.UtcNow, expires = new[] { Scope.ExpiresAtUtc, captured.AddMinutes(2) }.Min();
            var restore = new CurrentAuthArchiveRestoreScopeV2("current-auth-owned-disposable-restore-scope-v2", Guid.NewGuid(), Scope.OperationId,
                CurrentAuthLocalSessionArchivePolicy.Hash(_recoveryAudienceClaim), CurrentAuthLocalSessionArchivePolicy.Hash(Scope), CurrentAuthLocalSessionArchivePolicy.Hash(manifest),
                CurrentAuthLocalSessionArchivePolicy.Hash(journals.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, Sha256 = CurrentAuthLocalSessionArchivePolicy.HashBytes(pair.Value) })),
                _recoveryCapture.Evidence.FullPlanSha256, _recoveryCapture.Evidence.SourceIdentitySha256, _recoveryCapture.Evidence.DefinitionSha256,
                Scope.LocalObservationPolicy.RunBindingSha256, Scope.ProductionObservationPolicy.RunBindingSha256, Scope.LocalObservationPolicy.TargetObservationSha256, Scope.ProductionObservationPolicy.TargetObservationSha256,
                CurrentAuthLocalSessionArchivePolicy.Hash(currentEmpty.Databases), CurrentAuthLocalSessionArchivePolicy.Hash(currentComparison.Databases), currentEmpty.Auth.Native.Snapshot.Sha256,
                CurrentAuthArchiveRecoveryV2Preservation.NativeSha(currentEmpty.Auth.Native), Scope.DeleteSetSha256, Scope.DeleteCount,
                selected == CurrentAuthArchiveRecoveryV2Case.FirstOnly, cipher.Identity, cipher.Sha256, key.Identity, key.Sha256,
                CurrentAuthLocalSessionArchivePolicy.Hash(storage.Unavailable), Scope.RecoveryDeviceProofSha256, captured, expires);
            using var reviewer = DualSigner(_inputs.Pins.ReviewKeyId, CurrentAuthArchiveGenuineDualInputContract.ReviewKeyName, _inputs.Pins.ReviewFingerprint);
            using var authorizer = DualSigner(_inputs.Pins.AuthorizationKeyId, CurrentAuthArchiveGenuineDualInputContract.AuthorizationKeyName, _inputs.Pins.AuthorizationFingerprint);
            var review = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2.ReviewDomain, restore, reviewer);
            var authorization = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2.AuthorizationDomain,
                new CurrentAuthArchiveAuthorization(restore.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review), captured, expires), authorizer);
            await RecoveryValueAsync("restore-scope", restore, ct); await RecoveryValueAsync("restore-review", review, ct); await RecoveryValueAsync("restore-authorization", authorization, ct);
            var capability = RecoveryRestoreCapability.CreateOwned(this, restore, review, authorization, currentEmpty, currentComparison, storage, recovered);
            await capability.ExecuteAsync(ct);
            await storage.RequireCustodyAsync(ct);
        }
        finally { CryptographicOperations.ZeroMemory(recovered); }
        // The selected original files and exclusive other-domain handles retire before method return and target cleanup.
        storage.Dispose(); await RequireRecoveryCustodyAsync(ct);
        DateTimeOffset ended = DateTimeOffset.UtcNow;
        return new(await RecoveryBytesAsync("incomplete-precleanup-stage", JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "current-auth-genuine-recovery-incomplete-precleanup-v2",
            Phase = "recovery",
            CaseId = CurrentAuthArchiveRecoveryV2.CaseId(selected),
            Scope.OperationId,
            setup.BeganAtUtc,
            EndedAtUtc = ended,
            native.LocalPort,
            native.ComparisonPort,
            Artifacts = _recoveryArtifacts,
            SetupJournalSlots = setupSlots,
            RestoreCompleted = true,
            CleanupVerified = false,
            PhaseProofComplete = false,
            ProviderExitCode = (int?)null,
        }), ct), setup.BeganAtUtc, ended);
    }
    private async Task RecoveryValueAsync<T>(string name, T value, CancellationToken ct)
    {
        _ = await RecoveryBytesAsync(name, JsonSerializer.SerializeToUtf8Bytes(value), ct);
    }

    private async Task RecoveryFleetAsync(string name, CurrentAuthArchiveFleet fleet, CancellationToken ct)
    {
        await RecoveryValueAsync(name + "-databases", fleet.Databases, ct); await RecoveryValueAsync(name + "-catalogs", fleet.Catalogs, ct);
        await RecoveryValueAsync(name + "-sessions", fleet.Auth.Sessions, ct);
        await RecoveryValueAsync(name + "-native", new
        {
            Kind = "current-auth-native-evidence-v2",
            SnapshotSha256 = fleet.Auth.Native.Snapshot.Sha256,
            Sha256 = CurrentAuthArchiveRecoveryV2Preservation.NativeSha(fleet.Auth.Native),
            Tuples = fleet.Auth.Native.CopyTuples().OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new
            { pair.Key, Values = pair.Value.Select(text => CurrentAuthLocalSessionArchivePolicy.HashBytes(System.Text.Encoding.UTF8.GetBytes(text))).Order(StringComparer.Ordinal) }),
            Storage = fleet.Auth.Native.CopyStorage().OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { pair.Key, pair.Value.FileNode, pair.Value.Blocks }),
            Expressions = fleet.Auth.Native.CopyExpressions().OrderBy(pair => pair.Key, StringComparer.Ordinal),
        }, ct);
    }
    private async Task<CurrentAuthArchiveProofArtifact> RecoveryProofCopyAsync(string name, CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact original, CancellationToken ct)
    {
        byte[] bytes = files.Read(original.Path, sharedReader: true, maximumBytes: 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != original.Sha256) { throw Invalid(); }
        var copy = await RecoveryBytesAsync(name, bytes, ct); return new(copy.Path, copy.Sha256);
    }
    private async Task<CurrentAuthArchiveGenuineArtifact> RecoveryBytesAsync(string name, byte[] bytes, CancellationToken ct)
    {
        string path = Path.Combine(_inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath, $"genuine-recovery-v2-{Scope.OperationId:N}-{name}");
        await _inputs.ParentFiles.WriteNewAsync(path, bytes, ct);
        if (!_inputs.ParentFiles.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024).AsSpan().SequenceEqual(bytes)) { throw Invalid(); }
        var artifact = new CurrentAuthArchiveGenuineArtifact(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
        if (name != "incomplete-precleanup-stage") { _recoveryArtifacts.Add(name, artifact); }
        return artifact;
    }
    private static void RequireRecoveryFleetEqual(CurrentAuthArchiveFleet before, CurrentAuthArchiveFleet after)
    {
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(after.Auth, before.Auth);
        if (!before.Databases.Select(item => item.Database).SequenceEqual(after.Databases.Select(item => item.Database), StringComparer.Ordinal) ||
            before.Databases.Any(item => item.Sha256 != after.Databases.Single(row => row.Database == item.Database).Sha256)) { throw Invalid(); }
    }
}
