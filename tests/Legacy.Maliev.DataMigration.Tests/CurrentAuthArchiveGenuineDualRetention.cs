using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    private CurrentAuthArchiveDeviceProof? _dualDeviceProof;

    Task<CurrentAuthArchiveGenuineDualArtifacts> ICurrentAuthArchiveGenuineOwnedLease.RetainDualHelperFactsAsync(
        CurrentAuthArchiveGenuineDualFacts facts, CancellationToken ct)
    {
        return RetainHelperEvidenceAsync(facts, _environment?.RecoveryStorage ?? throw Invalid(), null, ct);
    }

    private async Task<CurrentAuthArchiveGenuineDualArtifacts> RetainHelperEvidenceAsync(CurrentAuthArchiveGenuineDualFacts facts,
        ICurrentAuthLocalSessionArchiveStorage storage, CurrentAuthArchiveGenuineRecoveryHelpersOutcome? outcome, CancellationToken ct)
    {
        if (_disposed || _environment is null || _firstPolicy is null || _secondPolicy is null || _firstFiles is null || _secondFiles is null ||
            _dualDeviceProof is null || CurrentAuthLocalSessionArchivePolicy.Hash(facts.Scope) != CurrentAuthLocalSessionArchivePolicy.Hash(Scope) ||
            CurrentAuthLocalSessionArchivePolicy.Hash(_dualDeviceProof) != Scope.RecoveryDeviceProofSha256) { throw Invalid(); }
        await _inputs.RequireAsync(ct);
        var helperCase = CurrentAuthArchiveGenuineRecoveryHelpers.Parse(_seed.CaseId);
        string caseId = CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(helperCase);
        bool dual = helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback;
        if (dual != (outcome is null) || (outcome is not null && outcome.Fault.CaseId != caseId)) { throw Invalid(); }
        string prefix = dual ? "genuine-dual" : "genuine-recovery";
        var native = await _environment.CaptureDualHelperNativeEvidenceAsync(Scope,
            _firstPolicy.HbaFile, _firstPolicy.RawRules, _secondPolicy.HbaFile, _secondPolicy.RawRules, ct);
        var artifacts = new Dictionary<string, CurrentAuthArchiveGenuineArtifact>(StringComparer.Ordinal);
        _ = await JsonAsync("scope", Scope); _ = await JsonAsync("source", _inputs.Source);
        _ = await JsonAsync("review", facts.Claims.Review); _ = await JsonAsync("authorization", facts.Claims.Authorization);
        _ = await JsonAsync("device-proof", _dualDeviceProof);
        _ = await JsonAsync("local-target", native.LocalTarget); _ = await JsonAsync("comparison-target", native.ComparisonTarget);
        _ = await JsonAsync("local-container", native.LocalContainer); _ = await JsonAsync("local-volume", native.LocalVolume);
        _ = await JsonAsync("comparison-container", native.ComparisonContainer); _ = await JsonAsync("comparison-volume", native.ComparisonVolume);
        _ = await JsonAsync("local-before", facts.LocalBefore.Databases); _ = await JsonAsync("local-after", facts.LocalAfter.Databases);
        _ = await JsonAsync("comparison-before", facts.ComparisonBefore.Databases); _ = await JsonAsync("comparison-after", facts.ComparisonAfter.Databases);
        _ = await JsonAsync("local-before-catalogs", facts.LocalBefore.Catalogs); _ = await JsonAsync("local-after-catalogs", facts.LocalAfter.Catalogs);
        _ = await JsonAsync("comparison-before-catalogs", facts.ComparisonBefore.Catalogs); _ = await JsonAsync("comparison-after-catalogs", facts.ComparisonAfter.Catalogs);
        _ = await JsonAsync("rows", facts.LocalBefore.Auth.Sessions);
        var firstHba = await CopyAsync("local-hba", _firstFiles, _firstPolicy.HbaFile);
        var firstRules = await CopyAsync("local-hba-rules", _firstFiles, _firstPolicy.RawRules);
        var secondHba = await CopyAsync("comparison-hba", _secondFiles, _secondPolicy.HbaFile);
        var secondRules = await CopyAsync("comparison-hba-rules", _secondFiles, _secondPolicy.RawRules);
        _ = await JsonAsync("local-policy", native.LocalPolicy with { HbaFile = AsProof(firstHba), RawRules = AsProof(firstRules) });
        _ = await JsonAsync("comparison-policy", native.ComparisonPolicy with { HbaFile = AsProof(secondHba), RawRules = AsProof(secondRules) });
        using (var signer = DualSigner(_inputs.Pins.EvidenceKeyId, CurrentAuthArchiveGenuineDualInputContract.EvidenceKeyName, _inputs.Pins.EvidenceFingerprint))
        {
            _ = await JsonAsync("recovery-manifest", CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.RecoveryDomain, facts.Manifest, signer));
        }
        string firstCipherHash = helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption
            ? outcome!.Fault.Files.Single().AfterSha256 : facts.Manifest.FirstCiphertextSha256;
        await RecoveryAsync("first-ciphertext", true, Scope.Paths.FirstCiphertext, 12 * 1024 * 1024, firstCipherHash);
        await RecoveryAsync("second-ciphertext", false, Scope.Paths.SecondCiphertext, 12 * 1024 * 1024, facts.Manifest.SecondCiphertextSha256);
        await RecoveryAsync("first-recovery-key", true, Scope.Paths.RecoveryPrivateKey, 65536, expected: null);
        await RecoveryAsync("second-recovery-key", false, Scope.Paths.SecondRecoveryPrivateKey, 65536, expected: null);
        if (helperCase != CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption && artifacts["first-recovery-key"].Sha256 != artifacts["second-recovery-key"].Sha256) { throw Invalid(); }
        if (helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption && artifacts["first-recovery-key"].Sha256 != outcome!.Fault.Files.Single().AfterSha256) { throw Invalid(); }
        if (outcome is not null) { _ = await JsonAsync("recovery-outcome", outcome); }
        var scenario = new CurrentAuthArchiveProofScenario(caseId, outcome?.RejectionCode, false, false,
            helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery,
            helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery,
            DateTimeOffset.UtcNow, []);
        CurrentAuthArchiveProofReader.RequireEffects(caseId, scenario, [],
            facts.LocalBefore.Auth.Native.Snapshot, facts.LocalAfter.Auth.Native.Snapshot);
        CurrentAuthArchiveProofReader.RequireComparisonFleetAfter(facts.ComparisonBefore.Databases.ToArray(), facts.ComparisonAfter.Databases.ToArray(), productionFault: false);
        _ = await JsonAsync("scenario", scenario);
        string root = _inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath;
        string test = typeof(CurrentAuthArchiveGenuineOwnedPair).Assembly.Location;
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(test), root)) { throw Invalid(); }
        artifacts.Add("test-assembly", new(test, _seed.TestAssemblySha256));
        await _inputs.RequireAsync(ct);
        DateTimeOffset ended = DateTimeOffset.UtcNow;
        var stage = await WriteAsync("incomplete-precleanup-stage", JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = dual ? "current-auth-genuine-dual-helper-incomplete-precleanup-v1" : "current-auth-genuine-recovery-helper-incomplete-precleanup-v1",
            CaseId = caseId,
            Scope.OperationId,
            facts.BeganAtUtc,
            EndedAtUtc = ended,
            NativeObservedAtUtc = native.ObservedAtUtc,
            native.LocalPort,
            native.ComparisonPort,
            Artifacts = artifacts,
            Receipts = Array.Empty<CurrentAuthArchiveGenuineArtifact>(),
            CleanupVerified = false,
            PhaseProofComplete = false,
            ProviderExitCode = (int?)null,
        }));
        return new(stage, facts.BeganAtUtc, ended);

        Task<CurrentAuthArchiveGenuineArtifact> JsonAsync<T>(string name, T value)
        {
            return WriteAsync(name, JsonSerializer.SerializeToUtf8Bytes(value));
        }

        async Task<CurrentAuthArchiveGenuineArtifact> CopyAsync(string name, CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact artifact)
        {
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 65536);
            return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256 ? throw Invalid() : await WriteAsync(name, bytes);
        }

        async Task RecoveryAsync(string name, bool first, string path, int maximum, string? expected)
        {
            byte[] bytes = await storage.ReadDomainHeldAsync(first, path, maximum, ct);
            try
            {
                if (expected is not null && CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != expected) { throw Invalid(); }
                _ = await WriteAsync(name, bytes);
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
        }

        async Task<CurrentAuthArchiveGenuineArtifact> WriteAsync(string name, byte[] bytes)
        {
            string path = Path.Combine(_inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath, $"{prefix}-{Scope.OperationId:N}-{name}.json");
            await _inputs.ParentFiles.WriteNewAsync(path, bytes, ct);
            if (!_inputs.ParentFiles.Read(path, sharedReader: true, maximumBytes: 12 * 1024 * 1024).AsSpan().SequenceEqual(bytes)) { throw Invalid(); }
            var artifact = new CurrentAuthArchiveGenuineArtifact(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
            if (name != "incomplete-precleanup-stage") { artifacts.Add(name, artifact); }
            return artifact;
        }

        static CurrentAuthArchiveProofArtifact AsProof(CurrentAuthArchiveGenuineArtifact value)
        {
            return new(value.Path, value.Sha256);
        }
    }
}
