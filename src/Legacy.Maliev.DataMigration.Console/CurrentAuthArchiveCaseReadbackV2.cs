using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveActualMethodV2(int ReturnCode, DateTimeOffset StartedAtUtc, DateTimeOffset ReturnedAtUtc,
    CurrentAuthArchiveGenuineDualArtifacts Artifacts);

internal sealed partial class CurrentAuthArchiveCaseReadbackV2
{
    private readonly CurrentAuthArchiveCaseCustodyV2 _roots;
    private readonly CurrentAuthArchivePins _pins;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly Dictionary<string, CurrentAuthArchiveGenuineArtifact> _artifacts;
    private readonly JsonElement _stage, _candidate;
    internal CurrentAuthArchiveGeneratedCaseRunV2 Run { get; }
    internal CurrentAuthArchiveScope Scope { get; }
    internal CurrentAuthArchiveActualMethodV2 Method { get; }
    internal CurrentAuthArchiveRecoverySourceEvidence Source { get; }
    private CurrentAuthArchiveCaseReadbackV2(CurrentAuthArchivePins pins,
        IReceiptAttestationTrustStore trust, CurrentAuthArchiveGeneratedCaseRunV2 run, CurrentAuthArchiveScope scope,
        CurrentAuthArchiveActualMethodV2 method, CurrentAuthArchiveRecoverySourceEvidence source,
        Dictionary<string, CurrentAuthArchiveGenuineArtifact> artifacts, JsonElement stage, JsonElement candidate, CurrentAuthArchiveCaseCustodyV2 roots)
    { _roots = roots; _pins = pins; _trust = trust; Run = run; Scope = scope; Method = method; Source = source; _artifacts = artifacts; _stage = stage; _candidate = candidate; }

    internal static async Task<CurrentAuthArchiveCaseReadbackV2> RequireAsync(CurrentAppOwnedRepairCustody files,
        CurrentAuthArchiveGeneratedCaseRunV2 run, CurrentAuthArchiveProofAudienceV2 audience, CurrentAuthArchivePins pins,
        IReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        files.Require(); CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        using var roots = CurrentAuthArchiveCaseCustodyV2.Open(files, run.Generated);
        var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(run.Generated.Case);
        MigrationConsole.RequireActualGeneratedProcesses(run, identity, ct);
        T Decode<T>(CurrentAuthArchiveProofArtifact artifact, int maximum = 65536)
        {
            return MigrationConsole.DecodeAuthRepair<T>(Read(artifact, maximum));
        }

        byte[] Read(CurrentAuthArchiveProofArtifact artifact, int maximum)
        { return roots.Read(artifact, maximum); }
        using var result = JsonDocument.Parse(Read(run.ProviderResult, 65536));
        var caseResult = result.RootElement.GetProperty("Case");
        var method = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveActualMethodV2>(JsonSerializer.SerializeToUtf8Bytes(caseResult.GetProperty(nameof(Method))));
        var candidateRef = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineArtifact>(JsonSerializer.SerializeToUtf8Bytes(caseResult.GetProperty(identity.Phase == "recovery" ? "Candidate" : "FinalCandidate")));
        using var candidate = JsonDocument.Parse(Read(new(candidateRef.Path, candidateRef.Sha256), 65536));
        using var stage = JsonDocument.Parse(Read(new(method.Artifacts.IncompletePreCleanupStage.Path, method.Artifacts.IncompletePreCleanupStage.Sha256), 65536));
        var artifacts = MigrationConsole.DecodeAuthRepair<Dictionary<string, CurrentAuthArchiveGenuineArtifact>>(JsonSerializer.SerializeToUtf8Bytes(stage.RootElement.GetProperty("Artifacts")));
        var scopeRef = artifacts["scope"]; var scope = Decode<CurrentAuthArchiveScope>(new(scopeRef.Path, scopeRef.Sha256), 1024 * 1024);
        var seed = scope.ComponentSubject?.Seed ?? throw Invalid();
        var source = Decode<CurrentAuthArchiveRecoverySourceEvidence>(run.Generated.SourceCapture, 32 * 1024 * 1024);
        var bindingClaim = Decode<CurrentAuthArchiveClaim>(run.Generated.BindingClaim);
        var binding = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveGeneratedBindingV2>(bindingClaim,
            CurrentAuthArchiveGeneratedCasesV2.BindingDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthArchiveRecoveryV2.RequireSource(source, audience.AcceptedCommitSha, audience.SourceIdentitySha256, audience.SourceDefinitionSha256, method.StartedAtUtc);
        CurrentAuthArchiveRecoveryV2.RequireAudience(audience, seed, pins, method.StartedAtUtc);
        CurrentAuthArchiveComponentBootstrap.RequireClaims(scope, trust, pins, method.StartedAtUtc);
        if (scope.OperationId != run.Generated.OperationId || seed.CaseId != identity.CaseId || method.ReturnCode != identity.ExpectedProviderExitCode ||
            seed.ParentRunBindingSha256 != Decode<LocalExecutionBinding>(run.Generated.QualifiedInputBinding).ComputeSha256() ||
            method.StartedAtUtc < run.BeganAtUtc || method.ReturnedAtUtc > run.CompletedAtUtc || method.StartedAtUtc > method.ReturnedAtUtc ||
            method.Artifacts.BeganAtUtc != method.StartedAtUtc || method.Artifacts.EndedAtUtc > method.ReturnedAtUtc ||
            binding.Kind != "current-auth-archive-generated-case-binding-v2" || binding.AudienceSha256 != run.Generated.Audience.Sha256 ||
            binding.OperationId != scope.OperationId || binding.CaseId != identity.CaseId || binding.Phase != identity.Phase ||
            binding.SeedSha256 != run.Generated.Seed.Sha256 || binding.InputSha256 != run.Generated.Input.Sha256 ||
            binding.HostConfigurationSha256 != run.Generated.HostConfiguration.Sha256 || binding.SourceFullSha256 != source.FullPlanSha256 ||
            seed.SourceSchemaPlanSha256 != source.FullPlanSha256 || binding.SourceIdentitySha256 != audience.SourceIdentitySha256 ||
            binding.SourceDefinitionSha256 != audience.SourceDefinitionSha256 || binding.IntendedObservationSha256 != run.Generated.IntendedObservation.Sha256 ||
            binding.PreDefinitionIntendedObservationSha256 != run.Generated.PreDefinitionIntendedObservation.Sha256 ||
            binding.DefinitionPrecursorSha256 != run.Generated.Definition.Definition.Sha256 || binding.IssuedAtUtc > run.BeganAtUtc ||
            binding.ExpiresAtUtc <= method.StartedAtUtc || binding.ExpiresAtUtc > seed.ExpiresAtUtc ||
            !JsonSerializer.SerializeToUtf8Bytes(seed).AsSpan().SequenceEqual(Read(run.Generated.Seed, 65536))) { throw Invalid(); }
        var sourceRef = artifacts[identity.Phase == "recovery" ? "original-source" : "source"];
        var original = Decode<FreshSchemaPlan>(new(sourceRef.Path, sourceRef.Sha256), 32 * 1024 * 1024);
        if (SchemaPlanCanonicalizer.ComputeSha256(original) != source.FullPlanSha256 ||
            stage.RootElement.GetProperty("OperationId").GetGuid() != scope.OperationId || stage.RootElement.GetProperty("CaseId").GetString() != identity.CaseId ||
            stage.RootElement.GetProperty("CleanupVerified").GetBoolean() || stage.RootElement.GetProperty("PhaseProofComplete").GetBoolean() ||
            candidate.RootElement.GetProperty("OperationId").GetGuid() != scope.OperationId || candidate.RootElement.GetProperty("CaseId").GetString() != identity.CaseId ||
            !candidate.RootElement.GetProperty("CleanupVerified").GetBoolean() || candidate.RootElement.GetProperty("PhaseProofComplete").GetBoolean() ||
            candidate.RootElement.GetProperty("ProviderProcessExitCode").ValueKind != JsonValueKind.Null) { throw Invalid(); }
        var precursor = Decode<CurrentAuthRepairScope>(run.Generated.Definition.CompletedScope, 1024 * 1024);
        var precursorSource = Decode<FreshSchemaPlan>(run.Generated.Definition.Source, 32 * 1024 * 1024);
        string precursorRoot = Path.GetDirectoryName(run.Generated.Definition.RunBinding.Path)!;
        var precursorFiles = roots.For(run.Generated.Definition.RunBinding.Path);
        var precursorPins = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairSigningPins>(precursorFiles.Read(Path.Combine(precursorRoot, "archive-definition-pins.json"), sharedReader: true, maximumBytes: 65536));
        CurrentAuthArchiveComponentReadback.RequirePrecursorBinding(precursor, seed,
            Decode<LocalExecutionBinding>(run.Generated.Definition.RunBinding).ComputeSha256(), SchemaPlanCanonicalizer.ComputeSha256(precursorSource), run.Generated.Definition.Definition.Sha256);
        await CurrentAuthRepairProofReader.RequireAsync(precursorFiles, new(run.Generated.Definition.Definition.Path, run.Generated.Definition.Definition.Sha256),
            run.Generated.Definition.Definition.Sha256, "helper", precursor, trust, precursorPins, precursorSource, ct);
        var value = new CurrentAuthArchiveCaseReadbackV2(pins, trust, run, scope, method, source, artifacts, stage.RootElement.Clone(), candidate.RootElement.Clone(), roots);
        value.RequireCandidateAndCleanup(identity); await value.RequireFamilyAsync(identity, ct); files.Require(); return value;
    }

    private T Value<T>(string name, int maximum = 32 * 1024 * 1024)
    {
        return MigrationConsole.DecodeAuthRepair<T>(Bytes(name, maximum));
    }

    private byte[] Bytes(string name, int maximum = 32 * 1024 * 1024)
    { var artifact = _artifacts[name]; return _roots.Read(new(artifact.Path, artifact.Sha256), maximum); }
    private T Artifact<T>(CurrentAuthArchiveGenuineArtifact artifact, int maximum = 65536)
    { return MigrationConsole.DecodeAuthRepair<T>(_roots.Read(new(artifact.Path, artifact.Sha256), maximum)); }
    private void RequireCandidateAndCleanup(CurrentAuthArchiveGenuineCase identity)
    {
        string expected = identity.Phase == "recovery" ? "current-auth-genuine-recovery-candidate-v2" :
            Run.Generated.Case is CurrentAuthArchiveProofCaseV2.HostUnprobed or CurrentAuthArchiveProofCaseV2.LocalTrust ? "current-auth-genuine-policy-preflight-candidate-v1" :
            identity.Phase != "helper" ? "current-auth-genuine-execution-candidate-v1" : Run.Generated.Case == CurrentAuthArchiveProofCaseV2.Dual ? "current-auth-genuine-dual-helper-candidate-v1" : "current-auth-genuine-recovery-helper-candidate-v1";
        if (_candidate.GetProperty("Kind").GetString() != expected) { throw Invalid(); }
        string stageKind = identity.Phase == "recovery" ? "current-auth-genuine-recovery-incomplete-precleanup-v2" :
            Run.Generated.Case is CurrentAuthArchiveProofCaseV2.HostUnprobed or CurrentAuthArchiveProofCaseV2.LocalTrust ? "current-auth-genuine-preflight-incomplete-precleanup-v1" :
            identity.Phase != "helper" ? "current-auth-genuine-execution-incomplete-precleanup-v1" : Run.Generated.Case == CurrentAuthArchiveProofCaseV2.Dual ?
            "current-auth-genuine-dual-helper-incomplete-precleanup-v1" : "current-auth-genuine-recovery-helper-incomplete-precleanup-v1";
        var candidateStage = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineArtifact>(JsonSerializer.SerializeToUtf8Bytes(_candidate.GetProperty("IncompletePreCleanupStage")));
        var candidateMethod = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineArtifact>(JsonSerializer.SerializeToUtf8Bytes(_candidate.GetProperty("ProviderMethod")));
        if (_stage.GetProperty("Kind").GetString() != stageKind || candidateStage != Method.Artifacts.IncompletePreCleanupStage ||
            CurrentAuthLocalSessionArchivePolicy.Hash(Artifact<CurrentAuthArchiveActualMethodV2>(candidateMethod)) != CurrentAuthLocalSessionArchivePolicy.Hash(Method) ||
            _stage.GetProperty("BeganAtUtc").GetDateTimeOffset() != Method.StartedAtUtc ||
            _stage.GetProperty("EndedAtUtc").GetDateTimeOffset() != Method.Artifacts.EndedAtUtc) { throw Invalid(); }
        foreach (bool comparison in new[] { false, true })
        {
            var cleanup = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineCleanupArtifacts>(JsonSerializer.SerializeToUtf8Bytes(_candidate.GetProperty(comparison ? "ComparisonCleanup" : "LocalCleanup")));
            var target = comparison ? Scope.ComponentSubject!.Comparison : Scope.ComponentSubject!.Local;
            _roots.AddFixture(cleanup.Binding, target.RunBindingSha256);
            var binding = Artifact<LocalExecutionBinding>(cleanup.Binding);
            if (binding.ComputeSha256() != target.RunBindingSha256) { throw Invalid(); }
            using var disposed = JsonDocument.Parse(Artifact<JsonElement>(cleanup.Disposal).GetRawText());
            using var absent = JsonDocument.Parse(Artifact<JsonElement>(cleanup.Absence).GetRawText());
            JsonElement d = disposed.RootElement, a = absent.RootElement;
            int port = _stage.GetProperty(comparison ? "ComparisonPort" : "LocalPort").GetInt32();
            if (d.GetProperty("Operation").GetGuid() != Scope.OperationId || a.GetProperty("Operation").GetGuid() != Scope.OperationId ||
                d.GetProperty("_id").GetString() != target.ContainerId || a.GetProperty("_id").GetString() != target.ContainerId ||
                d.GetProperty("volume").GetString() != target.VolumeName || a.GetProperty("volume").GetString() != target.VolumeName ||
                d.GetProperty("cleanupFailed").GetBoolean() || !d.GetProperty("removed").GetBoolean() || !d.GetProperty("sdkDisposed").GetBoolean() || !d.GetProperty("verifiedAbsence").GetBoolean() ||
                d.GetProperty("removedAtUtc").GetDateTimeOffset() < Method.ReturnedAtUtc || a.GetProperty("observedAtUtc").GetDateTimeOffset() < d.GetProperty("removedAtUtc").GetDateTimeOffset() ||
                a.GetProperty("observedAtUtc").GetDateTimeOffset() > _candidate.GetProperty("PublishedAtUtc").GetDateTimeOffset() ||
                a.GetProperty("observedPort").GetInt32() != port || a.GetProperty("containerIds").EnumerateArray().Any(item => item.GetString() == target.ContainerId) ||
                a.GetProperty("containerNames").EnumerateArray().Any(item => item.GetString()?.TrimStart('/') == target.ContainerName.TrimStart('/')) ||
                a.GetProperty("volumeNames").EnumerateArray().Any(item => item.GetString() == target.VolumeName) ||
                a.GetProperty("listeningPorts").EnumerateArray().Any(item => item.GetInt32() == port)) { throw Invalid(); }
        }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
