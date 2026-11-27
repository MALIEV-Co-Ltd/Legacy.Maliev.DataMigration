using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveFinal6CaseReadback
{
    private readonly CurrentAuthArchiveFinal6CaseCustody _roots;
    private readonly CurrentAuthArchivePins _pins;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly Dictionary<string, CurrentAuthArchiveGenuineArtifact> _artifacts;
    private readonly JsonElement _stage, _candidate;
    internal CurrentAuthArchiveFinal6CaseRun Run { get; }
    internal CurrentAuthArchiveScope Scope { get; }
    internal CurrentAuthArchiveActualMethodV2 Method { get; }
    internal CurrentAuthArchiveRecoverySourceEvidence Source { get; }
    private CurrentAuthArchiveFinal6CaseReadback(CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust,
        CurrentAuthArchiveFinal6CaseRun run, CurrentAuthArchiveScope scope, CurrentAuthArchiveActualMethodV2 method,
        CurrentAuthArchiveRecoverySourceEvidence source, Dictionary<string, CurrentAuthArchiveGenuineArtifact> artifacts,
        JsonElement stage, JsonElement candidate, CurrentAuthArchiveFinal6CaseCustody roots)
    { _pins = pins; _trust = trust; Run = run; Scope = scope; Method = method; Source = source; _artifacts = artifacts; _stage = stage; _candidate = candidate; _roots = roots; }

    internal static async Task<CurrentAuthArchiveFinal6CaseReadback> RequireAsync(CurrentAppOwnedRepairCustody parent,
        CurrentAuthArchiveFinal6CaseRun run, CurrentAuthArchiveClaim audienceClaim, CurrentAuthArchivePins pins,
        IReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        parent.Require(); CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        using var roots = CurrentAuthArchiveFinal6CaseCustody.Open(parent, run.Generated);
        var generated = run.Generated;
        var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(generated.Case);
        MigrationConsole.RequireActualFinal6Processes(run, identity, ct);
        T Decode<T>(CurrentAuthArchiveProofArtifact artifact, int maximum = 65536)
        {
            return MigrationConsole.DecodeAuthRepair<T>(roots.Read(artifact, maximum));
        }

        var result = Decode<CurrentAuthArchiveFinal6ProviderResult>(run.ProviderResult);
        var executed = result.Case;
        var method = executed.Method;
        if (executed.Kind != "current-auth-archive-final6-executed-case-v1" || executed.Case != generated.Case || executed.OperationId != generated.OperationId ||
            executed.Audience != generated.Audience || executed.OriginalSourceCapture != generated.SourceCapture || executed.Definition != generated.Definition ||
            executed.CaseBinding != generated.CaseBinding) { throw Invalid(); }
        using var candidate = JsonDocument.Parse(roots.Read(new(executed.EffectCandidate.Path, executed.EffectCandidate.Sha256), 65536));
        using var stage = JsonDocument.Parse(roots.Read(new(method.Artifacts.IncompletePreCleanupStage.Path, method.Artifacts.IncompletePreCleanupStage.Sha256), 65536));
        var artifacts = MigrationConsole.DecodeAuthRepair<Dictionary<string, CurrentAuthArchiveGenuineArtifact>>(JsonSerializer.SerializeToUtf8Bytes(stage.RootElement.GetProperty("Artifacts")));
        var scopeArtifact = artifacts["scope"];
        var scope = Decode<CurrentAuthArchiveScope>(new(scopeArtifact.Path, scopeArtifact.Sha256), 1024 * 1024);
        var seed = scope.ComponentSubject?.Seed ?? throw Invalid();
        var source = Decode<CurrentAuthArchiveFinal6SourceEvidence>(generated.SourceCapture, 32 * 1024 * 1024);
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(audienceClaim,
            CurrentAuthArchiveFinal6AudiencePolicy.Domain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthArchiveFinal6AudiencePolicy.Require(audience, pins, method.StartedAtUtc);
        if (CurrentAuthLocalSessionArchivePolicy.Hash(audienceClaim) != generated.Audience.Sha256) { throw Invalid(); }
        _ = CurrentAuthArchiveFinal6CasePolicy.Require(Decode<CurrentAuthArchiveClaim>(generated.CaseBinding), audienceClaim,
            seed, source, generated.Definition.Sha256, identity.Phase, identity.CaseId, pins, trust, method.StartedAtUtc);
        var generation = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6GenerationBinding>(Decode<CurrentAuthArchiveClaim>(generated.GenerationBinding),
            CurrentAuthArchiveFinal6GenerationPolicy.Domain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthArchiveFinal6GenerationPolicy.Require(generation, generated, seed, method.StartedAtUtc);
        CurrentAuthArchiveComponentBootstrap.RequireClaims(scope, trust, pins, method.StartedAtUtc);
        if (scope.OperationId != generated.OperationId || method.ReturnCode != identity.ExpectedProviderExitCode ||
            method.StartedAtUtc < run.BeganAtUtc || method.ReturnedAtUtc > run.CompletedAtUtc || method.StartedAtUtc > method.ReturnedAtUtc ||
            method.Artifacts.BeganAtUtc != method.StartedAtUtc || method.Artifacts.EndedAtUtc > method.ReturnedAtUtc ||
            seed.ParentRunBindingSha256 != Decode<LocalExecutionBinding>(generated.QualifiedInputBinding).ComputeSha256() ||
            generated.Seed.Sha256 != CurrentAuthLocalSessionArchivePolicy.Hash(seed)) { throw Invalid(); }
        var packet = Decode<CurrentAuthArchiveFinal6CaseInput>(generated.Input);
        CurrentAuthArchiveFinal6Host.RequirePacket(packet, generated.Case);
        var host = Decode<CurrentAuthArchiveFinal6HostConfiguration>(generated.HostConfiguration);
        CurrentAuthArchiveFinal6Host.RequireConfiguration(host, generated.HostConfiguration.Path);
        if (host.ExpectedCase != generated.Case || host.CaseInput != generated.Input || packet.Request.Inputs.ParentBinding != generated.QualifiedInputBinding ||
            packet.Request.Inputs.ParentSeed != generated.Seed || packet.Audience != generated.Audience || packet.CaseBinding != generated.CaseBinding ||
            packet.Definition != generated.Definition || packet.OriginalSourceCapture != generated.SourceCapture) { throw Invalid(); }
        var current = Decode<CurrentAuthArchiveFinal6SourceEvidence>(executed.CurrentSourceCapture, 32 * 1024 * 1024);
        CurrentAuthArchiveFinal6Source.Require(current, audience.AcceptedCommitSha, audience.SourceIdentitySha256, audience.SourceDefinitionSha256, method.StartedAtUtc);
        if (current.Capture.BeganAtUtc < generation.IssuedAtUtc || current.Capture.CompletedAtUtc > method.StartedAtUtc) { throw Invalid(); }
        var originalRef = artifacts[identity.Phase == "recovery" ? "original-source" : "source"];
        if (SchemaPlanCanonicalizer.ComputeSha256(Decode<FreshSchemaPlan>(new(originalRef.Path, originalRef.Sha256), 32 * 1024 * 1024)) != source.Capture.FullPlanSha256 ||
            stage.RootElement.GetProperty("OperationId").GetGuid() != scope.OperationId || stage.RootElement.GetProperty("CaseId").GetString() != identity.CaseId ||
            stage.RootElement.GetProperty("CleanupVerified").GetBoolean() || stage.RootElement.GetProperty("PhaseProofComplete").GetBoolean() ||
            candidate.RootElement.GetProperty("OperationId").GetGuid() != scope.OperationId || candidate.RootElement.GetProperty("CaseId").GetString() != identity.CaseId ||
            !candidate.RootElement.GetProperty("CleanupVerified").GetBoolean() || candidate.RootElement.GetProperty("PhaseProofComplete").GetBoolean() ||
            candidate.RootElement.GetProperty("ProviderProcessExitCode").ValueKind != JsonValueKind.Null) { throw Invalid(); }
        var signing = new CurrentAuthRepairSigningPins(pins.ReviewKeyId, pins.ReviewFingerprint, pins.AuthorizationKeyId,
            pins.AuthorizationFingerprint, pins.EvidenceKeyId, pins.EvidenceFingerprint);
        var definition = await CurrentAuthArchiveFinal6DefinitionReader.RequireCopiedAsync(roots.For(generated.Input.Path), packet.DefinitionOwnerCopies,
            generated.Definition, source, audienceClaim, signing, trust, method.StartedAtUtc, ct);
        if (definition.Definition.Sha256 != seed.DefinitionPrecursorSha256 || definition.SubjectSha256 != seed.PrecursorSubjectSha256 ||
            definition.RunBinding != packet.Request.Inputs.PrecursorBinding || definition.CompletedScope != packet.Request.Inputs.PrecursorScope ||
            definition.Source != packet.Request.Inputs.PrecursorSource || definition.Definition != packet.Request.Inputs.DefinitionPrecursor) { throw Invalid(); }
        var value = new CurrentAuthArchiveFinal6CaseReadback(pins, trust, run, scope, method, source.Capture, artifacts,
            stage.RootElement.Clone(), candidate.RootElement.Clone(), roots);
        value.RequireCandidateAndCleanup(identity); await value.RequireFamilyAsync(identity, ct); parent.Require(); return value;
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
