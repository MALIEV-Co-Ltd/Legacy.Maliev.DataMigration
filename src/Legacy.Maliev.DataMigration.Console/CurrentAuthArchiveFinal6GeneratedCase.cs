namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveFinal6GenerationBinding(string Kind, CurrentAuthArchiveProofCaseV2 Case, Guid OperationId,
    string AudienceSha256, string SeedSha256, string CaseBindingSha256, string SourceCaptureSha256, string DefinitionSha256,
    string InputSha256, string HostConfigurationSha256, string IntendedSha256, string PreDefinitionIntendedSha256,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentAuthArchiveFinal6GeneratedCase(CurrentAuthArchiveProofCaseV2 Case, Guid OperationId,
    CurrentAuthArchiveProofArtifact QualifiedInputBinding, CurrentAuthArchiveProofArtifact GenerationBinding,
    CurrentAuthArchiveProofArtifact CaseBinding, CurrentAuthArchiveProofArtifact SourceCapture,
    CurrentAuthArchiveProofArtifact IntendedObservation, CurrentAuthArchiveProofArtifact PreDefinitionIntendedObservation,
    CurrentAuthArchiveProofArtifact Seed, CurrentAuthArchiveProofArtifact Input, CurrentAuthArchiveProofArtifact HostConfiguration,
    CurrentAuthArchiveProofArtifact Definition, CurrentAuthArchiveProofArtifact Audience);
internal sealed record CurrentAuthArchiveFinal6CaseRun(string Kind, CurrentAuthArchiveFinal6GeneratedCase Generated,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, int ActualHostReturnCode,
    CurrentAuthArchiveProofArtifact RunMetadata, CurrentAuthArchiveProofArtifact ProviderResult,
    CurrentAuthArchiveProofArtifact ProviderProcess, CurrentAuthArchiveProofArtifact VstestProcess,
    CurrentAuthArchiveProofArtifact Trx, CurrentAuthArchiveProofArtifact HostExit, CurrentAuthArchiveProofArtifact ResourceCleanup,
    bool PhaseProofComplete);

internal static class CurrentAuthArchiveFinal6GenerationPolicy
{
    internal const string Domain = "Legacy.Maliev.CurrentAuth.Final6.GeneratedCase.v1";
    internal static void Require(CurrentAuthArchiveFinal6GenerationBinding value, CurrentAuthArchiveFinal6GeneratedCase generated,
        CurrentAuthArchiveComponentBootstrapSeed seed, DateTimeOffset before)
    {
        _ = CurrentAuthArchiveGeneratedCasesV2.Identity(generated.Case);
        if (value.Kind != "current-auth-archive-final6-generated-binding-v1" || value.Case != generated.Case ||
            value.OperationId == Guid.Empty || value.OperationId != generated.OperationId || value.OperationId != seed.OperationId ||
            value.AudienceSha256 != generated.Audience.Sha256 || value.SeedSha256 != generated.Seed.Sha256 ||
            value.CaseBindingSha256 != generated.CaseBinding.Sha256 || value.SourceCaptureSha256 != generated.SourceCapture.Sha256 ||
            value.DefinitionSha256 != generated.Definition.Sha256 || value.InputSha256 != generated.Input.Sha256 ||
            value.HostConfigurationSha256 != generated.HostConfiguration.Sha256 || value.IntendedSha256 != generated.IntendedObservation.Sha256 ||
            value.PreDefinitionIntendedSha256 != generated.PreDefinitionIntendedObservation.Sha256 ||
            value.IssuedAtUtc.Offset != TimeSpan.Zero || value.ExpiresAtUtc.Offset != TimeSpan.Zero || before.Offset != TimeSpan.Zero ||
            value.IssuedAtUtc < seed.IssuedAtUtc || value.IssuedAtUtc > before || value.ExpiresAtUtc <= before || value.ExpiresAtUtc > seed.ExpiresAtUtc ||
            new[] { value.AudienceSha256, value.SeedSha256, value.CaseBindingSha256, value.SourceCaptureSha256, value.DefinitionSha256,
                value.InputSha256, value.HostConfigurationSha256, value.IntendedSha256, value.PreDefinitionIntendedSha256 }
                .Any(hash => !CurrentAuthRepairPermit.HashShape(hash))) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
    }
}
