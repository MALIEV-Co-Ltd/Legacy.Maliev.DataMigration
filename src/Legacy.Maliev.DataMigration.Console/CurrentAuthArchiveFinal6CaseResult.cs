namespace Legacy.Maliev.DataMigration.Console;

// Executed method facts and a cleanup-verified effect candidate; never a complete proof or persistent authorization.
internal sealed record CurrentAuthArchiveFinal6CaseResult(string Kind, CurrentAuthArchiveProofCaseV2 Case, Guid OperationId,
    CurrentAuthArchiveActualMethodV2 Method, CurrentAuthArchiveGenuineArtifact EffectCandidate,
    CurrentAuthArchiveProofArtifact CurrentSourceCapture, CurrentAuthArchiveProofArtifact OriginalSourceCapture,
    CurrentAuthArchiveProofArtifact Audience, CurrentAuthArchiveProofArtifact Definition, CurrentAuthArchiveProofArtifact CaseBinding);
