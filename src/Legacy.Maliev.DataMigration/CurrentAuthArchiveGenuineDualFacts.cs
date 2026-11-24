namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchiveGenuineHelperClaims(CurrentAuthArchiveClaim Review, CurrentAuthArchiveClaim Authorization);
internal sealed record CurrentAuthArchiveGenuineArtifact(string Path, string Sha256);
internal sealed record CurrentAuthArchiveGenuineDualArtifacts(CurrentAuthArchiveGenuineArtifact IncompletePreCleanupStage,
    DateTimeOffset BeganAtUtc, DateTimeOffset EndedAtUtc);
internal sealed record CurrentAuthArchiveGenuineCleanupArtifacts(CurrentAuthArchiveGenuineArtifact Binding,
    CurrentAuthArchiveGenuineArtifact Disposal, CurrentAuthArchiveGenuineArtifact Absence);

// Internal transport ONLY to the fixed authenticated issuer receiver. The helper
// never returns these native observations or rows to its caller.
internal sealed record CurrentAuthArchiveGenuineDualFacts(CurrentAuthArchiveScope Scope,
    CurrentAuthArchiveGenuineHelperClaims Claims, CurrentAuthArchiveRecoveryManifest Manifest,
    CurrentAuthArchiveFleet LocalBefore, CurrentAuthArchiveFleet LocalAfter,
    CurrentAuthArchiveFleet ComparisonBefore, CurrentAuthArchiveFleet ComparisonAfter, DateTimeOffset BeganAtUtc);
