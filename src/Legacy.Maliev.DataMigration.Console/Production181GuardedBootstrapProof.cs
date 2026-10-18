namespace Legacy.Maliev.DataMigration.Console;

// Engine-specific proof retains the original completed13 root/binding and trust.
// The copied definition bytes in the active immediate root must match the fully validated original.
internal sealed record Production181GuardedBootstrapProof(string Kind, CustomerDefinitionSubject IntendedSubject,
    CustomerDefinitionArtifact DefinitionPrecursor, Production181PrerequisitePaths DefinitionPaths,
    CustomerDefinitionArtifact Trx, CustomerDefinitionArtifact HostExit, IReadOnlyList<CustomerGuardedBootstrapCase> Cases,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc,
    string DefinitionKeyId, string DefinitionFingerprint, string KeyId, string? Signature);
