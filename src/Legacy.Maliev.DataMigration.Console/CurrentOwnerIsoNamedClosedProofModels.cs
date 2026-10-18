namespace Legacy.Maliev.DataMigration.Console;

// Completed observation report only. No permit, review or authorization can be
// obtained by deserializing this report or by selecting its proof phase.
internal sealed record IsoNamedClosedCase(string CaseId, string TestName, string TestId, string ExecutionId, Guid OperationId,
    IsoDefinitionArtifact ParentEntry, IsoDefinitionArtifact Configuration, IReadOnlyList<IsoDefinitionArtifact> Files);
internal sealed record IsoNamedClosedProof(string Kind, IsoComponentProofPhase Phase, IsoDefinitionSubject DefinitionSubject,
    IsoComponentHostEvidence Host, IsoDefinitionArtifact Trx, IsoDefinitionArtifact ExecutedTestAssembly,
    string ExecutedTestAssemblyPath, IReadOnlyList<IsoNamedClosedCase> Cases,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);
