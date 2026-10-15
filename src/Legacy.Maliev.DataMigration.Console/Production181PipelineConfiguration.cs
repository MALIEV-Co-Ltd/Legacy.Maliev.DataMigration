namespace Legacy.Maliev.DataMigration.Console;

internal sealed record Production181InputRoot(string Id, LocalExecutionBinding Binding);
internal sealed record Production181Input(string RootId, string Name, string Sha256);
internal sealed record Production181BundleFile(Production181Input Input, string RelativePath);
internal sealed record Production181PipelineConfiguration(IReadOnlyList<Production181InputRoot> Roots,
    Production181Input Subject, Production181Input Schema, Production181Input Catalog, Production181Input Source,
    Production181Input Owner, Production181Input NativeBefore, Production181Input TargetPins, Production181Input IntendedBinding,
    IReadOnlyList<Production181BundleFile> Bundle, string FreshBundleRoot, string FreshDefinitionRoot,
    string FreshProviderRoot, string FreshMaintenanceRoot, string AcceptedSourceCommitSha, string AcceptedCatalogSha256,
    string TestAssemblySha256, string SequenceOwner);
internal sealed record Production181PhaseResult(string Phase, LocalExecutionBinding Binding, string BindingPath,
    CustomerDefinitionArtifact Component, CustomerDefinitionArtifact SemanticEnvelope, CustomerDefinitionArtifact PublicKey,
    string KeyId, string Fingerprint, CustomerDefinitionArtifact HostExit);
internal sealed record Production181PipelineResult(string Kind, CustomerDefinitionSubject IntendedSubject,
    Production181PhaseResult Definition, Production181PhaseResult Provider, Production181PhaseResult Maintenance,
    DateTimeOffset CompletedAtUtc, string Status);
