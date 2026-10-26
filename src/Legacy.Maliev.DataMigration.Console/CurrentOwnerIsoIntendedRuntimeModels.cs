namespace Legacy.Maliev.DataMigration.Console;

// No future native/maintenance proof digest, review, authorization or permission.
internal sealed record IsoIntendedRuntimeFacts(Guid OperationId, string SourceCommitSha, string SourceSchemaPlanSha256,
    string SourceCatalogSha256, string OwnerSourcesSha256, string ContractSha256, string OperationSha256,
    DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster, string TargetGeneration,
    string TargetObservationSha256, string RunBindingSha256, IReadOnlyDictionary<string, string> BeforeDatabaseSha256,
    string GlobalPreservationSha256, CurrentAppOwnedMaintenancePin Maintenance, string MaintenanceValidatorSha256);
internal sealed record IsoIntendedRuntimeObservation(string Kind, IsoIntendedRuntimeFacts Facts,
    IsoDefinitionSubject DefinitionSubject, string DefinitionPrecursorSha256, IsoDefinitionArtifact Source,
    IsoDefinitionArtifact Owners, IsoDefinitionArtifact SourceCatalog, IsoDefinitionArtifact TargetPins,
    IsoDefinitionArtifact CountryBefore, IsoDefinitionArtifact MaterialBefore, IsoDefinitionArtifact FreshFleet,
    int ServerVersionNumber, DateTimeOffset ObservedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);
internal sealed record IsoIntendedClosedPhase(string Kind, IsoComponentProofPhase Phase,
    string IntendedObservationSha256, string DefinitionPrecursorSha256, IsoDefinitionArtifact CompletedNamedReport,
    DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);
internal sealed record IsoIntendedRuntimeEvidence(string BindingPath, IsoDefinitionArtifact Observation,
    string SigningPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys);
internal sealed record IsoExternalClosedEvidence(string ProofBindingPath, string ProofSigningPinsPath,
    IReadOnlyList<DeltaTrustedKeyReference> ProofTrustedKeys, IsoDefinitionArtifact OriginalNativePhase,
    IsoDefinitionArtifact OriginalMaintenancePhase, IsoIntendedRuntimeEvidence IntendedRuntime);

internal sealed record IsoIntendedObservationConfiguration(string BindingPath, string FactsPath, string SourcePath,
    string OwnersPath, CurrentOwnerIsoRepairSourceInputs SourceInputs, string TargetPinsPath, string GlobalBeforePath,
    string OperatorConnectionPath, string OrdinaryConnectionPath, string MaintenanceValidatorPath,
    string SigningPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys, string ReviewPrivateKeyPath,
    IsoClosedBootstrapInputs CompletedPrecursors, CurrentOwnerIsoClosedPrecursorPins PrecursorPins,
    IsoDefinitionSubject DefinitionSubject, string NativeComponentSha256, string MaintenanceComponentSha256,
    string OutputPath);
