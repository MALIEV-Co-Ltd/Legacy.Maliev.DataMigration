namespace Legacy.Maliev.DataMigration.Console;

// Input paths are actual held owner-only artifacts, not callbacks or proof summaries.
// The fixed closed host must validate the completed precursor before releasing its child gate.
internal sealed record CurrentAuthClosedLaneConfiguration(string SourceSchemaPath,
    CurrentAuthClosedBootstrapEvidence CompletedComponents, string PrecursorReviewPrivateKeyPath,
    string TestAssemblyPath, string TestAssemblySha256, string ConsoleAssemblySha256,
    string CoreAssemblySha256, string ParentRunBindingPath, string ParentRunBindingSha256,
    CurrentAuthNamedClosedIntendedEvidence IntendedEvidence);
