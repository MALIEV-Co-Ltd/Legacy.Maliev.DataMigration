namespace Legacy.Maliev.DataMigration.Console;

// Precursor subject: no operational scope, authorization, or future self-proof digest.
internal sealed record IsoDefinitionSubject(string SourceCommitSha, string SourceCatalogSha256,
    string SourceSchemaPlanSha256, string RawSourceFileSha256, string OwnerSourcesSha256, string ContractSha256,
    string IntendedTargetObservationSha256, string IntendedRunBindingSha256,
    string ConsoleAssemblySha256, string CoreAssemblySha256, string TestAssemblySha256);
internal sealed record IsoDefinitionArtifact(string Path, string Sha256, string? SourcePath = null);
internal sealed record IsoCapturedNative(CurrentAppOwnedDatabaseSnapshot Snapshot, string OverlaySha256,
    bool Selected, CurrentOwnerIsoLiteralRows LiteralRows, uint SnapshotXmin,
    Dictionary<string, string[]> Catalog, Dictionary<string, CurrentOwnerIsoStorage> Storage)
{
    internal static IsoCapturedNative Capture(CurrentOwnerIsoNativeObservation value)
    {
        return new(value.Snapshot,
        value.OverlaySha256, value.Selected, value.LiteralRows, value.SnapshotXmin, value.CopyCatalog(), value.CopyStorage());
    }

    internal CurrentOwnerIsoNativeObservation Observe()
    {
        return new(Snapshot, OverlaySha256, Selected,
            LiteralRows, Catalog, Storage, SnapshotXmin);
    }
}
internal sealed record IsoDefinitionProjection(string Database, string Rows, string Outside);
internal sealed record IsoDefinitionNativePhases(IsoDefinitionArtifact Before, IsoDefinitionArtifact Candidate,
    IsoDefinitionArtifact RolledBack, IsoDefinitionArtifact CommitCandidate, IsoDefinitionArtifact IndependentReadback);
internal sealed record IsoDefinitionCase(string CaseId, string TestName, string TestId, string ExecutionId,
    Guid? RunId, string ExecutedTestAssemblyPath, IsoDefinitionArtifact TestAssembly,
    IsoDefinitionArtifact Entered, IsoDefinitionArtifact Exited,
    IsoDefinitionNativePhases? Native, IReadOnlyList<IsoDefinitionArtifact> Projections,
    IsoDefinitionArtifact? Rejection, IReadOnlyList<IsoDefinitionArtifact> RejectedSnapshots);
internal sealed record IsoDefinitionRun(Guid RunId, string ContainerId, string Name, int Port,
    IsoDefinitionArtifact Attempt, IsoDefinitionArtifact ContainerMetadata,
    IsoDefinitionArtifact Capacity, IsoDefinitionArtifact Disposed, IsoDefinitionArtifact Absence);
internal sealed record IsoDefinitionAbsence(Guid RunId, DateTimeOffset ObservedAtUtc,
    bool ContainerInventorySucceeded, bool VolumeInventorySucceeded, bool ListenerInventorySucceeded,
    IReadOnlyList<string> ContainerIds, IReadOnlyList<string> ContainerNames,
    IReadOnlyList<string> VolumeNames, IReadOnlyList<int> ListeningPorts);
internal sealed record IsoDefinitionEntry(string Kind, string CaseId, Guid? RunId, string? FaultSql,
    string TestAssemblySha256, DateTimeOffset ObservedAtUtc);
internal sealed record IsoDefinitionExit(string Kind, string CaseId, Guid? RunId, DateTimeOffset ObservedAtUtc);
internal sealed record IsoDefinitionRejection(string Kind, string CaseId, string Boundary,
    string Code, DateTimeOffset ObservedAtUtc);
internal sealed record IsoDefinitionProof(string Kind, IsoDefinitionSubject Subject,
    IsoDefinitionArtifact AcceptedSource, IsoDefinitionArtifact AcceptedOwners, IsoDefinitionArtifact SourceCatalog,
    FreshSchemaPlan FixtureSource, IReadOnlyList<CurrentOwnerIsoSourceObservation> FixtureOwners,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc,
    IsoDefinitionArtifact Trx, IReadOnlyList<IsoDefinitionCase> Cases,
    IReadOnlyList<IsoDefinitionRun> Runs, string KeyId, string? Signature);

internal static class IsoDefinitionCases
{
    internal static readonly string[] Required = ["literal-Country", "literal-Material", "width",
        "unsupported-index", "unsupported-expression", "unsupported-check", "unsupported-view",
        "unsupported-statistics", "unsupported-analyze", "unsupported-partial",
        "candidate-index", "candidate-expression", "candidate-check", "candidate-view",
        "candidate-generated", "candidate-partial", "pure-storage"];
    internal static string Method(string id)
    {
        return id switch
        {
            "literal-Country" or "literal-Material" => "Literal_bytes_complete_rows_catalogs_sequences_rollback_commit_and_independent_readback",
            "width" => "Width_expansion_preserves_native_bytes_nulls_outside_catalogs_rows_and_sequence_and_rollback",
            "pure-storage" => "Physical_storage_does_not_accept_invented_file_sizes_counts_or_visibility",
            _ when id.StartsWith("unsupported-", StringComparison.Ordinal) => "Unsupported_native_preimage_is_rejected_without_candidate",
            _ when id.StartsWith("candidate-", StringComparison.Ordinal) => "Candidate_refuses_dependencies_or_partial_type_state_before_transition",
            _ => throw Invalid(),
        };
    }

    internal static string Fault(string sql, bool candidate)
    {
        string suffix = sql switch
        {
            "CREATE INDEX unknown_iso ON public.\"Country\"(\"ISO2\");" when !candidate => "index",
            "CREATE INDEX unknown_iso ON public.\"Country\" (\"ISO2\");" when candidate => "index",
            "CREATE INDEX unknown_expression ON public.\"Country\"(lower(\"ISO2\"::text));" when !candidate => "expression",
            "CREATE INDEX unknown_expression ON public.\"Country\" (lower(\"ISO2\"::text));" when candidate => "expression",
            "ALTER TABLE public.\"Country\" ADD CONSTRAINT unknown_check CHECK(octet_length(bpcharsend(\"ISO3\"))>0);" when !candidate => "check",
            "ALTER TABLE public.\"Country\" ADD CONSTRAINT unknown_check CHECK (octet_length(bpcharsend(\"ISO3\")) > 0);" when candidate => "check",
            "CREATE VIEW public.unknown_view AS SELECT \"ISO2\" FROM public.\"Country\";" => "view",
            "CREATE STATISTICS unknown_stats ON \"ISO2\",\"ISO3\" FROM public.\"Country\";" when !candidate => "statistics",
            "ANALYZE public.\"Country\";" when !candidate => "analyze",
            "ALTER TABLE public.\"Country\" ADD COLUMN unknown_generated text GENERATED ALWAYS AS (\"ISO2\"::text) STORED;" when candidate => "generated",
            "ALTER TABLE public.\"Country\" ALTER COLUMN \"ISO2\" TYPE varchar(2);" => "partial",
            _ => throw Invalid(),
        };
        return (candidate ? "candidate-" : "unsupported-") + suffix;
    }
    internal static MigrationExecutionException Invalid()
    {
        return new("iso_definition_precursor_invalid",
        "Genuine ISO definition precursor evidence is required; it grants no operational authority.");
    }
}
