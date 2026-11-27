namespace Legacy.Maliev.DataMigration;

// This is source evidence, never a permit, a successful case or a complete proof.
internal sealed record CurrentAuthArchiveFinal6SourceEvidence(string Kind, CurrentAuthArchiveRecoverySourceEvidence Capture);

internal static class CurrentAuthArchiveFinal6Source
{
    internal const string Kind = "current-auth-archive-final6-actual-source-v1";

    internal static void RequireProfiles(FreshSchemaPlan plan, DateTimeOffset now)
    {
        ProductionSchemaCatalogInspector.ValidatePlan(plan, now);
        if (!ApprovedConsumerOverlaySelection.IsApproved(plan) || plan.Databases.Sum(database => database.Tables.Count) != 100 ||
            plan.Databases.Any(database => database.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(
                database.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3CompanyStorageSourceOrder))) { throw Invalid(); }
        // The source disposition is retained, and the expected physical target must be its final mapped state.
        DatabaseSchemaPlan quotation = plan.Databases.Single(database => database.Database == "Quotation");
        if (quotation.SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1 ||
            quotation.TargetSchemaSha256 != ReviewedQuotationPhysicalSchemaResolver.GetExpected(quotation, ReviewedQuotationPhysicalVariant.MappedFinal))
        { throw Invalid(); }
        if (quotation.SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1 ||
            quotation.TargetSchemaSha256 != ReviewedQuotationPhysicalSchemaResolver.GetExpected(quotation, ReviewedQuotationPhysicalVariant.MappedFinal))
        { throw Invalid(); }
    }

    internal static void Require(CurrentAuthArchiveFinal6SourceEvidence evidence, string acceptedCommit, string identity,
        string definition, DateTimeOffset now)
    {
        var capture = evidence.Capture;
        if (evidence.Kind != Kind || !CurrentAuthRepairPermit.HashShape(identity) || !CurrentAuthRepairPermit.HashShape(definition) ||
            capture.Plan.SourceCommitSha != acceptedCommit || capture.SourceIdentitySha256 != identity || capture.DefinitionSha256 != definition ||
            capture.FullPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(capture.Plan)) { throw Invalid(); }
        RequireProfiles(capture.Plan, now);
        RequireWindows(capture, now);
        if (SourceCatalogDefinitionFingerprintV1.Compute(capture.Plan, acceptedCommit, identity, now) != definition) { throw Invalid(); }
    }

    internal static void RequireWindows(CurrentAuthArchiveRecoverySourceEvidence capture, DateTimeOffset now)
    {
        if (capture.BeganAtUtc.Offset != TimeSpan.Zero || capture.CompletedAtUtc.Offset != TimeSpan.Zero || now.Offset != TimeSpan.Zero ||
            capture.Plan.CapturedAtUtc.Offset != TimeSpan.Zero || capture.BeganAtUtc > capture.Plan.CapturedAtUtc ||
            capture.Plan.CapturedAtUtc > capture.CompletedAtUtc || capture.CompletedAtUtc > now ||
            now - capture.BeganAtUtc > TimeSpan.FromMinutes(5) || capture.Windows.Count != 23 ||
            !capture.Windows.Select(window => window.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal)) { throw Invalid(); }
        DateTimeOffset previous = capture.Plan.CapturedAtUtc;
        foreach (var window in capture.Windows)
        {
            if (window.BeginRequestedAtUtc.Offset != TimeSpan.Zero || window.SnapshotOpenedAtUtc.Offset != TimeSpan.Zero || window.SnapshotClosedAtUtc.Offset != TimeSpan.Zero ||
                window.BeginRequestedAtUtc < previous || window.SnapshotOpenedAtUtc < window.BeginRequestedAtUtc ||
                window.SnapshotClosedAtUtc < window.SnapshotOpenedAtUtc || window.SnapshotClosedAtUtc > capture.CompletedAtUtc) { throw Invalid(); }
            previous = window.SnapshotClosedAtUtc;
        }
    }

    internal static MigrationExecutionException Invalid()
    {
        return new("current_auth_archive_final6_source_invalid",
        "The distinct Final6 source, mapped physical contract or actual snapshot windows are unavailable, changed or expired.");
    }
}
