namespace Legacy.Maliev.DataMigration;

internal enum CurrentAuthArchiveRecoveryV2Case { FirstOnly = 1, SecondOnly = 2 }
internal sealed record CurrentAuthArchiveProofAudienceV2(string Kind, Guid AudienceId, string AcceptedCommitSha,
    string SourceIdentitySha256, string SourceDefinitionSha256, string OwnerPinsSha256, string ClosureSha256,
    string CoreImageSha256, string ConsoleImageSha256, string TestsImageSha256, string SigningPinsSha256,
    string CaseInventorySha256, string IntendedLocalIdentitySha256, string IntendedComparisonIdentitySha256, string IntendedAuthRowsSha256,
    int IntendedAuthRows, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentAuthArchiveRecoveryCaseBindingV2(string Kind, string AudienceSha256, string OriginalSeedSha256,
    Guid OperationId, string CaseId, string OriginalSourceFullSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentAuthArchiveRecoverySourceWindow(string Database, DateTimeOffset BeginRequestedAtUtc,
    DateTimeOffset SnapshotOpenedAtUtc, DateTimeOffset SnapshotClosedAtUtc);
internal sealed record CurrentAuthArchiveRecoverySourceEvidence(FreshSchemaPlan Plan, string FullPlanSha256,
    string SourceIdentitySha256, string DefinitionSha256, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc,
    IReadOnlyList<CurrentAuthArchiveRecoverySourceWindow> Windows);
internal sealed record CurrentAuthArchiveRestoreScopeV2(string Kind, Guid OperationId, Guid SetupOperationId,
    string AudienceSha256, string SetupScopeSha256, string SetupManifestSha256, string SetupJournalsSha256,
    string SourceFullSha256, string SourceIdentitySha256, string SourceDefinitionSha256,
    string LocalRunBindingSha256, string ComparisonRunBindingSha256, string LocalTargetSha256, string ComparisonTargetSha256,
    string EmptyFleetSha256, string ComparisonFleetSha256, string EmptyAuthSha256, string EmptyNativeSha256,
    string OriginalRowsSha256, int OriginalRows, bool FirstDomain, string SelectedCipherIdentity, string SelectedCipherSha256,
    string SelectedKeyIdentity, string SelectedKeySha256, string UnavailableDomainSha256, string DeviceProofSha256,
    DateTimeOffset CapturedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentAuthArchiveRestoreReceiptV2(Guid OperationId, string AuthorizationSha256, string PreviousSha256,
    string SetupManifestSha256, string BeforeAuthSha256, string? AfterAuthSha256, string RecoveredRowsSha256,
    CurrentAppOwnedCommitClassification Classification, DateTimeOffset ObservedAtUtc);
internal sealed record CurrentAuthArchiveRestoreReservationV2(Guid OperationId, string ScopeSha256, string AuthorizationSha256);
internal sealed record CurrentAuthArchiveRecoveryMethodV2(int ReturnCode, DateTimeOffset StartedAtUtc, DateTimeOffset ReturnedAtUtc,
    CurrentAuthArchiveGenuineDualArtifacts Artifacts);
internal sealed record CurrentAuthArchiveRecoveryResultV2(CurrentAuthArchiveRecoveryMethodV2 Method, CurrentAuthArchiveGenuineArtifact Candidate);

internal static class CurrentAuthArchiveRecoveryV2
{
    internal const string AudienceDomain = "Legacy.Maliev.CurrentAuth.ArchiveProofAudience.v2";
    internal const string CaseDomain = "Legacy.Maliev.CurrentAuth.ArchiveRecoveryCase.v2";
    internal const string ReviewDomain = "Legacy.Maliev.CurrentAuth.DisposableRestoreReview.v2";
    internal const string AuthorizationDomain = "Legacy.Maliev.CurrentAuth.DisposableRestoreAuthorization.v2";
    internal const string ReceiptDomain = "Legacy.Maliev.CurrentAuth.DisposableRestoreReceipt.v2";
    internal static (string Phase, string CaseId) Identity(CurrentAuthArchiveRecoveryV2Case value)
    {
        return ("recovery", CaseId(value));
    }

    internal static string CaseId(CurrentAuthArchiveRecoveryV2Case value)
    {
        return value switch
        {
            CurrentAuthArchiveRecoveryV2Case.FirstOnly => "first-only-decrypt-insert-readback",
            CurrentAuthArchiveRecoveryV2Case.SecondOnly => "second-only-decrypt-insert-readback",
            _ => throw Invalid(),
        };
    }

    internal static CurrentAuthArchiveGenuineExecutionCase SetupCase(CurrentAuthArchiveRecoveryV2Case value)
    {
        return value switch
        {
            CurrentAuthArchiveRecoveryV2Case.FirstOnly => CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback,
            CurrentAuthArchiveRecoveryV2Case.SecondOnly => CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback,
            _ => throw Invalid(),
        };
    }

    internal static void RequireAudience(CurrentAuthArchiveProofAudienceV2 value, CurrentAuthArchiveComponentBootstrapSeed seed,
        CurrentAuthArchivePins pins, DateTimeOffset now)
    {
        if (value.Kind != "current-auth-archive-proof-audience-v2" || value.AudienceId == Guid.Empty || value.AcceptedCommitSha != seed.AcceptedSourceCommitSha ||
            value.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 || value.ClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
            value.CoreImageSha256 != seed.CoreAssemblySha256 || value.ConsoleImageSha256 != seed.ConsoleAssemblySha256 || value.TestsImageSha256 != seed.TestAssemblySha256 ||
            value.SigningPinsSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(pins) || value.IntendedAuthRows is < 0 or > CurrentAuthLocalSessionArchivePolicy.MaximumRows ||
            value.CaseInventorySha256 != CurrentAuthLocalSessionArchivePolicy.Hash(CurrentAuthArchiveGenuineCases.Inventory()) ||
            new[] { value.SourceIdentitySha256, value.SourceDefinitionSha256, value.IntendedLocalIdentitySha256, value.IntendedComparisonIdentitySha256,
                value.IntendedAuthRowsSha256 }.Any(hash => !CurrentAuthRepairPermit.HashShape(hash)) || value.IntendedLocalIdentitySha256 == value.IntendedComparisonIdentitySha256 ||
            value.IssuedAtUtc.Offset != TimeSpan.Zero || value.ExpiresAtUtc.Offset != TimeSpan.Zero || value.IssuedAtUtc > now || value.ExpiresAtUtc <= now ||
            value.ExpiresAtUtc <= value.IssuedAtUtc || value.ExpiresAtUtc - value.IssuedAtUtc > TimeSpan.FromHours(12)) { throw Invalid(); }
    }
    internal static void RequireCaseBinding(CurrentAuthArchiveRecoveryCaseBindingV2 value, CurrentAuthArchiveClaim audience,
        CurrentAuthArchiveComponentBootstrapSeed seed, CurrentAuthArchiveRecoveryV2Case expected, DateTimeOffset now)
    {
        if (value.Kind != "current-auth-archive-recovery-case-binding-v2" || value.AudienceSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(audience) ||
            value.OriginalSeedSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(seed) || value.OperationId != seed.OperationId || value.CaseId != CaseId(expected) ||
            seed.CaseId != value.CaseId || value.OriginalSourceFullSha256 != seed.SourceSchemaPlanSha256 || value.IssuedAtUtc.Offset != TimeSpan.Zero ||
            value.ExpiresAtUtc.Offset != TimeSpan.Zero || value.IssuedAtUtc > now || value.ExpiresAtUtc <= now || value.ExpiresAtUtc > seed.ExpiresAtUtc ||
            value.ExpiresAtUtc <= value.IssuedAtUtc) { throw Invalid(); }
    }
    internal static void RequireSource(CurrentAuthArchiveRecoverySourceEvidence value, string commit, string identity, string definition, DateTimeOffset now)
    {
        if (value.SourceIdentitySha256 != identity || value.DefinitionSha256 != definition || value.FullPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(value.Plan) ||
            value.Plan.SourceCommitSha != commit || value.BeganAtUtc.Offset != TimeSpan.Zero || value.CompletedAtUtc.Offset != TimeSpan.Zero || now.Offset != TimeSpan.Zero ||
            value.BeganAtUtc > value.Plan.CapturedAtUtc || value.Plan.CapturedAtUtc > value.CompletedAtUtc || value.CompletedAtUtc > now || now - value.BeganAtUtc > TimeSpan.FromMinutes(5) ||
            value.Plan.Databases.Any(database => database.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(database.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)) ||
            value.Windows.Count != 23 || !value.Windows.Select(window => window.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            SourceCatalogDefinitionFingerprintV1.Compute(value.Plan, commit, identity, now) != definition) { throw Invalid(); }
        DateTimeOffset previous = value.Plan.CapturedAtUtc;
        foreach (var window in value.Windows)
        {
            if (window.BeginRequestedAtUtc.Offset != TimeSpan.Zero || window.SnapshotOpenedAtUtc.Offset != TimeSpan.Zero || window.SnapshotClosedAtUtc.Offset != TimeSpan.Zero ||
                window.BeginRequestedAtUtc < previous || window.SnapshotOpenedAtUtc < window.BeginRequestedAtUtc || window.SnapshotClosedAtUtc < window.SnapshotOpenedAtUtc ||
                window.SnapshotClosedAtUtc > value.CompletedAtUtc) { throw Invalid(); }
            previous = window.SnapshotClosedAtUtc;
        }
    }
    internal static MigrationExecutionException Invalid()
    {
        return new("current_auth_archive_recovery_v2_invalid", "The fixed owned disposable recovery evidence or lease is unavailable, changed or expired.");
    }
}
