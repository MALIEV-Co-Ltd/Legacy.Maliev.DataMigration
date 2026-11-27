using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchivePersistentIntentV2(string Kind, CurrentAuthArchiveScope Scope,
    string ProofSha256, string FinalReadbackSha256, string AudienceSha256, string IntendedObservationSha256,
    string SourceDefinitionSha256, string SourceIdentitySha256, string LocalNativeSha256, string ComparisonNativeSha256,
    CurrentAuthArchiveGenuineArtifact SourceCapture, CurrentAuthArchiveGenuineArtifact DeviceProof, CurrentAuthArchiveGenuineArtifact CurrentIntendedObservation);
internal sealed record CurrentAuthArchivePersistentAuthorizationV2(string Kind, Guid OperationId, string ReviewSha256,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
// Data only; the closed Core issuer authentication below is the sole capability constructor.
internal sealed record CurrentAuthArchivePersistentAttestationV2(CurrentAuthArchivePersistentIntentV2 Intent,
    CurrentAuthArchiveClaim Review, CurrentAuthArchiveClaim Authorization, CurrentAuthArchivePins Pins, FreshSchemaPlan Source,
    [property: JsonIgnore] IReceiptAttestationTrustStore Trust,
    [property: JsonIgnore] ICurrentAuthLocalSessionArchiveEnvironment Environment);

internal static class CurrentAuthArchivePersistentV2Policy
{
    // Deliberately absent from the V1 enum. Every V1 RequireScope/Claims route rejects this serialized marker.
    internal const CurrentAuthArchiveProofAdmission Mode = (CurrentAuthArchiveProofAdmission)3;
    internal const string ReviewDomain = "Legacy.Maliev.CurrentAuth.PersistentArchive.Review.v2";
    internal const string AuthorizationDomain = "Legacy.Maliev.CurrentAuth.PersistentArchive.Authorization.v2";
    internal static CurrentAuthArchivePersistentIntentV2 Claims(CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization,
        CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        var intent = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchivePersistentIntentV2>(review, ReviewDomain,
            pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        RequireIntent(intent, now);
        var allowed = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchivePersistentAuthorizationV2>(authorization, AuthorizationDomain,
            pins.AuthorizationKeyId, pins.AuthorizationFingerprint, trust);
        return allowed.Kind != "current-auth-persistent-archive-authorization-v2" || allowed.OperationId != intent.Scope.OperationId ||
            allowed.ReviewSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(review) || allowed.IssuedAtUtc.Offset != TimeSpan.Zero ||
            allowed.ExpiresAtUtc.Offset != TimeSpan.Zero || allowed.IssuedAtUtc < intent.Scope.CapturedAtUtc || allowed.IssuedAtUtc > now ||
            allowed.ExpiresAtUtc <= now || allowed.ExpiresAtUtc > intent.Scope.ExpiresAtUtc
            ? throw Invalid()
            : intent;
    }
    internal static void RequireIntent(CurrentAuthArchivePersistentIntentV2 intent, DateTimeOffset now)
    {
        var scope = intent.Scope;
        string[] commitments = [intent.ProofSha256, intent.FinalReadbackSha256, intent.AudienceSha256, intent.IntendedObservationSha256,
            intent.SourceDefinitionSha256, intent.SourceIdentitySha256, intent.LocalNativeSha256, intent.ComparisonNativeSha256];
        if (intent.Kind != "current-auth-persistent-archive-intent-v2" || scope.ProofAdmission != Mode || scope.ComponentSubject is not null ||
            !CurrentAuthRepairPermit.HashShape(intent.SourceCapture.Sha256) || !CurrentAuthRepairPermit.HashShape(intent.DeviceProof.Sha256) ||
            intent.IntendedObservationSha256 != intent.CurrentIntendedObservation.Sha256 ||
            commitments.Any(value => !CurrentAuthRepairPermit.HashShape(value)) ||
            scope.ArchiveHelperProofSha256 != string.Empty || scope.ArchiveNativeProofSha256 != string.Empty ||
            scope.ExactDeleteReviewSha256 != string.Empty || scope.RecoveryReviewSha256 != string.Empty) { throw Invalid(); }
        // Only non-authorizing shared shape guards are reused. No V1-shaped evidence or scope is constructed.
        CurrentAuthLocalSessionArchivePolicy.RequireCommonScopeShape(scope, now);
        if (!DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.LocalObservationPolicy.Target) ||
            scope.ProductionObservationPolicy.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg ||
            scope.LocalObservationPolicy.AuthBeforeSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) ||
            scope.ProductionObservationPolicy.AuthBeforeSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true)) { throw Invalid(); }
        if (scope.ExpiresAtUtc - scope.CapturedAtUtc > TimeSpan.FromMinutes(2)) { throw Invalid(); }
    }
    internal static void RequireFleets(CurrentAuthArchivePersistentIntentV2 intent, CurrentAuthArchiveFleet local, CurrentAuthArchiveFleet comparison)
    {
        if (CurrentAuthArchiveRecoveryV2Preservation.NativeSha(local.Auth.Native) != intent.LocalNativeSha256 ||
            CurrentAuthArchiveRecoveryV2Preservation.NativeSha(comparison.Auth.Native) != intent.ComparisonNativeSha256)
        { throw Invalid(); }
    }
    internal static MigrationExecutionException Invalid()
    {
        return CurrentAuthLocalSessionArchivePolicy.Invalid();
    }
}
