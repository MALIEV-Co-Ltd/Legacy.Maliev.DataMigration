using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchiveFinal6PersistentIntent(string Kind, CurrentAuthArchiveScope Scope,
    string ProofSha256, string FinalReadbackSha256, string AudienceSha256, string IntendedObservationSha256,
    string SourceDefinitionSha256, string SourceIdentitySha256, string LocalNativeSha256, string ComparisonNativeSha256,
    CurrentAuthArchiveGenuineArtifact SourceCapture, CurrentAuthArchiveGenuineArtifact DeviceProof, CurrentAuthArchiveGenuineArtifact CurrentIntendedObservation);
internal sealed record CurrentAuthArchiveFinal6PersistentAuthorization(string Kind, Guid OperationId, string ReviewSha256,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
// Data only; the closed Core issuer authentication below is the sole capability constructor.
internal sealed record CurrentAuthArchiveFinal6PersistentAttestation(CurrentAuthArchiveFinal6PersistentIntent Intent,
    CurrentAuthArchiveClaim Review, CurrentAuthArchiveClaim Authorization, CurrentAuthArchivePins Pins, FreshSchemaPlan Source,
    [property: JsonIgnore] IReceiptAttestationTrustStore Trust,
    [property: JsonIgnore] ICurrentAuthLocalSessionArchiveEnvironment Environment);

internal static class CurrentAuthArchiveFinal6PersistentPolicy
{
    // Deliberately absent from the V1 enum. Every V1 RequireScope/Claims route rejects this serialized marker.
    internal const CurrentAuthArchiveProofAdmission Mode = (CurrentAuthArchiveProofAdmission)3;
    internal const string ReviewDomain = "Legacy.Maliev.CurrentAuth.Final6.PersistentArchive.Review.v1";
    internal const string AuthorizationDomain = "Legacy.Maliev.CurrentAuth.Final6.PersistentArchive.Authorization.v1";
    internal static CurrentAuthArchiveFinal6PersistentIntent Claims(CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization,
        CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        var intent = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6PersistentIntent>(review, ReviewDomain,
            pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        RequireIntent(intent, now);
        var allowed = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6PersistentAuthorization>(authorization, AuthorizationDomain,
            pins.AuthorizationKeyId, pins.AuthorizationFingerprint, trust);
        return allowed.Kind != "current-auth-final6-persistent-archive-authorization-v1" || allowed.OperationId != intent.Scope.OperationId ||
            allowed.ReviewSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(review) || allowed.IssuedAtUtc.Offset != TimeSpan.Zero ||
            allowed.ExpiresAtUtc.Offset != TimeSpan.Zero || allowed.IssuedAtUtc < intent.Scope.CapturedAtUtc || allowed.IssuedAtUtc > now ||
            allowed.ExpiresAtUtc <= now || allowed.ExpiresAtUtc > intent.Scope.ExpiresAtUtc
            ? throw Invalid()
            : intent;
    }
    internal static void RequireIntent(CurrentAuthArchiveFinal6PersistentIntent intent, DateTimeOffset now)
    {
        var scope = intent.Scope;
        string[] commitments = [intent.ProofSha256, intent.FinalReadbackSha256, intent.AudienceSha256, intent.IntendedObservationSha256,
            intent.SourceDefinitionSha256, intent.SourceIdentitySha256, intent.LocalNativeSha256, intent.ComparisonNativeSha256];
        if (intent.Kind != "current-auth-final6-persistent-archive-intent-v1" || scope.ProofAdmission != Mode || scope.ComponentSubject is not null ||
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
    internal static void RequireFleets(CurrentAuthArchiveFinal6PersistentIntent intent, CurrentAuthArchiveFleet local, CurrentAuthArchiveFleet comparison)
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
