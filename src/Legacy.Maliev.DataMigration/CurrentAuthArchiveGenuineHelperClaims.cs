namespace Legacy.Maliev.DataMigration;

internal sealed partial class CurrentAuthLocalSessionArchivePermit
{
    // Pure verification only. Does not construct a permit or contact a target.
    internal static CurrentAuthArchiveScope RequireGenuineDualHelperClaims(CurrentAuthArchiveGenuineHelperClaims claims,
        IReceiptAttestationTrustStore trust, CurrentAuthArchivePins pins, DateTimeOffset now)
    {
        CurrentAuthArchiveScope scope = Claims(claims.Review, claims.Authorization, trust, pins, now);
        return scope.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap ||
            scope.ComponentSubject?.Seed.CaseId != "dual-durable-readback"
            ? throw CurrentAuthLocalSessionArchivePolicy.Invalid() : scope;
    }
}
