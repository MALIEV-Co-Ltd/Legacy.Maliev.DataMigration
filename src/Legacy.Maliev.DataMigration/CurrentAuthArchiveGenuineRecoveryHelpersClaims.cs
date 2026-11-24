namespace Legacy.Maliev.DataMigration;

internal sealed partial class CurrentAuthLocalSessionArchivePermit
{
    internal static CurrentAuthArchiveScope RequireGenuineRecoveryHelperClaims(CurrentAuthArchiveGenuineHelperClaims claims,
        IReceiptAttestationTrustStore trust, CurrentAuthArchivePins pins, CurrentAuthArchiveGenuineRecoveryHelperCase helperCase, DateTimeOffset now)
    {
        var scope = Claims(claims.Review, claims.Authorization, trust, pins, now);
        return helperCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback ||
            scope.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap ||
            scope.ComponentSubject?.Seed.CaseId != CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(helperCase)
            ? throw CurrentAuthLocalSessionArchivePolicy.Invalid() : scope;
    }
}
