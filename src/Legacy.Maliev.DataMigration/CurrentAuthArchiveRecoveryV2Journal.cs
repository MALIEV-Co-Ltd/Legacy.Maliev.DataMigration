namespace Legacy.Maliev.DataMigration;

internal static class CurrentAuthArchiveRecoveryV2Journal
{
    internal const string ReservationDomain = "Legacy.Maliev.CurrentAuth.DisposableRestoreReservation.v2";
    internal static void Require(CurrentAuthArchiveRestoreScopeV2 scope, CurrentAuthArchiveScope original,
        CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization, CurrentAuthArchiveClaim reservation,
        CurrentAuthArchiveClaim prepared, CurrentAuthArchiveClaim terminal, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        CurrentAuthArchiveRecoveryV2Preservation.RequireScope(scope, original, now);
        var reviewed = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRestoreScopeV2>(review, CurrentAuthArchiveRecoveryV2.ReviewDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        var permission = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(authorization, CurrentAuthArchiveRecoveryV2.AuthorizationDomain, pins.AuthorizationKeyId, pins.AuthorizationFingerprint, trust);
        var reserved = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRestoreReservationV2>(reservation, ReservationDomain, pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
        string auth = CurrentAuthLocalSessionArchivePolicy.Hash(authorization);
        if (reviewed != scope || permission.OperationId != scope.OperationId || permission.ReviewSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(review) ||
            permission.IssuedAtUtc != scope.CapturedAtUtc || permission.ExpiresAtUtc != scope.ExpiresAtUtc || reserved.OperationId != scope.OperationId ||
            reserved.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(scope) || reserved.AuthorizationSha256 != auth) { throw Invalid(); }
        var first = Decode(prepared); var last = Decode(terminal);
        if (first.Classification != CurrentAppOwnedCommitClassification.Prepared || last.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback ||
            first.PreviousSha256 != new string('0', 64) || last.PreviousSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(prepared) ||
            first.ObservedAtUtc > last.ObservedAtUtc) { throw Invalid(); }
        CurrentAuthArchiveRestoreReceiptV2 Decode(CurrentAuthArchiveClaim claim)
        {
            var receipt = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRestoreReceiptV2>(claim, CurrentAuthArchiveRecoveryV2.ReceiptDomain, pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
            return receipt.OperationId != scope.OperationId || receipt.AuthorizationSha256 != auth || receipt.SetupManifestSha256 != scope.SetupManifestSha256 ||
                receipt.BeforeAuthSha256 != scope.EmptyAuthSha256 || receipt.AfterAuthSha256 != original.LocalObservationPolicy.BeforeDatabaseSha256["Auth"] ||
                receipt.RecoveredRowsSha256 != scope.OriginalRowsSha256 || receipt.ObservedAtUtc.Offset != TimeSpan.Zero || receipt.ObservedAtUtc < scope.CapturedAtUtc ||
                receipt.ObservedAtUtc > scope.ExpiresAtUtc || receipt.ObservedAtUtc > now
                ? throw Invalid()
                : receipt;
        }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
