namespace Legacy.Maliev.DataMigration;

internal sealed record OrderSubtotalOwnedScope(string Kind, Guid OperationId, string OriginalIntentSha256, string SourceFullSha256,
    string SourceDefinitionSha256, string ContractSha256, string ContainerId, string Volume, string SystemIdentifierSha256,
    string BeforeNativeSha256, string FaultCase, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record OrderSubtotalOwnedFaultReceipt(string Kind, Guid OperationId, string ScopeSha256, string AuthorizationSha256,
    string PreviousSha256, string BeforeNativeSha256, string? AfterNativeSha256, string ClonedLogicalSha256,
    CurrentAppOwnedCommitClassification Classification, DateTimeOffset ObservedAtUtc);

internal static class OrderSubtotalRepairJournal
{
    internal static void RequirePersistent(CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization, IReadOnlyList<CurrentAuthArchiveClaim> receipts,
        CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust)
    {
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        var scope = CurrentAuthLocalSessionArchivePolicy.Verify<OrderSubtotalRepairScope>(review, OrderSubtotalRepairProtocol.ReviewDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        RequireAuthorization(authorization, review, scope.OperationId, scope.IssuedAtUtc, scope.ExpiresAtUtc, OrderSubtotalRepairProtocol.AuthorizationDomain, pins, trust);
        var values = receipts.Select(claim => CurrentAuthLocalSessionArchivePolicy.Verify<OrderSubtotalRepairReceipt>(claim, OrderSubtotalRepairProtocol.ReceiptDomain,
            pins.EvidenceKeyId, pins.EvidenceFingerprint, trust)).ToArray();
        RequireChain(receipts, values.Select(x => (x.OperationId, x.ScopeSha256, x.AuthorizationSha256, x.PreviousSha256, x.BeforeNativeSha256, x.AfterNativeSha256,
            x.Classification, x.ObservedAtUtc)).ToArray(), scope.OperationId, OrderSubtotalRepairProtocol.Hash(scope), OrderSubtotalRepairProtocol.Hash(authorization), scope.Intent.NativePreimageSha256);
        if (scope.Kind != "current-order-subtotal-target-scope-v1" || values.Any(x => x.Kind != "current-order-subtotal-receipt-v1" || x.CharacterizationSha256 != scope.CharacterizationSha256))
        { throw OrderSubtotalRepairProtocol.Invalid(); }
    }
    internal static void RequireOwned(CurrentAuthArchiveClaim review, CurrentAuthArchiveClaim authorization, IReadOnlyList<CurrentAuthArchiveClaim> receipts,
        string logicalSha256, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust)
    {
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        var scope = CurrentAuthLocalSessionArchivePolicy.Verify<OrderSubtotalOwnedScope>(review, "Legacy.Maliev.OrderSubtotal.OwnedFaultReview.v1", pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        RequireAuthorization(authorization, review, scope.OperationId, scope.IssuedAtUtc, scope.ExpiresAtUtc, "Legacy.Maliev.OrderSubtotal.OwnedFaultAuthorization.v1", pins, trust);
        var values = receipts.Select(claim => CurrentAuthLocalSessionArchivePolicy.Verify<OrderSubtotalOwnedFaultReceipt>(claim, "Legacy.Maliev.OrderSubtotal.OwnedFaultReceipt.v1",
            pins.EvidenceKeyId, pins.EvidenceFingerprint, trust)).ToArray();
        RequireChain(receipts, values.Select(x => (x.OperationId, x.ScopeSha256, x.AuthorizationSha256, x.PreviousSha256, x.BeforeNativeSha256, x.AfterNativeSha256,
            x.Classification, x.ObservedAtUtc)).ToArray(), scope.OperationId, OrderSubtotalRepairProtocol.Hash(scope), OrderSubtotalRepairProtocol.Hash(authorization), scope.BeforeNativeSha256);
        if (scope.Kind != "order-subtotal-owned-fault-scope-v1" || values.Any(x => x.Kind != "order-subtotal-owned-fault-receipt-v1" || x.ClonedLogicalSha256 != logicalSha256))
        { throw OrderSubtotalRepairProtocol.Invalid(); }
        bool expected = scope.FaultCase switch
        {
            "PreparedPublication" => values.Length == 1 && values[0].Classification == CurrentAppOwnedCommitClassification.RolledBackBeforeCommit,
            "LostCommitAcknowledgement" or "TerminalPublication" => values.Length == 2 && values[0].Classification == CurrentAppOwnedCommitClassification.Prepared && values[1].Classification == CurrentAppOwnedCommitClassification.Uncertain,
            _ => false
        };
        if (!expected) { throw OrderSubtotalRepairProtocol.Invalid(); }
    }
    private static void RequireAuthorization(CurrentAuthArchiveClaim authorization, CurrentAuthArchiveClaim review, Guid operation,
        DateTimeOffset issued, DateTimeOffset expires, string domain, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust)
    {
        var permission = CurrentAuthLocalSessionArchivePolicy.Verify<OrderSubtotalRepairAuthorization>(authorization, domain, pins.AuthorizationKeyId, pins.AuthorizationFingerprint, trust);
        if (permission.OperationId != operation || permission.ReviewSha256 != OrderSubtotalRepairProtocol.Hash(review) || permission.IssuedAtUtc.Offset != TimeSpan.Zero ||
            permission.ExpiresAtUtc.Offset != TimeSpan.Zero || permission.IssuedAtUtc < issued || permission.ExpiresAtUtc > expires || permission.ExpiresAtUtc <= permission.IssuedAtUtc)
        { throw OrderSubtotalRepairProtocol.Invalid(); }
    }
    private static void RequireChain(IReadOnlyList<CurrentAuthArchiveClaim> claims,
        (Guid Operation, string Scope, string Authorization, string Previous, string Before, string? After, CurrentAppOwnedCommitClassification Classification, DateTimeOffset At)[] values,
        Guid operation, string scope, string authorization, string before)
    {
        if (operation == Guid.Empty || values.Length is < 1 or > 3 || values.Length != claims.Count) { throw OrderSubtotalRepairProtocol.Invalid(); }
        string previous = new('0', 64); bool prepared = false, committed = false, failed = false; string? after = null; DateTimeOffset at = DateTimeOffset.MinValue;
        for (int index = 0; index < values.Length; index++)
        {
            var (Operation, Scope, Authorization, Previous, Before, After, Classification, At) = values[index];
            if (failed || Operation != operation || Scope != scope || Authorization != authorization || Previous != previous ||
                Before != before || At.Offset != TimeSpan.Zero || At < at || At > DateTimeOffset.UtcNow ||
                (prepared && After != after) ||
                (After is not null && !OrderSubtotalRepairProtocol.IsHash(After))) { throw OrderSubtotalRepairProtocol.Invalid(); }
            switch (Classification)
            {
                case CurrentAppOwnedCommitClassification.Prepared:
                    if (prepared || committed || After is null) { throw OrderSubtotalRepairProtocol.Invalid(); }
                    prepared = true; after = After; break;
                case CurrentAppOwnedCommitClassification.CommittedAndReadback:
                    if (!prepared || committed || After != after) { throw OrderSubtotalRepairProtocol.Invalid(); }
                    committed = true; break;
                case CurrentAppOwnedCommitClassification.FailedBeforeCommit:
                case CurrentAppOwnedCommitClassification.RolledBackBeforeCommit:
                    if (committed) { throw OrderSubtotalRepairProtocol.Invalid(); }
                    failed = true; break;
                case CurrentAppOwnedCommitClassification.Uncertain: failed = true; break;
                default: throw OrderSubtotalRepairProtocol.Invalid();
            }
            previous = OrderSubtotalRepairProtocol.Hash(claims[index]); at = At;
        }
        if (!committed && !failed) { throw OrderSubtotalRepairProtocol.Invalid(); }
    }
}
