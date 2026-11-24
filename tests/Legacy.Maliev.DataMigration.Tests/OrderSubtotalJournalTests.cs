using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class OrderSubtotalJournalTests
{
    [Theory]
    [InlineData("PreparedPublication", "none")]
    [InlineData("LostCommitAcknowledgement", "none")]
    [InlineData("TerminalPublication", "none")]
    [InlineData("TerminalPublication", "link")]
    [InlineData("TerminalPublication", "scope")]
    [InlineData("TerminalPublication", "authorization")]
    [InlineData("TerminalPublication", "after")]
    [InlineData("TerminalPublication", "classification")]
    [InlineData("TerminalPublication", "wrong-domain")]
    [InlineData("TerminalPublication", "duplicate")]
    [InlineData("TerminalPublication", "empty")]
    public void Actual_owned_failure_journal_links_and_exact_classifications_are_required(string @case, string fault)
    {
        using var first = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var second = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var third = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var reviewer = new P256MigrationEvidenceSigner("order-review", first.ExportPkcs8PrivateKeyPem());
        using var authorizer = new P256MigrationEvidenceSigner("order-authorization", second.ExportPkcs8PrivateKeyPem());
        using var evidence = new P256MigrationEvidenceSigner("order-evidence", third.ExportPkcs8PrivateKeyPem());
        var pins = new CurrentAuthArchivePins(reviewer.KeyId, reviewer.PublicKeyFingerprintSha256, authorizer.KeyId, authorizer.PublicKeyFingerprintSha256, evidence.KeyId, evidence.PublicKeyFingerprintSha256);
        var trust = new ReceiptAttestationTrustStore([new(reviewer.KeyId, first.ExportSubjectPublicKeyInfo()), new(authorizer.KeyId, second.ExportSubjectPublicKeyInfo()), new(evidence.KeyId, third.ExportSubjectPublicKeyInfo())]);
        var now = DateTimeOffset.UtcNow.AddSeconds(-1); var operation = Guid.NewGuid();
        var scope = new OrderSubtotalOwnedScope("order-subtotal-owned-fault-scope-v1", operation, Hash('a'), Hash('b'), Hash('c'), Hash('d'), new('a', 64),
            "legacy-delta-proof-synthetic", Hash('e'), Hash('f'), @case, now, now.AddMinutes(2));
        var review = CurrentAuthLocalSessionArchivePolicy.Sign("Legacy.Maliev.OrderSubtotal.OwnedFaultReview.v1", scope, reviewer);
        var authorization = CurrentAuthLocalSessionArchivePolicy.Sign("Legacy.Maliev.OrderSubtotal.OwnedFaultAuthorization.v1",
            new OrderSubtotalRepairAuthorization(operation, OrderSubtotalRepairProtocol.Hash(review), now, scope.ExpiresAtUtc), authorizer);
        string domain = "Legacy.Maliev.OrderSubtotal.OwnedFaultReceipt.v1";
        var receipts = new List<CurrentAuthArchiveClaim>(); string previous = new('0', 64);
        if (@case != "PreparedPublication")
        {
            var prepared = Receipt(CurrentAppOwnedCommitClassification.Prepared, previous);
            var signed = CurrentAuthLocalSessionArchivePolicy.Sign(domain, prepared, evidence); receipts.Add(signed); previous = OrderSubtotalRepairProtocol.Hash(signed);
        }
        var failed = Receipt(@case == "PreparedPublication" ? CurrentAppOwnedCommitClassification.RolledBackBeforeCommit : CurrentAppOwnedCommitClassification.Uncertain, previous);
        failed = fault switch
        {
            "link" => failed with { PreviousSha256 = Hash('a') },
            "scope" => failed with { ScopeSha256 = Hash('a') },
            "authorization" => failed with { AuthorizationSha256 = Hash('a') },
            "after" => failed with { AfterNativeSha256 = Hash('e') },
            "classification" => failed with { Classification = CurrentAppOwnedCommitClassification.Prepared },
            _ => failed
        };
        receipts.Add(CurrentAuthLocalSessionArchivePolicy.Sign(fault == "wrong-domain" ? OrderSubtotalRepairProtocol.ReceiptDomain : domain, failed, evidence));
        if (fault == "duplicate") { receipts.Add(receipts[^1]); }
        if (fault == "empty") { receipts.Clear(); }
        if (fault == "none") { OrderSubtotalRepairJournal.RequireOwned(review, authorization, receipts, Hash('b'), pins, trust); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalRepairJournal.RequireOwned(review, authorization, receipts, Hash('b'), pins, trust)); }
        OrderSubtotalOwnedFaultReceipt Receipt(CurrentAppOwnedCommitClassification classification, string link)
        {
            return new("order-subtotal-owned-fault-receipt-v1", operation,
            OrderSubtotalRepairProtocol.Hash(scope), OrderSubtotalRepairProtocol.Hash(authorization), link, scope.BeforeNativeSha256, Hash('a'), Hash('b'), classification, now);
        }
    }
    private static string Hash(char value)
    {
        return new(value, 64);
    }
}
