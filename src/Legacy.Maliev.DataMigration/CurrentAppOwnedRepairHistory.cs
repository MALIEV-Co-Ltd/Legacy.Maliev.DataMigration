using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAppOwnedRetainedReceipt(string Name, byte[] ExactBytes);
internal sealed record CurrentAppOwnedHistoricalDatabase(string Database, string BeforeSha256,
    string? PreparedAfterSha256, CurrentAppOwnedCommitClassification? TerminalClassification,
    bool? ReceiptTimesWithinAuthorizationWindow, bool PreparedPublicationUncertain, bool CommittedPublicationUncertain);
internal sealed record CurrentAppOwnedHistoricalTranscript(Guid OperationId, string ReviewSha256,
    string AuthorizationSha256, string ReceiptManifestSha256,
    IReadOnlyList<CurrentAppOwnedHistoricalDatabase> Databases);

/// <summary>
/// Authenticates historical evidence only. It neither observes a live target nor grants
/// execution permission, renews a claim, selects a successor or classifies actual commit state.
/// Storage completeness and current native preservation require separate closed observations.
/// </summary>
internal static class CurrentAppOwnedRepairHistory
{
    internal static CurrentAppOwnedHistoricalTranscript Authenticate(byte[] exactReview, byte[] exactAuthorization,
        IReadOnlyList<CurrentAppOwnedRetainedReceipt> artifacts, IReceiptAttestationTrustStore trust,
        CurrentAppOwnedRepairSigningPins pins, DateTimeOffset observedAtUtc)
    {
        exactReview = [.. exactReview];
        exactAuthorization = [.. exactAuthorization];
        CurrentAppOwnedRepairSignedClaim review = Decode<CurrentAppOwnedRepairSignedClaim>(exactReview);
        CurrentAppOwnedRepairSignedClaim authorization = Decode<CurrentAppOwnedRepairSignedClaim>(exactAuthorization);
        if (observedAtUtc.Offset != TimeSpan.Zero || authorization.IssuedAtUtc > observedAtUtc || artifacts.Count > 7)
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
        // Expired claims are provenance only. This historical validation instant is never
        // used to construct a permit or to execute the original operation.
        CurrentAppOwnedRepairPermit.ValidateClaims(review, authorization, trust, pins, authorization.IssuedAtUtc);
        string reviewHash = CurrentAppOwnedRepairPermit.Hash(exactReview);
        string authorizationHash = CurrentAppOwnedRepairPermit.Hash(exactAuthorization);
        CurrentAppOwnedRepairScope scope = authorization.Scope;
        var retained = new Dictionary<string, (CurrentAppOwnedRepairReceipt Receipt, string Sha256)>(StringComparer.Ordinal);
        foreach (CurrentAppOwnedRetainedReceipt artifact in artifacts)
        {
            byte[] exactReceipt = [.. artifact.ExactBytes];
            CurrentAppOwnedRepairReceipt receipt = Decode<CurrentAppOwnedRepairReceipt>(exactReceipt);
            string suffix = receipt.Classification switch
            {
                CurrentAppOwnedCommitClassification.Prepared => "prepared",
                CurrentAppOwnedCommitClassification.CommittedAndReadback => "committed-readback",
                CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or
                    CurrentAppOwnedCommitClassification.FailedBeforeCommit or
                    CurrentAppOwnedCommitClassification.Uncertain => "failed-or-uncertain",
                _ => throw CurrentAppOwnedRepairPermit.Invalid(),
            };
            if (artifact.Name != $"{scope.OperationId:D}-{receipt.Database}-{suffix}.json" ||
                !retained.TryAdd(artifact.Name, (receipt, CurrentAppOwnedRepairPermit.Hash(exactReceipt))) ||
                receipt.Kind != "current-app-owned-eight-receipt-v1" || receipt.OperationId != scope.OperationId ||
                receipt.OperationSha256 != scope.OperationSha256 || receipt.AuthorizationSha256 != authorizationHash ||
                !scope.BeforeDatabaseSha256.TryGetValue(receipt.Database, out string? before) || receipt.BeforeSha256 != before ||
                receipt.KeyId != pins.ReceiptKeyId || receipt.ObservedAtUtc.Offset != TimeSpan.Zero ||
                receipt.ObservedAtUtc < authorization.IssuedAtUtc || receipt.ObservedAtUtc > observedAtUtc ||
                !CurrentAppOwnedRepairPermit.HashShape(receipt.PreviousReceiptSha256) ||
                (receipt.AfterSha256 is not null && !CurrentAppOwnedRepairPermit.HashShape(receipt.AfterSha256)) ||
                (receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or
                    CurrentAppOwnedCommitClassification.CommittedAndReadback &&
                    receipt.AfterSha256 is null))
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            try
            {
                byte[] payload = [.. "Legacy.Maliev.CurrentAppOwnedEight.Receipt.v1\0"u8,
                    .. JsonSerializer.SerializeToUtf8Bytes(receipt with { Signature = null })];
                if (string.IsNullOrWhiteSpace(receipt.Signature) ||
                    !trust.Verify(receipt.KeyId, payload, Convert.FromBase64String(receipt.Signature)))
                { throw CurrentAppOwnedRepairPermit.Invalid(); }
            }
            catch (FormatException) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
        string previous = new('0', 64);
        DateTimeOffset last = authorization.IssuedAtUtc;
        bool stopped = false;
        var databases = new List<CurrentAppOwnedHistoricalDatabase>();
        foreach (string database in CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables))
        {
            var entries = retained.Values.Where(x => x.Receipt.Database == database).ToArray();
            if (entries.Length == 0)
            {
                stopped = true;
                databases.Add(new(database, scope.BeforeDatabaseSha256[database], null, null, null, false, false));
                continue;
            }
            if (stopped) { throw CurrentAppOwnedRepairPermit.Invalid(); }
            var prepared = entries.Where(x => x.Receipt.Classification == CurrentAppOwnedCommitClassification.Prepared).ToArray();
            var terminal = entries.Where(x => x.Receipt.Classification != CurrentAppOwnedCommitClassification.Prepared)
                .OrderBy(x => x.Receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback ? 0 : 1).ToArray();
            if (prepared.Length > 1 || terminal.Length > 2 || entries.Length > 3 ||
                (terminal.Length == 2 && (prepared.Length != 1 ||
                    terminal[0].Receipt.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback ||
                    terminal[1].Receipt.Classification != CurrentAppOwnedCommitClassification.Uncertain)))
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            string beforePrepared = previous;
            bool preparedPublicationUncertain = false;
            if (prepared.Length == 1)
            {
                RequireLink(prepared[0].Receipt, previous, last);
                previous = prepared[0].Sha256;
                last = prepared[0].Receipt.ObservedAtUtc;
            }
            DateTimeOffset terminalTime = last;
            foreach (var entry in terminal)
            {
                CurrentAppOwnedRepairReceipt result = entry.Receipt;
                bool sibling = prepared.Length == 1 && terminal.Length == 1 &&
                    result.Classification is CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or
                        CurrentAppOwnedCommitClassification.FailedBeforeCommit && result.PreviousReceiptSha256 == beforePrepared;
                RequireLink(result, sibling ? beforePrepared : previous, terminalTime);
                preparedPublicationUncertain |= sibling;
                if ((result.Classification is CurrentAppOwnedCommitClassification.CommittedAndReadback or
                    CurrentAppOwnedCommitClassification.Uncertain && prepared.Length == 0) ||
                    (prepared.Length == 1 && result.AfterSha256 != prepared[0].Receipt.AfterSha256))
                { throw CurrentAppOwnedRepairPermit.Invalid(); }
                terminalTime = result.ObservedAtUtc;
            }
            if (terminal.Length != 0) { previous = terminal[^1].Sha256; last = terminalTime; }
            CurrentAppOwnedCommitClassification? classification = terminal.Length == 0 ? null : terminal[^1].Receipt.Classification;
            stopped = classification != CurrentAppOwnedCommitClassification.CommittedAndReadback;
            databases.Add(new(database, scope.BeforeDatabaseSha256[database],
                prepared.Length == 0 ? null : prepared[0].Receipt.AfterSha256, classification,
                entries.All(x => x.Receipt.ObservedAtUtc < authorization.ExpiresAtUtc),
                preparedPublicationUncertain, terminal.Length == 2));
        }
        string manifestHash = CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(
            retained.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { Name = x.Key, x.Value.Sha256 }).ToArray()));
        return new(scope.OperationId, reviewHash, authorizationHash, manifestHash, databases.AsReadOnly());
    }

    private static void RequireLink(CurrentAppOwnedRepairReceipt receipt, string previous, DateTimeOffset last)
    {
        if (receipt.PreviousReceiptSha256 != previous || receipt.ObservedAtUtc < last)
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
    }

    private static T Decode<T>(byte[] bytes)
    {
        if (bytes.Length is 0 or > 65536) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        try
        {
            T value = JsonSerializer.Deserialize<T>(bytes, RecoveryContractEncoding.Options)
                ?? throw CurrentAppOwnedRepairPermit.Invalid();
            if (!bytes.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(value)))
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            return value;
        }
        catch (JsonException) { throw CurrentAppOwnedRepairPermit.Invalid(); }
    }
}
