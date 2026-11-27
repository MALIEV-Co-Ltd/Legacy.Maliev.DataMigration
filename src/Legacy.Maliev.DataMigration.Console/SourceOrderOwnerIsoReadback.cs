using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class SourceOrderOwnerIsoRuntime
{
    private static CompanyStorageArtifact ReadRun(SourceOrderOwnerIsoInputs input, bool completed)
    {
        string root = input.Authority.Binding.ArtifactRootCanonicalPath;
        string path = Directory.GetFiles(root, "*-SourceOrderIso-run-" + (completed ? "completed" : "unfinished") + ".json").Single();
        byte[] bytes = input.Files.Read(path, sharedReader: true, maximumBytes: 65536); var pin = input.Configuration.SigningPins;
        var run = CurrentAuthLocalSessionArchivePolicy.Verify<JsonElement>(MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(bytes),
            SourceOrderOwnerIsoProtocol.ReceiptDomain, pin.ReceiptKeyId, pin.ReceiptFingerprint, input.Trust);
        Guid operation = run.GetProperty("OperationId").GetGuid();
        string Slot(string name)
        {
            return Path.Combine(root, $"{operation:D}-SourceOrderIso-{name}.json");
        }

        CurrentAuthArchiveClaim Claim(string name)
        {
            return MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(input.Files.Read(Slot(name), sharedReader: true, maximumBytes: 65536));
        }

        var review = Claim("review"); var scope = CurrentAuthLocalSessionArchivePolicy.Verify<SourceOrderOwnerIsoScope>(review,
            SourceOrderOwnerIsoProtocol.ReviewDomain, pin.ReviewKeyId, pin.ReviewFingerprint, input.Trust);
        var authClaim = Claim("authorization"); var auth = CurrentAuthLocalSessionArchivePolicy.Verify<SourceOrderOwnerIsoAuthorization>(authClaim,
            SourceOrderOwnerIsoProtocol.AuthorizationDomain, pin.AuthorizationKeyId, pin.AuthorizationFingerprint, input.Trust);
        var source = MigrationConsole.DecodeAuthRepair<ConsumerColumnBootstrapSourceCapture>(input.Files.Read(Slot("source-capture"), sharedReader: true, maximumBytes: 32 * 1024 * 1024));
        DateTimeOffset observed = run.GetProperty("ObservedAtUtc").GetDateTimeOffset();
        using var code = CompanyStorageAcceptedCodeCustody.Acquire();
        string scopeHash = SourceOrderOwnerIsoProtocol.Hash(scope), authHash = SourceOrderOwnerIsoProtocol.Hash(authClaim);
        var pending = SourceOrderOwnerIsoProtocol.Databases.Where(x => !input.Intent.Selected[x]).ToArray();
        if (run.GetProperty("Kind").GetString() != "source-order-owner-iso-run-v1" || run.GetProperty("Completed").GetBoolean() != completed ||
            run.GetProperty("RuntimeOperationCount").GetInt32() != pending.Length || run.GetProperty("ProofOperationCount").GetInt32() != 2 ||
            scope.Kind != "source-order-owner-iso-owned-scope-v1" || scope.OperationId != operation || auth.OperationId != operation ||
            !scope.PendingDatabases.SequenceEqual(pending, StringComparer.Ordinal) || auth.ReviewSha256 != SourceOrderOwnerIsoProtocol.Hash(review) ||
            scope.IntentSha256 != SourceOrderOwnerIsoProtocol.Hash(input.IntentClaim) || SourceOrderOwnerIsoProtocol.Hash(scope.Intent) != SourceOrderOwnerIsoProtocol.Hash(input.Intent) ||
            run.GetProperty("ScopeSha256").GetString() != scopeHash || run.GetProperty("AuthorizationSha256").GetString() != authHash ||
            scope.RunnerSha256 != code.RunnerDigestSha256 || scope.ActualFullSourceSha256 != source.FullPlanSha256 ||
            SchemaPlanCanonicalizer.ComputeSha256(source.Plan) != source.FullPlanSha256 || source.SourceIdentitySha256 != input.Intent.SourceIdentitySha256 ||
            SourceCatalogDefinitionFingerprintV1.Compute(source.Plan, input.Intent.SourceCommitSha, input.Intent.SourceIdentitySha256, scope.IssuedAtUtc) != input.Intent.SourceDefinitionSha256 ||
            scope.IssuedAtUtc > observed || observed > scope.ExpiresAtUtc || observed < source.BeganAtUtc || observed - source.BeganAtUtc > TimeSpan.FromMinutes(5) ||
            auth.IssuedAtUtc != scope.IssuedAtUtc || auth.ExpiresAtUtc != scope.ExpiresAtUtc) { throw Invalid(); }
        string proofPath = Directory.GetFiles(root, "*-SourceOrderIso-disposable-proof.json").Single();
        byte[] proofBytes = input.Files.Read(proofPath, sharedReader: true, maximumBytes: 65536);
        var proof = CurrentAuthLocalSessionArchivePolicy.Verify<JsonElement>(MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(proofBytes),
            SourceOrderOwnerIsoProtocol.ProofDomain, pin.ReceiptKeyId, pin.ReceiptFingerprint, input.Trust);
        var contract = SourceOrderOwnerIsoContract.Create(source.Plan, input.Intent.SourceCommitSha, input.Intent.CompanyAlreadyApplied, scope.Owners, scope.IssuedAtUtc);
        string nativePath = Directory.GetFiles(root, "*-SourceOrderIso-disposable-native-observations.json").Single();
        byte[] nativeEvidence = input.Files.Read(nativePath, sharedReader: true, maximumBytes: 64 * 1024 * 1024);
        if (SourceOrderOwnerIsoProtocol.Hash(proofBytes) != scope.ProofSha256 || run.GetProperty("ProofSha256").GetString() != scope.ProofSha256 ||
            SourceOrderOwnerIsoProtocol.Hash(nativeEvidence) != proof.GetProperty("NativeEvidenceSha256").GetString() ||
            scope.ContractSha256 != contract.ComputeSha256() || proof.GetProperty("ContractSha256").GetString() != scope.ContractSha256 ||
            proof.GetProperty("SourceFullSha256").GetString() != source.FullPlanSha256 || proof.GetProperty("SourceDefinitionSha256").GetString() != input.Intent.SourceDefinitionSha256 ||
            proof.GetProperty("CandidateSha256").GetString() != SourceOrderOwnerIsoProtocol.SqlSha256 || proof.GetProperty("RunnerSha256").GetString() != scope.RunnerSha256 ||
            !proof.GetProperty("CleanupVerified").GetBoolean() || !proof.GetProperty("RollbackReadback").GetBoolean() || !proof.GetProperty("IndependentReadback").GetBoolean() ||
            proof.GetProperty("SystemIdentifierSha256").GetString() == input.Intent.Target.SystemIdentifierSha256) { throw Invalid(); }
        string previous = new('0', 64); var terminal = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string database in pending)
        {
            foreach (string slot in ReceiptSlots)
            {
                string file = Slot(database + "-" + slot);
                if (!File.Exists(file) || new FileInfo(file).Length == 0) { continue; }
                var signed = Claim(database + "-" + slot);
                var receipt = CurrentAuthLocalSessionArchivePolicy.Verify<SourceOrderOwnerIsoReceipt>(signed, SourceOrderOwnerIsoProtocol.ReceiptDomain,
                    pin.ReceiptKeyId, pin.ReceiptFingerprint, input.Trust);
                if (receipt.Kind != "source-order-owner-iso-receipt-v1" || receipt.OperationId != operation || receipt.Database != database ||
                    receipt.ScopeSha256 != scopeHash || receipt.AuthorizationSha256 != authHash || receipt.PreviousSha256 != previous ||
                    receipt.BeforeNativeSha256 != input.Intent.NativePreimageSha256[database] || receipt.ObservedAtUtc < scope.IssuedAtUtc || receipt.ObservedAtUtc > observed ||
                    (slot == "prepared" && receipt.Classification != CurrentAppOwnedCommitClassification.Prepared) ||
                    (slot == "committed-readback" && receipt.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback) ||
                    (slot == "failed-or-uncertain" && receipt.Classification is not (CurrentAppOwnedCommitClassification.Uncertain or CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or CurrentAppOwnedCommitClassification.FailedBeforeCommit))) { throw Invalid(); }
                previous = SourceOrderOwnerIsoProtocol.Hash(signed);
                if (slot == "committed-readback") { terminal.Add(database, receipt.AfterNativeSha256 ?? throw Invalid()); }
            }
        }
        var retained = run.GetProperty("TerminallyReadbackDatabaseSha256"); var effects = run.GetProperty("IndependentlyObservedNativeSha256");
        return run.GetProperty("PreviousSha256").GetString() != previous || retained.EnumerateObject().Count() != terminal.Count ||
            terminal.Any(x => !retained.TryGetProperty(x.Key, out _) || !effects.TryGetProperty(x.Key, out var value) || value.GetString() != x.Value) ||
            (completed && terminal.Count != pending.Length)
            ? throw Invalid()
            : new(path, SourceOrderOwnerIsoProtocol.Hash(bytes));
    }
    private static readonly string[] ReceiptSlots = ["prepared", "committed-readback", "failed-or-uncertain"];
}
