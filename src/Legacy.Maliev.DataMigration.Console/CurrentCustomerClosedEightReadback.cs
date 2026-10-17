using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static partial class CurrentCustomerClosedEightReadback
{
    internal static async Task RequireEffectsAsync(CurrentAppOwnedRepairCustody files, CustomerClosedCase actual,
        CurrentCustomerSequenceRepairScope scope, CurrentCustomerSequenceRepairConfiguration config, FreshSchemaPlan source,
        DateTimeOffset now, CancellationToken ct, Func<string, string>? resolveOriginal = null,
        IReadOnlyList<CustomerDefinitionArtifact>? imported = null)
    {
        string PathOf(string path)
        {
            return resolveOriginal is null ? path : resolveOriginal(path);
        }

        byte[] Read(string path, int cap = 8_000_000)
        {
            return files.Read(PathOf(path), sharedReader: true, maximumBytes: cap);
        }

        T Decode<T>(string path)
        {
            return CustomerClosedCompletedReadback.Decode<T>(Read(path));
        }

        CurrentCustomerClosedConsoleCase.RequirePhases(actual);
        if (actual.CompletedAtUtc > now || actual.CompletedAtUtc < actual.BeganAtUtc) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        if (scope.OperationId != actual.OperationId || actual.BindingSha256 != scope.RunBindingSha256 || actual.CaseId != scope.ClosedConsoleSeed!.CaseId)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var pins = Decode<CurrentCustomerSequenceRepairSigningPins>(config.SigningPinsPath);
        var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            Convert.FromBase64String(Encoding.UTF8.GetString(Read(key.SubjectPublicKeyInfoPath, 65536)).Trim()))).ToArray());
        CurrentCustomerSequenceClosedBootstrap.Require(scope.ClosedConsoleSeed, scope, trust, pins.ReviewKeyId, pins.ReviewFingerprint,
            actual.BeganAtUtc);
        var before = Decode<CurrentCustomerSequenceObservation>(actual.BeforeNative.Path);
        var after = Decode<CurrentCustomerSequenceObservation>(actual.AfterNative.Path);
        ApprovedCurrentCustomerSequenceDefinition.RequireBefore(before, "legacy_local");
        if (before.Snapshot.Relations.Single(x => x.Schema == "public" && x.Name == "Customer").Rows != 2 ||
            before.Snapshot.Relations.Single(x => x.Schema == "private" && x.Name == "fixture_journal").Rows != 2)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        CurrentCustomerSequenceRepairPermit.RequireNativePreimage(before, scope, actual.BeganAtUtc);
        if (CurrentCustomerSequenceRepairPermit.Hash(Read(actual.BeforeNative.Path)) != actual.BeforeNative.Sha256 ||
            CurrentCustomerSequenceRepairPermit.Hash(Read(actual.AfterNative.Path)) != actual.AfterNative.Sha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        bool early = actual.CaseId is "host-unprobed-sdk" or "local-ordinary-trust";
        var receipts = actual.RetainedReceipts.Select(x =>
        {
            byte[] bytes = Read(x.Path, 65536);
            return CurrentCustomerSequenceRepairPermit.Hash(bytes) != x.Sha256
                ? throw CurrentCustomerSequenceRepairPermit.Invalid()
                : (Artifact: x, Value: CustomerClosedCompletedReadback.Decode<CurrentCustomerSequenceRepairReceipt>(bytes));
        }).ToArray();
        var prepared = receipts.SingleOrDefault(x => x.Value.Classification == CurrentAppOwnedCommitClassification.Prepared);
        var terminal = receipts.SingleOrDefault(x => x.Value.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback);
        var (Artifact, Value) = receipts.SingleOrDefault(x => x.Value.Classification is CurrentAppOwnedCommitClassification.Uncertain or CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or CurrentAppOwnedCommitClassification.FailedBeforeCommit);
        RequireClassifications(actual.CaseId, receipts.Select(x => x.Value.Classification).ToArray());
        if (early)
        {
            if (actual.Review is not null || actual.Authorization is not null || receipts.Length != 0 || before.Snapshot.Sha256 != after.Snapshot.Sha256 || before.State != after.State)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        else
        {
            byte[] reviewBytes = Read(actual.Review!.Path, 65536), permissionBytes = Read(actual.Authorization!.Path, 65536);
            if (CurrentCustomerSequenceRepairPermit.Hash(reviewBytes) != actual.Review.Sha256 || CurrentCustomerSequenceRepairPermit.Hash(permissionBytes) != actual.Authorization.Sha256)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            var review = CustomerClosedCompletedReadback.Decode<CurrentCustomerSequenceRepairSignedClaim>(reviewBytes);
            var permission = CustomerClosedCompletedReadback.Decode<CurrentCustomerSequenceRepairSignedClaim>(permissionBytes);
            CurrentCustomerSequenceRepairPermit.ValidateClaims(review, permission, source, trust, pins, actual.Commands[3].BeganAtUtc);
            if (JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(scope) || JsonSerializer.Serialize(permission.Scope) != JsonSerializer.Serialize(scope) || prepared.Value is null)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            string zero = new('0', 64), authorizationHash = actual.Authorization.Sha256;
            foreach (var receipt in receipts)
            {
                string predecessor = receipt.Value.Classification == CurrentAppOwnedCommitClassification.Prepared || actual.CaseId == "prepared-publication"
                    ? zero : actual.CaseId == "final-fleet" && receipt.Value.Classification == CurrentAppOwnedCommitClassification.Uncertain
                        ? terminal.Artifact.Sha256 : prepared.Artifact.Sha256;
                PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(receipt.Value, scope, authorizationHash, trust, pins, predecessor, receipt.Value.ObservedAtUtc);
                if (receipt.Value.ObservedAtUtc < actual.Commands[3].BeganAtUtc || receipt.Value.ObservedAtUtc > actual.Commands[3].CompletedAtUtc ||
                    receipt.Value.BeforeSha256 != before.Snapshot.Sha256 || receipt.Value.AfterSha256 != prepared.Value.AfterSha256)
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            if ((terminal.Value is not null && terminal.Value.ObservedAtUtc < prepared.Value.ObservedAtUtc) ||
                (Value is not null && (Value.ObservedAtUtc < prepared.Value.ObservedAtUtc ||
                    (terminal.Value is not null && Value.ObservedAtUtc < terminal.Value.ObservedAtUtc))))
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            string root = Path.GetDirectoryName(config.ScopePath)!;
            string[] originals = imported is null ? Directory.GetFiles(root) : imported.Select(x => x.SourcePath ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).ToArray();
            string[] fleetFaults = originals.Where(x => x.EndsWith("-fleet-fault-committed.json", StringComparison.Ordinal)).ToArray();
            if (actual.CaseId == "final-fleet")
            {
                if (fleetFaults.Length != 1 || terminal.Value is null || Value is null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                using var fact = JsonDocument.Parse(Read(fleetFaults[0], 65536)); var f = fact.RootElement;
                if (f.GetProperty("Database").GetString() != "postgres" || f.GetProperty("Relation").GetString() != "private.customer_closed_sentinel" || f.GetProperty("Count").GetInt32() != 1 ||
                    f.GetProperty("ObservedAtUtc").GetDateTimeOffset() < terminal.Value.ObservedAtUtc || f.GetProperty("ObservedAtUtc").GetDateTimeOffset() > Value.ObservedAtUtc)
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            else if (fleetFaults.Length != 0) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            string[] candidatePaths = originals.Where(x => Path.GetFileName(x).StartsWith("customer-closed-" + scope.OperationId.ToString("N") + "-", StringComparison.Ordinal) && x.EndsWith("-candidate.json", StringComparison.Ordinal)).ToArray();
            if (candidatePaths.Length != 1) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            var candidate = Decode<CurrentCustomerSequenceObservation>(candidatePaths[0]);
            ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, candidate, "legacy_local");
            if (prepared.Value.AfterSha256 != candidate.Snapshot.Sha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            if (actual.CaseId == "prepared-publication")
            {
                if (receipts.Length != 2 || terminal.Value is not null || Value?.Classification != CurrentAppOwnedCommitClassification.RolledBackBeforeCommit ||
                    before.Snapshot.Sha256 != after.Snapshot.Sha256 || before.State != after.State) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            else
            {
                ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, after, "legacy_local");
                if (after.Snapshot.Sha256 != candidate.Snapshot.Sha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                if (actual.CaseId is "success" or "replay")
                { if (receipts.Length != 2 || terminal.Value is null || Value is not null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
                else if (actual.CaseId is "terminal-publication" or "final-fleet")
                { if (receipts.Length != 3 || terminal.Value is null || Value?.Classification != CurrentAppOwnedCommitClassification.Uncertain) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
                else if (receipts.Length != 2 || terminal.Value is not null || Value?.Classification != CurrentAppOwnedCommitClassification.Uncertain)
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            string unackPath = Path.Combine(root, "customer-closed-publication-unack-" + scope.OperationId.ToString("N") + ".json");
            bool publication = actual.CaseId is "prepared-publication" or "terminal-publication";
            if (publication)
            {
                using var unack = JsonDocument.Parse(Read(unackPath, 65536)); var x = unack.RootElement;
                var expected = actual.CaseId == "prepared-publication" ? prepared : terminal;
                if (x.GetProperty("Slot").GetString() != Path.GetFileName(expected.Artifact.Path) || x.GetProperty("Sha256").GetString() != expected.Artifact.Sha256 ||
                    x.GetProperty("Acknowledged").GetBoolean() || x.GetProperty("PreviousAcknowledgedSha256").GetString() != (actual.CaseId == "prepared-publication" ? zero : prepared.Artifact.Sha256) ||
                    x.GetProperty("ObservedAtUtc").GetDateTimeOffset() < expected.Value.ObservedAtUtc ||
                    x.GetProperty("ObservedAtUtc").GetDateTimeOffset() > Value!.ObservedAtUtc ||
                    x.GetProperty("ObservedAtUtc").GetDateTimeOffset() < actual.Commands[3].BeganAtUtc || x.GetProperty("ObservedAtUtc").GetDateTimeOffset() > actual.Commands[3].CompletedAtUtc)
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            else if (originals.Contains(unackPath, StringComparer.Ordinal)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            string[] names = originals.Where(x => Path.GetFileName(x).StartsWith(scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase)).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray()!;
            string[] allowed = [.. receipts.Select(x => Path.GetFileName(x.Artifact.Path)), scope.OperationId.ToString("D") + "-customer-sequence-operation-start.json"];
            if (!names.SequenceEqual(allowed.Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            using var reservation = JsonDocument.Parse(Read(Path.Combine(root, allowed[^1]), 65536));
            var reserved = reservation.RootElement;
            if (reserved.GetProperty("Kind").GetString() != "current-customer-sequence-operation-start-v1" ||
                reserved.GetProperty("OperationId").GetGuid() != scope.OperationId ||
                reserved.GetProperty("ScopeSha256").GetString() != CurrentAppOwnedSnapshotSerialization.Sha256(scope) ||
                reserved.GetProperty("AuthorizationSha256").GetString() != authorizationHash) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        var beforeFleet = await ReadFleet(actual.BeforeFleet).ConfigureAwait(false); var afterFleet = await ReadFleet(actual.AfterFleet).ConfigureAwait(false);
        string[] expectedDatabases = [.. DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).Order(StringComparer.Ordinal)];
        if (!beforeFleet.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(expectedDatabases) ||
            !afterFleet.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(expectedDatabases) || beforeFleet.Length != 26 || afterFleet.Length != 26)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        foreach (var old in beforeFleet)
        {
            var current = afterFleet.Single(x => x.Database == old.Database);
            if (old.Database == "Customer")
            { if (old.Sha256 != before.Snapshot.Sha256 || current.Sha256 != after.Snapshot.Sha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
            else if (actual.CaseId == "final-fleet" && old.Database == "postgres") { RequireSentinelOnly(old, current); }
            else if (old.Sha256 != current.Sha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        files.Require();
        async Task<CurrentAppOwnedDatabaseSnapshot[]> ReadFleet(CustomerDefinitionArtifact artifact)
        {
            var stream = files.BorrowReadStream(PathOf(artifact.Path)); stream.Position = 0;
            if (Convert.ToHexStringLower(await System.Security.Cryptography.SHA256.HashDataAsync(stream, ct).ConfigureAwait(false)) != artifact.Sha256)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            files.Require(); return await files.ReadBaselineAsync(PathOf(artifact.Path), ct, sharedReader: true).ConfigureAwait(false);
        }
    }
    internal static void RequireClassifications(string caseId, IReadOnlyList<CurrentAppOwnedCommitClassification> actual)
    {
        CurrentAppOwnedCommitClassification[] expected = caseId switch
        {
            "host-unprobed-sdk" or "local-ordinary-trust" => [],
            "success" or "replay" => [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback],
            "prepared-publication" => [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.RolledBackBeforeCommit],
            "lost-commit-ack" => [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.Uncertain],
            "terminal-publication" or "final-fleet" => [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback, CurrentAppOwnedCommitClassification.Uncertain],
            _ => throw CurrentCustomerSequenceRepairPermit.Invalid()
        };
        if (!actual.Order().SequenceEqual(expected.Order())) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    internal static void RequireSentinelOnly(CurrentAppOwnedDatabaseSnapshot before, CurrentAppOwnedDatabaseSnapshot after)
    {
        var old = before.Relations.Single(x => x.Schema == "private" && x.Name == "customer_closed_sentinel");
        var current = after.Relations.Single(x => x.Schema == "private" && x.Name == "customer_closed_sentinel");
        if (old.Rows != 1 || current.Rows != 1 || old.RowSha256 != SentinelHash("unchanged") || current.RowSha256 != SentinelHash("changed-during-candidate") ||
            before.Sha256 != (after with { Relations = after.Relations.Select(x => x.Schema == old.Schema && x.Name == old.Name ? old : x).ToArray() }).Sha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    private static string SentinelHash(string text)
    {
        return CurrentCustomerSequenceRepairPermit.Hash(Encoding.UTF8.GetBytes(
        CurrentCustomerSequenceRepairPermit.Hash(Encoding.UTF8.GetBytes("{\"id\": 1, \"evidence\": \"" + text + "\"}"))));
    }
}
