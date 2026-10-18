using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentOwnerIsoProofArtifact(string Path, string Sha256);
internal sealed record CurrentOwnerIsoProofRun(Guid RunId, string Name, string ContainerId,
    CurrentOwnerIsoProofArtifact Attempt, CurrentOwnerIsoProofArtifact Observed, CurrentOwnerIsoProofArtifact Disposed,
    CurrentOwnerIsoProofArtifact AbsenceInventory);
internal sealed record CurrentOwnerIsoProofAbsence(string Kind, Guid RunId, DateTimeOffset ObservedAtUtc,
    IReadOnlyList<string> AllContainerIds, IReadOnlyList<string> AllContainerNames, IReadOnlyList<string> AllVolumeNames,
    IReadOnlyList<int> ListeningLoopbackPorts, bool ContainerInventorySucceeded, bool VolumeInventorySucceeded, bool ListenerInventorySucceeded); internal sealed record CurrentOwnerIsoProofCase(string TestName, string TestId, string ExecutionId, Guid RunId,
    CurrentOwnerIsoProofArtifact Invocation, CurrentOwnerIsoProofArtifact Scope, CurrentOwnerIsoProofArtifact Review,
    CurrentOwnerIsoProofArtifact Authorization, CurrentOwnerIsoProofArtifact TestAssembly,
    CurrentOwnerIsoProofArtifact NativeBefore, CurrentOwnerIsoProofArtifact NativeAfter,
    IReadOnlyList<CurrentOwnerIsoProofArtifact> EffectReceipts,
    CurrentOwnerIsoProofArtifact Configuration, CurrentOwnerIsoProofArtifact RunBinding, CurrentOwnerIsoProofArtifact TargetPins,
    CurrentOwnerIsoProofArtifact ContainerOwnership, CurrentOwnerIsoProofArtifact VolumeOwnership,
    int LoopbackPort, CurrentOwnerIsoProofArtifact ScenarioEvidence,
    CurrentOwnerIsoProofArtifact? FaultInjection = null);
internal sealed record CurrentOwnerIsoProofSlot(CurrentOwnerIsoProofArtifact Artifact, bool Acknowledged);
internal sealed record CurrentOwnerIsoProofScenario(string Kind, Guid OperationId, string InvocationSha256, string Boundary,
    string? RejectionCode, DateTimeOffset ObservedAtUtc, IReadOnlyList<CurrentOwnerIsoProofSlot> RetainedSlots,
    IReadOnlyList<string> OrdinaryRejectedDatabases, bool InstalledSemanticPolicyAccepted, bool CommitAcknowledged, bool MaterialAttempted); internal sealed record CurrentOwnerIsoProofFault(string Kind, Guid OperationId, string Database, string BeforeSha256, string AfterSha256,
    DateTimeOffset ObservedAtUtc);
internal sealed record CurrentOwnerIsoProofInvocation(string Kind, string Command, Guid OperationId, Guid RunId,
    string TestName, string TestId, string ExecutionId, string ScopeSha256, string ReviewSha256, string AuthorizationSha256,
    string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256, string ConfigurationSha256,
    DateTimeOffset StartedAtUtc, DateTimeOffset ExitedAtUtc, int ExitCode, string ExecutedTestAssemblyPath);
internal sealed record CurrentOwnerIsoClosedProof(string Kind, string SourceCommitSha, string SourceCatalogSha256,
    string ContractSha256, string OperationSha256, string MaintenanceValidatorSha256, string IntendedTargetObservationSha256,
    string ConsoleAssemblySha256, string CoreAssemblySha256,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc,
    CurrentOwnerIsoProofArtifact Trx, IReadOnlyList<CurrentOwnerIsoProofRun> Runs,
    IReadOnlyList<CurrentOwnerIsoProofCase> Cases, string KeyId, string? Signature);

internal static class CurrentOwnerIsoClosedProofReader
{
    private static readonly string[] CompletedReceiptDatabases = ["Country", "Country", "Material", "Material"];
    private static readonly string[] NativeCases = [
        "Complete_26_database_fleet_is_preserved_after_Country_and_Material_commit",
        "Prepared_receipt_publication_failure_rolls_back_without_commit",
        "Dropped_commit_ack_stops_without_Material_apply",
        "Terminal_publication_uncertainty_stops_without_Material_apply",
        "Wrong_owner_rejected_before_DDL",
        "Full_fleet_drift_after_Country_stops_Material"];
    private static readonly string[] MaintenanceCases = ["Unsafe_unprobed_host_rule_rejected","Local_trust_rejected",
        "Ordinary_client_rejected_in_all_26_databases","Exact_installed_policy_accepts_only_maintenance_client"];

    internal static void RequireTrxMethod(string testName, string? className, string? methodName)
    {
        if (className != "Legacy.Maliev.DataMigration.Tests.CurrentOwnerIsoGuardedNativeExecutionTests" || methodName != testName ||
            !NativeCases.Concat(MaintenanceCases).Contains(testName, StringComparer.Ordinal)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
    internal static void RequireExecutedAssemblyPath(string executed, string held, string? codeBase, string? storage)
    {
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        foreach (string? path in new[] { executed, held, codeBase, storage })
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !string.Equals(path, Path.GetFullPath(path), comparison) ||
                !string.Equals(path, executed, comparison)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        }
    }
    internal static void RequireAcknowledgedAfterImages(IReadOnlyList<CurrentOwnerIsoRepairReceipt> receipts)
    {
        var prepared = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var receipt in receipts)
        {
            if (receipt.Classification == CurrentAppOwnedCommitClassification.Prepared)
            {
                if (receipt.AfterSha256 is null || !prepared.TryAdd(receipt.Database, receipt.AfterSha256)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
            else if (receipt.Classification is CurrentAppOwnedCommitClassification.CommittedAndReadback or CurrentAppOwnedCommitClassification.Uncertain)
            {
                if (!prepared.TryGetValue(receipt.Database, out string? after) || receipt.AfterSha256 != after) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
        }
    }
    internal static void RequireUnacknowledgedLink(CurrentOwnerIsoRepairReceipt retained, IReadOnlyList<CurrentOwnerIsoRepairReceipt> acknowledged,
        IReadOnlyList<string> hashes, string boundary)
    {
        if (acknowledged.Count != hashes.Count || retained.AfterSha256 is null || retained.Database != "Country") { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        if (boundary == "prepared-publication-before-ack")
        {
            if (retained.Classification != CurrentAppOwnedCommitClassification.Prepared || retained.PreviousReceiptSha256 != new string('0', 64) ||
                acknowledged.Count != 1 || acknowledged[0].AfterSha256 != retained.AfterSha256 || acknowledged[0].ObservedAtUtc < retained.ObservedAtUtc)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        }
        else if (boundary == "terminal-publication")
        {
            if (retained.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback || acknowledged.Count != 2 ||
                acknowledged[0].Classification != CurrentAppOwnedCommitClassification.Prepared || acknowledged[1].Classification != CurrentAppOwnedCommitClassification.Uncertain ||
                retained.PreviousReceiptSha256 != hashes[0] || retained.AfterSha256 != acknowledged[0].AfterSha256 ||
                retained.ObservedAtUtc < acknowledged[0].ObservedAtUtc || retained.ObservedAtUtc > acknowledged[1].ObservedAtUtc)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        }
        else { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
    internal static void RequireAbsence(CurrentOwnerIsoProofAbsence absence, Guid run, string containerId, string name, IReadOnlyList<string> volumes,
        IReadOnlyList<int> ports, DateTimeOffset exited, DateTimeOffset completed)
    {
        if (absence.Kind != "current-owner-iso-cleanup-absence-v1" || absence.RunId != run || absence.ObservedAtUtc.Offset != TimeSpan.Zero ||
            absence.ObservedAtUtc < exited || absence.ObservedAtUtc > completed || !absence.ContainerInventorySucceeded ||
            !absence.VolumeInventorySucceeded || !absence.ListenerInventorySucceeded || absence.AllContainerIds.Contains(containerId, StringComparer.Ordinal) ||
            absence.AllContainerNames.Any(x => x == name || x == "/" + name) || volumes.Any(x => absence.AllVolumeNames.Contains(x, StringComparer.Ordinal)) ||
            ports.Any(x => absence.ListeningLoopbackPorts.Contains(x))) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
    internal static void RequireCaseEffects(string name, CurrentOwnerIsoProofScenario scenario,
        IReadOnlyList<CurrentOwnerIsoRepairReceipt> receipts, IReadOnlyDictionary<string, string> before, IReadOnlyDictionary<string, string> after)
    {
        string[] databases = before.Keys.Order(StringComparer.Ordinal).ToArray();
        if (!after.Keys.Order(StringComparer.Ordinal).SequenceEqual(databases) || (scenario.MaterialAttempted && name != NativeCases[0])) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        bool unchanged = databases.All(x => before[x] == after[x]);
        var classifications = receipts.Select(x => x.Classification).ToArray();
        var prepared = receipts.FirstOrDefault(x => x.Database == "Country" && x.Classification == CurrentAppOwnedCommitClassification.Prepared);
        bool countryAfter = prepared?.AfterSha256 is not null && after["Country"] == prepared.AfterSha256 && after["Country"] != before["Country"];
        bool onlyCountry = databases.Where(x => x != "Country").All(x => before[x] == after[x]);
        bool negativeCountryOnly = receipts.All(x => x.Database == "Country");
        bool FailureBoundary(string value)
        {
            return scenario.Boundary == value && !string.IsNullOrWhiteSpace(scenario.RejectionCode);
        }

        bool valid = name switch
        {
            var x when x == NativeCases[0] => scenario.Boundary == "complete" && scenario.CommitAcknowledged && scenario.MaterialAttempted &&
                classifications.SequenceEqual([CurrentAppOwnedCommitClassification.Prepared,CurrentAppOwnedCommitClassification.CommittedAndReadback,
                    CurrentAppOwnedCommitClassification.Prepared,CurrentAppOwnedCommitClassification.CommittedAndReadback]) &&
                receipts.Select(x => x.Database).SequenceEqual(CompletedReceiptDatabases) &&
                receipts.Where(x => x.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback).All(x => after[x.Database] == x.AfterSha256 && after[x.Database] != before[x.Database]),
            var x when x == NativeCases[1] => FailureBoundary("prepared-publication-before-ack") && !scenario.CommitAcknowledged && unchanged && negativeCountryOnly &&
                classifications.Length == 1 && (classifications[0] is CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or CurrentAppOwnedCommitClassification.FailedBeforeCommit) &&
                receipts[0].AfterSha256 is not null && scenario.RetainedSlots.All(x => !x.Acknowledged || x.Artifact.Sha256 == CurrentAppOwnedSnapshotSerialization.Sha256(receipts[0])),
            var x when x == NativeCases[2] => FailureBoundary("commit-ack-lost") && !scenario.CommitAcknowledged && countryAfter && onlyCountry && negativeCountryOnly &&
                classifications.SequenceEqual([CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.Uncertain]),
            var x when x == NativeCases[3] => FailureBoundary("terminal-publication") && scenario.CommitAcknowledged && countryAfter && onlyCountry && negativeCountryOnly &&
                (classifications.SequenceEqual([CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.Uncertain]) ||
                 classifications.SequenceEqual([CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback, CurrentAppOwnedCommitClassification.Uncertain])),
            var x when x == NativeCases[4] => FailureBoundary("owner-preflight") && receipts.Count == 0 && scenario.RetainedSlots.Count == 0 && unchanged && !scenario.CommitAcknowledged,
            var x when x == NativeCases[5] => FailureBoundary("fleet-after-country") && scenario.CommitAcknowledged && countryAfter && negativeCountryOnly &&
                classifications.SequenceEqual([CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback]) &&
                databases.Where(x => x is not ("Country" or "Upload")).All(x => before[x] == after[x]) && after["Upload"] != before["Upload"],
            var x when x == MaintenanceCases[0] || x == MaintenanceCases[1] => FailureBoundary("maintenance-semantic") &&
                scenario.RejectionCode == "current_app_owned_maintenance_hba_not_exclusive" && !scenario.InstalledSemanticPolicyAccepted && unchanged &&
                receipts.Count == 0 && scenario.RetainedSlots.Count == 0 && !scenario.CommitAcknowledged,
            var x when x == MaintenanceCases[2] || x == MaintenanceCases[3] => scenario.Boundary == "maintenance-probes" && scenario.RejectionCode is null &&
                scenario.InstalledSemanticPolicyAccepted && scenario.OrdinaryRejectedDatabases.Order(StringComparer.Ordinal).SequenceEqual(databases) &&
                unchanged && receipts.Count == 0 && scenario.RetainedSlots.Count == 0 && !scenario.CommitAcknowledged,
            _ => false
        };
        if (!valid) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
    private static string AssemblyHash(string path)
    {
        using var image = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(image));
    }
    internal static void Require(CurrentAppOwnedRepairCustody files, CurrentAppOwnedRepairArtifact artifact, string expected,
        string phase, CurrentOwnerIsoRepairScope scope, IReceiptAttestationTrustStore trust, CurrentOwnerIsoRepairSigningPins pins,
        FreshSchemaPlan source, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners)
    {
        byte[] bytes = files.Read(artifact.Path, maximumBytes: 1_000_000);
        if (artifact.Sha256 != expected || CurrentAppOwnedRepairPermit.Hash(bytes) != expected) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        var proof = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoClosedProof>(bytes);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string kind = phase switch
        {
            "native" => "current-owner-iso-native-console-proof-v1",
            "maintenance" => "current-owner-iso-maintenance-console-proof-v1",
            "native-component" => "current-owner-iso-native-provider-proof-v1",
            "maintenance-component" => "current-owner-iso-maintenance-provider-proof-v1",
            _ => throw CurrentOwnerIsoRepairPermit.Invalid()
        };
        if (proof.Kind != kind || proof.SourceCommitSha != scope.SourceCommitSha || proof.SourceCatalogSha256 != scope.SourceCatalogSha256 ||
            proof.ContractSha256 != scope.ContractSha256 || proof.OperationSha256 != scope.OperationSha256 ||
            proof.MaintenanceValidatorSha256 != scope.MaintenanceValidatorSha256 ||
            proof.IntendedTargetObservationSha256 != scope.TargetObservationSha256 ||
            proof.ConsoleAssemblySha256 != AssemblyHash(typeof(MigrationConsole).Assembly.Location) ||
            proof.CoreAssemblySha256 != AssemblyHash(typeof(CurrentOwnerIsoRepairPermit).Assembly.Location) || proof.KeyId != pins.ReceiptKeyId ||
            !trust.TryGetPublicKeyFingerprintSha256(proof.KeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint ||
            proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > now || now - proof.BeganAtUtc > TimeSpan.FromHours(12) ||
            proof.ExpiresAtUtc <= now || proof.ExpiresAtUtc - proof.BeganAtUtc > TimeSpan.FromHours(12) ||
            proof.Runs.Count == 0 || proof.Runs.Select(x => x.RunId).Distinct().Count() != proof.Runs.Count || string.IsNullOrWhiteSpace(proof.Signature))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        byte[] payload = [.. Encoding.UTF8.GetBytes("Legacy.Maliev.CurrentOwnerIso.ClosedProof."+phase+".v1\0"),
            ..JsonSerializer.SerializeToUtf8Bytes(proof with {Signature=null})];
        try { if (!trust.Verify(proof.KeyId, payload, Convert.FromBase64String(proof.Signature))) { throw CurrentOwnerIsoRepairPermit.Invalid(); } }
        catch (FormatException) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        byte[] trx = Read(proof.Trx);
        using var stream = new MemoryStream(trx, writable: false);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var document = XDocument.Load(reader);
        XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var counters = document.Descendants(ns + "Counters").Single();
        string[] required = phase.StartsWith("native", StringComparison.Ordinal) ? NativeCases : MaintenanceCases;
        var results = document.Descendants(ns + "UnitTestResult").ToArray();
        if ((string?)counters.Attribute("total") != required.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
            (string?)counters.Attribute("passed") != (string?)counters.Attribute("total") || (string?)counters.Attribute("failed") != "0" ||
            results.Length != required.Length || results.Any(x => (string?)x.Attribute("outcome") != "Passed") ||
            !results.Select(x => (string?)x.Attribute("testName")).Order(StringComparer.Ordinal).SequenceEqual(required.Order(StringComparer.Ordinal)))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        if (proof.Cases.Count != required.Length || !proof.Cases.Select(x => x.TestName).Order(StringComparer.Ordinal).SequenceEqual(required.Order(StringComparer.Ordinal)) ||
            proof.Cases.Select(x => x.ExecutionId).Distinct(StringComparer.Ordinal).Count() != required.Length ||
            !proof.Cases.Select(x => x.RunId).Distinct().Order().SequenceEqual(proof.Runs.Select(x => x.RunId).Order()))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        foreach (var item in proof.Cases)
        {
            var result = results.Single(x => (string?)x.Attribute("testName") == item.TestName);
            if ((string?)result.Attribute("testId") != item.TestId || (string?)result.Attribute("executionId") != item.ExecutionId)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            var definition = document.Descendants(ns + "UnitTest").Single(x => (string?)x.Attribute("id") == item.TestId);
            var method = definition.Element(ns + "TestMethod") ?? throw CurrentOwnerIsoRepairPermit.Invalid();
            RequireTrxMethod(item.TestName, (string?)method.Attribute("className"), (string?)method.Attribute("name"));
            var invocation = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoProofInvocation>(Read(item.Invocation));
            var caseScope = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairScope>(Read(item.Scope));
            var review = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairSignedClaim>(Read(item.Review));
            var authorization = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairSignedClaim>(Read(item.Authorization));
            bool component = phase.EndsWith("-component", StringComparison.Ordinal);
            string command = component ? (phase.StartsWith("native", StringComparison.Ordinal) ? "provider-current-owner-iso-proof" : "maintenance-current-owner-iso-proof") :
                (phase == "native" ? "apply-current-owner-iso-repair" : "verify-current-owner-iso-repair");
            if (invocation.Kind != (component ? "current-owner-iso-provider-invocation-v1" : "current-owner-iso-closed-invocation-v1") ||
                invocation.Command != command || invocation.RunId != item.RunId || invocation.TestName != item.TestName ||
                invocation.TestId != item.TestId || invocation.ExecutionId != item.ExecutionId || invocation.OperationId != caseScope.OperationId ||
                invocation.ScopeSha256 != item.Scope.Sha256 || invocation.ReviewSha256 != item.Review.Sha256 ||
                invocation.AuthorizationSha256 != item.Authorization.Sha256 || invocation.TestAssemblySha256 != item.TestAssembly.Sha256 ||
                invocation.ConsoleAssemblySha256 != proof.ConsoleAssemblySha256 || invocation.CoreAssemblySha256 != proof.CoreAssemblySha256 ||
                invocation.StartedAtUtc.Offset != TimeSpan.Zero || invocation.ExitedAtUtc.Offset != TimeSpan.Zero ||
                invocation.StartedAtUtc < proof.BeganAtUtc || invocation.ExitedAtUtc > proof.CompletedAtUtc || invocation.ExitedAtUtc < invocation.StartedAtUtc ||
                invocation.ExitCode != (item.TestName == NativeCases[0] || item.TestName == MaintenanceCases[2] || item.TestName == MaintenanceCases[3] ? 0 : 1) ||
                caseScope.ProofAdmission != CurrentOwnerIsoProofAdmission.DisposableNativeBootstrap ||
                !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(caseScope.Target) ||
                caseScope.SourceCatalogSha256 != scope.SourceCatalogSha256 || caseScope.ContractSha256 != scope.ContractSha256 ||
                caseScope.OperationSha256 != scope.OperationSha256 || (review.Scope != caseScope && JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(caseScope)))
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            RequireExecutedAssemblyPath(invocation.ExecutedTestAssemblyPath, item.TestAssembly.Path,
                (string?)method.Attribute("codeBase"), (string?)definition.Attribute("storage"));
            _ = Read(item.TestAssembly); // held exact executed-test image bytes.
            var run = proof.Runs.Single(x => x.RunId == item.RunId);
            var config = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairConfiguration>(Read(item.Configuration));
            var binding = MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(Read(item.RunBinding));
            var target = MigrationConsole.DecodeOwnerIso<CurrentAppOwnedRepairTargetPins>(Read(item.TargetPins));
            if (invocation.ConfigurationSha256 != item.Configuration.Sha256 || config.ProofAdmission != caseScope.ProofAdmission ||
                config.ScopePath != item.Scope.Path || config.ReviewPath != item.Review.Path || config.AuthorizationPath != item.Authorization.Path ||
                config.TargetPinsPath != item.TargetPins.Path || config.RunBindingPath != item.RunBinding.Path ||
                binding.ComputeSha256() != caseScope.RunBindingSha256 || target.DockerContainerId != run.ContainerId ||
                CurrentAppOwnedSnapshotSerialization.Sha256(target) != caseScope.TargetObservationSha256 ||
                CurrentOwnerIsoRepairLocalTarget.RequireClaim(caseScope.Target, caseScope.OperationId, caseScope.RunBindingSha256, target))
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            using (var container = JsonDocument.Parse(Read(item.ContainerOwnership)))
            using (var volume = JsonDocument.Parse(Read(item.VolumeOwnership)))
            {
                // Retain only the projected ownership metadata consumed here, never Config.Env/credential values.
                CurrentOwnerIsoRepairLocalTarget.RequireProofIdentity(container.RootElement, volume.RootElement,
                    caseScope, target, run.ContainerId, item.LoopbackPort);
                CurrentOwnerIsoRepairLocalTarget.RequireDisposableMetadata(container.RootElement, volume.RootElement,
                    caseScope.OperationId, caseScope.RunBindingSha256, invocation.StartedAtUtc);
            }
            CurrentOwnerIsoRepairPermit.ValidateClaims(review, authorization, source, owners, trust, pins, invocation.StartedAtUtc);
            var before = MigrationConsole.DecodeOwnerIso<CurrentAppOwnedDatabaseSnapshot[]>(Read(item.NativeBefore));
            var after = MigrationConsole.DecodeOwnerIso<CurrentAppOwnedDatabaseSnapshot[]>(Read(item.NativeAfter));
            if (before.Length != 26 || after.Length != 26 || before.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != 26 ||
                !before.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(caseScope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)) ||
                before.Any(x => x.Sha256 != caseScope.BeforeDatabaseSha256[x.Database]) ||
                CurrentAppOwnedSnapshotSerialization.Sha256(before) != caseScope.GlobalPreservationSha256 ||
                !after.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(before.Select(x => x.Database).Order(StringComparer.Ordinal)))
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            string predecessor = new('0', 64), authorizationHash = CurrentAppOwnedSnapshotSerialization.Sha256(authorization);
            var terminal = new Dictionary<string, CurrentOwnerIsoRepairReceipt>(StringComparer.Ordinal);
            var orderedReceipts = new List<CurrentOwnerIsoRepairReceipt>();
            foreach (var receiptArtifact in item.EffectReceipts)
            {
                var receipt = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairReceipt>(Read(receiptArtifact));
                PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(receipt, caseScope, authorizationHash, trust, pins);
                if (receipt.PreviousReceiptSha256 != predecessor || receipt.ObservedAtUtc < invocation.StartedAtUtc || receipt.ObservedAtUtc > invocation.ExitedAtUtc)
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                predecessor = receiptArtifact.Sha256; terminal[receipt.Database] = receipt; orderedReceipts.Add(receipt);
            }
            RequireAcknowledgedAfterImages(orderedReceipts);
            CurrentOwnerIsoProofFault? injected = null;
            if (item.FaultInjection is not null)
            {
                injected = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoProofFault>(Read(item.FaultInjection));
                if (item.TestName != NativeCases[5] || injected.Kind != "current-owner-iso-disposable-upload-fleet-fault-v1" ||
                    injected.OperationId != caseScope.OperationId || injected.Database != "Upload" ||
                    injected.BeforeSha256 != caseScope.BeforeDatabaseSha256["Upload"] || injected.BeforeSha256 == injected.AfterSha256 ||
                    injected.ObservedAtUtc < invocation.StartedAtUtc || injected.ObservedAtUtc > invocation.ExitedAtUtc) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
            if (item.TestName == NativeCases[5] && injected is null) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            if (injected is not null)
            {
                var original = before.Single(x => x.Database == "Upload"); var changed = after.Single(x => x.Database == "Upload");
                if (JsonSerializer.Serialize(original.Catalog) != JsonSerializer.Serialize(changed.Catalog) ||
                    JsonSerializer.Serialize(original.Sequences) != JsonSerializer.Serialize(changed.Sequences) ||
                    original.Relations.Count != changed.Relations.Count) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                int differences = 0;
                foreach (var (First, Second) in original.Relations.Zip(changed.Relations))
                {
                    if (First == Second) { continue; }
                    if (First.Schema != "public" || First.Name != "Upload" || Second.Schema != First.Schema ||
                        Second.Name != First.Name || Second.Rows != First.Rows || Second.RowSha256 == First.RowSha256)
                    { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                    differences++;
                }
                if (differences != 1) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
            foreach (var snapshot in after)
            {
                if (snapshot.Sha256 == caseScope.BeforeDatabaseSha256[snapshot.Database]) { continue; }
                if (injected is not null && snapshot.Database == injected.Database && snapshot.Sha256 == injected.AfterSha256) { continue; }
                if (!terminal.TryGetValue(snapshot.Database, out var receipt) || receipt.AfterSha256 != snapshot.Sha256 ||
                    !PostgreSqlCurrentOwnerIsoRepair.Databases().Contains(snapshot.Database, StringComparer.Ordinal)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
            var scenario = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoProofScenario>(Read(item.ScenarioEvidence));
            if (scenario.Kind != "current-owner-iso-proof-scenario-v1" || scenario.OperationId != caseScope.OperationId ||
                scenario.InvocationSha256 != item.Invocation.Sha256 || scenario.ObservedAtUtc.Offset != TimeSpan.Zero || scenario.ObservedAtUtc < invocation.StartedAtUtc ||
                scenario.ObservedAtUtc > invocation.ExitedAtUtc || scenario.RetainedSlots.Select(x => x.Artifact.Path).Distinct(StringComparer.Ordinal).Count() != scenario.RetainedSlots.Count)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            foreach (var slot in scenario.RetainedSlots)
            {
                var retained = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairReceipt>(Read(slot.Artifact));
                PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(retained, caseScope, authorizationHash, trust, pins);
                if (retained.ObservedAtUtc < invocation.StartedAtUtc || retained.ObservedAtUtc > invocation.ExitedAtUtc) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                if (!slot.Acknowledged) { RequireUnacknowledgedLink(retained, orderedReceipts, item.EffectReceipts.Select(x => x.Sha256).ToArray(), scenario.Boundary); }
                string suffix = CurrentOwnerIsoRepairConsoleEnvironment.ReceiptSuffix(retained.Classification);
                if (Path.GetFileName(slot.Artifact.Path) != $"{caseScope.OperationId:D}-{retained.Database}-{suffix}.json") { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                if (!slot.Acknowledged && (scenario.RetainedSlots.Count(x => !x.Acknowledged) != 1 || retained.Database != "Country" ||
                    !((scenario.Boundary == "prepared-publication-before-ack" && retained.Classification == CurrentAppOwnedCommitClassification.Prepared) ||
                      (scenario.Boundary == "terminal-publication" && retained.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback))))
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
            if (!scenario.RetainedSlots.Where(x => x.Acknowledged).Select(x => x.Artifact.Sha256).SequenceEqual(item.EffectReceipts.Select(x => x.Sha256)))
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            RequireCaseEffects(item.TestName, scenario, orderedReceipts, caseScope.BeforeDatabaseSha256,
                after.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal));
        }
        foreach (var run in proof.Runs)
        {
            if (run.RunId == Guid.Empty || run.ContainerId.Length != 64 || !run.ContainerId.All(char.IsAsciiHexDigit) ||
                !proof.Cases.Where(x => x.RunId == run.RunId).Select(x => MigrationConsole.DecodeOwnerIso<CurrentAppOwnedRepairTargetPins>(Read(x.TargetPins)).DockerVolume)
                    .All(x => x == run.Name) || !run.Name.StartsWith("legacy-delta-proof-", StringComparison.Ordinal)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            using var attempt = JsonDocument.Parse(Read(run.Attempt)); using var observed = JsonDocument.Parse(Read(run.Observed));
            using var disposed = JsonDocument.Parse(Read(run.Disposed));
            foreach (var item in new[] { attempt.RootElement, observed.RootElement, disposed.RootElement })
            {
                if (item.GetProperty("run").GetGuid() != run.RunId || item.GetProperty("name").GetString() != run.Name ||
                    item.GetProperty("purpose").GetString() != "current-owner-iso-proof" || item.GetProperty("persistent").GetBoolean())
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
            if (observed.RootElement.GetProperty("containerId").GetString() != run.ContainerId ||
                disposed.RootElement.GetProperty("containerId").GetString() != run.ContainerId ||
                !disposed.RootElement.GetProperty("removed").GetBoolean() || !disposed.RootElement.GetProperty("disposed").GetBoolean() ||
                disposed.RootElement.GetProperty("cleanupFailed").GetBoolean() ||
                !disposed.RootElement.GetProperty("proxyAbsent").GetBoolean()) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            string[] expectedVolumes = [..proof.Cases.Where(x=>x.RunId==run.RunId).Select(x=>
                MigrationConsole.DecodeOwnerIso<CurrentAppOwnedRepairTargetPins>(Read(x.TargetPins)).DockerVolume
                    ?? throw CurrentOwnerIsoRepairPermit.Invalid()).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
            string[] removedVolumes = [.. disposed.RootElement.GetProperty("removedVolumes").EnumerateArray().Select(x => x.GetString()!).Order(StringComparer.Ordinal)];
            if (!removedVolumes.SequenceEqual(expectedVolumes, StringComparer.Ordinal)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            DateTimeOffset began = attempt.RootElement.GetProperty("began").GetDateTimeOffset(), expires = attempt.RootElement.GetProperty("expires").GetDateTimeOffset();
            DateTimeOffset completed = disposed.RootElement.GetProperty("completedAtUtc").GetDateTimeOffset();
            if (began.Offset != TimeSpan.Zero || expires.Offset != TimeSpan.Zero || completed.Offset != TimeSpan.Zero ||
                began < proof.BeganAtUtc || expires - began != TimeSpan.FromMinutes(8) || completed < began || completed > proof.CompletedAtUtc ||
                observed.RootElement.GetProperty("began").GetDateTimeOffset() != began || observed.RootElement.GetProperty("expires").GetDateTimeOffset() != expires)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            var runCases = proof.Cases.Where(x => x.RunId == run.RunId).ToArray();
            var exits = runCases.Select(x => MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoProofInvocation>(Read(x.Invocation))).ToArray();
            if (exits.Any(x => x.StartedAtUtc < began || x.ExitedAtUtc > expires) || completed > expires) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            var absence = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoProofAbsence>(Read(run.AbsenceInventory));
            RequireAbsence(absence, run.RunId, run.ContainerId, run.Name, expectedVolumes, runCases.Select(x => x.LoopbackPort).ToArray(),
                exits.Max(x => x.ExitedAtUtc), completed);
        }
        files.Require();
        byte[] Read(CurrentOwnerIsoProofArtifact value)
        {
            byte[] held = files.Read(value.Path, maximumBytes: 8_000_000);
            return CurrentAppOwnedRepairPermit.Hash(held) != value.Sha256 ? throw CurrentOwnerIsoRepairPermit.Invalid() : held;
        }
    }
}

internal static class CurrentOwnerIsoCapacity
{
    private const ulong GiB = 1024UL * 1024 * 1024;
    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        internal uint Length, Load;
        internal ulong TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile, TotalVirtual, AvailableVirtual, AvailableExtendedVirtual;
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool ObserveMemory(ref MemoryStatus value);
    internal static void Require(bool admission)
    {
        if (!OperatingSystem.IsWindows()) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        nint library = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        try
        {
            var observer = Marshal.GetDelegateForFunctionPointer<ObserveMemory>(NativeLibrary.GetExport(library, "GlobalMemoryStatusEx"));
            var memory = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
            if (!observer(ref memory)) { throw new MigrationExecutionException("host_memory_observation_failed", "Host memory observation failed."); }
            using var process = Process.GetCurrentProcess(); process.Refresh();
            RequireValues(memory.AvailablePhysical, (ulong)process.WorkingSet64, admission);
        }
        finally { NativeLibrary.Free(library); }
    }
    internal static void RequireValues(ulong available, ulong ownedRss, bool admission)
    {
        if (available < (admission ? 3 * GiB : GiB))
        {
            throw new MigrationExecutionException(admission ?
            "host_free_memory_admission_below_3GiB" : "host_free_memory_floor_below_1GiB", "Host memory admission failed.");
        }
        if (ownedRss > 5 * GiB) { throw new MigrationExecutionException("owned_rss_above_5GiB", "Owned process memory admission failed."); }
    }
}
