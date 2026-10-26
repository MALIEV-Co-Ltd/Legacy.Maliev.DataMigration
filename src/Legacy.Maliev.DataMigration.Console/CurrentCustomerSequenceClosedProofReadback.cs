using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentCustomerSequenceProofArtifact(string Path, string Sha256);
internal sealed record CurrentCustomerSequenceProofRun(Guid RunId, string Name, string ContainerId,
    CurrentCustomerSequenceProofArtifact Attempt, CurrentCustomerSequenceProofArtifact Observed, CurrentCustomerSequenceProofArtifact Disposed,
    CurrentCustomerSequenceProofArtifact? AbsenceInventory = null);
internal sealed record CurrentCustomerSequenceProofAbsence(string Kind, Guid RunId, DateTimeOffset ObservedAtUtc,
    IReadOnlyList<string> AllContainerIds, IReadOnlyList<string> AllContainerNames, IReadOnlyList<string> AllVolumeNames,
    IReadOnlyList<int> ListeningLoopbackPorts, bool ContainerInventorySucceeded, bool VolumeInventorySucceeded, bool ListenerInventorySucceeded);
internal sealed record CurrentCustomerSequenceProofSlot(CurrentCustomerSequenceProofArtifact Artifact, bool Acknowledged);
internal sealed record CurrentCustomerSequenceProofScenario(string Kind, Guid OperationId, string InvocationSha256, string Boundary,
    string? RejectionCode, DateTimeOffset ObservedAtUtc, IReadOnlyList<CurrentCustomerSequenceProofSlot> RetainedSlots,
    IReadOnlyList<string> OrdinaryRejectedDatabases, bool InstalledSemanticPolicyAccepted, bool CommitAcknowledged, bool ReplayRejected);
internal sealed record CurrentCustomerSequenceProofInvocation(string Kind, string Command, Guid OperationId, Guid RunId,
    string TestName, string TestId, string ExecutionId, string ScopeSha256, string ReviewSha256, string AuthorizationSha256,
    string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256, string ConfigurationSha256,
    DateTimeOffset StartedAtUtc, DateTimeOffset ExitedAtUtc, int ExitCode, string ExecutedTestAssemblyPath);
internal sealed record CurrentCustomerSequenceProofCase(string CaseId, string TestName, string TestId, string ExecutionId, Guid RunId,
    CurrentCustomerSequenceProofArtifact Invocation, CurrentCustomerSequenceProofArtifact Scope, CurrentCustomerSequenceProofArtifact Review,
    CurrentCustomerSequenceProofArtifact Authorization, CurrentCustomerSequenceProofArtifact TestAssembly,
    CurrentCustomerSequenceProofArtifact NativeBefore, CurrentCustomerSequenceProofArtifact NativeAfter,
    CurrentCustomerSequenceProofArtifact CustomerBefore, CurrentCustomerSequenceProofArtifact CustomerAfter,
    IReadOnlyList<CurrentCustomerSequenceProofArtifact> EffectReceipts,
    CurrentCustomerSequenceProofArtifact Configuration, CurrentCustomerSequenceProofArtifact RunBinding, CurrentCustomerSequenceProofArtifact TargetPins,
    CurrentCustomerSequenceProofArtifact ContainerOwnership, CurrentCustomerSequenceProofArtifact VolumeOwnership,
    int LoopbackPort, CurrentCustomerSequenceProofArtifact ScenarioEvidence, CurrentCustomerSequenceProofArtifact InstalledPolicy,
    CurrentCustomerSequenceProofArtifact? CustomerRolledBack = null);
internal sealed record CurrentCustomerSequenceClosedProof(string Kind, string SourceCommitSha, string SourceSchemaPlanSha256,
    string CatalogReportSha256, string DefinitionSha256, string IntendedNativeBeforeStateSha256, string OperationSha256,
    string MaintenanceValidatorSha256, string IntendedTargetObservationSha256, string IntendedRunBindingSha256,
    string ConsoleAssemblySha256, string CoreAssemblySha256, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc,
    CurrentCustomerSequenceProofArtifact Trx, IReadOnlyList<CurrentCustomerSequenceProofRun> Runs,
    IReadOnlyList<CurrentCustomerSequenceProofCase> Cases, string KeyId, string? Signature);

internal sealed record CurrentCustomerSequenceProofPolicy(string SystemIdentifierSha256, DateTimeOffset Postmaster, DateTimeOffset ConfigLoaded,
    string Role, DateTimeOffset RoleExpiresAtUtc, string RoleComment, string HbaPath, CurrentCustomerSequenceProofArtifact HbaFile,
    CurrentCustomerSequenceProofArtifact RawHbaRules, bool Superuser, bool Login, bool CreateRole, bool CreateDatabase, bool Replication, bool BypassRls,
    long Memberships, bool Scram, long DefaultAcls, long OtherClients, long PreparedTransactions, long EventTriggers, bool Primary, DateTimeOffset ObservedAtUtc);
/// <summary>Held signed proof readback only. No artifacts or execution evidence are manufactured here.</summary>
internal static class CurrentCustomerSequenceClosedProofReader
{
    private static readonly CurrentAppOwnedCommitClassification[] PreparedCommitted = [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback];
    private static readonly CurrentAppOwnedCommitClassification[] PreparedUncertain = [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.Uncertain];
    private static readonly CurrentAppOwnedCommitClassification[] PreparedCommittedUncertain = [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback, CurrentAppOwnedCommitClassification.Uncertain];
    private static readonly string[] ProviderCases = ["complete", "prepared-publication", "commit-ack-lost", "terminal-publication", "final-fleet", "replay"];
    private static readonly string[] MaintenanceCases = ["unsafe-host", "local-trust", "ordinary-all26", "exclusive-policy"];
    private static readonly string[] DefinitionCases = ["start-1-false-1","start-1-false-9","start-69831-true-1","start-69831-true-9",
        "start-2000000000-true-1","start-2000000000-true-9","start-2000000000-false-1","start-2000000000-false-9",
        "reject-increment","reject-cache","reject-start","reject-generated","reject-owner"];
    internal static string[] Cases(string phase)
    {
        return phase switch
        {
            "definition" => DefinitionCases.ToArray(),
            "native" or "native-component" => ProviderCases.ToArray(),
            "maintenance" or "maintenance-component" => MaintenanceCases.ToArray(),
            _ => throw Invalid(),
        };
    }

    // Definition proof excludes OperationSha256 because that digest itself binds this artifact's SHA.
    internal static byte[] Payload(CurrentCustomerSequenceClosedProof proof, string phase)
    {
        return [..Encoding.UTF8.GetBytes("Legacy.Maliev.CurrentCustomerSequence.ClosedProof."+phase+".v1\0"),
         ..JsonSerializer.SerializeToUtf8Bytes(proof with {Signature=null})];
    }

    internal static void RequireHeader(CurrentCustomerSequenceClosedProof proof, string phase, CurrentCustomerSequenceRepairScope scope,
        IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins, DateTimeOffset now,
        string consoleAssemblySha256, string coreAssemblySha256)
    {
        string kind = phase switch
        {
            "definition" => "current-customer-sequence-native-definition-proof-v1",
            "native" => "current-customer-sequence-native-console-proof-v1",
            "native-component" => "current-customer-sequence-native-provider-proof-v1",
            "maintenance" => "current-customer-sequence-maintenance-console-proof-v1",
            "maintenance-component" => "current-customer-sequence-maintenance-provider-proof-v1",
            _ => throw Invalid(),
        };
        CurrentCustomerSequenceRepairPermit.RequireProofAdmission(scope);
        if ((phase != "definition" && phase.EndsWith("-component", StringComparison.Ordinal) != (scope.ProofAdmission == CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap)) ||
            proof.Kind != kind || proof.SourceCommitSha != scope.SourceCommitSha || proof.SourceSchemaPlanSha256 != scope.SourceSchemaPlanSha256 ||
            proof.CatalogReportSha256 != scope.CatalogReportSha256 || proof.DefinitionSha256 != scope.DefinitionSha256 ||
            proof.IntendedNativeBeforeStateSha256 != scope.NativeBeforeStateSha256 ||
            proof.OperationSha256 != (phase == "definition" ? "definition-subject-excludes-proof-hash-v1" : scope.OperationSha256) ||
            proof.MaintenanceValidatorSha256 != scope.MaintenanceValidatorSha256 ||
            proof.IntendedTargetObservationSha256 != scope.TargetObservationSha256 || proof.IntendedRunBindingSha256 != scope.RunBindingSha256 ||
            proof.ConsoleAssemblySha256 != consoleAssemblySha256 || proof.CoreAssemblySha256 != coreAssemblySha256 ||
            proof.KeyId != pins.ReceiptKeyId || !trust.TryGetPublicKeyFingerprintSha256(proof.KeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint ||
            now.Offset != TimeSpan.Zero || proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > now || now - proof.BeganAtUtc > TimeSpan.FromHours(12) ||
            proof.ExpiresAtUtc <= now || proof.ExpiresAtUtc - proof.BeganAtUtc > TimeSpan.FromHours(12) ||
            proof.Runs.Count == 0 || proof.Runs.Any(x => x.RunId == Guid.Empty) || proof.Runs.Select(x => x.RunId).Distinct().Count() != proof.Runs.Count ||
            string.IsNullOrWhiteSpace(proof.Signature)) { throw Invalid(); }
        try { if (!trust.Verify(proof.KeyId, Payload(proof, phase), Convert.FromBase64String(proof.Signature))) { throw Invalid(); } }
        catch (FormatException) { throw Invalid(); }
    }
    internal static void Require(CurrentAppOwnedRepairCustody files, CurrentAppOwnedRepairArtifact artifact, string expected, string phase,
        CurrentCustomerSequenceRepairScope scope, IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins, FreshSchemaPlan source)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 1_000_000);
        if (artifact.Sha256 != expected || CurrentCustomerSequenceRepairPermit.Hash(bytes) != expected) { throw Invalid(); }
        if (phase == "definition")
        {
            CustomerDefinitionPrecursorReader.Require(files, MigrationConsole.DecodeCustomerSequence<CustomerDefinitionProof>(bytes),
                new CustomerDefinitionSubject(scope.SourceObservation, scope.OwnerObservation, scope.SourceSchemaPlanSha256,
                    scope.DefinitionSha256, scope.NativeBeforeStateSha256, scope.TargetObservationSha256, scope.RunBindingSha256,
                    AssemblyHash(typeof(MigrationConsole).Assembly.Location), AssemblyHash(typeof(CurrentCustomerSequenceRepairPermit).Assembly.Location)),
                trust, pins.ReceiptKeyId, pins.ReceiptFingerprint, DateTimeOffset.UtcNow);
            return;
        }
        var proof = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceClosedProof>(bytes);
        RequireHeader(proof, phase, scope, trust, pins, DateTimeOffset.UtcNow,
            AssemblyHash(typeof(MigrationConsole).Assembly.Location), AssemblyHash(typeof(CurrentCustomerSequenceRepairPermit).Assembly.Location));
        string[] required = Cases(phase);
        if (proof.Cases.Count != required.Length || !proof.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(required.Order(StringComparer.Ordinal)) ||
            proof.Cases.Select(x => x.ExecutionId).Distinct(StringComparer.Ordinal).Count() != required.Length ||
            proof.Cases.Select(x => x.TestId).Distinct(StringComparer.Ordinal).Count() != required.Length ||
            !proof.Cases.Select(x => x.RunId).Distinct().Order().SequenceEqual(proof.Runs.Select(x => x.RunId).Order())) { throw Invalid(); }
        using var stream = new MemoryStream(Read(proof.Trx), writable: false);
        using var xml = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var document = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var counters = document.Descendants(ns + "Counters").Single(); var results = document.Descendants(ns + "UnitTestResult").ToArray();
        if ((string?)counters.Attribute("total") != required.Length.ToString(CultureInfo.InvariantCulture) ||
            (string?)counters.Attribute("passed") != (string?)counters.Attribute("total") || (string?)counters.Attribute("failed") != "0" ||
            results.Length != required.Length || results.Any(x => (string?)x.Attribute("outcome") != "Passed")) { throw Invalid(); }
        foreach (var item in proof.Cases)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false);
            var result = results.Single(x => (string?)x.Attribute("testId") == item.TestId && (string?)x.Attribute("executionId") == item.ExecutionId);
            if ((string?)result.Attribute("testName") != item.TestName) { throw Invalid(); }
            var method = document.Descendants(ns + "UnitTest").Single(x => (string?)x.Attribute("id") == item.TestId).Element(ns + "TestMethod") ?? throw Invalid();
            string expectedMethod = phase == "definition" ? (item.CaseId.StartsWith("start-", StringComparison.Ordinal) ?
                "Start_definition_replacement_preserves_allocation_and_exact_other_facts_with_rollback_and_independent_readback" : "Unexpected_preimage_fails_before_candidate") :
                "Customer_sequence_" + item.CaseId.Replace('-', '_');
            string expectedClass = phase == "definition" ? "Legacy.Maliev.DataMigration.Tests.CurrentCustomerSequenceNativeFeasibilityTests" :
                "Legacy.Maliev.DataMigration.Tests.CurrentCustomerSequenceGuardedNativeExecutionTests";
            if ((string?)method.Attribute("name") != expectedMethod || (string?)method.Attribute("className") != expectedClass) { throw Invalid(); }
            var invocation = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceProofInvocation>(Read(item.Invocation));
            var caseScope = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceRepairScope>(Read(item.Scope));
            var review = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceRepairSignedClaim>(Read(item.Review));
            var authorization = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceRepairSignedClaim>(Read(item.Authorization));
            bool component = phase.EndsWith("-component", StringComparison.Ordinal) || phase == "definition";
            string command = phase == "definition" ? "definition-current-customer-sequence-proof" : component ?
                (phase.StartsWith("native", StringComparison.Ordinal) ? "provider-current-customer-sequence-proof" : "maintenance-current-customer-sequence-proof") :
                (phase == "native" ? "apply-current-customer-sequence-repair" : "verify-current-customer-sequence-repair");
            if (invocation.Kind != (component ? "current-customer-sequence-provider-invocation-v1" : "current-customer-sequence-closed-invocation-v1") ||
                invocation.Command != command || invocation.RunId != item.RunId || invocation.TestName != item.TestName || invocation.TestId != item.TestId ||
                invocation.ExecutionId != item.ExecutionId || invocation.OperationId != caseScope.OperationId || invocation.ScopeSha256 != item.Scope.Sha256 ||
                invocation.ReviewSha256 != item.Review.Sha256 || invocation.AuthorizationSha256 != item.Authorization.Sha256 ||
                invocation.TestAssemblySha256 != item.TestAssembly.Sha256 || invocation.ConsoleAssemblySha256 != proof.ConsoleAssemblySha256 ||
                invocation.CoreAssemblySha256 != proof.CoreAssemblySha256 || invocation.StartedAtUtc.Offset != TimeSpan.Zero || invocation.ExitedAtUtc.Offset != TimeSpan.Zero ||
                invocation.StartedAtUtc < proof.BeganAtUtc || invocation.ExitedAtUtc > proof.CompletedAtUtc || invocation.ExitedAtUtc < invocation.StartedAtUtc ||
                invocation.ExitCode != ExpectedExitCode(phase, item.CaseId) || caseScope.ProofAdmission != CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap ||
                !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(caseScope.Target) || caseScope.SourceSchemaPlanSha256 != scope.SourceSchemaPlanSha256 ||
                caseScope.CatalogReportSha256 != scope.CatalogReportSha256 || caseScope.DefinitionSha256 != scope.DefinitionSha256 ||
                JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(caseScope)) { throw Invalid(); }
            RequireExecutedAssemblyPath(invocation.ExecutedTestAssemblyPath, item.TestAssembly.Path,
                (string?)method.Attribute("codeBase"), (string?)method.Parent!.Attribute("storage"));
            _ = Read(item.TestAssembly);
            CurrentCustomerSequenceRepairPermit.ValidateClaims(review, authorization, source, trust, pins, invocation.StartedAtUtc);
            var config = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceRepairConfiguration>(Read(item.Configuration));
            var binding = MigrationConsole.DecodeCustomerSequence<LocalExecutionBinding>(Read(item.RunBinding));
            var target = MigrationConsole.DecodeCustomerSequence<CurrentAppOwnedRepairTargetPins>(Read(item.TargetPins));
            var run = proof.Runs.Single(x => x.RunId == item.RunId);
            if (invocation.ConfigurationSha256 != item.Configuration.Sha256 || config.ProofAdmission != caseScope.ProofAdmission ||
                config.ScopePath != item.Scope.Path || config.ReviewPath != item.Review.Path || config.AuthorizationPath != item.Authorization.Path ||
                config.TargetPinsPath != item.TargetPins.Path || config.RunBindingPath != item.RunBinding.Path ||
                binding.ComputeSha256() != caseScope.RunBindingSha256 || target.DockerContainerId != run.ContainerId ||
                CurrentAppOwnedSnapshotSerialization.Sha256(target) != caseScope.TargetObservationSha256 ||
                CurrentCustomerSequenceRepairLocalTarget.RequireClaim(caseScope.Target, caseScope.OperationId, caseScope.RunBindingSha256, target)) { throw Invalid(); }
            using (var container = JsonDocument.Parse(Read(item.ContainerOwnership)))
            using (var volume = JsonDocument.Parse(Read(item.VolumeOwnership)))
            {
                CurrentCustomerSequenceRepairLocalTarget.RequireProofIdentity(container.RootElement, volume.RootElement, caseScope, target, run.ContainerId, item.LoopbackPort);
                CurrentCustomerSequenceRepairLocalTarget.RequireDisposableMetadata(container.RootElement, volume.RootElement,
                    caseScope.OperationId, caseScope.RunBindingSha256, invocation.StartedAtUtc);
            }
            var before = MigrationConsole.DecodeCustomerSequence<CurrentAppOwnedDatabaseSnapshot[]>(Read(item.NativeBefore));
            var after = MigrationConsole.DecodeCustomerSequence<CurrentAppOwnedDatabaseSnapshot[]>(Read(item.NativeAfter));
            if (before.Length != 26 || after.Length != 26 || before.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != 26 ||
                !before.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(caseScope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)) ||
                before.Any(x => x.Sha256 != caseScope.BeforeDatabaseSha256[x.Database]) ||
                CurrentCustomerSequenceRepairPermit.FleetSha256(before.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal)) != caseScope.GlobalPreservationSha256 ||
                !after.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(before.Select(x => x.Database).Order(StringComparer.Ordinal))) { throw Invalid(); }
            var customerBefore = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceObservation>(Read(item.CustomerBefore));
            var customerAfter = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceObservation>(Read(item.CustomerAfter));
            if (customerBefore.Snapshot.Sha256 != before.Single(x => x.Database == "Customer").Sha256 ||
                customerAfter.Snapshot.Sha256 != after.Single(x => x.Database == "Customer").Sha256 ||
                ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(customerBefore.State) != caseScope.NativeBeforeStateSha256) { throw Invalid(); }
            string predecessor = new('0', 64), authorizationHash = CurrentAppOwnedSnapshotSerialization.Sha256(authorization);
            var receipts = new List<CurrentCustomerSequenceRepairReceipt>();
            foreach (var value in item.EffectReceipts)
            {
                var receipt = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceRepairReceipt>(Read(value));
                PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(receipt, caseScope, authorizationHash, trust, pins, predecessor, invocation.ExitedAtUtc);
                if (receipt.ObservedAtUtc < invocation.StartedAtUtc) { throw Invalid(); }
                if (receipts.Count > 0 && receipt.AfterSha256 != receipts[0].AfterSha256) { throw Invalid(); }
                predecessor = value.Sha256; receipts.Add(receipt);
            }
            var scenario = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceProofScenario>(Read(item.ScenarioEvidence));
            if (scenario.Kind != "current-customer-sequence-proof-scenario-v1" || scenario.OperationId != caseScope.OperationId ||
                scenario.InvocationSha256 != item.Invocation.Sha256 || scenario.ObservedAtUtc < invocation.StartedAtUtc || scenario.ObservedAtUtc > invocation.ExitedAtUtc ||
                scenario.RetainedSlots.Select(x => x.Artifact.Path).Distinct(StringComparer.Ordinal).Count() != scenario.RetainedSlots.Count ||
                !scenario.RetainedSlots.Where(x => x.Acknowledged).Select(x => x.Artifact.Sha256).SequenceEqual(item.EffectReceipts.Select(x => x.Sha256))) { throw Invalid(); }
            foreach (var slot in scenario.RetainedSlots)
            {
                var retained = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceRepairReceipt>(Read(slot.Artifact));
                PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(retained, caseScope, authorizationHash, trust, pins, retained.PreviousReceiptSha256, invocation.ExitedAtUtc);
                RequireReceiptChronology(retained.ObservedAtUtc, invocation.StartedAtUtc, invocation.ExitedAtUtc);
                if (Path.GetFileName(slot.Artifact.Path) != $"{caseScope.OperationId:D}-Customer-{CurrentCustomerSequenceRepairConsoleEnvironment.ReceiptSuffix(retained.Classification)}.json") { throw Invalid(); }
                if (!slot.Acknowledged)
                {
                    bool sibling = item.CaseId == "prepared-publication" && retained.Classification == CurrentAppOwnedCommitClassification.Prepared &&
                        retained.PreviousReceiptSha256 == new string('0', 64) && receipts.Count == 1 && retained.AfterSha256 == receipts[0].AfterSha256;
                    var preparedReceipt = receipts.FirstOrDefault(x => x.Classification == CurrentAppOwnedCommitClassification.Prepared);
                    bool lostTerminal = item.CaseId == "terminal-publication" && retained.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback &&
                        preparedReceipt is not null && retained.PreviousReceiptSha256 == CurrentAppOwnedSnapshotSerialization.Sha256(preparedReceipt) &&
                        retained.AfterSha256 == preparedReceipt.AfterSha256;
                    if (!sibling && !lostTerminal) { throw Invalid(); }
                }
            }
            if (scenario.RetainedSlots.Count(x => !x.Acknowledged) > 1) { throw Invalid(); }
            var policy = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceProofPolicy>(Read(item.InstalledPolicy));
            if (policy.ObservedAtUtc < invocation.StartedAtUtc || policy.ObservedAtUtc > invocation.ExitedAtUtc) { throw Invalid(); }
            RequirePolicyEvidence(policy, caseScope, scenario, Read);
            if (phase == "definition")
            {
                RequireDefinitionCase(item.CaseId, customerBefore, customerAfter, scenario, receipts);
                if (item.CaseId.StartsWith("start-", StringComparison.Ordinal))
                {
                    var rolled = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceObservation>(Read(item.CustomerRolledBack ?? throw Invalid()));
                    if (rolled.State != customerBefore.State || rolled.Snapshot.Sha256 != customerBefore.Snapshot.Sha256) { throw Invalid(); }
                }
                else if (item.CustomerRolledBack is not null) { throw Invalid(); }
            }
            else
            {
                if (!phase.StartsWith("maintenance", StringComparison.Ordinal))
                {
                    CurrentCustomerSequenceRepairPermit.RequireNativePreimage(customerBefore, caseScope, invocation.StartedAtUtc);
                    if (customerAfter.Snapshot.Sha256 != customerBefore.Snapshot.Sha256)
                    { ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(customerBefore, customerAfter, customerBefore.State.Owner); }
                }
                RequireCaseEffects(item.CaseId, scenario, receipts, before.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal),
                    after.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal));
            }
            if (before.Where(x => x.Database != "Customer").Any(x => x.Sha256 != after.Single(y => y.Database == x.Database).Sha256)) { throw Invalid(); }
        }
        foreach (var run in proof.Runs)
        {
            string[] volumes = proof.Cases.Where(x => x.RunId == run.RunId).Select(x => MigrationConsole.DecodeCustomerSequence<CurrentAppOwnedRepairTargetPins>(Read(x.TargetPins)).DockerVolume
                ?? throw Invalid()).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            if (run.ContainerId.Length != 64 || !run.ContainerId.All(char.IsAsciiHexDigitLower) || volumes.Length != 1 ||
                run.Name != volumes[0] || !run.Name.StartsWith("legacy-delta-proof-", StringComparison.Ordinal)) { throw Invalid(); }
            using var attempt = JsonDocument.Parse(Read(run.Attempt)); using var observed = JsonDocument.Parse(Read(run.Observed)); using var disposed = JsonDocument.Parse(Read(run.Disposed));
            foreach (var value in new[] { attempt.RootElement, observed.RootElement, disposed.RootElement })
            {
                if (value.GetProperty("run").GetGuid() != run.RunId || value.GetProperty("name").GetString() != run.Name ||
                value.GetProperty("purpose").GetString() != "current-customer-sequence-proof" || value.GetProperty("persistent").GetBoolean()) { throw Invalid(); }
            }
            if (observed.RootElement.GetProperty("containerId").GetString() != run.ContainerId || disposed.RootElement.GetProperty("containerId").GetString() != run.ContainerId ||
                !disposed.RootElement.GetProperty("removed").GetBoolean() || !disposed.RootElement.GetProperty("disposed").GetBoolean() ||
                disposed.RootElement.GetProperty("cleanupFailed").GetBoolean() || !disposed.RootElement.GetProperty("proxyAbsent").GetBoolean() ||
                !disposed.RootElement.GetProperty("removedVolumes").EnumerateArray().Select(x => x.GetString()).Order(StringComparer.Ordinal).SequenceEqual(volumes)) { throw Invalid(); }
            DateTimeOffset began = attempt.RootElement.GetProperty("began").GetDateTimeOffset(), expires = attempt.RootElement.GetProperty("expires").GetDateTimeOffset(),
                completed = disposed.RootElement.GetProperty("completedAtUtc").GetDateTimeOffset();
            if (began.Offset != TimeSpan.Zero || expires.Offset != TimeSpan.Zero || completed.Offset != TimeSpan.Zero ||
                began < proof.BeganAtUtc || expires - began != TimeSpan.FromMinutes(8) || completed < began || completed > proof.CompletedAtUtc ||
                observed.RootElement.GetProperty("began").GetDateTimeOffset() != began || observed.RootElement.GetProperty("expires").GetDateTimeOffset() != expires ||
                completed > expires.AddMinutes(1)) { throw Invalid(); }
            DateTimeOffset lastInvocationExit = began;
            foreach (var item in proof.Cases.Where(x => x.RunId == run.RunId))
            {
                var invocation = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceProofInvocation>(Read(item.Invocation));
                if (invocation.StartedAtUtc < began || invocation.ExitedAtUtc > expires) { throw Invalid(); }
                if (invocation.ExitedAtUtc > lastInvocationExit) { lastInvocationExit = invocation.ExitedAtUtc; }
            }
            var absence = MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceProofAbsence>(Read(run.AbsenceInventory ?? throw Invalid()));
            RequireAbsenceChronology(absence.ObservedAtUtc, lastInvocationExit, disposed.RootElement.GetProperty("removedAtUtc").GetDateTimeOffset(),
                began, expires, completed, proof.CompletedAtUtc);
            if (absence.Kind != "current-customer-sequence-cleanup-absence-v1" || absence.RunId != run.RunId || absence.ObservedAtUtc.Offset != TimeSpan.Zero ||
                absence.ObservedAtUtc < began || absence.ObservedAtUtc > completed || !absence.ContainerInventorySucceeded || !absence.VolumeInventorySucceeded || !absence.ListenerInventorySucceeded ||
                absence.AllContainerIds.Contains(run.ContainerId, StringComparer.Ordinal) || absence.AllContainerNames.Contains(run.Name, StringComparer.Ordinal) || absence.AllContainerNames.Contains("/" + run.Name, StringComparer.Ordinal) ||
                volumes.Any(x => absence.AllVolumeNames.Contains(x, StringComparer.Ordinal)) ||
                proof.Cases.Where(x => x.RunId == run.RunId).Any(x => absence.ListeningLoopbackPorts.Contains(x.LoopbackPort))) { throw Invalid(); }
        }
        files.Require(); CurrentCustomerSequenceCapacity.Require(admission: false);
        byte[] Read(CurrentCustomerSequenceProofArtifact value)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false);
            byte[] held = files.Read(value.Path, maximumBytes: 8_000_000);
            return CurrentCustomerSequenceRepairPermit.Hash(held) != value.Sha256 ? throw Invalid() : held;
        }
    }
    internal static void RequireReceiptChronology(DateTimeOffset observed, DateTimeOffset started, DateTimeOffset exited)
    {
        if (observed.Offset != TimeSpan.Zero || started.Offset != TimeSpan.Zero || exited.Offset != TimeSpan.Zero ||
            exited < started || observed < started || observed > exited) { throw Invalid(); }
    }
    internal static void RequireAbsenceChronology(DateTimeOffset observed, DateTimeOffset lastInvocationExit,
        DateTimeOffset removedAtUtc, DateTimeOffset began, DateTimeOffset expires, DateTimeOffset cleanupCompleted, DateTimeOffset proofCompleted)
    {
        if (observed.Offset != TimeSpan.Zero || lastInvocationExit.Offset != TimeSpan.Zero || removedAtUtc.Offset != TimeSpan.Zero ||
            began.Offset != TimeSpan.Zero || expires.Offset != TimeSpan.Zero || cleanupCompleted.Offset != TimeSpan.Zero || proofCompleted.Offset != TimeSpan.Zero ||
            lastInvocationExit < began || removedAtUtc < lastInvocationExit || observed < removedAtUtc || observed > expires ||
            expires <= began || cleanupCompleted < observed || cleanupCompleted > proofCompleted) { throw Invalid(); }
    }
    internal static void RequireExecutedAssemblyPath(string executed, string held, string? codeBase, string? storage)
    {
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.IsNullOrWhiteSpace(executed) || !Path.IsPathFullyQualified(executed) ||
            !string.Equals(executed, Path.GetFullPath(executed), comparison)) { throw Invalid(); }
        foreach (string? candidate in new[] { held, codeBase, storage })
        {
            if (string.IsNullOrWhiteSpace(candidate) || !Path.IsPathFullyQualified(candidate) ||
                !string.Equals(candidate, Path.GetFullPath(candidate), comparison) || !string.Equals(candidate, executed, comparison)) { throw Invalid(); }
        }
    }
    private static int ExpectedExitCode(string phase, string id)
    {
        return phase == "definition" || id is "complete" or "ordinary-all26" or "exclusive-policy" ? 0 : 1;
    }

    internal static void RequireCaseEffects(string id, CurrentCustomerSequenceProofScenario scenario,
        IReadOnlyList<CurrentCustomerSequenceRepairReceipt> receipts, IReadOnlyDictionary<string, string> before, IReadOnlyDictionary<string, string> after)
    {
        if (!before.Keys.Order(StringComparer.Ordinal).SequenceEqual(after.Keys.Order(StringComparer.Ordinal)) || !before.ContainsKey("Customer")) { throw Invalid(); }
        bool unchanged = before.All(x => after[x.Key] == x.Value), outside = before.Where(x => x.Key != "Customer").All(x => after[x.Key] == x.Value);
        var classifications = receipts.Select(x => x.Classification).ToArray();
        var prepared = receipts.FirstOrDefault(x => x.Classification == CurrentAppOwnedCommitClassification.Prepared);
        bool customerAfter = prepared?.AfterSha256 is not null && after["Customer"] == prepared.AfterSha256 && after["Customer"] != before["Customer"];
        bool Failure(string boundary)
        {
            return scenario.Boundary == boundary && !string.IsNullOrWhiteSpace(scenario.RejectionCode);
        }

        bool valid = id switch
        {
            "complete" or "replay" => outside && customerAfter && scenario.CommitAcknowledged && scenario.Boundary == (id == "complete" ? "complete" : "replay-blocked") &&
                scenario.ReplayRejected == (id == "replay") && (id == "replay" ? !string.IsNullOrWhiteSpace(scenario.RejectionCode) : scenario.RejectionCode is null) && classifications.SequenceEqual(PreparedCommitted),
            "prepared-publication" => Failure("prepared-publication-before-ack") && !scenario.CommitAcknowledged && unchanged &&
                classifications.Length == 1 && (classifications[0] is CurrentAppOwnedCommitClassification.FailedBeforeCommit or CurrentAppOwnedCommitClassification.RolledBackBeforeCommit) && receipts[0].AfterSha256 is not null,
            "commit-ack-lost" => Failure("commit-ack-lost") && !scenario.CommitAcknowledged && outside && customerAfter &&
                classifications.SequenceEqual(PreparedUncertain),
            "terminal-publication" => Failure("terminal-publication") && scenario.CommitAcknowledged && outside && customerAfter &&
                (classifications.SequenceEqual(PreparedUncertain) ||
                 classifications.SequenceEqual(PreparedCommittedUncertain)),
            "final-fleet" => Failure("final-fleet-after-terminal") && scenario.CommitAcknowledged && outside && customerAfter &&
                classifications.SequenceEqual(PreparedCommittedUncertain),
            "unsafe-host" or "local-trust" => Failure("maintenance-semantic") && scenario.RejectionCode == "current_app_owned_maintenance_hba_not_exclusive" &&
                !scenario.InstalledSemanticPolicyAccepted && !scenario.CommitAcknowledged && unchanged && receipts.Count == 0 && scenario.RetainedSlots.Count == 0,
            "ordinary-all26" or "exclusive-policy" => scenario.Boundary == "maintenance-probes" && scenario.RejectionCode is null && scenario.InstalledSemanticPolicyAccepted &&
                !scenario.CommitAcknowledged && unchanged && receipts.Count == 0 && scenario.RetainedSlots.Count == 0 &&
                scenario.OrdinaryRejectedDatabases.Order(StringComparer.Ordinal).SequenceEqual(before.Keys.Order(StringComparer.Ordinal)),
            _ => false,
        };
        if (!valid || receipts.Any(x => x.Database != "Customer") || (ProviderCases.Contains(id, StringComparer.Ordinal) && !scenario.InstalledSemanticPolicyAccepted)) { throw Invalid(); }
    }
    internal static void RequireDefinitionCase(string id, CurrentCustomerSequenceObservation before, CurrentCustomerSequenceObservation after,
        CurrentCustomerSequenceProofScenario scenario, IReadOnlyList<CurrentCustomerSequenceRepairReceipt> receipts)
    {
        if (!scenario.InstalledSemanticPolicyAccepted || receipts.Count != 0 || scenario.RetainedSlots.Count != 0 || !DefinitionCases.Contains(id, StringComparer.Ordinal)) { throw Invalid(); }
        if (id.StartsWith("start-", StringComparison.Ordinal))
        {
            string[] operands = id.Split('-'); long last = long.Parse(operands[1], CultureInfo.InvariantCulture); bool called = bool.Parse(operands[2]); short ordinal = short.Parse(operands[3], CultureInfo.InvariantCulture);
            if (!scenario.CommitAcknowledged || scenario.Boundary != "definition-rollback-and-readback" || scenario.RejectionCode is not null || before.State.LastValue != last || before.State.IsCalled != called ||
                before.State.AttributeNumber != ordinal || before.State.Owner != "legacy_local" || (called && before.State.LogCount <= 0)) { throw Invalid(); }
            ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, after, before.State.Owner);
        }
        else
        {
            bool expected = id switch
            {
                "reject-increment" => before.State.Increment == 2,
                "reject-cache" => before.State.Cache == 2,
                "reject-start" => before.State.Start == 1000,
                "reject-generated" => before.State.Identity == "a",
                "reject-owner" => before.State.Owner == "other_owner",
                _ => false,
            };
            if (scenario.CommitAcknowledged || !expected || scenario.Boundary != "definition-preimage-rejected" || string.IsNullOrWhiteSpace(scenario.RejectionCode) ||
                before.State != after.State || before.Snapshot.Sha256 != after.Snapshot.Sha256) { throw Invalid(); }
            bool rejected = false;
            try { ApprovedCurrentCustomerSequenceDefinition.RequireBefore(before, "legacy_local"); }
            catch (MigrationExecutionException) { rejected = true; }
            if (!rejected) { throw Invalid(); }
        }
    }
    internal static void RequirePolicyEvidence(CurrentCustomerSequenceProofPolicy policy, CurrentCustomerSequenceRepairScope scope,
        CurrentCustomerSequenceProofScenario scenario, Func<CurrentCustomerSequenceProofArtifact, byte[]> read)
    {
        CurrentAppOwnedMaintenancePin maintenance = scope.Maintenance;
        if (policy.SystemIdentifierSha256 != scope.Target.SystemIdentifierSha256 || policy.Postmaster != maintenance.Postmaster ||
            policy.ConfigLoaded != maintenance.ConfigLoaded || policy.Role != maintenance.Role || policy.RoleExpiresAtUtc != maintenance.ExpiresAtUtc ||
            policy.RoleComment != maintenance.RoleComment || policy.HbaPath != maintenance.HbaPath || policy.HbaFile.Sha256 != maintenance.HbaSha256 ||
            policy.RawHbaRules.Sha256 != maintenance.HbaRulesSha256 || !policy.Superuser || !policy.Login || policy.CreateRole || policy.CreateDatabase ||
            policy.Replication || policy.BypassRls || policy.Memberships != 0 || !policy.Scram || policy.DefaultAcls != 0 || policy.OtherClients != 0 ||
            policy.PreparedTransactions != 0 || policy.EventTriggers != 0 || !policy.Primary || policy.ObservedAtUtc.Offset != TimeSpan.Zero ||
            policy.ObservedAtUtc >= maintenance.ExpiresAtUtc) { throw Invalid(); }
        _ = read(policy.HbaFile);
        using var document = JsonDocument.Parse(read(policy.RawHbaRules));
        var rules = document.RootElement.EnumerateArray().Select(row => new CurrentAppOwnedMaintenanceHbaRule(
            row.GetProperty("rule_number").GetInt32(), row.GetProperty("type").GetString()!, Strings(row, "database"), Strings(row, "user_name"),
            Text(row, "address"), Text(row, "netmask"), row.GetProperty("auth_method").GetString()!, Strings(row, "options"), Text(row, "error"))).ToArray();
        bool accepted = true;
        try { CurrentAppOwnedMaintenanceHba.Require(rules, maintenance.Role, scope.Target.Kind); }
        catch (MigrationExecutionException) { accepted = false; }
        if (accepted != scenario.InstalledSemanticPolicyAccepted) { throw Invalid(); }
        static string? Text(JsonElement row, string property)
        {
            return row.GetProperty(property).ValueKind == JsonValueKind.Null ? null : row.GetProperty(property).GetString();
        }

        static string[] Strings(JsonElement row, string property)
        {
            return row.GetProperty(property).ValueKind == JsonValueKind.Null ? [] :
                    row.GetProperty(property).EnumerateArray().Select(x => x.GetString()!).ToArray();
        }
    }
    private static string AssemblyHash(string path)
    { using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    private static MigrationExecutionException Invalid()
    {
        return CurrentCustomerSequenceRepairPermit.Invalid();
    }
}
