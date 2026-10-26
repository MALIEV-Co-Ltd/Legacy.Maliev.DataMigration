using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveProofArtifact(string Path, string Sha256);
internal sealed record CurrentAuthArchiveProofInvocation(string Kind, string Command, Guid RunId, Guid OperationId, string CaseId,
    string TestId, string ExecutionId, string ExecutedTestAssemblyPath, string TestAssemblySha256, string CoreAssemblySha256, string ConsoleAssemblySha256,
    string ScopeSha256, string ReviewSha256, string AuthorizationSha256, DateTimeOffset StartedAtUtc, DateTimeOffset ExitedAtUtc, int ExitCode);
internal sealed record CurrentAuthArchiveProofRun(Guid RunId, string ContainerId, string ComparisonContainerId, string Volume, string ComparisonVolume,
    DateTimeOffset BeganAtUtc, DateTimeOffset ExpiresAtUtc, CurrentAuthArchiveProofArtifact Ownership, CurrentAuthArchiveProofArtifact Cleanup, CurrentAuthArchiveProofArtifact Absence,
    CurrentAuthArchiveProofArtifact? Attempt = null);
internal sealed record CurrentAuthArchiveProofAttempt(Guid RunId, string Purpose, string Volume, string ComparisonVolume, bool Persistent,
    DateTimeOffset BeganAtUtc, DateTimeOffset ExpiresAtUtc, bool FreshNamesAbsent, ulong AdmissionFreeBytes);
internal sealed record CurrentAuthArchiveProofCleanup(Guid RunId, DateTimeOffset RemovedAtUtc, DateTimeOffset CompletedAtUtc, bool Exited, bool ReadersSettled,
    bool CleanupFailed, IReadOnlyList<string> RemovedContainerIds, IReadOnlyList<string> RemovedVolumes);
internal sealed record CurrentAuthArchiveProofAbsence(Guid RunId, DateTimeOffset ObservedAtUtc, bool ContainerInventorySucceeded, bool VolumeInventorySucceeded,
    bool ListenerInventorySucceeded, IReadOnlyList<string> ContainerIds, IReadOnlyList<string> Volumes, IReadOnlyList<int> LoopbackListeners);
internal sealed record CurrentAuthArchiveProofOwnership(Guid RunId, string Purpose, bool Persistent,
    CurrentAuthArchiveProofArtifact LocalContainer, CurrentAuthArchiveProofArtifact LocalVolume, CurrentAuthArchiveProofArtifact ComparisonContainer,
    CurrentAuthArchiveProofArtifact ComparisonVolume, IReadOnlyList<string> LocalVolumeConsumers, IReadOnlyList<string> ComparisonVolumeConsumers,
    int LocalPort, int ComparisonPort, DateTimeOffset ObservedAtUtc, int? ProxyPort = null);
internal sealed record CurrentAuthArchiveProofPolicy(CurrentAppOwnedMaintenancePin Maintenance, string SystemIdentifierSha256,
    bool Superuser, bool Login, bool CreateRole, bool CreateDatabase, bool Replication, bool BypassRls, bool Scram, long Memberships, long DefaultAcls,
    long OtherClients, long PreparedTransactions, long EventTriggers, bool Primary, DateTimeOffset ObservedAtUtc,
    CurrentAuthArchiveProofArtifact HbaFile, CurrentAuthArchiveProofArtifact RawRules);
internal sealed record CurrentAuthArchiveProofScenario(string Boundary, string? RejectionCode, bool CommitAcknowledged, bool LocalDeleteAttempted,
    bool FirstDomainUnavailable, bool SecondDomainUnavailable, DateTimeOffset ObservedAtUtc, IReadOnlyList<CurrentAuthArchiveProofSlot>? RetainedSlots = null);
internal sealed record CurrentAuthArchiveProofSlot(CurrentAuthArchiveProofArtifact Artifact, bool Acknowledged);
internal sealed record CurrentAuthArchiveProofCase(string CaseId, string TestId, string ExecutionId, Guid RunId,
    CurrentAuthArchiveProofArtifact Invocation, CurrentAuthArchiveProofArtifact Scope, CurrentAuthArchiveProofArtifact Review,
    CurrentAuthArchiveProofArtifact Authorization, CurrentAuthArchiveProofArtifact TestAssembly, CurrentAuthArchiveProofArtifact Configuration,
    CurrentAuthArchiveProofArtifact LocalTarget, CurrentAuthArchiveProofArtifact ComparisonTarget, CurrentAuthArchiveProofArtifact DeviceProof,
    CurrentAuthArchiveProofArtifact LocalPolicy, CurrentAuthArchiveProofArtifact ComparisonPolicy,
    CurrentAuthArchiveProofArtifact LocalBefore, CurrentAuthArchiveProofArtifact LocalAfter, CurrentAuthArchiveProofArtifact ComparisonBefore,
    CurrentAuthArchiveProofArtifact ComparisonAfter, CurrentAuthArchiveProofArtifact Rows, CurrentAuthArchiveProofArtifact? RecoveryManifest,
    CurrentAuthArchiveProofArtifact FirstCiphertext, CurrentAuthArchiveProofArtifact SecondCiphertext,
    CurrentAuthArchiveProofArtifact FirstRecoveryKey, CurrentAuthArchiveProofArtifact SecondRecoveryKey,
    CurrentAuthArchiveProofArtifact Scenario, IReadOnlyList<CurrentAuthArchiveProofArtifact> Receipts,
    CurrentAuthArchiveProofArtifact? RestoreBefore = null, CurrentAuthArchiveProofArtifact? RestoreAfter = null,
    CurrentAuthArchiveProofArtifact? SourcePlan = null, CurrentAuthArchiveProofArtifact? FaultSnapshot = null,
    CurrentAuthArchiveProofArtifact? FaultRows = null,
    CurrentAuthArchiveProofArtifact? LocalBeforeCatalogs = null, CurrentAuthArchiveProofArtifact? LocalAfterCatalogs = null,
    CurrentAuthArchiveProofArtifact? ComparisonBeforeCatalogs = null, CurrentAuthArchiveProofArtifact? ComparisonAfterCatalogs = null);
internal sealed record CurrentAuthArchiveExecutionProof(string Kind, string SubjectSha256, string SourceCommitSha, string CoreAssemblySha256,
    string ConsoleAssemblySha256, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc,
    CurrentAuthArchiveProofArtifact Trx, IReadOnlyList<CurrentAuthArchiveProofRun> Runs, IReadOnlyList<CurrentAuthArchiveProofCase> Cases);

// Genuine producers are prerequisites. No success report or signature is manufactured here.
internal static partial class CurrentAuthArchiveProofReader
{
    private static readonly string[] HelperCases = ["dual-durable-readback", "first-only-recovery", "second-only-recovery", "key-corruption", "cipher-corruption"];
    private static readonly string[] NativeCases = ["complete", "prepared-publication", "commit-ack-lost", "terminal-publication", "host-unprobed-sdk", "local-trust"];
    private static readonly string[] DeleteCases = ["exact-reviewed-delete", "CAS-field-drift", "private-journal-drift", "sequence-drift", "production-drift"];
    private static readonly string[] RecoveryCases = ["first-only-decrypt-insert-readback", "second-only-decrypt-insert-readback"];
    internal static string[] Cases(string phase)
    {
        return phase switch
        { "helper" => HelperCases.ToArray(), "native" => NativeCases.ToArray(), "delete" => DeleteCases.ToArray(), "recovery" => RecoveryCases.ToArray(), _ => throw Invalid() };
    }

    internal static string Domain(string phase, CurrentAuthArchiveProofAdmission mode)
    {
        _ = Cases(phase); return !Enum.IsDefined(mode)
            ? throw Invalid()
            : "Legacy.Maliev.CurrentAuth.SessionArchive.Proof." + phase + "." + (mode == CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap ? "DisposableProvider" : "ClosedConsole") + ".v1";
    }
    // Review/auth bind actual proof hashes; only these four hashes are excluded from the proof's own subject.
    internal static string Subject(CurrentAuthArchiveScope scope)
    {
        return CurrentAuthLocalSessionArchivePolicy.Hash(scope with
        { ArchiveHelperProofSha256 = new('0', 64), ArchiveNativeProofSha256 = new('0', 64), ExactDeleteReviewSha256 = new('0', 64), RecoveryReviewSha256 = new('0', 64) });
    }

    internal static void RequireHeader(CurrentAuthArchiveExecutionProof proof, CurrentAuthArchiveScope scope, string phase,
        string coreImage, string consoleImage, DateTimeOffset now)
    {
        if (proof.Kind != "current-auth-session-archive-execution-proof-v1" || proof.SubjectSha256 != Subject(scope) ||
            proof.SourceCommitSha != scope.LocalObservationPolicy.SourceCommitSha || proof.CoreAssemblySha256 != coreImage || proof.ConsoleAssemblySha256 != consoleImage ||
            now.Offset != TimeSpan.Zero || proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > now || proof.ExpiresAtUtc <= now ||
            proof.ExpiresAtUtc - proof.BeganAtUtc > TimeSpan.FromHours(12) || now - proof.BeganAtUtc > TimeSpan.FromHours(12) || proof.Runs.Count == 0 ||
            proof.Runs.Select(x => x.RunId).Distinct().Count() != proof.Runs.Count || proof.Cases.Count != Cases(phase).Length ||
            !proof.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(Cases(phase).Order(StringComparer.Ordinal))) { throw Invalid(); }
    }
    internal static void Require(CurrentAppOwnedRepairCustody files, CurrentAppOwnedRepairArtifact artifact, string expected, string phase,
        CurrentAuthArchiveScope scope, IReceiptAttestationTrustStore trust, CurrentAuthArchivePins pins, FreshSchemaPlan source)
    {
        CurrentAuthArchiveCapacity.Require(admission: false); byte[] bytes = files.Read(artifact.Path, maximumBytes: 1_000_000);
        if (artifact.Sha256 != expected || CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != expected) { throw Invalid(); }
        var signed = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(bytes);
        var proof = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveExecutionProof>(signed, Domain(phase, scope.ProofAdmission), pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
        RequireHeader(proof, scope, phase, AssemblyHash(typeof(CurrentAuthLocalSessionArchivePermit).Assembly.Location), AssemblyHash(typeof(MigrationConsole).Assembly.Location), DateTimeOffset.UtcNow);
        using var stream = new MemoryStream(Read(proof.Trx), writable: false);
        using var xml = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var document = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var results = document.Descendants(ns + "UnitTestResult").ToArray(); var counters = document.Descendants(ns + "Counters").Single();
        if (results.Length != proof.Cases.Count || results.Any(x => (string?)x.Attribute("outcome") != "Passed") ||
            (string?)counters.Attribute("total") != proof.Cases.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
            (string?)counters.Attribute("passed") != (string?)counters.Attribute("total") || (string?)counters.Attribute("failed") != "0" ||
            proof.Cases.Select(x => x.ExecutionId).Distinct(StringComparer.Ordinal).Count() != proof.Cases.Count ||
            !proof.Runs.Select(x => x.RunId).Order().SequenceEqual(proof.Cases.Select(x => x.RunId).Distinct().Order())) { throw Invalid(); }
        var exits = new Dictionary<Guid, DateTimeOffset>();
        foreach (var item in proof.Cases)
        {
            var invocation = Decode<CurrentAuthArchiveProofInvocation>(item.Invocation); var caseScope = Decode<CurrentAuthArchiveScope>(item.Scope);
            var review = Decode<CurrentAuthArchiveClaim>(item.Review); var authorization = Decode<CurrentAuthArchiveClaim>(item.Authorization);
            var reviewed = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveScope>(review, CurrentAuthLocalSessionArchivePolicy.ReviewDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
            var permission = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(authorization, CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, pins.AuthorizationKeyId, pins.AuthorizationFingerprint, trust);
            CurrentAuthLocalSessionArchivePolicy.RequireScope(caseScope, invocation.StartedAtUtc); var run = proof.Runs.Single(x => x.RunId == item.RunId);
            var caseSource = Decode<FreshSchemaPlan>(item.SourcePlan ?? throw Invalid());
            ProductionSchemaCatalogInspector.ValidatePlan(caseSource, invocation.StartedAtUtc);
            if (!ApprovedConsumerOverlaySelection.IsApproved(caseSource) || caseSource.SourceCommitSha != proof.SourceCommitSha ||
                SchemaPlanCanonicalizer.ComputeSha256(caseSource) != caseScope.LocalObservationPolicy.SourceSchemaPlanSha256 ||
                JsonSerializer.Serialize(caseSource.Databases) != JsonSerializer.Serialize(source.Databases)) { throw Invalid(); }
            var result = results.Single(x => (string?)x.Attribute("testId") == item.TestId && (string?)x.Attribute("executionId") == item.ExecutionId);
            var method = document.Descendants(ns + "UnitTest").Single(x => (string?)x.Attribute("id") == item.TestId).Element(ns + "TestMethod") ?? throw Invalid();
            string methodName = "Archive_" + phase + "_" + item.CaseId.Replace('-', '_'); bool component = scope.ProofAdmission == CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap;
            if (invocation.Kind != (component ? "current-auth-archive-provider-invocation-v1" : "current-auth-archive-closed-invocation-v1") ||
                invocation.Command != (component ? "provider-current-auth-archive-proof" : "apply-current-auth-local-session-archive") ||
                invocation.CaseId != item.CaseId || invocation.RunId != run.RunId || invocation.OperationId != caseScope.OperationId ||
                invocation.TestId != item.TestId || invocation.ExecutionId != item.ExecutionId || invocation.ScopeSha256 != item.Scope.Sha256 ||
                invocation.ReviewSha256 != item.Review.Sha256 || invocation.AuthorizationSha256 != item.Authorization.Sha256 ||
                invocation.TestAssemblySha256 != item.TestAssembly.Sha256 || invocation.CoreAssemblySha256 != proof.CoreAssemblySha256 || invocation.ConsoleAssemblySha256 != proof.ConsoleAssemblySha256 ||
                invocation.StartedAtUtc.Offset != TimeSpan.Zero || invocation.ExitedAtUtc.Offset != TimeSpan.Zero || invocation.StartedAtUtc < run.BeganAtUtc ||
                invocation.ExitedAtUtc < invocation.StartedAtUtc || invocation.ExitedAtUtc > run.ExpiresAtUtc || invocation.ExitedAtUtc > proof.CompletedAtUtc ||
                invocation.ExitCode != (Positive(item.CaseId) ? 0 : 1) || caseScope.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap ||
                CurrentAuthLocalSessionArchivePolicy.Hash(reviewed) != CurrentAuthLocalSessionArchivePolicy.Hash(caseScope) || permission.OperationId != caseScope.OperationId ||
                permission.ReviewSha256 != item.Review.Sha256 || permission.IssuedAtUtc > invocation.StartedAtUtc || permission.ExpiresAtUtc <= invocation.StartedAtUtc ||
                caseScope.LocalObservationPolicy.SourceCommitSha != proof.SourceCommitSha ||
                (string?)result.Attribute("testName") != methodName || (string?)method.Attribute("name") != methodName ||
                (string?)method.Attribute("className") != "Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGuardedExecutionTests") { throw Invalid(); }
            RequireImagePath(invocation.ExecutedTestAssemblyPath, item.TestAssembly.Path, (string?)method.Attribute("codeBase"), (string?)method.Parent!.Attribute("storage")); _ = Read(item.TestAssembly);
            exits[run.RunId] = !exits.TryGetValue(run.RunId, out DateTimeOffset prior) || invocation.ExitedAtUtc > prior ? invocation.ExitedAtUtc : prior;
            var config = Decode<CurrentAuthLocalSessionArchiveConfiguration>(item.Configuration);
            if (config.ScopePath != item.Scope.Path || config.ReviewPath != item.Review.Path || config.AuthorizationPath != item.Authorization.Path ||
                config.LocalTargetPinsPath != item.LocalTarget.Path || config.ProductionTargetPinsPath != item.ComparisonTarget.Path) { throw Invalid(); }
            var localTarget = Decode<CurrentAppOwnedRepairTargetPins>(item.LocalTarget); var comparisonTarget = Decode<CurrentAppOwnedRepairTargetPins>(item.ComparisonTarget);
            if (CurrentAuthLocalSessionArchivePolicy.Hash(localTarget) != caseScope.LocalObservationPolicy.TargetObservationSha256 ||
                CurrentAuthLocalSessionArchivePolicy.Hash(comparisonTarget) != caseScope.ProductionObservationPolicy.TargetObservationSha256) { throw Invalid(); }
            RequireOwnership(Decode<CurrentAuthArchiveProofOwnership>(run.Ownership), run, caseScope, localTarget, comparisonTarget, invocation.StartedAtUtc, Read);
            var devices = Decode<CurrentAuthArchiveDeviceProof>(item.DeviceProof);
            if (CurrentAuthLocalSessionArchivePolicy.Hash(devices) != caseScope.RecoveryDeviceProofSha256 || devices.OperationId != caseScope.OperationId || devices.Paths != caseScope.Paths ||
                devices.LocalRunBindingSha256 != caseScope.LocalObservationPolicy.RunBindingSha256 || devices.ProductionRunBindingSha256 != caseScope.ProductionObservationPolicy.RunBindingSha256 ||
                devices.LocalTargetObservationSha256 != caseScope.LocalObservationPolicy.TargetObservationSha256 || devices.ProductionTargetObservationSha256 != caseScope.ProductionObservationPolicy.TargetObservationSha256 ||
                devices.ObservedAtUtc > invocation.StartedAtUtc || invocation.StartedAtUtc - devices.ObservedAtUtc > TimeSpan.FromMinutes(5)) { throw Invalid(); }
            CurrentAuthLocalSessionArchiveRecoveryDevices.RequireIndependent(devices.First, devices.Second);
            RequirePolicy(Decode<CurrentAuthArchiveProofPolicy>(item.LocalPolicy), caseScope.LocalObservationPolicy, invocation, Read, item.CaseId);
            RequirePolicy(Decode<CurrentAuthArchiveProofPolicy>(item.ComparisonPolicy), caseScope.ProductionObservationPolicy, invocation, Read, "safe");
            var before = Decode<CurrentAppOwnedDatabaseSnapshot[]>(item.LocalBefore); var after = Decode<CurrentAppOwnedDatabaseSnapshot[]>(item.LocalAfter);
            var comparisonBefore = Decode<CurrentAppOwnedDatabaseSnapshot[]>(item.ComparisonBefore); var comparisonAfter = Decode<CurrentAppOwnedDatabaseSnapshot[]>(item.ComparisonAfter);
            RequireFleet(before, caseScope.LocalObservationPolicy, false); RequireFleet(comparisonBefore, caseScope.ProductionObservationPolicy, true);
            var localBeforeCatalogs = Decode<CurrentAuthArchiveFleetCatalogs>(item.LocalBeforeCatalogs ?? throw Invalid());
            var localAfterCatalogs = Decode<CurrentAuthArchiveFleetCatalogs>(item.LocalAfterCatalogs ?? throw Invalid());
            var comparisonBeforeCatalogs = Decode<CurrentAuthArchiveFleetCatalogs>(item.ComparisonBeforeCatalogs ?? throw Invalid());
            var comparisonAfterCatalogs = Decode<CurrentAuthArchiveFleetCatalogs>(item.ComparisonAfterCatalogs ?? throw Invalid());
            RequireProofCatalogs(localBeforeCatalogs, caseScope.LocalObservationPolicy, false, before, invocation);
            RequireProofCatalogs(localAfterCatalogs, caseScope.LocalObservationPolicy, false, after, invocation);
            RequireProofCatalogs(comparisonBeforeCatalogs, caseScope.ProductionObservationPolicy, true, comparisonBefore, invocation);
            RequireProofCatalogs(comparisonAfterCatalogs, caseScope.ProductionObservationPolicy, true, comparisonAfter, invocation);
            if (localBeforeCatalogs.After.EndedAtUtc > localAfterCatalogs.Before.BeganAtUtc ||
                comparisonBeforeCatalogs.After.EndedAtUtc > comparisonAfterCatalogs.Before.BeganAtUtc) { throw Invalid(); }
            bool productionFault = item.CaseId == "production-drift";
            RequireComparisonFleetAfter(comparisonBefore, comparisonAfter, productionFault);
            if (!after.Select(x => x.Database).SequenceEqual(before.Select(x => x.Database)) ||
                before.Where(x => x.Database != "Auth").Any(x => x.Sha256 != after.Single(y => y.Database == x.Database).Sha256)) { throw Invalid(); }
            var scenario = Decode<CurrentAuthArchiveProofScenario>(item.Scenario);
            if (scenario.ObservedAtUtc.Offset != TimeSpan.Zero || scenario.ObservedAtUtc < invocation.StartedAtUtc || scenario.ObservedAtUtc > invocation.ExitedAtUtc) { throw Invalid(); }
            var rows = Decode<CurrentAuthArchiveSession[]>(item.Rows); byte[] encoded = CurrentAuthLocalSessionArchivePolicy.EncodeRows(rows);
            try { if (rows.Length != caseScope.DeleteCount || CurrentAuthLocalSessionArchivePolicy.HashBytes(encoded) != caseScope.DeleteSetSha256) { throw Invalid(); } }
            finally { CryptographicOperations.ZeroMemory(encoded); }
            CurrentAuthArchiveRecoveryManifest? manifest = item.RecoveryManifest is null ? null :
                CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveRecoveryManifest>(Decode<CurrentAuthArchiveClaim>(item.RecoveryManifest),
                    CurrentAuthLocalSessionArchivePolicy.RecoveryDomain, pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
            bool preEffect = item.CaseId is "host-unprobed-sdk" or "local-trust" or "CAS-field-drift" or "private-journal-drift" or "sequence-drift" or "production-drift";
            if (manifest is null && (!preEffect || item.Receipts.Count != 0)) { throw Invalid(); }
            if (manifest is not null)
            {
                if (manifest.ScopeSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(caseScope) || manifest.AuthorizationSha256 != item.Authorization.Sha256 ||
                    !CurrentAuthRepairPermit.HashShape(manifest.RecoveryPublicKeySha256) || !CurrentAuthRepairPermit.HashShape(manifest.FirstCiphertextSha256) ||
                    !CurrentAuthRepairPermit.HashShape(manifest.SecondCiphertextSha256) || manifest.FirstCiphertextSha256 == manifest.SecondCiphertextSha256) { throw Invalid(); }
                RequireRecovery(phase, item, caseScope, manifest, scenario, rows, before.Single(x => x.Database == "Auth"), Read);
            }
            var receipts = new List<CurrentAuthArchiveReceipt>(); string previous = new('0', 64);
            foreach (var value in item.Receipts)
            {
                var claim = Decode<CurrentAuthArchiveClaim>(value); var receipt = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveReceipt>(claim, CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
                if (receipt.OperationId != caseScope.OperationId || receipt.AuthorizationSha256 != item.Authorization.Sha256 || receipt.PreviousSha256 != previous ||
                    receipt.BeforeAuthSha256 != caseScope.LocalObservationPolicy.BeforeDatabaseSha256["Auth"] || receipt.ObservedAtUtc < invocation.StartedAtUtc || receipt.ObservedAtUtc > invocation.ExitedAtUtc ||
                    receipt.ObservedAtUtc.Offset != TimeSpan.Zero || !Enum.IsDefined(receipt.Classification) ||
                    receipt.RecoveryManifestSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(manifest ?? throw Invalid()) ||
                    (receipts.Count > 0 && receipt.AfterAuthSha256 != receipts[0].AfterAuthSha256)) { throw Invalid(); }
                previous = value.Sha256; receipts.Add(receipt);
            }
            if (scenario.RetainedSlots is null || scenario.RetainedSlots.Count > 3 ||
                scenario.RetainedSlots.Select(x => x.Artifact.Path).Distinct(StringComparer.Ordinal).Count() != scenario.RetainedSlots.Count ||
                !scenario.RetainedSlots.Where(x => x.Acknowledged).Select(x => x.Artifact.Sha256).SequenceEqual(item.Receipts.Select(x => x.Sha256)) ||
                scenario.RetainedSlots.Count(x => !x.Acknowledged) > 1) { throw Invalid(); }
            foreach (var slot in scenario.RetainedSlots)
            {
                var claim = Decode<CurrentAuthArchiveClaim>(slot.Artifact);
                var retained = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveReceipt>(claim, CurrentAuthLocalSessionArchivePolicy.ReceiptDomain, pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
                string suffix = retained.Classification switch
                {
                    CurrentAppOwnedCommitClassification.Prepared => "prepared",
                    CurrentAppOwnedCommitClassification.CommittedAndReadback => "committed-readback",
                    CurrentAppOwnedCommitClassification.FailedBeforeCommit or CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or CurrentAppOwnedCommitClassification.Uncertain => "failed-or-uncertain",
                    _ => throw Invalid()
                };
                if (retained.OperationId != caseScope.OperationId || retained.AuthorizationSha256 != item.Authorization.Sha256 ||
                    retained.BeforeAuthSha256 != caseScope.LocalObservationPolicy.BeforeDatabaseSha256["Auth"] || retained.ObservedAtUtc.Offset != TimeSpan.Zero ||
                    retained.ObservedAtUtc < invocation.StartedAtUtc || retained.ObservedAtUtc > invocation.ExitedAtUtc ||
                    retained.RecoveryManifestSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(manifest ?? throw Invalid()) ||
                    Path.GetFileName(slot.Artifact.Path) != $"{caseScope.OperationId:D}-Auth-session-archive-{suffix}.json") { throw Invalid(); }
                if (!slot.Acknowledged)
                {
                    bool sibling = item.CaseId == "prepared-publication" && retained.Classification == CurrentAppOwnedCommitClassification.Prepared &&
                        retained.PreviousSha256 == new string('0', 64) && receipts.Count == 1 && retained.AfterAuthSha256 == receipts[0].AfterAuthSha256;
                    bool terminal = item.CaseId == "terminal-publication" && retained.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback &&
                        receipts.Count > 0 && receipts[0].Classification == CurrentAppOwnedCommitClassification.Prepared && retained.PreviousSha256 == item.Receipts[0].Sha256 &&
                        retained.AfterAuthSha256 == receipts[0].AfterAuthSha256;
                    if (!sibling && !terminal) { throw Invalid(); }
                }
            }
            CurrentAppOwnedDatabaseSnapshot effectsBefore = before.Single(x => x.Database == "Auth");
            if (item.CaseId is "CAS-field-drift" or "private-journal-drift" or "sequence-drift" or "production-drift")
            {
                var fault = Decode<CurrentAppOwnedDatabaseSnapshot>(item.FaultSnapshot ?? throw Invalid());
                var original = productionFault ? comparisonBefore.Single(x => x.Database == "Auth") : effectsBefore;
                RequireFault(item.CaseId, original, fault);
                if (productionFault)
                {
                    if (!comparisonAfter.Select(x => x.Database).SequenceEqual(comparisonBefore.Select(x => x.Database)) ||
                        comparisonAfter.Single(x => x.Database == "Auth").Sha256 != fault.Sha256 ||
                        comparisonBefore.Where(x => x.Database != "Auth").Any(x => x.Sha256 != comparisonAfter.Single(y => y.Database == x.Database).Sha256)) { throw Invalid(); }
                }
                else { effectsBefore = fault; }
                if (item.CaseId == "CAS-field-drift")
                {
                    var changed = Decode<CurrentAuthArchiveSession[]>(item.FaultRows ?? throw Invalid());
                    RequireCasFaultRows(rows, changed);
                }
            }
            else if (item.FaultSnapshot is not null || item.FaultRows is not null) { throw Invalid(); }
            RequireEffects(item.CaseId, scenario, receipts, effectsBefore, after.Single(x => x.Database == "Auth"));
        }
        foreach (var run in proof.Runs)
        {
            var attempt = Decode<CurrentAuthArchiveProofAttempt>(run.Attempt ?? throw Invalid());
            if (attempt.RunId != run.RunId || attempt.Purpose != "current-auth-local-session-archive-proof" || attempt.Volume != run.Volume || attempt.ComparisonVolume != run.ComparisonVolume ||
                attempt.Persistent || attempt.BeganAtUtc != run.BeganAtUtc || attempt.ExpiresAtUtc != run.ExpiresAtUtc || !attempt.FreshNamesAbsent || attempt.AdmissionFreeBytes < 3UL * 1024 * 1024 * 1024) { throw Invalid(); }
            var ownership = Decode<CurrentAuthArchiveProofOwnership>(run.Ownership);
            int[] ownedPorts = ownership.ProxyPort is { } proxy ? [ownership.LocalPort, ownership.ComparisonPort, proxy] : [ownership.LocalPort, ownership.ComparisonPort];
            RequireCleanup(run, Decode<CurrentAuthArchiveProofCleanup>(run.Cleanup), Decode<CurrentAuthArchiveProofAbsence>(run.Absence), exits[run.RunId], proof.CompletedAtUtc, ownedPorts);
        }
        files.Require(); CurrentAuthArchiveCapacity.Require(admission: false);
        byte[] Read(CurrentAuthArchiveProofArtifact value)
        {
            CurrentAuthArchiveCapacity.Require(admission: false); byte[] held = files.Read(value.Path, maximumBytes: 12 * 1024 * 1024); return CurrentAuthLocalSessionArchivePolicy.HashBytes(held) != value.Sha256 ? throw Invalid() : held;
        }
        T Decode<T>(CurrentAuthArchiveProofArtifact value)
        {
            return MigrationConsole.DecodeAuthRepair<T>(Read(value));
        }
    }
    private static string AssemblyHash(string path) { using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); return Convert.ToHexStringLower(SHA256.HashData(file)); }
    private static bool Positive(string id)
    {
        return id is "dual-durable-readback" or "first-only-recovery" or "second-only-recovery" or "complete" or "exact-reviewed-delete" or "first-only-decrypt-insert-readback" or "second-only-decrypt-insert-readback";
    }

    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthLocalSessionArchivePolicy.Invalid();
    }
}
