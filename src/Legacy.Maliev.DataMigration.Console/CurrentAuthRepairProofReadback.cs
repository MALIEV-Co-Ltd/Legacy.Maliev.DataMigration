using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthProofArtifact(string Path, string Sha256);
internal sealed record CurrentAuthProofStorage(uint FileNode, long Blocks);
internal sealed record CurrentAuthProofNative(CurrentAppOwnedDatabaseSnapshot Snapshot,
    Dictionary<string, string[]> Tuples, Dictionary<string, CurrentAuthProofStorage> Storage, Dictionary<string, string> Expressions)
{
    internal CurrentAuthNativeObservation Observation() => new(Snapshot, Tuples,
        Storage.ToDictionary(x => x.Key, x => (x.Value.FileNode, x.Value.Blocks), StringComparer.Ordinal), Expressions);
}
internal sealed record CurrentAuthProofInvocation(string Command, Guid OperationId, Guid RunId,
    string TestName, string TestId, string ExecutionId, string ExecutedTestAssemblyPath,
    string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256,
    string ScopeSha256, string ReviewSha256, string AuthorizationSha256, string ConfigurationSha256,
    DateTimeOffset StartedAtUtc, DateTimeOffset ExitedAtUtc, int ExitCode);
internal sealed record CurrentAuthProofSlot(CurrentAuthProofArtifact Artifact, bool Acknowledged);
internal sealed record CurrentAuthProofScenario(string CaseId, Guid OperationId, string InvocationSha256,
    string Boundary, string? RejectionCode, bool CommitAcknowledged, bool ReplayRejected,
    IReadOnlyList<string> OrdinaryRejectedDatabases, IReadOnlyList<CurrentAuthProofSlot> RetainedSlots);
internal sealed record CurrentAuthProofRun(Guid RunId, string Name, string ContainerId, string? Volume,
    CurrentAuthProofArtifact Container, CurrentAuthProofArtifact? VolumeMetadata,
    CurrentAuthProofArtifact Attempt, CurrentAuthProofArtifact Disposed, CurrentAuthProofArtifact Absence,
    int LoopbackPort, CurrentAuthProofArtifact? FilesystemCapacity = null,
    CurrentAuthProofArtifact? PreviousVolumes = null, CurrentAuthProofArtifact? VolumeConsumers = null,
    CurrentAuthProofArtifact? ImageMetadata = null, CurrentAuthProofArtifact? ProxyCreated = null, CurrentAuthProofArtifact? ProxyDisposed = null);
internal sealed record CurrentAuthProofAbsence(Guid RunId, DateTimeOffset ObservedAtUtc,
    bool ContainersObserved, bool VolumesObserved, bool ListenersObserved, bool SecretsAbsent,
    IReadOnlyList<string> ContainerIds, IReadOnlyList<string> ContainerNames, IReadOnlyList<string> VolumeNames,
    IReadOnlyList<int> ListeningPorts);
internal sealed record CurrentAuthProofPolicy(CurrentAuthRepairScope Scope, DateTimeOffset ObservedAtUtc,
    string SystemIdentifierSha256, DateTimeOffset Postmaster, DateTimeOffset ConfigLoaded, string Role,
    DateTimeOffset RoleExpiresAtUtc, string RoleComment, string HbaPath,
    CurrentAuthProofArtifact RawHba, CurrentAuthProofArtifact HbaRules, bool Primary, bool Superuser,
    bool Login, bool CreateRole, bool CreateDatabase, bool Replication, bool BypassRls, bool Scram,
    long Memberships, long DefaultAcls, long OtherClients, long PreparedTransactions, long EventTriggers,
    IReadOnlyList<CurrentAppOwnedMaintenanceHbaRule> Rules);
internal sealed record CurrentAuthProofCase(string CaseId, CurrentAuthProofInvocation Invocation,
    CurrentAuthProofArtifact InvocationArtifact, CurrentAuthProofArtifact TestAssembly,
    CurrentAuthProofArtifact NativeBefore, CurrentAuthProofArtifact NativeAfter, CurrentAuthProofArtifact? RolledBack,
    CurrentAuthProofArtifact? FleetBefore, CurrentAuthProofArtifact? FleetAfter,
    CurrentAuthProofArtifact? Scope, CurrentAuthProofArtifact? Review, CurrentAuthProofArtifact? Authorization,
    CurrentAuthProofArtifact? Configuration, CurrentAuthProofArtifact? RunBinding, CurrentAuthProofArtifact? TargetPins,
    CurrentAuthProofArtifact? InstalledPolicy, CurrentAuthProofArtifact Scenario,
    CurrentAuthProofArtifact? PreparedCandidate = null, CurrentAuthProofArtifact? CaseSigningPins = null,
    CurrentAuthProofArtifact? CasePublicKeys = null, CurrentAuthProofArtifact? ComponentObservation = null, CurrentAuthProofArtifact? CaseSource = null, CurrentAuthProofArtifact? SourcePhysical = null);
internal sealed record CurrentAuthProofPublicKey(string KeyId, string SubjectPublicKeyInfoBase64);
internal sealed record CurrentAuthProofComponentObservation(string Kind, string SourceEvidenceKind,
    CurrentAuthProofArtifact HeldBinding, string ActualTargetGeneration, string ActualImageId);
internal sealed record CurrentAuthClosedProof(string Kind, string SubjectSha256, string SourceCommitSha,
    string ConsoleAssemblySha256, string CoreAssemblySha256, DateTimeOffset BeganAtUtc,
    DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc, CurrentAuthProofArtifact Trx,
    IReadOnlyList<CurrentAuthProofRun> Runs, IReadOnlyList<CurrentAuthProofCase> Cases, string KeyId, string? Signature);

/// <summary>Authenticates held executed evidence. Does not produce proof, signatures or authority.</summary>
internal static class CurrentAuthRepairProofReader
{
    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    private static readonly string[] HelperCases = ["history-10.0.12", "history-10.0.10", "reject-expression", "reject-extended-statistics", "reject-statistics", "reject-column", "reject-partial"];
    private static readonly string[] ComponentCases = ["success", "prepared-publication", "lost-commit-ack", "terminal-publication", "host-unprobed-sdk", "local-ordinary-trust"];
    private static readonly string[] ClosedCases = [.. ComponentCases, "final-fleet", "replay"];
    // No proof digest, operation digest or signed claim enters this precursor subject.
    internal static string Subject(CurrentAuthRepairScope scope) => CurrentAppOwnedSnapshotSerialization.Sha256(new
    {
        scope.SourceCommitSha, scope.SourceSchemaPlanSha256, scope.AuthOwnerCommitSha, scope.AuthOwnerSourcePinsSha256,
        scope.AuthClosureSha256, scope.AuthBeforeSchemaSha256, scope.AuthAfterSchemaSha256, scope.MaintenanceValidatorSha256,
        scope.Target, scope.TargetNamespace, scope.TargetCluster, scope.TargetGeneration, scope.TargetObservationSha256,
        scope.RunBindingSha256, scope.GlobalPreservationSha256, scope.ProofAdmission
    });
    internal static byte[] Payload(CurrentAuthClosedProof proof, string phase) =>
        [.. Encoding.UTF8.GetBytes("Legacy.Maliev.CurrentAuth.ExecutedProof." + phase + ".v1\0"),
         .. JsonSerializer.SerializeToUtf8Bytes(proof with { Signature = null })];
    internal static string[] Cases(string phase, CurrentAuthProofAdmission mode, bool component = false) => phase == "helper" ? [.. HelperCases] :
        phase is "native" or "recovery" or "maintenance" ? (component && mode == CurrentAuthProofAdmission.DisposableNativeBootstrap ? [.. ComponentCases] : [.. ClosedCases]) : throw Invalid();
    internal static void RequireHeader(CurrentAuthClosedProof proof, string phase, CurrentAuthRepairScope scope,
        IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins, DateTimeOffset now,
        string consoleHash, string coreHash, bool requireSignature = true, bool component = false)
    {
        CurrentAuthRepairPermit.RequireProofAdmission(scope);
        if (component && scope.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeBootstrap) { throw Invalid(); }
        string mode = phase == "helper" ? "definition" : component ? "provider-component" : "closed-console";
        if (proof.Kind != "current-auth-" + phase + "-" + mode + "-proof-v1" || proof.SubjectSha256 != Subject(scope) ||
            proof.SourceCommitSha != scope.SourceCommitSha || proof.ConsoleAssemblySha256 != consoleHash || proof.CoreAssemblySha256 != coreHash ||
            proof.KeyId != pins.ReceiptKeyId || !trust.TryGetPublicKeyFingerprintSha256(proof.KeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint ||
            now.Offset != TimeSpan.Zero || proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > now || now - proof.BeganAtUtc > TimeSpan.FromHours(12) ||
            proof.ExpiresAtUtc <= now || proof.ExpiresAtUtc <= proof.CompletedAtUtc || proof.ExpiresAtUtc - proof.BeganAtUtc > TimeSpan.FromHours(12) || (requireSignature && string.IsNullOrWhiteSpace(proof.Signature))) { throw Invalid(); }
        _ = Cases(phase, scope.ProofAdmission, component);
        if (!requireSignature) { if (proof.Signature is not null) { throw Invalid(); } return; }
        try { if (!trust.Verify(proof.KeyId, Payload(proof, phase), Convert.FromBase64String(proof.Signature!))) { throw Invalid(); } }
        catch (FormatException) { throw Invalid(); }
    }
    internal static Task RequireAsync(CurrentAppOwnedRepairCustody files, CurrentAppOwnedRepairArtifact artifact, string expected,
        string phase, CurrentAuthRepairScope intended, IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins, FreshSchemaPlan source, CancellationToken ct) =>
        RequireExecutedEvidenceCoreAsync(files, artifact, expected, phase, intended, trust, pins, source, requireSignature: true, component: false, ct: ct);
    // Genuine precursor readback only. The ordinary closed Console never invokes this entry.
    internal static Task RequireComponentAsync(CurrentAppOwnedRepairCustody files, CurrentAppOwnedRepairArtifact artifact, string expected,
        string phase, CurrentAuthRepairScope intended, IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins, FreshSchemaPlan source, CancellationToken ct) =>
        RequireExecutedEvidenceCoreAsync(files, artifact, expected, phase, intended, trust, pins, source, requireSignature: true, component: true, ct: ct);
    // Observation validation for the external assembler only; this method emits no claim, permit or signature.
    internal static Task RequireUnsignedForAssemblerAsync(CurrentAppOwnedRepairCustody files, CurrentAppOwnedRepairArtifact artifact, string expected,
        string phase, CurrentAuthRepairScope intended, IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins, FreshSchemaPlan source, CancellationToken ct) =>
        RequireExecutedEvidenceCoreAsync(files, artifact, expected, phase, intended, trust, pins, source, requireSignature: false, component: true, ct: ct);
    private static async Task RequireExecutedEvidenceCoreAsync(CurrentAppOwnedRepairCustody files, CurrentAppOwnedRepairArtifact artifact, string expected,
        string phase, CurrentAuthRepairScope intended, IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins, FreshSchemaPlan source, bool requireSignature, bool component, CancellationToken ct)
    {
        CurrentAuthRepairCapacity.Require(admission: false);
        if (artifact.Sha256 != expected) { throw Invalid(); }
        var proof = Decode<CurrentAuthClosedProof>(Read(new(artifact.Path, expected)));
        RequireHeader(proof, phase, intended, trust, pins, DateTimeOffset.UtcNow,
            AssemblyHash(typeof(MigrationConsole).Assembly.Location), AssemblyHash(typeof(CurrentAuthRepairPermit).Assembly.Location), requireSignature, component);
        string[] required = Cases(phase, intended.ProofAdmission, component);
        if (!proof.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(required.Order(StringComparer.Ordinal)) ||
            proof.Cases.Select(x => x.Invocation.ExecutionId).Distinct(StringComparer.Ordinal).Count() != required.Length ||
            proof.Cases.Select(x => x.Invocation.TestId).Distinct(StringComparer.Ordinal).Count() != required.Length ||
            proof.Runs.Count == 0 || proof.Runs.Select(x => x.RunId).Distinct().Count() != proof.Runs.Count ||
            !proof.Cases.Select(x => x.Invocation.RunId).Distinct().Order().SequenceEqual(proof.Runs.Select(x => x.RunId).Order())) { throw Invalid(); }
        using var stream = new MemoryStream(Read(proof.Trx), writable: false);
        using var xml = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        XDocument document = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        XElement counters = document.Descendants(ns + "Counters").Single(); XElement[] results = [.. document.Descendants(ns + "UnitTestResult")];
        if ((string?)counters.Attribute("total") != required.Length.ToString(CultureInfo.InvariantCulture) ||
            (string?)counters.Attribute("passed") != (string?)counters.Attribute("total") || (string?)counters.Attribute("failed") != "0" ||
            results.Length != required.Length || results.Any(x => (string?)x.Attribute("outcome") != "Passed")) { throw Invalid(); }
        var usedCaseFingerprints = new HashSet<string>(StringComparer.Ordinal);
        foreach (CurrentAuthProofCase item in proof.Cases)
        {
            CurrentAuthProofInvocation invocation = Decode<CurrentAuthProofInvocation>(Read(item.InvocationArtifact));
            if (invocation != item.Invocation || invocation.OperationId == Guid.Empty || invocation.StartedAtUtc.Offset != TimeSpan.Zero || invocation.ExitedAtUtc.Offset != TimeSpan.Zero ||
                invocation.StartedAtUtc < proof.BeganAtUtc || invocation.ExitedAtUtc > proof.CompletedAtUtc || invocation.ExitedAtUtc < invocation.StartedAtUtc ||
                invocation.ConsoleAssemblySha256 != proof.ConsoleAssemblySha256 || invocation.CoreAssemblySha256 != proof.CoreAssemblySha256 ||
                invocation.TestAssemblySha256 != item.TestAssembly.Sha256 || !SamePath(invocation.ExecutedTestAssemblyPath, item.TestAssembly.Path)) { throw Invalid(); }
            _ = Read(item.TestAssembly);
            XElement result = results.Single(x => (string?)x.Attribute("testId") == invocation.TestId && (string?)x.Attribute("executionId") == invocation.ExecutionId);
            XElement unit = document.Descendants(ns + "UnitTest").Single(x => (string?)x.Attribute("id") == invocation.TestId);
            XElement method = unit.Element(ns + "TestMethod") ?? throw Invalid();
            bool helper = phase == "helper";
            string expectedClass = helper ? "CurrentAuthNativePreservationTests" : component ? "CurrentAuthGuardedNativeExecutionTests" : "CurrentAuthClosedConsoleExecutionTests";
            string expectedMethod = helper ? item.CaseId.StartsWith("history-", StringComparison.Ordinal) ?
                "Fixed_transition_preserves_populated_rows_private_state_and_independent_history_through_rollback_commit_readback" : "Unsupported_preimage_fails_before_candidate" :
                component ? "Genuine_auth_provider_preserves_fleet_and_receipts_or_stops" : "Closed_Auth_" + item.CaseId.Replace('-', '_');
            if ((string?)result.Attribute("testName") != invocation.TestName || (string?)method.Attribute("className") != "Legacy.Maliev.DataMigration.Tests." + expectedClass ||
                (string?)method.Attribute("name") != expectedMethod || !SamePath((string?)method.Attribute("codeBase") ?? "", item.TestAssembly.Path) ||
                !SamePath((string?)unit.Attribute("storage") ?? "", item.TestAssembly.Path)) { throw Invalid(); }
            var before = Decode<CurrentAuthProofNative>(Read(item.NativeBefore)).Observation();
            var after = Decode<CurrentAuthProofNative>(Read(item.NativeAfter)).Observation();
            CurrentAuthProofScenario scenario = Decode<CurrentAuthProofScenario>(Read(item.Scenario));
            if (scenario.CaseId != item.CaseId || scenario.OperationId != invocation.OperationId || scenario.InvocationSha256 != item.InvocationArtifact.Sha256) { throw Invalid(); }
            if (helper)
            {
                string parameter = item.CaseId switch
                {
                    "history-10.0.12" => "10.0.12", "history-10.0.10" => "10.0.10", "reject-expression" => "unreviewed_auth_expression",
                    "reject-extended-statistics" => "unreviewed_auth_statistics", "reject-statistics" => "ANALYZE public.refresh_sessions;",
                    "reject-column" => "ADD COLUMN unreviewed", "reject-partial" => "TokenHash", _ => throw Invalid()
                };
                if (!invocation.TestName.Contains(parameter, StringComparison.Ordinal)) { throw Invalid(); }
                if (invocation.Command != "definition-current-auth-proof" || invocation.ExitCode != 0 || scenario.RetainedSlots.Count != 0) { throw Invalid(); }
                if (item.CaseId.StartsWith("history-", StringComparison.Ordinal))
                {
                    CurrentAuthNativePreservation.RequireBefore(before); CurrentAuthNativePreservation.RequirePreserved(before, after);
                    var rolled = Decode<CurrentAuthProofNative>(Read(item.RolledBack ?? throw Invalid())).Observation();
                    CurrentAuthNativePreservation.RequireBefore(rolled);
                    if (rolled.Snapshot.Sha256 != before.Snapshot.Sha256 || scenario.Boundary != "rollback-commit-independent-readback" || !scenario.CommitAcknowledged || scenario.RejectionCode is not null) { throw Invalid(); }
                }
                else
                {
                    bool rejected = false; try { CurrentAuthNativePreservation.RequireBefore(before); } catch (MigrationExecutionException) { rejected = true; }
                    if (!rejected || before.Snapshot.Sha256 != after.Snapshot.Sha256 || scenario.Boundary != "unsupported-preimage" || scenario.CommitAcknowledged || string.IsNullOrWhiteSpace(scenario.RejectionCode)) { throw Invalid(); }
                }
                continue;
            }
            if (!component && (item.CaseSigningPins is not null || item.CasePublicKeys is not null || item.ComponentObservation is not null || item.CaseSource is not null)) { throw Invalid(); }
            var caseScope = Decode<CurrentAuthRepairScope>(Read(item.Scope ?? throw Invalid()));
            var review = Decode<CurrentAuthRepairSignedClaim>(Read(item.Review ?? throw Invalid()));
            var authorization = Decode<CurrentAuthRepairSignedClaim>(Read(item.Authorization ?? throw Invalid()));
            if (caseScope.OperationId != invocation.OperationId || invocation.ScopeSha256 != item.Scope.Sha256 || invocation.ReviewSha256 != item.Review.Sha256 ||
                invocation.AuthorizationSha256 != item.Authorization.Sha256 || caseScope.ProofAdmission != (component ? CurrentAuthProofAdmission.DisposableNativeComponent : CurrentAuthProofAdmission.DisposableNativeBootstrap) ||
                (!component && (caseScope.SourceCommitSha != intended.SourceCommitSha || caseScope.SourceSchemaPlanSha256 != intended.SourceSchemaPlanSha256)) ||
                caseScope.AuthClosureSha256 != intended.AuthClosureSha256) { throw Invalid(); }
            RequireCaseScope(review.Scope, caseScope);
            var casePins = component ? Decode<CurrentAuthRepairSigningPins>(Read(item.CaseSigningPins ?? throw Invalid())) : pins;
            IReceiptAttestationTrustStore caseTrust = component ? CaseTrust(Read(item.CasePublicKeys ?? throw Invalid()), casePins,
                (caseScope.ComponentSubject ?? throw Invalid()).Seed.KeyId) : trust;
            if (component && new[] { casePins.ReviewFingerprint, casePins.AuthorizationFingerprint, casePins.ReceiptFingerprint }.Any(x => !usedCaseFingerprints.Add(x))) { throw Invalid(); }
            if (component)
            {
                var seed = caseScope.ComponentSubject!.Seed;
                CurrentAuthComponentBootstrap.RequireSeed(seed, trust, pins.ReviewKeyId, pins.ReviewFingerprint, invocation.StartedAtUtc);
                if (seed.AcceptedSourceCommitSha != intended.SourceCommitSha || seed.AcceptedSourceSchemaPlanSha256 != intended.SourceSchemaPlanSha256 ||
                    seed.DefinitionPrecursorSha256 != intended.AuthHelperProofSha256 || seed.ParentRunBindingSha256 != intended.RunBindingSha256 ||
                    seed.TestAssemblySha256 != item.TestAssembly.Sha256 || seed.ConsoleAssemblySha256 != proof.ConsoleAssemblySha256 ||
                    seed.CoreAssemblySha256 != proof.CoreAssemblySha256) { throw Invalid(); }
            }
            FreshSchemaPlan caseSource = component ? Decode<FreshSchemaPlan>(Read(item.CaseSource ?? throw Invalid())) : source;
            if (caseSource.SourceCommitSha != caseScope.SourceCommitSha || SchemaPlanCanonicalizer.ComputeSha256(caseSource) != caseScope.SourceSchemaPlanSha256 ||
                caseSource.Databases.Count != 23 || caseSource.Databases.Sum(x => x.Tables.Count) != 100 ||
                caseScope.AuthOwnerCommitSha != intended.AuthOwnerCommitSha || caseScope.AuthOwnerSourcePinsSha256 != intended.AuthOwnerSourcePinsSha256) { throw Invalid(); }
            CurrentAuthRepairPermit.ValidateClaims(review, authorization, caseSource, caseTrust, casePins, invocation.StartedAtUtc);
            string command = component ? "provider-current-auth-proof" : "apply-current-auth-repair";
            if (invocation.Command != command || (component && !invocation.TestName.Contains(item.CaseId, StringComparison.Ordinal)) ||
                invocation.ExitCode != (item.CaseId is "success" or "replay" ? 0 : 1)) { throw Invalid(); }
                        CurrentAuthProofRun run = proof.Runs.Single(x => x.RunId == invocation.RunId);
            if (component) { RequireComponentObservation(item, caseScope, run, Read); }
            else
            {
var config = Decode<CurrentAuthRepairConfiguration>(Read(item.Configuration ?? throw Invalid()));
            var binding = Decode<LocalExecutionBinding>(Read(item.RunBinding ?? throw Invalid()));
            var target = Decode<CurrentAppOwnedRepairTargetPins>(Read(item.TargetPins ?? throw Invalid()));
            if (invocation.ConfigurationSha256 != item.Configuration.Sha256 || config.ScopePath != item.Scope.Path || config.ReviewPath != item.Review.Path ||
                config.AuthorizationPath != item.Authorization.Path || config.RunBindingPath != item.RunBinding.Path || config.TargetPinsPath != item.TargetPins.Path ||
                binding.ComputeSha256() != caseScope.RunBindingSha256 || CurrentAppOwnedSnapshotSerialization.Sha256(target) != caseScope.TargetObservationSha256) { throw Invalid(); }
            if (target.DockerContainerId != run.ContainerId || target.DockerVolume != run.Volume ||
                CurrentAppOwnedRepairLocalTarget.RequireClaim(caseScope.Target, caseScope.OperationId, caseScope.RunBindingSha256, target)) { throw Invalid(); }
            using (var container = JsonDocument.Parse(Read(run.Container)))
            using (var volume = JsonDocument.Parse(Read(run.VolumeMetadata ?? throw Invalid())))
            {
                RequireDockerIdentity(container.RootElement,volume.RootElement,caseScope,target,run.LoopbackPort);
                CurrentAuthRepairEnvironment.RequireAuthDisposable(container.RootElement, volume.RootElement, caseScope.OperationId, caseScope.RunBindingSha256, invocation.StartedAtUtc);
                if (volume.RootElement.GetProperty("Driver").GetString() != "local" || volume.RootElement.GetProperty("Scope").GetString() != "local") { throw Invalid(); }
                string[] previousVolumes = Decode<string[]>(Read(run.PreviousVolumes ?? throw Invalid()));
                string[] consumers = Decode<string[]>(Read(run.VolumeConsumers ?? throw Invalid()));
                if (previousVolumes.Contains(run.Volume, StringComparer.Ordinal) || !consumers.SequenceEqual([run.ContainerId], StringComparer.Ordinal)) { throw Invalid(); }
            }
                        }
var fleetBefore = await files.ReadBaselineAsync((item.FleetBefore ?? throw Invalid()).Path, ct, sharedReader: true).ConfigureAwait(false);
            var fleetAfter = await files.ReadBaselineAsync((item.FleetAfter ?? throw Invalid()).Path, ct, sharedReader: true).ConfigureAwait(false);
            // Verify artifact bytes as well as pooled snapshot hashes. Stream hashing avoids a whole baseline byte array.
            RequireBaselineHash(item.FleetBefore!, files); RequireBaselineHash(item.FleetAfter!, files);
            if (fleetBefore.Length != 26 || fleetAfter.Length != 26 || fleetBefore.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != 26 ||
                fleetAfter.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != 26 ||
                !fleetBefore.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(caseScope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)) ||
                fleetBefore.Any(x => x.Sha256 != caseScope.BeforeDatabaseSha256[x.Database]) ||
                !fleetAfter.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(fleetBefore.Select(x => x.Database).Order(StringComparer.Ordinal)) ||
                fleetBefore.Where(x => x.Database != "Auth").Any(x => x.Sha256 != fleetAfter.Single(y => y.Database == x.Database).Sha256) ||
                before.Snapshot.Sha256 != fleetBefore.Single(x => x.Database == "Auth").Sha256 || after.Snapshot.Sha256 != fleetAfter.Single(x => x.Database == "Auth").Sha256) { throw Invalid(); }
            var observedPhysical = Decode<Dictionary<string, string>>(Read(item.SourcePhysical ?? throw Invalid()));
            if (observedPhysical.Count != 23 || !observedPhysical.Keys.Order(StringComparer.Ordinal).SequenceEqual(caseSource.Databases.Select(x => x.Database).Order(StringComparer.Ordinal)) ||
                caseSource.Databases.Any(x => observedPhysical[x.Database] != x.TargetSchemaSha256)) { throw Invalid(); }
            var policy = Decode<CurrentAuthProofPolicy>(Read(item.InstalledPolicy ?? throw Invalid()));
            RequirePolicy(policy, caseScope, invocation, item.CaseId, Read);
            if (item.CaseId is not ("host-unprobed-sdk" or "local-ordinary-trust") &&
                !scenario.OrdinaryRejectedDatabases.Order(StringComparer.Ordinal).SequenceEqual(caseScope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))) { throw Invalid(); }
            var receipts = new List<CurrentAuthRepairReceipt>(); string predecessor = new('0', 64);
            string candidateHash = after.Snapshot.Sha256;
            if (item.CaseId == "prepared-publication")
            {
                var candidate = Decode<CurrentAuthProofNative>(Read(item.PreparedCandidate ?? throw Invalid())).Observation();
                CurrentAuthNativePreservation.RequirePreserved(before, candidate); candidateHash = candidate.Snapshot.Sha256;
            }
            if (scenario.RetainedSlots.Select(x => x.Artifact.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != scenario.RetainedSlots.Count || scenario.RetainedSlots.Count(x => !x.Acknowledged) > 1) { throw Invalid(); }
            DateTimeOffset lastObserved=invocation.StartedAtUtc;
            foreach (CurrentAuthProofSlot slot in scenario.RetainedSlots)
            {
                byte[] receiptBytes = Read(slot.Artifact);
                var receipt = Decode<CurrentAuthRepairReceipt>(receiptBytes);
                if (!JsonSerializer.SerializeToUtf8Bytes(receipt).AsSpan().SequenceEqual(receiptBytes)) { throw Invalid(); }
                PostgreSqlCurrentAuthRepair.RequireReceipt(receipt, caseScope, CurrentAppOwnedSnapshotSerialization.Sha256(authorization), caseTrust, casePins, predecessor, invocation.ExitedAtUtc);
                RequireReceiptObservation(lastObserved,receipt.ObservedAtUtc);
                if (Path.GetFileName(slot.Artifact.Path) != $"{caseScope.OperationId:D}-Auth-{CurrentAuthRepairEnvironment.Suffix(receipt.Classification)}.json") { throw Invalid(); }
                if (item.CaseId is not ("host-unprobed-sdk" or "local-ordinary-trust") && receipt.AfterSha256 != candidateHash) { throw Invalid(); }
                lastObserved=receipt.ObservedAtUtc;
                if (slot.Acknowledged) { predecessor = slot.Artifact.Sha256; receipts.Add(receipt); }
                else if (!((item.CaseId == "prepared-publication" && receipt.Classification == CurrentAppOwnedCommitClassification.Prepared) ||
                    (item.CaseId == "terminal-publication" && receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback))) { throw Invalid(); }
            }
            RequireEffects(item.CaseId, scenario, receipts, before.Snapshot.Sha256, after.Snapshot.Sha256, component);
            if (item.CaseId is not ("host-unprobed-sdk" or "local-ordinary-trust"))
            { CurrentAuthNativePreservation.RequireBefore(before); if (before.Snapshot.Sha256 != after.Snapshot.Sha256) { CurrentAuthNativePreservation.RequirePreserved(before, after); } }
        }
        foreach (CurrentAuthProofRun run in proof.Runs) { RequireRun(run, proof, Read); }
        files.Require(); CurrentAuthRepairCapacity.Require(admission: false);
        byte[] Read(CurrentAuthProofArtifact value)
        {
            ct.ThrowIfCancellationRequested(); CurrentAuthRepairCapacity.Require(admission: false); byte[] bytes = files.Read(value.Path, sharedReader: true, maximumBytes: 8_000_000);
            if (CurrentAuthRepairPermit.Hash(bytes) != value.Sha256) { throw Invalid(); } return bytes;
        }
    }
    private static void RequireBaselineHash(CurrentAuthProofArtifact artifact, CurrentAppOwnedRepairCustody files)
    {
        files.Require(); using FileStream stream = SecureLocalFile.OpenReadShared(artifact.Path);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(stream, artifact.Path) || stream.Length is < 1 or > 512L * 1024 * 1024 ||
            Convert.ToHexStringLower(SHA256.HashData(stream)) != artifact.Sha256) { throw Invalid(); } files.Require();
    }
    internal static void RequireEffects(string id, CurrentAuthProofScenario scenario, IReadOnlyList<CurrentAuthRepairReceipt> receipts, string before, string after, bool component = false)
    {
        CurrentAppOwnedCommitClassification[] classifications = [.. receipts.Select(x => x.Classification)];
        bool unchanged = before == after, transitioned = !unchanged && receipts.FirstOrDefault(x => x.Classification == CurrentAppOwnedCommitClassification.Prepared)?.AfterSha256 == after;
        bool valid = id switch
        {
            "success" or "replay" => transitioned && scenario.CommitAcknowledged && scenario.Boundary == (id == "success" ? "complete" : "replay-blocked") &&
                (scenario.ReplayRejected == (id == "replay") || (component && id == "success" && scenario.ReplayRejected)) && classifications.SequenceEqual([CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback]),
            "prepared-publication" => unchanged && !scenario.CommitAcknowledged && scenario.Boundary == "prepared-publication-before-ack" &&
                classifications.Length == 1 && classifications[0] is CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or CurrentAppOwnedCommitClassification.FailedBeforeCommit,
            "lost-commit-ack" or "terminal-publication" => transitioned && scenario.CommitAcknowledged == (id == "terminal-publication") && scenario.Boundary == id &&
                classifications.SequenceEqual([CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.Uncertain]),
            "final-fleet" => transitioned && scenario.CommitAcknowledged && scenario.Boundary == "final-fleet-after-terminal" && classifications.SequenceEqual(
                [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback, CurrentAppOwnedCommitClassification.Uncertain]),
            "host-unprobed-sdk" or "local-ordinary-trust" => unchanged && !scenario.CommitAcknowledged && scenario.Boundary == "maintenance-semantic" &&
                scenario.RejectionCode == "current_app_owned_maintenance_hba_not_exclusive" && receipts.Count == 0 && scenario.RetainedSlots.Count == 0,
            _ => false
        };
        if (!valid || (id != "success" && string.IsNullOrWhiteSpace(scenario.RejectionCode)) ||
            (id == "success" && scenario.RejectionCode is not null) || receipts.Any(x => x.BeforeSha256 != before || x.Database != "Auth")) { throw Invalid(); }
    }
    private static void RequirePolicy(CurrentAuthProofPolicy policy, CurrentAuthRepairScope scope, CurrentAuthProofInvocation invocation,
        string caseId, Func<CurrentAuthProofArtifact, byte[]> read)
    {
        if (JsonSerializer.Serialize(policy.Scope) != JsonSerializer.Serialize(scope) || policy.ObservedAtUtc.Offset != TimeSpan.Zero ||
            policy.ObservedAtUtc < invocation.StartedAtUtc || policy.ObservedAtUtc > invocation.ExitedAtUtc || policy.RawHba.Sha256 != scope.Maintenance.HbaSha256 ||
            policy.HbaRules.Sha256 != scope.Maintenance.HbaRulesSha256 || !policy.Primary || !policy.Superuser || !policy.Login || policy.CreateRole || policy.CreateDatabase ||
            policy.Replication || policy.BypassRls || !policy.Scram || policy.Memberships != 0 || policy.DefaultAcls != 0 || policy.OtherClients != 0 ||
            policy.PreparedTransactions != 0 || policy.EventTriggers != 0) { throw Invalid(); }
        if (policy.SystemIdentifierSha256 != scope.Target.SystemIdentifierSha256 || policy.Postmaster != scope.Maintenance.Postmaster ||
            policy.ConfigLoaded != scope.Maintenance.ConfigLoaded || policy.Role != scope.Maintenance.Role || policy.RoleExpiresAtUtc != scope.Maintenance.ExpiresAtUtc ||
            policy.RoleComment != scope.Maintenance.RoleComment || policy.HbaPath != scope.Maintenance.HbaPath || policy.ObservedAtUtc >= policy.RoleExpiresAtUtc) { throw Invalid(); }
        _ = read(policy.RawHba);
        using var rulesDocument = JsonDocument.Parse(read(policy.HbaRules));
        var rules = rulesDocument.RootElement.EnumerateArray().Select(row => new CurrentAppOwnedMaintenanceHbaRule(
            row.GetProperty("rule_number").GetInt32(), row.GetProperty("type").GetString()!, Strings(row, "database"), Strings(row, "user_name"),
            Text(row, "address"), Text(row, "netmask"), row.GetProperty("auth_method").GetString()!, Strings(row, "options"), Text(row, "error"))).ToArray();
        if (JsonSerializer.Serialize(rules) != JsonSerializer.Serialize(policy.Rules)) { throw Invalid(); }
        if (caseId is "host-unprobed-sdk" or "local-ordinary-trust")
        {
            bool rejected = false; try { CurrentAppOwnedMaintenanceHba.Require(rules, scope.Maintenance.Role, scope.Target.Kind); }
            catch (MigrationExecutionException) { rejected = true; } if (!rejected) { throw Invalid(); }
        }
        else { CurrentAppOwnedMaintenanceHba.Require(rules, scope.Maintenance.Role, scope.Target.Kind); }
        static string? Text(JsonElement row, string name) => row.GetProperty(name).ValueKind == JsonValueKind.Null ? null : row.GetProperty(name).GetString();
        static string[] Strings(JsonElement row, string name) => row.GetProperty(name).ValueKind == JsonValueKind.Null ? [] : [.. row.GetProperty(name).EnumerateArray().Select(x => x.GetString()!)];
    }
    private static void RequireRun(CurrentAuthProofRun run, CurrentAuthClosedProof proof, Func<CurrentAuthProofArtifact, byte[]> read)
    {
        if (run.RunId == Guid.Empty || run.ContainerId.Length != 64 || !run.ContainerId.All(char.IsAsciiHexDigitLower) || run.LoopbackPort is < 1 or > 65535) { throw Invalid(); }
        using var attempt = JsonDocument.Parse(read(run.Attempt)); using var disposed = JsonDocument.Parse(read(run.Disposed));
        DateTimeOffset began = attempt.RootElement.GetProperty("began").GetDateTimeOffset(), expires = attempt.RootElement.GetProperty("expires").GetDateTimeOffset();
        DateTimeOffset completed = disposed.RootElement.GetProperty("completedAtUtc").GetDateTimeOffset();
        if (attempt.RootElement.GetProperty("run").GetGuid() != run.RunId || attempt.RootElement.GetProperty("name").GetString() != run.Name || attempt.RootElement.GetProperty("persistent").GetBoolean() ||
            disposed.RootElement.GetProperty("run").GetGuid() != run.RunId || disposed.RootElement.GetProperty("containerId").GetString() != run.ContainerId ||
            !disposed.RootElement.GetProperty("removed").GetBoolean() || !disposed.RootElement.GetProperty("disposed").GetBoolean() || disposed.RootElement.GetProperty("cleanupFailed").GetBoolean() ||
            began.Offset != TimeSpan.Zero || expires.Offset != TimeSpan.Zero || completed.Offset != TimeSpan.Zero || began < proof.BeganAtUtc || expires - began != TimeSpan.FromMinutes(8) ||
            completed < began || completed > proof.CompletedAtUtc || completed > expires.AddMinutes(1)) { throw Invalid(); }
        using var metadata = JsonDocument.Parse(read(run.Container)); JsonElement container = metadata.RootElement;
        DateTimeOffset created = container.GetProperty("Created").GetDateTimeOffset();
        if (created.Offset != TimeSpan.Zero || created < began.AddSeconds(-1) || created > expires ||
            proof.Cases.Where(x => x.Invocation.RunId == run.RunId).Any(x => x.Invocation.StartedAtUtc < began || x.Invocation.ExitedAtUtc > expires)) { throw Invalid(); }
        using var image = JsonDocument.Parse(read(run.ImageMetadata ?? throw Invalid()));
        if (image.RootElement.GetProperty("Id").GetString() != container.GetProperty("Image").GetString() ||
            !image.RootElement.GetProperty("RepoDigests").EnumerateArray().Any(x => x.GetString() == "postgres@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382")) { throw Invalid(); }
        JsonElement host = container.GetProperty("HostConfig"), config = container.GetProperty("Config");
        if (container.GetProperty("Id").GetString() != run.ContainerId || container.GetProperty("Name").GetString() != "/" + run.Name || config.GetProperty("Image").GetString() != Image ||
            host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("NanoCpus").GetInt64() != 750000000 ||
            !Empty(host, "Binds") || !Empty(host, "VolumesFrom") || !Empty(host, "Mounts") ||
            container.GetProperty("NetworkSettings").GetProperty("Ports").EnumerateObject().Any(port => port.Value.ValueKind != JsonValueKind.Null && port.Value.EnumerateArray().Any(x => x.GetProperty("HostIp").GetString() != "127.0.0.1"))) { throw Invalid(); }
        if (run.Volume is null)
        {
            if (run.Name != "auth-closure-proof-" + run.RunId.ToString("N") || container.GetProperty("Mounts").GetArrayLength() != 0 ||
                host.GetProperty("Tmpfs").EnumerateObject().Count() != 1 || host.GetProperty("Tmpfs").GetProperty("/var/lib/postgresql").GetString() != "rw,nosuid,size=384m") { throw Invalid(); }
            using var capacity = JsonDocument.Parse(read(run.FilesystemCapacity ?? throw Invalid()));
            if (capacity.RootElement.GetProperty("run").GetGuid() != run.RunId || capacity.RootElement.GetProperty("containerId").GetString() != run.ContainerId ||
                capacity.RootElement.GetProperty("capacityBytes").GetInt64() != 384L * 1024 * 1024 ||
                config.GetProperty("Labels").GetProperty("codex.repair.purpose").GetString() != "current-auth-native-proof" ||
                config.GetProperty("Labels").GetProperty("codex.repair.operation").GetString() != run.RunId.ToString("D")) { throw Invalid(); }
        }
        var absence = Decode<CurrentAuthProofAbsence>(read(run.Absence));
        DateTimeOffset removedAt=disposed.RootElement.GetProperty("removedAtUtc").GetDateTimeOffset();        if ((run.ProxyCreated is null) != (run.ProxyDisposed is null)) { throw Invalid(); }
        if (run.ProxyCreated is not null)
        {
            using var createdProxy = JsonDocument.Parse(read(run.ProxyCreated)); using var disposedProxy = JsonDocument.Parse(read(run.ProxyDisposed!));
            int proxyPort = createdProxy.RootElement.GetProperty("port").GetInt32();
            if (createdProxy.RootElement.GetProperty("operation").GetGuid() != run.RunId || createdProxy.RootElement.GetProperty("persistent").GetBoolean() ||
                createdProxy.RootElement.GetProperty("processId").GetInt32() < 1 || proxyPort is < 1 or > 65535 ||
                !CurrentAuthRepairPermit.HashShape(createdProxy.RootElement.GetProperty("executableSha256").GetString()!) ||
                disposedProxy.RootElement.GetProperty("operation").GetGuid() != run.RunId || disposedProxy.RootElement.GetProperty("port").GetInt32() != proxyPort ||
                !disposedProxy.RootElement.GetProperty("workerCompleted").GetBoolean() || disposedProxy.RootElement.GetProperty("completedAtUtc").GetDateTimeOffset() > removedAt ||
                absence.ListeningPorts.Contains(proxyPort)) { throw Invalid(); }
        }
        DateTimeOffset lastExited=proof.Cases.Where(x=>x.Invocation.RunId==run.RunId).Max(x=>x.Invocation.ExitedAtUtc);
        RequireCleanupChronology(lastExited,removedAt,absence.ObservedAtUtc,completed,expires,proof.CompletedAtUtc);
        if (absence.RunId != run.RunId || absence.ObservedAtUtc.Offset != TimeSpan.Zero || absence.ObservedAtUtc < began || absence.ObservedAtUtc > completed ||
            !absence.ContainersObserved || !absence.VolumesObserved || !absence.ListenersObserved || !absence.SecretsAbsent ||
            absence.ContainerIds.Contains(run.ContainerId, StringComparer.Ordinal) || absence.ContainerNames.Contains(run.Name, StringComparer.Ordinal) || absence.ContainerNames.Contains("/" + run.Name, StringComparer.Ordinal) ||
            (run.Volume is not null && absence.VolumeNames.Contains(run.Volume, StringComparer.Ordinal)) || absence.ListeningPorts.Contains(run.LoopbackPort)) { throw Invalid(); }
        static bool Empty(JsonElement host, string field) => !host.TryGetProperty(field, out JsonElement value) || value.ValueKind == JsonValueKind.Null ||
            (value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 0);
    }
    internal static void RequireReceiptObservation(DateTimeOffset previous,DateTimeOffset current)
    {if(previous.Offset!=TimeSpan.Zero || current.Offset!=TimeSpan.Zero || current<previous) {throw Invalid();}}
    internal static void RequireCaseScope(CurrentAuthRepairScope reviewed,CurrentAuthRepairScope held)
    {if(JsonSerializer.Serialize(reviewed)!=JsonSerializer.Serialize(held)) {throw Invalid();}}
    internal static void RequireCleanupChronology(DateTimeOffset exited,DateTimeOffset removed,DateTimeOffset observed,
        DateTimeOffset disposed,DateTimeOffset lease,DateTimeOffset proofCompleted)
    {
        if(new[] {exited,removed,observed,disposed,lease,proofCompleted}.Any(x=>x.Offset!=TimeSpan.Zero) ||
            removed<exited || observed<removed || disposed<observed || disposed>lease.AddMinutes(1) || disposed>proofCompleted) {throw Invalid();}
    }
    internal static void RequireDockerIdentity(JsonElement container,JsonElement volume,CurrentAuthRepairScope scope,
        CurrentAppOwnedRepairTargetPins target,int port)
    {
        try
        {
            if(container.GetProperty("Id").GetString()!=target.DockerContainerId || container.GetProperty("Image").GetString()!=target.DockerImageId ||
                container.GetProperty("Config").GetProperty("Image").GetString()!=target.DockerImageReference ||
                target.DockerImageReference!=Image || volume.GetProperty("Name").GetString()!=target.DockerVolume)
            {throw Invalid();}
            string pgData=container.GetProperty("Config").GetProperty("PgData").GetString() ?? throw Invalid();
            if(target.HbaPath!=pgData.TrimEnd('/')+"/pg_hba.conf") {throw Invalid();}
            var projected=JsonSerializer.SerializeToElement(new
            {
                Id=target.DockerContainerId,Name=container.GetProperty("Name").GetString(),
                Created=container.GetProperty("Created"),State=container.GetProperty("State"),
                Mounts=container.GetProperty("Mounts"),NetworkSettings=container.GetProperty("NetworkSettings"),
                Config=new {Env=new[] {"PGDATA="+pgData}}
            });
            DockerLocalTargetObservation observed=DockerLocalTargetObservation.Parse("["+projected.GetRawText()+"]","["+volume.GetRawText()+"]",
                target.DockerContainerId ?? throw Invalid(),target.DockerVolume ?? throw Invalid(),port,false);
            if(observed.VolumeDestination!="/var/lib/postgresql" || LocalDockerGenerationGuard.ComposeGeneration(observed)!=scope.TargetGeneration)
            {throw Invalid();}
        }
        catch(Exception failure) when(failure is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or MigrationConsoleException)
        {throw Invalid();}
    }    private static ReceiptAttestationTrustStore CaseTrust(byte[] bytes, CurrentAuthRepairSigningPins pins, string parentKeyId)
    {
        CurrentAuthProofPublicKey[] keys = Decode<CurrentAuthProofPublicKey[]>(bytes);
        if (keys.Length != 4 || keys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != 4 ||
            !keys.Select(x => x.KeyId).Order(StringComparer.Ordinal).SequenceEqual(new[] { pins.ReviewKeyId, pins.AuthorizationKeyId, pins.ReceiptKeyId, parentKeyId }.Order(StringComparer.Ordinal))) { throw Invalid(); }
        var trust = new ReceiptAttestationTrustStore(keys.Select(x => new TrustedAttestationKey(x.KeyId, Convert.FromBase64String(x.SubjectPublicKeyInfoBase64))));
        if (!trust.TryGetPublicKeyFingerprintSha256(pins.ReviewKeyId, out string r) || r != pins.ReviewFingerprint ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.AuthorizationKeyId, out string a) || a != pins.AuthorizationFingerprint ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.ReceiptKeyId, out string e) || e != pins.ReceiptFingerprint ||
            new[] { r, a, e }.Distinct(StringComparer.Ordinal).Count() != 3) { throw Invalid(); }
        return trust;
    }
    private static void RequireComponentObservation(CurrentAuthProofCase item, CurrentAuthRepairScope scope, CurrentAuthProofRun run,
        Func<CurrentAuthProofArtifact, byte[]> read)
    {
        if (scope.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeComponent ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) || item.Configuration is not null || item.TargetPins is not null || item.RunBinding is not null)
        { throw Invalid(); }
        var observation = Decode<CurrentAuthProofComponentObservation>(read(item.ComponentObservation ?? throw Invalid()));
        if (observation.Kind != "current-auth-disposable-component-observation-v1" ||
            observation.SourceEvidenceKind != "generated-synthetic-schema-physically-observed-not-accepted-source-capture") { throw Invalid(); }
        var binding = Decode<LocalExecutionBinding>(read(observation.HeldBinding));
        if (binding.ComputeSha256() != scope.RunBindingSha256) { throw Invalid(); }
        using var containerDoc = JsonDocument.Parse(read(run.Container)); using var volumeDoc = JsonDocument.Parse(read(run.VolumeMetadata ?? throw Invalid()));
        JsonElement container = containerDoc.RootElement, volume = volumeDoc.RootElement, config = container.GetProperty("Config");
        string pgData = config.GetProperty("PgData").GetString() ?? throw Invalid();
        var subject = scope.ComponentSubject ?? throw Invalid();
        if (subject.ContainerId != run.ContainerId || subject.ContainerName != run.Name || subject.AnonymousVolumeName != run.Volume ||
            subject.ActualImageId != observation.ActualImageId || subject.PgData != pgData || subject.ActualTargetGeneration != observation.ActualTargetGeneration ||
            subject.ContainerObservationSha256 != run.Container.Sha256 || subject.VolumeObservationSha256 != run.VolumeMetadata?.Sha256) { throw Invalid(); }
        if (container.GetProperty("Image").GetString() != observation.ActualImageId ||
            !observation.ActualImageId.StartsWith("sha256:", StringComparison.Ordinal) || observation.ActualImageId.Length != 71 ||
            scope.Maintenance.HbaPath != pgData.TrimEnd('/') + "/pg_hba.conf" ||
            config.GetProperty("Labels").GetProperty("codex.repair.purpose").GetString() != "current-auth-guarded-native-proof" ||
            config.GetProperty("Labels").GetProperty("codex.repair.operation").GetString() != run.RunId.ToString("D") ||
            run.Name != "auth-guarded-provider-" + run.RunId.ToString("N") || run.Volume is null || run.Volume.Length != 64 || !run.Volume.All(char.IsAsciiHexDigitLower) ||
            volume.GetProperty("Name").GetString() != run.Volume || volume.GetProperty("Driver").GetString() != "local" || volume.GetProperty("Scope").GetString() != "local") { throw Invalid(); }
        if (volume.TryGetProperty("Options", out JsonElement options) && options.ValueKind != JsonValueKind.Null && options.EnumerateObject().Any()) { throw Invalid(); }
        if (volume.TryGetProperty("Labels", out JsonElement labels) && labels.ValueKind != JsonValueKind.Null && labels.EnumerateObject().Any() &&
            (labels.EnumerateObject().Count() != 1 || !labels.TryGetProperty("com.docker.volume.anonymous", out JsonElement anonymous) || anonymous.GetString() != string.Empty)) { throw Invalid(); }
        string[] previous = Decode<string[]>(read(run.PreviousVolumes ?? throw Invalid())), consumers = Decode<string[]>(read(run.VolumeConsumers ?? throw Invalid()));
        if (previous.Contains(run.Volume, StringComparer.Ordinal) || !consumers.SequenceEqual([run.ContainerId], StringComparer.Ordinal)) { throw Invalid(); }
                if (ComponentGeneration(container, volume, run) != observation.ActualTargetGeneration) { throw Invalid(); }
using var attempt = JsonDocument.Parse(read(run.Attempt));
        DateTimeOffset created = volume.GetProperty("CreatedAt").GetDateTimeOffset();
        if (created < attempt.RootElement.GetProperty("began").GetDateTimeOffset().AddSeconds(-1) || created > attempt.RootElement.GetProperty("expires").GetDateTimeOffset()) { throw Invalid(); }
    }
    internal static string ComponentGeneration(JsonElement container, JsonElement volume, CurrentAuthProofRun run)
    {
        string pgData = container.GetProperty("Config").GetProperty("PgData").GetString() ?? throw Invalid();
        JsonElement[] mounts = [.. container.GetProperty("Mounts").EnumerateArray()];
        if (mounts.Length != 1 || mounts[0].GetProperty("Type").GetString() != "volume" ||
            mounts[0].GetProperty("Name").GetString() != run.Volume || mounts[0].GetProperty("Destination").GetString() != "/var/lib/postgresql" ||
            !mounts[0].GetProperty("RW").GetBoolean() || !pgData.StartsWith("/var/lib/postgresql/", StringComparison.Ordinal) ||
            !container.GetProperty("State").GetProperty("Running").GetBoolean()) { throw Invalid(); }
        JsonElement ports = container.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp");
        if (ports.ValueKind != JsonValueKind.Array || ports.GetArrayLength() != 1 || ports[0].GetProperty("HostIp").GetString() != "127.0.0.1" ||
            ports[0].GetProperty("HostPort").GetString() != run.LoopbackPort.ToString(CultureInfo.InvariantCulture)) { throw Invalid(); }
        DateTimeOffset created = container.GetProperty("Created").GetDateTimeOffset().ToUniversalTime(),
            started = container.GetProperty("State").GetProperty("StartedAt").GetDateTimeOffset().ToUniversalTime(),
            volumeCreated = volume.GetProperty("CreatedAt").GetDateTimeOffset().ToUniversalTime();
        if (created > started || volumeCreated > started || started > DateTimeOffset.UtcNow) { throw Invalid(); }
        return LocalDockerGenerationGuard.ComposeGeneration(new DockerLocalTargetObservation(run.ContainerId, "/" + run.Name,
            run.Volume ?? throw Invalid(), "/var/lib/postgresql", pgData, created, started, volumeCreated));
    }
    private static T Decode<T>(byte[] bytes) => MigrationConsole.DecodeAuthRepair<T>(bytes);
    private static string AssemblyHash(string path) { using FileStream stream = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    private static bool SamePath(string left, string right) => Path.IsPathFullyQualified(left) && Path.IsPathFullyQualified(right) && StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(left), Path.GetFullPath(right));
    private static MigrationExecutionException Invalid() => new("current_auth_executed_proof_invalid", "Current Auth requires authentic executed typed proof readback.");
}
