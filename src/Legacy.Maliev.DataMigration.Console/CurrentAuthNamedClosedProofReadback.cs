using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthNamedClosedCase(string CaseId, Guid OperationId, string Root,
    string BindingPath, string BindingSha256, IReadOnlyList<CurrentAuthProofArtifact> Artifacts);
internal sealed record CurrentAuthNamedClosedReport(string Kind, string Phase, string SubjectSha256,
    string SourceCommitSha, CurrentAuthProofArtifact Host, CurrentAuthProofArtifact LaneInput,
    CurrentAuthProofArtifact HostScope, DateTimeOffset CompletedAtUtc,
    IReadOnlyList<CurrentAuthNamedClosedCase> Cases, string KeyId, string? Signature);

// Semantic reader for actual eight named Console cases. It is deliberately separate
// from the six anonymous provider cases; no component artifact becomes a closed case.
internal static class CurrentAuthNamedClosedProofReadback
{
    internal static readonly string[] Cases = ["success", "prepared-publication", "lost-commit-ack", "terminal-publication", "host-unprobed-sdk", "local-ordinary-trust", "final-fleet", "replay"];
    internal static byte[] Payload(CurrentAuthNamedClosedReport value) =>
        [.. "Legacy.Maliev.CurrentAuth.NamedClosedReport.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(value with { Signature = null })];
    internal static void RequireCaseSet(IReadOnlyList<CurrentAuthNamedClosedCase> cases)
    {
        if (cases is null || cases.Count != 8 || cases.Any(x => x is null) || !cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(Cases.Order(StringComparer.Ordinal)) ||
            cases.Any(x => x.OperationId == Guid.Empty) || cases.Select(x => x.OperationId).Distinct().Count() != 8 ||
            cases.Select(x => x.Root).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 8)
        { throw CurrentAuthRepairPermit.Invalid(); }
    }

    internal static async Task RequireAsync(CurrentAppOwnedRepairCustody files, LocalExecutionBinding binding,
        CurrentAuthNamedClosedReport report, CurrentAuthRepairScope intended, FreshSchemaPlan source,
        CurrentAuthRepairSigningPins pins, IReceiptAttestationTrustStore trust, bool requireSignature,
        CurrentAppOwnedRepairCustody? heldIntendedFiles, CancellationToken ct)
    {
        files.Require(); CurrentAuthRepairCapacity.Require(admission: false);
        RequireCaseSet(report.Cases);
        if (report.Kind != "current-auth-eight-named-console-proof-v1" || report.Phase is not ("native" or "recovery" or "maintenance") ||
            report.SourceCommitSha != intended.SourceCommitSha ||
            report.SourceCommitSha != source.SourceCommitSha || report.KeyId != pins.ReceiptKeyId ||
            !trust.TryGetPublicKeyFingerprintSha256(report.KeyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint ||
            report.CompletedAtUtc.Offset != TimeSpan.Zero || report.CompletedAtUtc > DateTimeOffset.UtcNow ||
            !report.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(Cases.Order(StringComparer.Ordinal)) ||
            report.Cases.Select(x => x.OperationId).Distinct().Count() != 8 || report.Cases.Select(x => x.Root).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 8)
        { throw CurrentAuthRepairPermit.Invalid(); }
        if (requireSignature)
        {
            if (string.IsNullOrWhiteSpace(report.Signature) || !trust.Verify(report.KeyId, Payload(report), Convert.FromBase64String(report.Signature)))
            { throw CurrentAuthRepairPermit.Invalid(); }
        }
        else if (report.Signature is not null) { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] Read(CurrentAuthProofArtifact artifact, int cap = 32 * 1024 * 1024)
        {
            byte[] value = files.Read(artifact.Path, sharedReader: true, maximumBytes: cap);
            if (CurrentAuthRepairPermit.Hash(value) != artifact.Sha256) { throw CurrentAuthRepairPermit.Invalid(); } return value;
        }
        var host = MigrationConsole.DecodeAuthRepair<CurrentAuthTypedHostExit>(Read(report.Host));
        var hostScope = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairScope>(Read(report.HostScope));
        CurrentAuthTypedProofAssembler.RequireHost(host, binding, hostScope, pins, trust, DateTimeOffset.UtcNow);
        if (host.Group != "closed" || host.ExitedAtUtc > report.CompletedAtUtc) { throw CurrentAuthRepairPermit.Invalid(); }
        CurrentAuthTypedProofAssembler.RequireCapacity(MigrationConsole.DecodeAuthRepair<CurrentAuthTypedHostCapacity[]>(Read(host.Capacity)), host);
        FileStream actualTest = files.BorrowReadStream(host.TestAssemblyPath, 128L * 1024 * 1024);
        if (Convert.ToHexStringLower(await SHA256.HashDataAsync(actualTest, ct).ConfigureAwait(false)) != host.TestAssemblySha256) { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] processJournalBytes = Read(host.ProcessObservations ?? throw CurrentAuthRepairPermit.Invalid());
        string processJournal = new UTF8Encoding(false, true).GetString(processJournalBytes);
        if (!processJournal.EndsWith('\n')) { throw CurrentAuthRepairPermit.Invalid(); }
        JsonElement[] processFrames = [.. processJournal.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line =>
            { if (line.Length > 65536) { throw CurrentAuthRepairPermit.Invalid(); } using var frame = JsonDocument.Parse(line); return frame.RootElement.Clone(); })];
        if (processFrames.Length is < 1 or > 20000) { throw CurrentAuthRepairPermit.Invalid(); }
        var input = MigrationConsole.DecodeAuthRepair<CurrentAuthClosedLaneConfiguration>(Read(report.LaneInput));
        if (input.ParentRunBindingSha256 != binding.ComputeSha256() || input.TestAssemblyPath != host.TestAssemblyPath ||
            input.TestAssemblySha256 != host.TestAssemblySha256 || input.ConsoleAssemblySha256 != host.ConsoleAssemblySha256 || input.CoreAssemblySha256 != host.CoreAssemblySha256)
        { throw CurrentAuthRepairPermit.Invalid(); }
        var intent = heldIntendedFiles is null
            ? await CurrentAuthNamedClosedIntent.ReadHeldAsync(input.IntendedEvidence, source, ct).ConfigureAwait(false)
            : await CurrentAuthNamedClosedIntent.ReadThroughOperationalCustodyAsync(input.IntendedEvidence, source, heldIntendedFiles, ct).ConfigureAwait(false);
        if (report.SubjectSha256 != CurrentAuthNamedClosedIntent.Subject(intent) || intent.TestAssemblySha256 != host.TestAssemblySha256 ||
            intent.ConsoleAssemblySha256 != host.ConsoleAssemblySha256 || intent.CoreAssemblySha256 != host.CoreAssemblySha256 ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(input.IntendedEvidence.RunBindingPath), binding.ArtifactRootCanonicalPath))
        { throw CurrentAuthRepairPermit.Invalid(); }
        if (intended.ProofAdmission == CurrentAuthProofAdmission.ClosedConsole) { CurrentAuthNamedClosedIntent.RequireRuntime(intent, intended); }
        else if (intended.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeBootstrap) { throw CurrentAuthRepairPermit.Invalid(); }
        await CurrentAuthClosedBootstrapReadback.RequireCompletedForHostAsync(input.CompletedComponents, source,
            host.TestAssemblySha256, host.ConsoleAssemblySha256, host.CoreAssemblySha256, ct).ConfigureAwait(false);
        using var xml = XmlReader.Create(new MemoryStream(Read(host.Trx, 8_000_000), writable: false), new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        XDocument trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        XElement[] results = [.. trx.Descendants(ns + "UnitTestResult")];
        if (results.Length != 8 || results.Any(x => (string?)x.Attribute("outcome") != "Passed") ||
            results.Select(x => (string?)x.Attribute("testId")).Distinct().Count() != 8 ||
            results.Select(x => (string?)x.Attribute("executionId")).Distinct().Count() != 8) { throw CurrentAuthRepairPermit.Invalid(); }
        using var absent = JsonDocument.Parse(Read(host.IndependentAbsence ?? throw CurrentAuthRepairPermit.Invalid()));
        if (absent.RootElement.GetProperty("observedAtUtc").GetDateTimeOffset() < host.ExitedAtUtc || absent.RootElement.GetProperty("group").GetString() != "closed")
        { throw CurrentAuthRepairPermit.Invalid(); }
        var allKeyIds = new HashSet<string>(StringComparer.Ordinal); var allFingerprints = new HashSet<string>(StringComparer.Ordinal);
        foreach (CurrentAuthNamedClosedCase item in report.Cases)
        {
            ct.ThrowIfCancellationRequested(); CurrentAuthRepairCapacity.Require(admission: false);
            if (item.OperationId == Guid.Empty || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(item.Root), binding.ArtifactRootCanonicalPath) ||
                Path.GetFileName(item.Root) != "auth-closed-case-" + item.OperationId.ToString("N") ||
                !StringComparer.OrdinalIgnoreCase.Equals(item.BindingPath, Path.Combine(item.Root, "fixture-binding.json"))) { throw CurrentAuthRepairPermit.Invalid(); }
            LocalExecutionBinding childBinding = ReadBinding(item.BindingPath);
            if (childBinding.ComputeSha256() != item.BindingSha256 || !StringComparer.OrdinalIgnoreCase.Equals(childBinding.ArtifactRootCanonicalPath, item.Root))
            { throw CurrentAuthRepairPermit.Invalid(); }
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(item.Root, childBinding);
            using var held = new CurrentAppOwnedRepairCustody(authority);
            string[] current = Directory.GetFiles(item.Root, "*", SearchOption.TopDirectoryOnly).Where(x => Path.GetFileName(x) != WindowsLocalRunAuthority.RunLockRelativeName).Order(StringComparer.OrdinalIgnoreCase).ToArray();
            if (Directory.EnumerateDirectories(item.Root).Any() || item.Artifacts.Count is < 20 or > 8000 ||
                !current.SequenceEqual(item.Artifacts.Select(x => x.Path).Order(StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase))
            { throw CurrentAuthRepairPermit.Invalid(); }
            foreach (CurrentAuthProofArtifact artifact in item.Artifacts)
            {
                FileStream stream = held.BorrowReadStream(artifact.Path); string sha = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false));
                if (sha != artifact.Sha256) { throw CurrentAuthRepairPermit.Invalid(); } held.Require();
            }
            byte[] Bytes(string name, int cap = 32 * 1024 * 1024) => held.Read(Path.Combine(item.Root, name), sharedReader: true, maximumBytes: cap);
            T Decode<T>(string name) => MigrationConsole.DecodeAuthRepair<T>(Bytes(name));
            JsonDocument Doc(string name) => JsonDocument.Parse(Bytes(name));
            string One(string pattern) => Path.GetFileName(Directory.GetFiles(item.Root, pattern).Single());
            using var executed = Doc(One("auth-closed-resource-*-test-image.json"));
            if (!StringComparer.OrdinalIgnoreCase.Equals(executed.RootElement.GetProperty("testAssemblyPath").GetString(), host.TestAssemblyPath) ||
                executed.RootElement.GetProperty("TestAssemblySha256").GetString() != host.TestAssemblySha256 ||
                executed.RootElement.GetProperty("ConsoleAssemblySha256").GetString() != host.ConsoleAssemblySha256 ||
                executed.RootElement.GetProperty("CoreAssemblySha256").GetString() != host.CoreAssemblySha256 ||
                !processFrames.Any(frame => frame.GetProperty("Processes").EnumerateArray().Any(p =>
                    p.GetProperty("ProcessId").GetInt32() == executed.RootElement.GetProperty("processId").GetInt32() &&
                    p.GetProperty("StartTimeUtc").GetDateTimeOffset() == executed.RootElement.GetProperty("processStartTimeUtc").GetDateTimeOffset() &&
                    !p.GetProperty("Exited").GetBoolean() && p.GetProperty("WorkingSetBytes").GetUInt64() > 0)))
            { throw CurrentAuthRepairPermit.Invalid(); }
            var config = Decode<CurrentAuthRepairConfiguration>("closed-config.json");
            var scope = Decode<CurrentAuthRepairScope>("closed-scope.json"); var caseSource = Decode<FreshSchemaPlan>("closed-source.json");
            var casePins = Decode<CurrentAuthRepairSigningPins>("closed-signing-pins.json"); var target = Decode<CurrentAppOwnedRepairTargetPins>("closed-target-pins.json");
            var seed = scope.ClosedBootstrapSubject ?? throw CurrentAuthRepairPermit.Invalid();
            if (config.ScopePath != Path.Combine(item.Root, "closed-scope.json") || config.RunBindingPath != Path.Combine(item.Root, "closed-binding.json") ||
                Decode<LocalExecutionBinding>("closed-binding.json") != childBinding || scope.OperationId != item.OperationId || seed.CaseId != item.CaseId ||
                config.ClosedBootstrap is null || JsonSerializer.Serialize(config.ClosedBootstrap.Seed) != JsonSerializer.Serialize(seed) ||
                caseSource.SourceCommitSha != intended.SourceCommitSha || SchemaPlanCanonicalizer.ComputeSha256(caseSource) != intended.SourceSchemaPlanSha256)
            { throw CurrentAuthRepairPermit.Invalid(); }
            if (CurrentAppOwnedSnapshotSerialization.Sha256(target) != scope.TargetObservationSha256 ||
                scope.RunBindingSha256 != childBinding.ComputeSha256()) { throw CurrentAuthRepairPermit.Invalid(); }
            var caseTrust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
                Convert.FromBase64String(Encoding.UTF8.GetString(held.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))))));
            if (config.TrustedKeys.Count != 4 || config.TrustedKeys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != 4)
            { throw CurrentAuthRepairPermit.Invalid(); }
            foreach ((string key, string pin) in new[] { (casePins.ReviewKeyId, casePins.ReviewFingerprint), (casePins.AuthorizationKeyId, casePins.AuthorizationFingerprint), (casePins.ReceiptKeyId, casePins.ReceiptFingerprint) })
            {
                if (!caseTrust.TryGetPublicKeyFingerprintSha256(key, out string actual) || actual != pin || !allKeyIds.Add(key) || !allFingerprints.Add(actual))
                { throw CurrentAuthRepairPermit.Invalid(); }
            }
            using var calls = Doc("closed-invocations.json"); JsonElement[] invocations = [.. calls.RootElement.EnumerateArray()];
            bool unsafePolicy = item.CaseId is "host-unprobed-sdk" or "local-ordinary-trust";
            string[] commands = unsafePolicy ? ["review-current-auth-repair"] : item.CaseId == "replay"
                ? ["review-current-auth-repair", "authorize-current-auth-repair", "verify-current-auth-repair", "apply-current-auth-repair", "apply-current-auth-repair"]
                : ["review-current-auth-repair", "authorize-current-auth-repair", "verify-current-auth-repair", "apply-current-auth-repair"];
            if (!invocations.Select(x => x.GetProperty("command").GetString()).SequenceEqual(commands, StringComparer.Ordinal)) { throw CurrentAuthRepairPermit.Invalid(); }
            DateTimeOffset first = invocations[0].GetProperty("startedAtUtc").GetDateTimeOffset(), last = invocations[^1].GetProperty("exitedAtUtc").GetDateTimeOffset();
            DateTimeOffset previous = first;
            foreach (JsonElement call in invocations)
            {
                DateTimeOffset start = call.GetProperty("startedAtUtc").GetDateTimeOffset(), end = call.GetProperty("exitedAtUtc").GetDateTimeOffset();
                int expected = unsafePolicy || (call.GetProperty("command").GetString() == "apply-current-auth-repair" && item.CaseId is not ("success" or "replay")) ? 1 : 0;
                if (item.CaseId == "replay" && call.Equals(invocations[^1])) { expected = 1; }
                if (call.GetProperty("operation").GetGuid() != item.OperationId || start.Offset != TimeSpan.Zero || end.Offset != TimeSpan.Zero || start < previous || end < start || end > host.ExitedAtUtc ||
                    call.GetProperty("exitCode").GetInt32() != expected) { throw CurrentAuthRepairPermit.Invalid(); } previous = end;
            }
            XElement result = results.Single(x => ((string?)x.Attribute("testName"))?.Contains("caseId: \"" + item.CaseId + "\"", StringComparison.Ordinal) == true);
            XElement definition = trx.Descendants(ns + "UnitTest").Single(x => (string?)x.Attribute("id") == (string?)result.Attribute("testId"));
            XElement method = definition.Element(ns + "TestMethod") ?? throw CurrentAuthRepairPermit.Invalid();
            if ((string?)method.Attribute("name") != "Genuine_named_closed_auth_console_preserves_or_stops" ||
                !((string?)method.Attribute("className"))!.StartsWith("Legacy.Maliev.DataMigration.Tests.CurrentAuthClosedConsoleExecutionTests", StringComparison.Ordinal) ||
                !StringComparer.OrdinalIgnoreCase.Equals((string?)definition.Attribute("storage"), host.TestAssemblyPath) ||
                !StringComparer.OrdinalIgnoreCase.Equals((string?)method.Attribute("codeBase"), host.TestAssemblyPath) ||
                DateTimeOffset.Parse((string)result.Attribute("startTime")!, CultureInfo.InvariantCulture) > first ||
                DateTimeOffset.Parse((string)result.Attribute("endTime")!, CultureInfo.InvariantCulture) < last)
            { throw CurrentAuthRepairPermit.Invalid(); }
            var precursorPins = ReadPrecursorPins(input.CompletedComponents);
            CurrentAuthClosedBootstrap.RequireScope(seed, scope, caseSource, caseTrust, precursorPins.ReviewKeyId, precursorPins.ReviewFingerprint, first);
            CurrentAuthNativeObservation before = Decode<CurrentAuthProofNative>("auth-template-native-before.json").Observation(), after = Decode<CurrentAuthProofNative>("closed-native-after.json").Observation();
            CurrentAuthNativePreservation.RequireBefore(before);
            if (before.Snapshot.Sha256 != scope.BeforeDatabaseSha256["Auth"]) { throw CurrentAuthRepairPermit.Invalid(); }
            if (unsafePolicy || item.CaseId == "prepared-publication")
            { if (before.Snapshot.Sha256 != after.Snapshot.Sha256) { throw CurrentAuthRepairPermit.Invalid(); } }
            else { CurrentAuthNativePreservation.RequirePreserved(before, after); }
            using var container = Doc(One("auth-closed-resource-*-target.json")); using var volume = Doc(Directory.GetFiles(item.Root, "auth-closed-resource-*-volume.json").Order(StringComparer.Ordinal).Select(Path.GetFileName).First()!);
            int port = int.Parse(container.RootElement.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp")[0].GetProperty("HostPort").GetString()!, CultureInfo.InvariantCulture);
            CurrentAuthRepairProofReader.RequireDockerIdentity(container.RootElement, volume.RootElement, scope, target, port);
            CurrentAuthRepairEnvironment.RequireAuthDisposable(container.RootElement, volume.RootElement, item.OperationId, item.BindingSha256, first);
            var policy = Decode<CurrentAuthProofPolicy>("closed-policy.json");
            RequirePolicy(policy, scope, unsafePolicy, Bytes);
            if (policy.ObservedAtUtc.Offset != TimeSpan.Zero || policy.ObservedAtUtc < seed.IssuedAtUtc || policy.ObservedAtUtc > first)
            { throw CurrentAuthRepairPermit.Invalid(); }
            using var attempts = Doc("closed-ordinary-attempts.json");
            if (!attempts.RootElement.EnumerateArray().Select(x => x.GetProperty("database").GetString()).Order(StringComparer.Ordinal).SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)))
            { throw CurrentAuthRepairPermit.Invalid(); }
            foreach (JsonElement attempt in attempts.RootElement.EnumerateArray())
            {
                bool admitted = attempt.GetProperty("admitted").GetBoolean();
                DateTimeOffset began = attempt.GetProperty("beganAtUtc").GetDateTimeOffset(), observed = attempt.GetProperty("observedAtUtc").GetDateTimeOffset();
                if (began < policy.ObservedAtUtc || observed < began || observed > first || admitted != (item.CaseId == "host-unprobed-sdk") ||
                    (!admitted && attempt.GetProperty("sqlState").GetString() != "28000")) { throw CurrentAuthRepairPermit.Invalid(); }
            }
            var fleetPool = new CurrentAppOwnedSnapshotInternPool();
            FileStream beforeStream = held.BorrowReadStream(config.GlobalBeforePath);
            var baseline = await CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(beforeStream, fleetPool, ct).ConfigureAwait(false);
            held.Require();
            FileStream afterStream = held.BorrowReadStream(Path.Combine(item.Root, "closed-fleet-after.json"));
            var endFleet = await CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(afterStream, fleetPool, ct).ConfigureAwait(false);
            held.Require();
            if (baseline.Length != 26 || endFleet.Length != 26 || baseline.Select(x => x.Database).Distinct().Count() != 26 || endFleet.Select(x => x.Database).Distinct().Count() != 26 ||
                !baseline.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal).OrderBy(x => x.Key).SequenceEqual(scope.BeforeDatabaseSha256.OrderBy(x => x.Key)) ||
                endFleet.Any(x => x.Sha256 != (x.Database == "Auth" ? after.Snapshot.Sha256 : scope.BeforeDatabaseSha256[x.Database])))
            { throw CurrentAuthRepairPermit.Invalid(); }
            if (unsafePolicy)
            {
                if (File.Exists(config.ReviewPath) || File.Exists(config.AuthorizationPath) || Directory.GetFiles(item.Root, item.OperationId.ToString("D") + "-*.json").Length != 0)
                { throw CurrentAuthRepairPermit.Invalid(); }
            }
            else
            {
                var review = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairSignedClaim>(held.Read(config.ReviewPath, sharedReader: true, maximumBytes: 65536));
                var authorization = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairSignedClaim>(held.Read(config.AuthorizationPath, sharedReader: true, maximumBytes: 65536));
                CurrentAuthRepairProofReader.RequireCaseScope(review.Scope, scope);
                CurrentAuthRepairPermit.ValidateClaims(review, authorization, caseSource, caseTrust, casePins, invocations[3].GetProperty("startedAtUtc").GetDateTimeOffset());
                var locked = Decode<CurrentAuthProofNative>(One("auth-closed-observation-*-locked-before.json")).Observation();
                var candidate = Decode<CurrentAuthProofNative>(One("auth-closed-observation-*-native-candidate.json")).Observation();
                if (locked.Snapshot.Sha256 != before.Snapshot.Sha256) { throw CurrentAuthRepairPermit.Invalid(); }
                CurrentAuthNativePreservation.RequirePreserved(locked, candidate);
                var prepared = Decode<CurrentAuthRepairReceipt>(item.OperationId.ToString("D") + "-Auth-prepared.json");
                if (prepared.AfterSha256 != candidate.Snapshot.Sha256) { throw CurrentAuthRepairPermit.Invalid(); }
                RequireReceipts(item, held, scope, authorization, caseTrust, casePins, before, after, last);
            }
            if (item.CaseId == "lost-commit-ack")
            {
                using var created = Doc("auth-closed-proxy-" + item.OperationId.ToString("N") + "-created.json");
                using var proxy = Doc("auth-closed-proxy-" + item.OperationId.ToString("N") + "-disposed.json");
                if (created.RootElement.GetProperty("_operation").GetGuid() != item.OperationId || created.RootElement.GetProperty("upstreamPort").GetInt32() != port ||
                    created.RootElement.GetProperty("loopbackAddress").GetString() != "127.0.0.1" || created.RootElement.GetProperty("upstreamAddress").GetString() != "127.0.0.1" ||
                    proxy.RootElement.GetProperty("_operation").GetGuid() != item.OperationId || proxy.RootElement.GetProperty("droppedCommits").GetInt32() != 1 ||
                    !proxy.RootElement.GetProperty("workerCompleted").GetBoolean() || !proxy.RootElement.GetProperty("readersSettled").GetBoolean() || proxy.RootElement.GetProperty("cleanupFailed").GetBoolean() ||
                    proxy.RootElement.GetProperty("droppedAtUtc").GetDateTimeOffset() < proxy.RootElement.GetProperty("armedAtUtc").GetDateTimeOffset() ||
                    proxy.RootElement.GetProperty("completedAtUtc").GetDateTimeOffset() > last)
                { throw CurrentAuthRepairPermit.Invalid(); }
            }
            using var disposed = Doc(One("auth-closed-resource-*-disposed.json")); using var absence = Doc(One("auth-closed-resource-*-absent.json"));
            using var returned = Doc("closed-case-return.json");
            DateTimeOffset returnedAt = returned.RootElement.GetProperty("returnedAtUtc").GetDateTimeOffset();
            if (returnedAt < last || returnedAt > host.ExitedAtUtc || disposed.RootElement.GetProperty("cleanupFailed").GetBoolean() ||
                !disposed.RootElement.GetProperty("removed").GetBoolean() || !disposed.RootElement.GetProperty("sdkDisposed").GetBoolean() ||
                !disposed.RootElement.GetProperty("verifiedAbsence").GetBoolean() || !absence.RootElement.GetProperty("secretsAbsent").GetBoolean())
            { throw CurrentAuthRepairPermit.Invalid(); }
            CurrentAuthRepairProofReader.RequireCleanupChronology(returnedAt, disposed.RootElement.GetProperty("removedAtUtc").GetDateTimeOffset(),
                absence.RootElement.GetProperty("observedAtUtc").GetDateTimeOffset(), disposed.RootElement.GetProperty("completedAtUtc").GetDateTimeOffset(),
                disposed.RootElement.GetProperty("expiresAtUtc").GetDateTimeOffset(), report.CompletedAtUtc);
            RequireAbsent(absence.RootElement, scope, target.DockerContainerId ?? throw CurrentAuthRepairPermit.Invalid(), port);
            RequireAbsent(absent.RootElement, scope, target.DockerContainerId ?? throw CurrentAuthRepairPermit.Invalid(), port); held.Require();
        }
        files.Require();
    }

    private static void RequireReceipts(CurrentAuthNamedClosedCase item, CurrentAppOwnedRepairCustody files, CurrentAuthRepairScope scope,
        CurrentAuthRepairSignedClaim authorization, IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins,
        CurrentAuthNativeObservation before, CurrentAuthNativeObservation after, DateTimeOffset last)
    {
        string[] receiptPaths = Directory.GetFiles(item.Root, item.OperationId.ToString("D") + "-Auth-*.json");
        var receipts = receiptPaths.Select(path => (Path: path, Receipt: MigrationConsole.DecodeAuthRepair<CurrentAuthRepairReceipt>(files.Read(path, sharedReader: true, maximumBytes: 65536))))
            .OrderBy(x => x.Receipt.ObservedAtUtc).ToArray();
        string predecessor = CurrentAuthRetainedReceiptChainInitial(); string authorizationHash = CurrentAppOwnedSnapshotSerialization.Sha256(authorization);
        DateTimeOffset previous = authorization.IssuedAtUtc; var acknowledged = new List<CurrentAuthRepairReceipt>();
        foreach (var value in receipts)
        {
            PostgreSqlCurrentAuthRepair.RequireReceipt(value.Receipt, scope, authorizationHash, trust, pins, predecessor, last);
            if (value.Receipt.ObservedAtUtc < previous) { throw CurrentAuthRepairPermit.Invalid(); } previous = value.Receipt.ObservedAtUtc;
            string suffix = CurrentAuthRepairEnvironment.Suffix(value.Receipt.Classification);
            bool unack = (item.CaseId == "prepared-publication" && suffix == "prepared") || (item.CaseId == "terminal-publication" && suffix == "committed-readback");
            if (unack)
            {
                string marker = Path.Combine(item.Root, "auth-closed-unacknowledged-" + item.OperationId.ToString("N") + "-" + suffix + ".json");
                using var frame = JsonDocument.Parse(files.Read(marker, sharedReader: true, maximumBytes: 65536));
                if (frame.RootElement.GetProperty("name").GetString() != Path.GetFileName(value.Path) || frame.RootElement.GetProperty("acknowledged").GetBoolean() ||
                    frame.RootElement.GetProperty("sha256").GetString() != CurrentAuthRepairPermit.Hash(files.Read(value.Path, sharedReader: true, maximumBytes: 65536)))
                { throw CurrentAuthRepairPermit.Invalid(); }
            }
            else
            {
                acknowledged.Add(value.Receipt);
                if (value.Receipt.Classification is CurrentAppOwnedCommitClassification.Prepared or CurrentAppOwnedCommitClassification.CommittedAndReadback)
                { predecessor = CurrentAppOwnedSnapshotSerialization.Sha256(value.Receipt); }
            }
        }
        CurrentAppOwnedCommitClassification[] actual = [.. acknowledged.Select(x => x.Classification)];
        bool valid = item.CaseId switch
        {
            "success" or "replay" => actual.SequenceEqual([CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback]),
            "prepared-publication" => actual.Length == 1 && actual[0] is CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or CurrentAppOwnedCommitClassification.FailedBeforeCommit,
            "lost-commit-ack" or "terminal-publication" => actual.SequenceEqual([CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.Uncertain]),
            "final-fleet" => actual.SequenceEqual([CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback, CurrentAppOwnedCommitClassification.Uncertain]),
            _ => false
        };
        if (!valid || receipts.Any(x => x.Receipt.BeforeSha256 != before.Snapshot.Sha256) ||
            (item.CaseId == "prepared-publication" ? before.Snapshot.Sha256 != after.Snapshot.Sha256 :
                receipts.Single(x => x.Receipt.Classification == CurrentAppOwnedCommitClassification.Prepared).Receipt.AfterSha256 != after.Snapshot.Sha256))
        { throw CurrentAuthRepairPermit.Invalid(); }
        var reservation = Path.Combine(item.Root, item.OperationId.ToString("D") + "-auth-operation-start.json");
        using var start = JsonDocument.Parse(files.Read(reservation, sharedReader: true, maximumBytes: 65536));
        if (start.RootElement.GetProperty("Kind").GetString() != "current-auth-operation-start-v1" || start.RootElement.GetProperty("OperationId").GetGuid() != item.OperationId ||
            start.RootElement.GetProperty("ScopeSha256").GetString() != CurrentAppOwnedSnapshotSerialization.Sha256(scope) || start.RootElement.GetProperty("AuthorizationSha256").GetString() != authorizationHash)
        { throw CurrentAuthRepairPermit.Invalid(); }
        // These are exact provider classifications/readbacks, not a supplied success marker.
    }
    private static string CurrentAuthRetainedReceiptChainInitial() => new CurrentAuthRetainedReceiptChain().PreviousSha256;
    private static void RequirePolicy(CurrentAuthProofPolicy policy, CurrentAuthRepairScope scope, bool unsafePolicy, Func<string, int, byte[]> read)
    {
        if (JsonSerializer.Serialize(policy.Scope) != JsonSerializer.Serialize(scope) || policy.SystemIdentifierSha256 != scope.Target.SystemIdentifierSha256 ||
            policy.Postmaster != scope.Maintenance.Postmaster || policy.ConfigLoaded != scope.Maintenance.ConfigLoaded || policy.Role != scope.Maintenance.Role ||
            policy.RoleExpiresAtUtc != scope.Maintenance.ExpiresAtUtc || policy.RoleComment != scope.Maintenance.RoleComment || policy.HbaPath != scope.Maintenance.HbaPath ||
            policy.RawHba.Sha256 != scope.Maintenance.HbaSha256 || policy.HbaRules.Sha256 != scope.Maintenance.HbaRulesSha256 ||
            !policy.Primary || !policy.Superuser || !policy.Login || policy.CreateRole || policy.CreateDatabase || policy.Replication || policy.BypassRls || !policy.Scram ||
            policy.Memberships != 0 || policy.DefaultAcls != 0 || policy.OtherClients != 0 || policy.PreparedTransactions != 0 || policy.EventTriggers != 0 ||
            CurrentAuthRepairPermit.Hash(read(Path.GetFileName(policy.RawHba.Path), 65536)) != policy.RawHba.Sha256 ||
            CurrentAuthRepairPermit.Hash(read(Path.GetFileName(policy.HbaRules.Path), 65536)) != policy.HbaRules.Sha256)
        { throw CurrentAuthRepairPermit.Invalid(); }
        using var rawRules = JsonDocument.Parse(read(Path.GetFileName(policy.HbaRules.Path), 65536));
        CurrentAppOwnedMaintenanceHbaRule[] parsed = [.. rawRules.RootElement.EnumerateArray().Select(row => new CurrentAppOwnedMaintenanceHbaRule(
            row.GetProperty("rule_number").GetInt32(), row.GetProperty("type").GetString()!, Strings(row, "database"), Strings(row, "user_name"),
            Text(row, "address"), Text(row, "netmask"), row.GetProperty("auth_method").GetString()!, Strings(row, "options"), Text(row, "error")))];
        if (JsonSerializer.Serialize(parsed) != JsonSerializer.Serialize(policy.Rules)) { throw CurrentAuthRepairPermit.Invalid(); }
        bool rejected = false;
        try { CurrentAppOwnedMaintenanceHba.Require(policy.Rules, scope.Maintenance.Role, scope.Target.Kind); }
        catch (MigrationExecutionException) { rejected = true; }
        if (rejected != unsafePolicy) { throw CurrentAuthRepairPermit.Invalid(); }
        static string? Text(JsonElement row, string name) => row.GetProperty(name).ValueKind == JsonValueKind.Null ? null : row.GetProperty(name).GetString();
        static string[] Strings(JsonElement row, string name) => row.GetProperty(name).ValueKind == JsonValueKind.Null ? [] : [.. row.GetProperty(name).EnumerateArray().Select(x => x.GetString()!)];
    }
    private static void RequireAbsent(JsonElement value, CurrentAuthRepairScope scope, string containerId, int port)
    {
        string name = "legacy-delta-proof-" + scope.OperationId.ToString("N");
        if (value.GetProperty("containerIds").EnumerateArray().Any(x => x.GetString() == containerId) || value.GetProperty("containerNames").EnumerateArray().Any(x => x.GetString()?.TrimStart('/') == name) ||
            value.GetProperty("volumeNames").EnumerateArray().Any(x => x.GetString() == name) || value.GetProperty("listeningPorts").EnumerateArray().Any(x => x.GetInt32() == port))
        { throw CurrentAuthRepairPermit.Invalid(); }
    }
    private static LocalExecutionBinding ReadBinding(string path)
    {
        using var file = SecureLocalFile.OpenReadShared(path); if (file.Length is < 1 or > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] bytes = new byte[checked((int)file.Length)]; file.ReadExactly(bytes); return MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bytes);
    }
    private static CurrentAuthRepairSigningPins ReadPrecursorPins(CurrentAuthClosedBootstrapEvidence evidence)
    {
        var binding = ReadBinding(evidence.PrecursorRunBindingPath);
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        return MigrationConsole.DecodeAuthRepair<CurrentAuthRepairSigningPins>(files.Read(evidence.PrecursorSigningPinsPath, sharedReader: true, maximumBytes: 65536));
    }
}
