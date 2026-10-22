using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal static class IsoNamedClosedProofReader
{
    internal static byte[] Payload(IsoNamedClosedProof proof)
    {
        return [.. "Legacy.Maliev.OwnerIso.CompletedNamedConsole.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(proof with { Signature = null })];
    }

    internal static async Task RequireAsync(CurrentAppOwnedRepairCustody files, IsoNamedClosedProof proof, IsoDefinitionSubject expected,
        IReceiptAttestationTrustStore trust, string keyId, string fingerprint, DateTimeOffset now, CancellationToken ct)
    {
        if (proof.KeyId != keyId || string.IsNullOrWhiteSpace(proof.Signature) || !trust.TryGetPublicKeyFingerprintSha256(keyId, out string actual) || actual != fingerprint) { throw Invalid(); }
        try { if (!trust.Verify(keyId, Payload(proof), Convert.FromBase64String(proof.Signature))) { throw Invalid(); } } catch (FormatException) { throw Invalid(); }
        await RequireBodyAsync(files, proof, expected, now, ct).ConfigureAwait(false);
    }
    internal static async Task RequireBodyAsync(CurrentAppOwnedRepairCustody files, IsoNamedClosedProof proof, IsoDefinitionSubject expected, DateTimeOffset now, CancellationToken ct)
    {
        string[] required = IsoComponentCases.Required(proof.Phase);
        if (proof.Kind != "current-owner-iso-completed-named-console-v1" || CurrentAppOwnedSnapshotSerialization.Sha256(proof.DefinitionSubject) != CurrentAppOwnedSnapshotSerialization.Sha256(expected) ||
            proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > now || proof.ExpiresAtUtc <= now || proof.ExpiresAtUtc - proof.BeganAtUtc > TimeSpan.FromHours(12) ||
            proof.Cases.Count != required.Length || !proof.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(required.Order(StringComparer.Ordinal)) ||
            proof.Cases.Select(x => x.OperationId).Distinct().Count() != required.Length || proof.ExecutedTestAssembly.Sha256 != expected.TestAssemblySha256) { throw Invalid(); }
        var host = Read<OwnerIsoGuardedBootstrapHostExit>(proof.Host.Exit);
        if (host.ExitCode != 0 || !host.ProcessExitObserved || !host.NativeMembershipObserved || !host.EmptyJobObservedAfterExit || host.JobNonce != proof.Host.Nonce ||
            host.TestAssemblySha256 != expected.TestAssemblySha256 || !host.RunIds.Order().SequenceEqual(proof.Cases.Select(x => x.OperationId).Order())) { throw Invalid(); }
        using var cleanup = JsonDocument.Parse(Bytes(proof.Host.Cleanup)); using var absence = JsonDocument.Parse(Bytes(proof.Host.PostExitAbsence));
        var clean = cleanup.RootElement; var absent = absence.RootElement;
        if (clean.GetProperty("nonce").GetString() != host.JobNonce || !clean.GetProperty("allMemberExitObserved").GetBoolean() || !clean.GetProperty("waitingChildExited").GetBoolean() ||
            !clean.GetProperty("streamsSettled").GetBoolean() || clean.GetProperty("cleanupFailure").GetBoolean() || clean.GetProperty("completedAtUtc").GetDateTimeOffset() < host.ExitedAtUtc ||
            clean.GetProperty("completedAtUtc").GetDateTimeOffset() > proof.CompletedAtUtc || absent.GetProperty("nonce").GetString() != host.JobNonce ||
            absent.GetProperty("observedAtUtc").GetDateTimeOffset() < host.ExitedAtUtc || absent.GetProperty("observedAtUtc").GetDateTimeOffset() > clean.GetProperty("completedAtUtc").GetDateTimeOffset() ||
            !absent.GetProperty("containerInventorySucceeded").GetBoolean() || !absent.GetProperty("volumeInventorySucceeded").GetBoolean() || !absent.GetProperty("listenerInventorySucceeded").GetBoolean()) { throw Invalid(); }
        bool memberObserved = false;
        foreach (var artifact in proof.Host.JobFrames)
        {
            using var frame = JsonDocument.Parse(Bytes(artifact)); var f = frame.RootElement; if (f.GetProperty("nonce").GetString() != host.JobNonce) { throw Invalid(); }
            var capacity = f.GetProperty("Capacity"); CurrentOwnerIsoCapacity.RequireValues(capacity.GetProperty("AvailablePhysicalBytes").GetUInt64(), capacity.GetProperty("OwnedRssBytes").GetUInt64(), false);
            foreach (var process in f.GetProperty("Processes").EnumerateArray())
            { if (process.GetProperty("ProcessId").GetInt32() == host.ProcessId && process.GetProperty("StartTimeUtc").GetDateTimeOffset() == host.ProcessStartTimeUtc && process.GetProperty("ExecutableSha256").GetString() == host.ExecutableSha256) { memberObserved = true; } }
        }
        if (!memberObserved) { throw Invalid(); }
        using var child = JsonDocument.Parse(Bytes(proof.Host.ChildConfiguration)); var configuration = child.RootElement.GetProperty("Configuration");
        if (child.RootElement.GetProperty("Nonce").GetString() != host.JobNonce || configuration.GetProperty("Group").GetString() != (proof.Phase == IsoComponentProofPhase.Native ? "native-closed" : "maintenance-closed") ||
            configuration.GetProperty("TestAssemblySha256").GetString() != expected.TestAssemblySha256 || configuration.GetProperty("ConsoleAssemblySha256").GetString() != expected.ConsoleAssemblySha256 || configuration.GetProperty("CoreAssemblySha256").GetString() != expected.CoreAssemblySha256 ||
            !Bytes(proof.Host.RunSettings).AsSpan().SequenceEqual("<RunSettings><RunConfiguration><MaxCpuCount>1</MaxCpuCount></RunConfiguration></RunSettings>"u8)) { throw Invalid(); }
        _ = Bytes(proof.Host.Stdout); _ = Bytes(proof.Host.Stderr); _ = Bytes(proof.ExecutedTestAssembly, 512 * 1024 * 1024);
        using var xml = XmlReader.Create(new MemoryStream(Bytes(proof.Trx), false), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 }); var trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var results = trx.Descendants(ns + "UnitTestResult").ToArray(); var counters = trx.Descendants(ns + "Counters").Single();
        if (results.Length != required.Length || results.Any(x => (string?)x.Attribute("outcome") != "Passed") || (string?)counters.Attribute("failed") != "0" ||
            (string?)counters.Attribute("passed") != required.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) || (string?)counters.Attribute("total") != (string?)counters.Attribute("passed")) { throw Invalid(); }
        foreach (var item in proof.Cases)
        {
            ct.ThrowIfCancellationRequested(); if (item.TestName != IsoComponentCases.Method(item.CaseId)) { throw Invalid(); }
            var result = results.Single(x => (string?)x.Attribute("testId") == item.TestId && (string?)x.Attribute("executionId") == item.ExecutionId);
            var definition = trx.Descendants(ns + "UnitTest").Single(x => (string?)x.Attribute("id") == item.TestId); var method = definition.Element(ns + "TestMethod") ?? throw Invalid();
            if ((string?)result.Attribute("testName") != item.TestName || (string?)method.Attribute("className") != "Legacy.Maliev.DataMigration.Tests.CurrentOwnerIsoClosedConsoleExecutionTests" || (string?)method.Attribute("name") != item.TestName ||
                (string?)definition.Element(ns + "Execution")?.Attribute("id") != item.ExecutionId) { throw Invalid(); }
            CurrentOwnerIsoClosedProofReader.RequireExecutedAssemblyPath(proof.ExecutedTestAssemblyPath, proof.ExecutedTestAssembly.SourcePath ?? proof.ExecutedTestAssembly.Path, (string?)method.Attribute("codeBase"), (string?)definition.Attribute("storage"));
            var parent = Read<IsoNamedClosedHostEntry>(item.ParentEntry); var entry = parent.Host;
            if (entry.RunId != item.OperationId || entry.CaseId != item.CaseId || entry.JobNonce != host.JobNonce || !entry.NativeJobMembershipObserved || entry.ProcessId != host.ProcessId || entry.ProcessStartTimeUtc != host.ProcessStartTimeUtc || entry.ExecutableSha256 != host.ExecutableSha256 || entry.TestAssemblySha256 != expected.TestAssemblySha256) { throw Invalid(); }
            if (item.Files.Count is < 1 or > 3000 || item.Files.Any(x => x.SourcePath is null) || item.Files.Select(x => x.SourcePath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != item.Files.Count) { throw Invalid(); }
            var artifacts = item.Files.ToDictionary(x => x.SourcePath!, StringComparer.OrdinalIgnoreCase); foreach (var artifact in item.Files) { _ = Digest(artifact); }
            var config = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairConfiguration>(Bytes(item.Configuration));
            T Case<T>(string path)
            {
                return MigrationConsole.DecodeOwnerIso<T>(Bytes(artifacts.TryGetValue(path, out var artifact) ? artifact : throw Invalid(), 32 * 1024 * 1024));
            }

            var scope = Case<CurrentOwnerIsoRepairScope>(config.ScopePath); var source = Case<FreshSchemaPlan>(config.SourceSchemaPath); var owners = Case<CurrentOwnerIsoSourceObservation[]>(config.OwnersPath); var pins = Case<CurrentOwnerIsoRepairSigningPins>(config.SigningPinsPath);
            var binding = Case<LocalExecutionBinding>(config.RunBindingPath); var target = Case<CurrentAppOwnedRepairTargetPins>(config.TargetPinsPath);
            var keys = config.TrustedKeys.Select(x => new TrustedAttestationKey(x.KeyId, Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(Bytes(artifacts[x.SubjectPublicKeyInfoPath])).Trim()))).ToArray(); var caseTrust = new ReceiptAttestationTrustStore(keys);
            var validationCalls = Read<IsoNamedClosedInvocation[]>(item.Files.Single(x => Path.GetFileName(x.SourcePath) == "iso-closed-case-" + item.OperationId.ToString("N") + "-closed-invocations-final.json"));
            if (validationCalls.Length == 0) { throw Invalid(); }
            CurrentOwnerIsoRepairPermit.ValidateClosedBootstrapScope(scope, source, owners, caseTrust, pins, validationCalls[0].StartedAtUtc);
            if (scope.OperationId != item.OperationId || binding.ComputeSha256() != scope.RunBindingSha256 || scope.BootstrapSubject!.CaseId != item.CaseId ||
                scope.SourceCommitSha != expected.SourceCommitSha || scope.SourceCatalogSha256 != expected.SourceCatalogSha256 || scope.BeforeSchemaPlanSha256 != expected.SourceSchemaPlanSha256 || scope.OwnerSourcesSha256 != expected.OwnerSourcesSha256 || scope.ContractSha256 != expected.ContractSha256 ||
                scope.BootstrapSubject.Claim.Subject.ConsoleAssemblySha256 != expected.ConsoleAssemblySha256 || scope.BootstrapSubject.Claim.Subject.CoreAssemblySha256 != expected.CoreAssemblySha256 || scope.BootstrapSubject.Claim.Subject.TestAssemblySha256 != expected.TestAssemblySha256) { throw Invalid(); }
            // The original separate precursor roots are retained. Reauthenticate them under
            // their own custody, without a recursive active-root lock or a forged seed.
            await IsoClosedBootstrapReadback.RequireAsync(files, binding, scope, config.ClosedBootstrap ?? throw Invalid(), ct).ConfigureAwait(false);
            string prefix = "iso-closed-case-" + item.OperationId.ToString("N") + "-";
            IsoDefinitionArtifact Find(string name)
            {
                return item.Files.Single(x => Path.GetFileName(x.SourcePath) == prefix + name);
            }

            IsoDefinitionArtifact Frame(string phase)
            {
                return item.Files.Single(x => Path.GetFileName(x.SourcePath)!.StartsWith("iso-closed-resource-" + item.OperationId.ToString("N") + "-", StringComparison.Ordinal) && Path.GetFileName(x.SourcePath)!.EndsWith("-" + phase + ".json", StringComparison.Ordinal));
            }

            var calls = Read<IsoNamedClosedInvocation[]>(Find("closed-invocations-final.json")); RequireCalls(item.CaseId, calls, item.OperationId);
            DateTimeOffset began = calls[0].StartedAtUtc, ended = calls[^1].ExitedAtUtc;
            var before = await files.ReadBaselineAsync(artifacts[config.GlobalBeforePath].Path, ct, sharedReader: true).ConfigureAwait(false); var after = await files.ReadBaselineAsync(Find("closed-fleet-after.json").Path, ct, sharedReader: true).ConfigureAwait(false);
            if (before.Length != 26 || after.Length != 26 || !before.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)) ||
                before.Any(x => x.Sha256 != scope.BeforeDatabaseSha256[x.Database]) || CurrentAppOwnedSnapshotSerialization.Sha256(before) != scope.GlobalPreservationSha256 || !after.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(before.Select(x => x.Database).Order(StringComparer.Ordinal))) { throw Invalid(); }
            var contract = ApprovedCurrentOwnerIsoOverlay.Create(source, scope.SourceCommitSha, scope.Operation, owners, began);
            foreach (string database in new[] { "Country", "Material" })
            {
                var original = Read<IsoCapturedNative>(Find("before-native-" + database + ".json")).Observe(); var current = Read<IsoCapturedNative>(Frame("after-native-" + database)).Observe(); CurrentOwnerIsoNativePreservation.RequireBefore(original, contract);
                bool selected = database == "Material" ? item.CaseId == "complete" : item.CaseId is "complete" or "lost-commit-ack" or "terminal-publication" or "fleet-drift";
                if (original.Snapshot.Sha256 != scope.BeforeDatabaseSha256[database] || current.Snapshot.Sha256 != after.Single(x => x.Database == database).Sha256) { throw Invalid(); }
                var candidateArtifacts = item.Files.Where(x => Path.GetFileName(x.SourcePath)!.EndsWith("-candidate-" + database + ".json", StringComparison.Ordinal)).ToArray();
                foreach (var artifact in candidateArtifacts) { CurrentOwnerIsoNativePreservation.RequirePreserved(original, Read<IsoCapturedNative>(artifact).Observe(), contract); }
                if (selected) { var candidate = Read<IsoCapturedNative>(item.Files.Single(x => Path.GetFileName(x.SourcePath)!.EndsWith("-candidate-" + database + ".json", StringComparison.Ordinal))).Observe(); CurrentOwnerIsoNativePreservation.RequirePreserved(original, current, contract); CurrentOwnerIsoNamedClosedProofEnvironment.RequireReadback(candidate, current); }
                else if (current.Selected || current.Snapshot.Sha256 != original.Snapshot.Sha256) { throw Invalid(); }
            }
            bool rejected = item.CaseId is "wrong-owner" or "unsafe-host" or "local-trust";
            bool executed = !rejected && item.CaseId is not ("ordinary-all26" or "exclusive-policy");
            var policy = Read<JsonElement>(Find("installed-policy.json"));
            var pin = MigrationConsole.DecodeOwnerIso<CurrentAppOwnedMaintenancePin>(System.Text.Encoding.UTF8.GetBytes(policy.GetProperty("Pin").GetRawText()));
            string rawHba = policy.GetProperty("rawHba").GetString() ?? throw Invalid(), rawRules = policy.GetProperty("rawRules").GetString() ?? throw Invalid();
            if (CurrentAppOwnedSnapshotSerialization.Sha256(pin) != CurrentAppOwnedSnapshotSerialization.Sha256(scope.Maintenance) ||
                policy.GetProperty("Identity").GetString() != scope.Target.SystemIdentifierSha256 || CurrentAppOwnedRepairPermit.Hash(System.Text.Encoding.UTF8.GetBytes(rawHba)) != pin.HbaSha256 || CurrentAppOwnedRepairPermit.Hash(System.Text.Encoding.UTF8.GetBytes(rawRules)) != pin.HbaRulesSha256) { throw Invalid(); }
            IsoMaintenanceNativeObserver.Require(Read<IsoMaintenanceNativeObservation>(Find("native-policy.json")), scope);
            if (item.CaseId is "unsafe-host" or "local-trust")
            { bool rejectedPolicy = false; try { CurrentAppOwnedMaintenanceHba.Require(ParseRules(rawRules), pin.Role, scope.Target.Kind); } catch (MigrationExecutionException error) when (error.Code == "current_app_owned_maintenance_hba_not_exclusive") { rejectedPolicy = true; } if (!rejectedPolicy) { throw Invalid(); } }
            else { CurrentAppOwnedMaintenanceHba.Require(ParseRules(rawRules), pin.Role, scope.Target.Kind); }
            if (item.CaseId == "unsafe-host") { var probe = Read<JsonElement>(Frame("unprobed-sdk-allowed")); if (probe.GetProperty("role").GetString() != "iso_unprobed_sdk" || probe.GetProperty("observedAtUtc").GetDateTimeOffset() > began) { throw Invalid(); } }
            if (item.CaseId == "local-trust") { var probe = Read<JsonElement>(Frame("local-client-allowed")); if (probe.GetProperty("role").GetString() != "postgres" || probe.GetProperty("transport").GetString() != "unix" || probe.GetProperty("observedAtUtc").GetDateTimeOffset() > began) { throw Invalid(); } }
            string reservationName = CurrentOwnerIsoRepairConsoleEnvironment.ReservationName(item.OperationId);
            var operationFiles = item.Files.Where(x => Path.GetFileName(x.SourcePath)!.StartsWith(item.OperationId.ToString("D") + "-", StringComparison.Ordinal)).ToArray();
            if (rejected)
            {
                if (artifacts.ContainsKey(config.ReviewPath) || artifacts.ContainsKey(config.AuthorizationPath) || operationFiles.Length != 0) { throw Invalid(); }
                var failures = item.Files.Where(x => Path.GetFileName(x.SourcePath)!.StartsWith("iso-closed-boundary-" + item.OperationId.ToString("N") + "-", StringComparison.Ordinal)).Select(Read<JsonElement>).ToArray();
                if (!failures.Any(x => x.GetProperty("command").GetString() == "review-current-owner-iso-repair" && x.GetProperty("rejectionCode").GetString() == (item.CaseId == "wrong-owner" ? "current_owner_iso_admission_invalid" : "current_app_owned_maintenance_hba_not_exclusive"))) { throw Invalid(); }
            }
            else
            {
                var review = Case<CurrentOwnerIsoRepairSignedClaim>(config.ReviewPath); CurrentOwnerIsoRepairPermit.ValidateReview(review, source, owners, caseTrust, pins, review.IssuedAtUtc);
                if (review.IssuedAtUtc < calls[0].StartedAtUtc || review.IssuedAtUtc > calls[0].ExitedAtUtc) { throw Invalid(); }
                if (CurrentAppOwnedSnapshotSerialization.Sha256(review.Scope) != CurrentAppOwnedSnapshotSerialization.Sha256(scope)) { throw Invalid(); }
                if (executed)
                {
                    var authorization = Case<CurrentOwnerIsoRepairSignedClaim>(config.AuthorizationPath); CurrentOwnerIsoRepairPermit.ValidateClaims(review, authorization, source, owners, caseTrust, pins, calls[2].StartedAtUtc);
                    var reservation = Read<JsonElement>(operationFiles.Single(x => Path.GetFileName(x.SourcePath) == reservationName));
                    if (reservation.GetProperty("Kind").GetString() != "current-owner-iso-operation-start-v1" || reservation.GetProperty("OperationId").GetGuid() != item.OperationId || reservation.GetProperty("ScopeSha256").GetString() != CurrentAppOwnedSnapshotSerialization.Sha256(scope) || reservation.GetProperty("AuthorizationSha256").GetString() != CurrentAppOwnedSnapshotSerialization.Sha256(authorization)) { throw Invalid(); }
                    string previous = new('0', 64); DateTimeOffset last = scope.Maintenance.IssuedAtUtc, lastPublished = last; var tuples = new List<(string Db, CurrentAppOwnedCommitClassification Class, bool Ack)>(); var declared = new HashSet<string>(StringComparer.Ordinal) { reservationName };
                    var publications = item.Files.Where(x => Path.GetFileName(x.SourcePath)!.StartsWith("iso-closed-publication-" + item.OperationId.ToString("N") + "-", StringComparison.Ordinal)).OrderBy(x => x.SourcePath, StringComparer.Ordinal).ToArray();
                    foreach (var publication in publications)
                    {
                        var ack = Read<JsonElement>(publication); string name = ack.GetProperty("name").GetString() ?? throw Invalid();
                        if (!declared.Add(name)) { throw Invalid(); }
                        var receiptFile = operationFiles.Single(x => Path.GetFileName(x.SourcePath) == name); var receipt = Read<CurrentOwnerIsoRepairReceipt>(receiptFile); bool acknowledged = ack.GetProperty("acknowledged").GetBoolean();
                        if (ack.GetProperty("OperationId").GetGuid() != item.OperationId || ack.GetProperty("payloadSha256").GetString() != receiptFile.Sha256 || receipt.PreviousReceiptSha256 != previous || receipt.ObservedAtUtc < last || receipt.ObservedAtUtc > scope.Maintenance.ExpiresAtUtc || ack.GetProperty("observedAtUtc").GetDateTimeOffset() < lastPublished || ack.GetProperty("observedAtUtc").GetDateTimeOffset() < receipt.ObservedAtUtc || ack.GetProperty("observedAtUtc").GetDateTimeOffset() > ended) { throw Invalid(); }
                        PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(receipt, scope, CurrentAppOwnedSnapshotSerialization.Sha256(authorization), caseTrust, pins);
                        var candidate = Read<IsoCapturedNative>(item.Files.Single(x => Path.GetFileName(x.SourcePath)!.EndsWith("-candidate-" + receipt.Database + ".json", StringComparison.Ordinal)));
                        if (receipt.AfterSha256 != candidate.Snapshot.Sha256) { throw Invalid(); }
                        last = receipt.ObservedAtUtc; lastPublished = ack.GetProperty("observedAtUtc").GetDateTimeOffset(); if (acknowledged) { previous = CurrentAppOwnedSnapshotSerialization.Sha256(receipt); }
                        tuples.Add((receipt.Database, receipt.Classification, acknowledged));
                    }
                    IsoComponentProofReader.RequireScenarioSlots(item.CaseId, tuples);
                    if (!operationFiles.Select(x => Path.GetFileName(x.SourcePath)!).Order(StringComparer.Ordinal).SequenceEqual(declared.Order(StringComparer.Ordinal))) { throw Invalid(); }
                    var replay = Read<JsonElement>(Frame("replay-rejected")); if (replay.GetProperty("reservations").GetInt32() != 1 || replay.GetProperty("unchangedSlots").GetInt32() != operationFiles.Length) { throw Invalid(); }
                }
                else if (artifacts.ContainsKey(config.AuthorizationPath) || operationFiles.Length != 0) { throw Invalid(); }
                var probes = item.Files.Where(x => Path.GetFileName(x.SourcePath)!.StartsWith("iso-closed-ordinary-" + item.OperationId.ToString("N") + "-", StringComparison.Ordinal)).ToArray();
                if (probes.Length == 0) { throw Invalid(); }
                foreach (var probe in probes) { var observed = Read<JsonElement>(probe); if (!observed.GetProperty("databases").EnumerateArray().Select(x => x.GetString()).SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))) { throw Invalid(); } }
            }
            var candidateFleets = item.Files.Where(x => Path.GetFileName(x.SourcePath)!.Contains("-candidate-fleet-", StringComparison.Ordinal)).OrderBy(x => x.SourcePath, StringComparer.Ordinal).ToArray();
            if (candidateFleets.Length != (item.CaseId == "complete" ? 2 : executed ? 1 : 0)) { throw Invalid(); }
            for (int index = 0; index < candidateFleets.Length; index++)
            {
                string selected = index == 0 ? "Country" : "Material"; var fleet = await files.ReadBaselineAsync(candidateFleets[index].Path, ct, sharedReader: true).ConfigureAwait(false);
                if (fleet.Length != 26 || !fleet.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))) { throw Invalid(); }
                foreach (var captured in fleet)
                { string expectedHash = captured.Database == selected ? Read<IsoCapturedNative>(item.Files.Single(x => Path.GetFileName(x.SourcePath)!.EndsWith("-candidate-" + selected + ".json", StringComparison.Ordinal))).Snapshot.Sha256 : index == 1 && captured.Database == "Country" ? after.Single(x => x.Database == "Country").Sha256 : scope.BeforeDatabaseSha256[captured.Database]; if (captured.Sha256 != expectedHash) { throw Invalid(); } }
            }
            foreach (var current in after.Where(x => x.Database is not ("Country" or "Material")))
            {
                var original = before.Single(x => x.Database == current.Database);
                if (item.CaseId == "fleet-drift" && current.Database == "Upload")
                {
                    if (!original.Catalog.SequenceEqual(current.Catalog) || !original.Sequences.SequenceEqual(current.Sequences) || original.Relations.Count != current.Relations.Count) { throw Invalid(); }
                    foreach (var relation in original.Relations) { var actual = current.Relations.Single(x => x.Schema == relation.Schema && x.Name == relation.Name); if (relation.Schema == "private" && relation.Name == "owner_iso_closed_sentinel") { if (actual.Rows != relation.Rows || actual.RowSha256 == relation.RowSha256) { throw Invalid(); } } else if (actual != relation) { throw Invalid(); } }
                }
                else if (current.Sha256 != original.Sha256) { throw Invalid(); }
            }
            var targetMetadata = Bytes(Frame("target")); var volumeMetadata = Bytes(item.Files.Where(x => Path.GetFileName(x.SourcePath)!.EndsWith("-volume.json", StringComparison.Ordinal)).OrderBy(x => x.SourcePath, StringComparer.Ordinal).First());
            using (var container = JsonDocument.Parse(targetMetadata)) using (var volume = JsonDocument.Parse(volumeMetadata))
            { CurrentOwnerIsoNamedClosedTarget.Require(scope, target, container.RootElement, volume.RootElement, scope.BootstrapSubject.LoopbackPort ?? throw Invalid(), began); }
            var proxies = item.Files.Where(x => Path.GetFileName(x.SourcePath)!.StartsWith("iso-closed-proxy-" + item.OperationId.ToString("N") + "-", StringComparison.Ordinal)).ToArray();
            if (item.CaseId == "lost-commit-ack")
            {
                var created = Read<JsonElement>(proxies.Single(x => Path.GetFileName(x.SourcePath)!.EndsWith("-created.json", StringComparison.Ordinal)));
                var finished = Read<JsonElement>(proxies.Single(x => Path.GetFileName(x.SourcePath)!.EndsWith("-disposed.json", StringComparison.Ordinal))); int port = created.GetProperty("port").GetInt32();
                if (created.GetProperty("_operation").GetGuid() != item.OperationId || created.GetProperty("loopbackAddress").GetString() != "127.0.0.1" || created.GetProperty("upstreamAddress").GetString() != "127.0.0.1" || created.GetProperty("upstreamPort").GetInt32() != scope.BootstrapSubject.LoopbackPort ||
                    finished.GetProperty("_operation").GetGuid() != item.OperationId || finished.GetProperty("port").GetInt32() != port || finished.GetProperty("droppedCommits").GetInt32() != 1 || !finished.GetProperty("workerCompleted").GetBoolean() || !finished.GetProperty("readersSettled").GetBoolean() || finished.GetProperty("cleanupFailed").GetBoolean() ||
                    finished.GetProperty("armedAtUtc").GetDateTimeOffset() > finished.GetProperty("droppedAtUtc").GetDateTimeOffset() || finished.GetProperty("droppedAtUtc").GetDateTimeOffset() > finished.GetProperty("completedAtUtc").GetDateTimeOffset() || absent.GetProperty("listeningPorts").EnumerateArray().Any(x => x.GetInt32() == port)) { throw Invalid(); }
            }
            else if (proxies.Length != 0) { throw Invalid(); }
            var disposed = Read<JsonElement>(Frame("disposed")); var absentCase = Read<JsonElement>(Frame("absent"));
            if (!disposed.GetProperty("removed").GetBoolean() || !disposed.GetProperty("sdkDisposed").GetBoolean() || !disposed.GetProperty("verifiedAbsence").GetBoolean() || disposed.GetProperty("cleanupFailed").GetBoolean() ||
                disposed.GetProperty("removedAtUtc").GetDateTimeOffset() < ended || disposed.GetProperty("completedAtUtc").GetDateTimeOffset() > host.ExitedAtUtc ||
                absentCase.GetProperty("observedAtUtc").GetDateTimeOffset() < disposed.GetProperty("removedAtUtc").GetDateTimeOffset()) { throw Invalid(); }
            foreach (var inventory in new[] { absentCase, absent })
            { if (inventory.GetProperty("containerIds").EnumerateArray().Any(x => x.GetString() == target.DockerContainerId) || inventory.GetProperty("containerNames").EnumerateArray().Any(x => x.GetString() == "/" + scope.BootstrapSubject.ContainerName) || inventory.GetProperty("volumeNames").EnumerateArray().Any(x => x.GetString() == target.DockerVolume) || inventory.GetProperty("listeningPorts").EnumerateArray().Any(x => x.GetInt32() == scope.BootstrapSubject.LoopbackPort)) { throw Invalid(); } }
        }
        files.Require();
        byte[] Bytes(IsoDefinitionArtifact artifact, int maximum = 8_000_000) { byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum); return CurrentAppOwnedRepairPermit.Hash(bytes) != artifact.Sha256 ? throw Invalid() : bytes; }
        string Digest(IsoDefinitionArtifact artifact) { using var held = SecureLocalFile.OpenReadShared(artifact.Path); if (held.Length > 512L * 1024 * 1024) { throw Invalid(); } string sha = Convert.ToHexStringLower(SHA256.HashData(held)); return sha != artifact.Sha256 ? throw Invalid() : sha; }
        T Read<T>(IsoDefinitionArtifact artifact)
        {
            return MigrationConsole.DecodeOwnerIso<T>(Bytes(artifact, 32 * 1024 * 1024));
        }
    }
    internal static void RequireCalls(string id, IReadOnlyList<IsoNamedClosedInvocation> calls, Guid operation)
    {
        bool rejected = id is "wrong-owner" or "unsafe-host" or "local-trust"; bool maintenance = id is "ordinary-all26" or "exclusive-policy";
        string[] commands = rejected || maintenance ? ["review-current-owner-iso-repair"] : ["review-current-owner-iso-repair", "authorize-current-owner-iso-repair", "verify-current-owner-iso-repair", "apply-current-owner-iso-repair", "apply-current-owner-iso-repair"];
        if (!IsoComponentCases.Required(IsoComponentProofPhase.Native).Concat(IsoComponentCases.Required(IsoComponentProofPhase.Maintenance)).Contains(id, StringComparer.Ordinal) || operation == Guid.Empty || !calls.Select(x => x.Command).SequenceEqual(commands) || calls.Any(x => x.OperationId != operation || x.StartedAtUtc.Offset != TimeSpan.Zero || x.ExitedAtUtc.Offset != TimeSpan.Zero || x.ExitedAtUtc < x.StartedAtUtc) || calls.Zip(calls.Skip(1)).Any(x => x.First.ExitedAtUtc > x.Second.StartedAtUtc) ||
            calls[0].ExitCode != (rejected ? 1 : 0) || (!rejected && !maintenance && (calls[1].ExitCode != 0 || calls[2].ExitCode != 0 || calls[3].ExitCode != (id == "complete" ? 0 : 1) || calls[4].ExitCode != 1))) { throw Invalid(); }
    }
    private static CurrentAppOwnedMaintenanceHbaRule[] ParseRules(string raw)
    {
        using var document = JsonDocument.Parse(raw); return document.RootElement.EnumerateArray().Select(x => new CurrentAppOwnedMaintenanceHbaRule(x.GetProperty("rule_number").GetInt32(), x.GetProperty("type").GetString() ?? string.Empty,
            Strings(x.GetProperty("database")), Strings(x.GetProperty("user_name")), Nullable(x.GetProperty("address")), Nullable(x.GetProperty("netmask")), x.GetProperty("auth_method").GetString() ?? string.Empty, Strings(x.GetProperty("options")), Nullable(x.GetProperty("error")))).ToArray();
        static string? Nullable(JsonElement x)
        {
            return x.ValueKind == JsonValueKind.Null ? null : x.GetString();
        }

        static string[] Strings(JsonElement x)
        {
            return x.ValueKind == JsonValueKind.Null ? [] : x.EnumerateArray().Select(v => v.GetString() ?? throw Invalid()).ToArray();
        }
    }
    private static MigrationExecutionException Invalid()
    {
        return new("iso_named_closed_proof_invalid", "Actual named closed Console invocations, native candidates, whole-fleet preservation and post-exit cleanup are required.");
    }
}
