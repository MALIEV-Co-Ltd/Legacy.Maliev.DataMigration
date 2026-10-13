using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthTypedHostCapacity(DateTimeOffset ObservedAtUtc, ulong AvailablePhysicalBytes, ulong OwnedRssBytes);
internal sealed record CurrentAuthTypedHostExit(string Kind, string SourceCommitSha, string RunBindingSha256,
    string Group, string TestAssemblyPath, string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256,
    string ExecutablePath, string ExecutableSha256, int ProcessId, DateTimeOffset ProcessStartTimeUtc,
    DateTimeOffset BeganAtUtc, DateTimeOffset ExitedAtUtc, DateTimeOffset ExpiresAtUtc,
    int ExitCode, bool ProcessExited, bool ReadersSettled, bool CleanupFailed,
    CurrentAuthProofArtifact Trx, CurrentAuthProofArtifact Capacity, string KeyId, string? Signature,
    CurrentAuthProofArtifact? ProcessObservations = null, CurrentAuthProofArtifact? IndependentAbsence = null);

/// <summary>Post-run assembler. No test invocation, key creation, DB connection or execution authority.</summary>
internal static class CurrentAuthTypedProofAssembler
{
    private static readonly JsonSerializerOptions Strict = new() { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };
    internal static byte[] HostPayload(CurrentAuthTypedHostExit value) =>
        [.. "Legacy.Maliev.CurrentAuth.TypedHostExit.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(value with { Signature = null })];

    internal static void RequireHost(CurrentAuthTypedHostExit host, LocalExecutionBinding binding, CurrentAuthRepairScope scope,
        CurrentAuthRepairSigningPins pins, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        if (host.Kind != "current-auth-typed-host-exit-v1" || host.SourceCommitSha != scope.SourceCommitSha ||
            host.RunBindingSha256 != binding.ComputeSha256() || host.Group is not ("definition" or "provider" or "closed") ||
            host.ProcessId < 1 || host.ExitCode != 0 || !host.ProcessExited || !host.ReadersSettled || host.CleanupFailed ||
            !Path.IsPathFullyQualified(host.ExecutablePath) || Path.GetFileName(host.ExecutablePath) != "dotnet.exe" ||
            !CurrentAuthRepairPermit.HashShape(host.ExecutableSha256) || !CurrentAuthRepairPermit.HashShape(host.TestAssemblySha256) ||
            !CurrentAuthRepairPermit.HashShape(host.ConsoleAssemblySha256) || !CurrentAuthRepairPermit.HashShape(host.CoreAssemblySha256) ||
            host.ProcessObservations is null || !CurrentAuthRepairPermit.HashShape(host.ProcessObservations.Sha256) ||
            host.IndependentAbsence is null || !CurrentAuthRepairPermit.HashShape(host.IndependentAbsence.Sha256) ||
            host.ProcessStartTimeUtc.Offset != TimeSpan.Zero || host.BeganAtUtc.Offset != TimeSpan.Zero || host.ExitedAtUtc.Offset != TimeSpan.Zero || host.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            host.ProcessStartTimeUtc < host.BeganAtUtc || host.ProcessStartTimeUtc > host.ExitedAtUtc || host.ExitedAtUtc > now ||
            host.ExitedAtUtc > host.ExpiresAtUtc || host.ExpiresAtUtc - host.BeganAtUtc > TimeSpan.FromHours(2) ||
            host.ExpiresAtUtc <= host.BeganAtUtc || now - host.BeganAtUtc > TimeSpan.FromHours(12) ||
            host.KeyId != pins.ReviewKeyId || !trust.TryGetPublicKeyFingerprintSha256(host.KeyId, out string fingerprint) || fingerprint != pins.ReviewFingerprint ||
            string.IsNullOrWhiteSpace(host.Signature) || !trust.Verify(host.KeyId, HostPayload(host), Convert.FromBase64String(host.Signature)))
        { throw Invalid(); }
    }

    internal static async Task<CurrentAuthProofArtifact> AssembleAsync(CurrentAppOwnedRepairCustody files, LocalExecutionBinding binding,
        CurrentAuthProofArtifact hostArtifact, string phase, CurrentAuthRepairScope intended, FreshSchemaPlan source,
        CurrentAuthRepairSigningPins pins, IReceiptAttestationTrustStore trust, P256MigrationEvidenceSigner signer,
        string outputPath, CancellationToken ct)
    {
        // The caller must already have admitted the exact accepted producer source/binaries and external continuous resource observer.
        // A signed host record is accepted only from its independently pinned actual process observer, never supplied test metadata.
        files.Require(); CurrentAuthRepairPermit.RequireProofAdmission(intended);
        if (intended.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeBootstrap || phase is not ("helper" or "native" or "recovery" or "maintenance")) { throw Invalid(); }
        CurrentAuthTypedHostExit host = Decode<CurrentAuthTypedHostExit>(Read(hostArtifact));
        RequireHost(host, binding, intended, pins, trust, DateTimeOffset.UtcNow);
        if (host.Group == "closed" || (phase == "helper") != (host.Group == "definition") || signer.KeyId != pins.ReceiptKeyId) { throw Invalid(); }
        RequireCapacity(Decode<CurrentAuthTypedHostCapacity[]>(Read(host.Capacity)), host);
        string journalText = new UTF8Encoding(false, true).GetString(Read(host.ProcessObservations ?? throw Invalid()));
        if (!journalText.EndsWith('\n') || journalText.Length > 32 * 1024 * 1024) { throw Invalid(); }
        HostProcessObservation[] processObservations = journalText.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Length > 65536 ? throw Invalid() : Decode<HostProcessObservation>(Encoding.UTF8.GetBytes(line))).ToArray();
        if (processObservations.Length is < 1 or > 20000 || processObservations.Any(x => x.Processes.Length > 64)) { throw Invalid(); }
        using var independentAbsence = JsonDocument.Parse(Read(host.IndependentAbsence ?? throw Invalid()));
        if (independentAbsence.RootElement.GetProperty("observedAtUtc").GetDateTimeOffset() < host.ExitedAtUtc ||
            independentAbsence.RootElement.GetProperty("group").GetString() != host.Group) { throw Invalid(); }
        // Hold and hash the actual executed images, not the source paths or an assembly-name marker.
        _ = Read(new(host.TestAssemblyPath, host.TestAssemblySha256));
        if (HashAssembly(typeof(MigrationConsole).Assembly.Location) != host.ConsoleAssemblySha256 ||
            HashAssembly(typeof(CurrentAuthRepairPermit).Assembly.Location) != host.CoreAssemblySha256) { throw Invalid(); }
        string[] required = CurrentAuthRepairProofReader.Cases(phase, intended.ProofAdmission, component: true);
        using var xml = XmlReader.Create(new MemoryStream(Read(host.Trx), writable: false), new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        XDocument trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        XElement[] results = [.. trx.Descendants(ns + "UnitTestResult")];
        if (results.Length != required.Length || results.Any(x => (string?)x.Attribute("outcome") != "Passed") ||
            results.Any(x => DateTimeOffset.Parse((string)x.Attribute("endTime")!, CultureInfo.InvariantCulture) > host.ExitedAtUtc)) { throw Invalid(); }
        var cases = new List<CurrentAuthProofCase>(); var runs = new List<CurrentAuthProofRun>();
        string root = binding.ArtifactRootCanonicalPath;
        foreach (string directory in Directory.EnumerateDirectories(root, "auth-executed-*", SearchOption.TopDirectoryOnly).Order(StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            if (!Guid.TryParseExact(Path.GetFileName(directory)["auth-executed-".Length..], "N", out Guid runId)) { throw Invalid(); }
            string[] eventPaths = Directory.GetFiles(directory, $"auth-observed-{runId:N}-*-event.json", SearchOption.TopDirectoryOnly);
            if (eventPaths.Length is < 1 or > 4000) { throw Invalid(); }
            LocalExecutionBinding caseBinding = CurrentAuthTypedProofArtifactImport.ReadChildBinding(directory, runId);
            using WindowsLocalRunAuthority caseAuthority = WindowsLocalRunAuthority.AcquireResume(directory, caseBinding);
            using var caseFiles = new CurrentAppOwnedRepairCustody(caseAuthority);
            Observed[] events = eventPaths.Select(path => Decode<Observed>(caseFiles.Read(path, sharedReader: true, maximumBytes: 65536))).OrderBy(x => x.ObservedAtUtc).ToArray();
            string id = events.Select(x => x.CaseId).Distinct(StringComparer.Ordinal).Single();
            if (!required.Contains(id, StringComparer.Ordinal)) { continue; } // Other genuine group directories are not proof cases in this envelope.
            if (events.Any(x => x.RunId != runId || x.ObservedAtUtc.Offset != TimeSpan.Zero || x.ObservedAtUtc < host.BeganAtUtc || x.ObservedAtUtc > host.ExitedAtUtc) ||
                cases.Any(x => x.CaseId == id)) { throw Invalid(); }
            var imported = new Dictionary<string, CurrentAuthProofArtifact>(StringComparer.OrdinalIgnoreCase);
            foreach (Observed observed in events)
            {
                if (!imported.ContainsKey(observed.Artifact.Path)) { imported.Add(observed.Artifact.Path,
                    await CurrentAuthTypedProofArtifactImport.ImportAsync(files, binding, caseFiles, caseBinding, observed.Artifact, runId, ct).ConfigureAwait(false)); }
            }
            CurrentAuthProofArtifact Artifact(string name, bool last = false)
            {
                Observed[] found = events.Where(x => x.Phase == name).ToArray();
                if (found.Length == 0 || (!last && found.Length != 1)) { throw Invalid(); }
                CurrentAuthProofArtifact value = (last ? found[^1] : found[0]).Artifact;
                if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(value.Path)), directory)) { throw Invalid(); }
                return imported[value.Path];
            }
            CurrentAuthProofArtifact heldBinding = Artifact("run-binding");
            var executedImage = Decode<ExecutedTestImage>(Read(Artifact("test-image")));
            if (!StringComparer.OrdinalIgnoreCase.Equals(executedImage.TestAssemblyPath, host.TestAssemblyPath) ||
                executedImage.TestAssemblySha256 != host.TestAssemblySha256 || executedImage.ConsoleAssemblySha256 != host.ConsoleAssemblySha256 ||
                executedImage.CoreAssemblySha256 != host.CoreAssemblySha256 ||
                !processObservations.Any(x => x.Processes.Any(p => p.ProcessId == executedImage.ProcessId &&
                    p.StartTimeUtc == executedImage.ProcessStartTimeUtc && !p.Exited && p.WorkingSetBytes > 0))) { throw Invalid(); }
            if (Decode<LocalExecutionBinding>(Read(heldBinding)) != caseBinding) { throw Invalid(); }
            if (!StringComparer.OrdinalIgnoreCase.Equals(caseBinding.ArtifactRootCanonicalPath, directory)) { throw Invalid(); }
            using var attempt = JsonDocument.Parse(Read(Artifact("attempt"))); using var disposed = JsonDocument.Parse(Read(Artifact("disposed")));
            using var container = JsonDocument.Parse(Read(Artifact("container"))); using var absence = JsonDocument.Parse(Read(Artifact("absence-inventory")));
            string containerId = container.RootElement.GetProperty("Id").GetString() ?? throw Invalid();
            string name = attempt.RootElement.GetProperty("name").GetString() ?? throw Invalid();
            string? volume = disposed.RootElement.TryGetProperty("volume", out JsonElement volumeValue) ? volumeValue.GetString() : null;
            int port = int.Parse(container.RootElement.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp")[0].GetProperty("HostPort").GetString()!, CultureInfo.InvariantCulture);
            // Absence inventory comes from the real fixture after exact removal, before SDK disposal. Secret absence remains a distinct required host observer fact.
            var secretObservation = Decode<SecretAbsenceObservation>(Read(Artifact("secret-absence")));
            RequireSecretAbsence(secretObservation, runId, caseBinding, directory, absence.RootElement.GetProperty("observedAtUtc").GetDateTimeOffset());
            var absenceRecord = new CurrentAuthProofAbsence(runId, secretObservation.ObservedAtUtc, true, true, true,
                true, Strings(absence.RootElement, "containerIds"), Strings(absence.RootElement, "containerNames"),
                Strings(absence.RootElement, "volumeNames"), [.. absence.RootElement.GetProperty("listeningPorts").EnumerateArray().Select(x => x.GetInt32())]);
            CurrentAuthProofArtifact absencePath = await Write(directory, "assembled-absence.json", absenceRecord);
            var run = new CurrentAuthProofRun(runId, name, containerId, volume, Artifact("container"), volume is null ? null : Artifact("volume-metadata", last: true),
                Artifact("attempt"), Artifact("disposed"), absencePath, port, volume is null ? Artifact("filesystem-capacity") : null,
                volume is null ? null : Artifact("previous-volumes"), volume is null ? null : Artifact("volume-consumers", last: true), Artifact("image-metadata"),
                events.Any(x => x.Phase == "proxy-created") ? Artifact("proxy-created") : null, events.Any(x => x.Phase == "proxy-disposed") ? Artifact("proxy-disposed") : null);
            runs.Add(run);
            CurrentAuthProofArtifact before = Artifact("native-before"), after = Artifact("native-after"), scenarioPath;
            CurrentAuthProofArtifact? scopeArtifact = null, review = null, authorization = null, fleetBefore = null, fleetAfter = null, candidate = null, policy = null, componentObservation = null;
            Guid operation = runId; string scopeHash = new('0', 64), reviewHash = scopeHash, authorizationHash = scopeHash;
            using var window = JsonDocument.Parse(Read(Artifact(host.Group == "definition" ? "invocation-window" : "provider-invocation")));
            var slots = new List<CurrentAuthProofSlot>(); bool commitAcknowledged = false, replay = false; string? rejection = null;
            string boundary;
            if (host.Group == "definition")
            {
                boundary = id.StartsWith("history-", StringComparison.Ordinal) ? "rollback-commit-independent-readback" : "unsupported-preimage";
                commitAcknowledged = id.StartsWith("history-", StringComparison.Ordinal);
                if (!commitAcknowledged) { using var failure = JsonDocument.Parse(Read(Artifact("rejection"))); rejection = failure.RootElement.GetProperty("code").GetString(); }
            }
            else
            {
                scopeArtifact = Artifact("scope"); review = Artifact("review"); authorization = Artifact("authorization");
                CurrentAuthRepairScope caseScope = Decode<CurrentAuthRepairScope>(Read(scopeArtifact)); operation = caseScope.OperationId;
                scopeHash = scopeArtifact.Sha256; reviewHash = review.Sha256; authorizationHash = authorization.Sha256;
                fleetBefore = Artifact("fleet-before"); fleetAfter = Artifact("fleet-after");
                policy = Artifact("installed-policy");
                candidate = id is "host-unprobed-sdk" or "local-ordinary-trust" ? null : Artifact("native-candidate");
                using var volumeDocument = JsonDocument.Parse(Read(run.VolumeMetadata ?? throw Invalid()));
                componentObservation = await Write(directory, "assembled-component-observation.json", new CurrentAuthProofComponentObservation(
                    "current-auth-disposable-component-observation-v1", "generated-synthetic-schema-physically-observed-not-accepted-source-capture", heldBinding,
                    CurrentAuthRepairProofReader.ComponentGeneration(container.RootElement, volumeDocument.RootElement, run), container.RootElement.GetProperty("Image").GetString()!));
                foreach (Observed item in events.Where(x => x.Phase == "receipt-slot"))
                {
                    using var frame = JsonDocument.Parse(Read(imported[item.Artifact.Path]));
                    string receiptName = frame.RootElement.GetProperty("name").GetString() ?? throw Invalid();
                    if (Path.GetFileName(receiptName) != receiptName || !receiptName.StartsWith(operation.ToString("D") + "-Auth-", StringComparison.Ordinal)) { throw Invalid(); }
                    byte[] bytes = Convert.FromBase64String(frame.RootElement.GetProperty("payload").GetString()!);
                    string receiptPath = Path.Combine(root, receiptName);
                    if (File.Exists(receiptPath))
                    {
                        // A second genuine phase reuses the exact immutable original slot; it cannot replace or invent it.
                        if (!files.Read(receiptPath, sharedReader: true, maximumBytes: 1024 * 1024).AsSpan().SequenceEqual(bytes)) { throw Invalid(); }
                    }
                    else { await files.WriteNewAsync(receiptPath, bytes, ct).ConfigureAwait(false); }
                    slots.Add(new(new(receiptPath, Convert.ToHexStringLower(SHA256.HashData(bytes))), frame.RootElement.GetProperty("acknowledged").GetBoolean()));
                }
                rejection = window.RootElement.TryGetProperty("rejectionCode", out JsonElement error) ? error.GetString() : null;
                replay = window.RootElement.TryGetProperty("replayRejected", out JsonElement replayed) && replayed.GetBoolean();
                boundary = id switch { "success" => "complete", "prepared-publication" => "prepared-publication-before-ack",
                    "host-unprobed-sdk" or "local-ordinary-trust" => "maintenance-semantic", _ => id };
                CurrentAuthRepairReceipt[] receipts = slots.Select(x => Decode<CurrentAuthRepairReceipt>(Read(x.Artifact))).ToArray();
                commitAcknowledged = id == "success" ? window.RootElement.GetProperty("returned").GetBoolean() :
                    receipts.Any(x => x.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback);
                if (id == "lost-commit-ack" && window.RootElement.GetProperty("droppedCommitCount").GetInt32() != 1) { throw Invalid(); }
            }
            XElement result = results.Single(x => Match(id, (string)x.Attribute("testName")!));
            string testName = (string)result.Attribute("testName")!, testId = (string)result.Attribute("testId")!, executionId = (string)result.Attribute("executionId")!;
            var invocation = new CurrentAuthProofInvocation(host.Group == "definition" ? "definition-current-auth-proof" : "provider-current-auth-proof", operation, runId,
                testName, testId, executionId, host.TestAssemblyPath, host.TestAssemblySha256, host.ConsoleAssemblySha256, host.CoreAssemblySha256,
                scopeHash, reviewHash, authorizationHash, new string('0', 64), window.RootElement.GetProperty("startedAtUtc").GetDateTimeOffset(),
                window.RootElement.GetProperty("exitedAtUtc").GetDateTimeOffset(), host.Group == "definition" || window.RootElement.GetProperty("returned").GetBoolean() ? 0 : 1);
            CurrentAuthProofArtifact invocationPath = await Write(directory, "assembled-invocation.json", invocation);
            scenarioPath = await Write(directory, "assembled-scenario.json", new CurrentAuthProofScenario(id, operation, invocationPath.Sha256, boundary, rejection,
                commitAcknowledged, replay, host.Group == "definition" || id is "host-unprobed-sdk" or "local-ordinary-trust" ? [] : Decode<string[]>(Read(Artifact("ordinary-rejections", last: true))), slots));
            cases.Add(new(id, invocation, invocationPath, new(host.TestAssemblyPath, host.TestAssemblySha256), before, after,
                id.StartsWith("history-", StringComparison.Ordinal) ? Artifact("native-rolled-back") : null, fleetBefore, fleetAfter, scopeArtifact, review, authorization,
                null, null, null, policy, scenarioPath, candidate, host.Group == "definition" ? null : Artifact("case-pins"),
                host.Group == "definition" ? null : Artifact("case-public-keys"), componentObservation, host.Group == "definition" ? null : Artifact("case-source"), host.Group == "definition" ? null : Artifact("source-physical", last: true)));
        }
        if (!cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(required.Order(StringComparer.Ordinal))) { throw Invalid(); }
        DateTimeOffset began = runs.Min(run => { using var doc = JsonDocument.Parse(Read(run.Attempt)); return doc.RootElement.GetProperty("began").GetDateTimeOffset(); });
        var unsigned = new CurrentAuthClosedProof("current-auth-" + phase + "-" + (phase == "helper" ? "definition" : "provider-component") + "-proof-v1",
            CurrentAuthRepairProofReader.Subject(intended), intended.SourceCommitSha, host.ConsoleAssemblySha256, host.CoreAssemblySha256,
            began, DateTimeOffset.UtcNow, began.AddHours(12), host.Trx, runs, cases, signer.KeyId, null);
        CurrentAuthProofArtifact unsignedPath = await Write(root, Path.GetFileName(outputPath) + ".unsigned.json", unsigned);
        await CurrentAuthRepairProofReader.RequireUnsignedForAssemblerAsync(files, new(unsignedPath.Path, unsignedPath.Sha256), unsignedPath.Sha256, phase,
            intended, trust, pins, source, ct).ConfigureAwait(false);
        // No signature is requested before all actual executed/custody/native/receipt evidence has passed readback.
        CurrentAuthClosedProof signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthRepairProofReader.Payload(unsigned, phase))) };
        await files.WriteNewAsync(outputPath, JsonSerializer.SerializeToUtf8Bytes(signed), ct).ConfigureAwait(false);
        string hash = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(signed)));
        await CurrentAuthRepairProofReader.RequireComponentAsync(files, new(outputPath, hash), hash, phase, intended, trust, pins, source, ct).ConfigureAwait(false);
        return new(outputPath, hash);

        byte[] Read(CurrentAuthProofArtifact artifact)
        {
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 32 * 1024 * 1024);
            if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != artifact.Sha256) { throw Invalid(); } return bytes;
        }
        async Task<CurrentAuthProofArtifact> Write<T>(string directory, string name, T value)
        {
            if (Path.GetFileName(name) != name) { throw Invalid(); }
            string path = Path.Combine(root, phase + "-" + (StringComparer.OrdinalIgnoreCase.Equals(directory, root) ? string.Empty : Path.GetFileName(directory) + "-") + name); byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
            await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false); return new(path, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        }
    }

    private sealed record FileObservation(string Name, long Length, string Sha256);
    private sealed record SecretAbsenceObservation(Guid RunId, DateTimeOffset ObservedAtUtc, string Kind,
        string BindingSha256, string[] CreatedCredentialPaths, string[] RemainingCredentialPaths, IReadOnlyList<FileObservation> Files);
    private static void RequireSecretAbsence(SecretAbsenceObservation observation, Guid runId, LocalExecutionBinding binding,
        string directory, DateTimeOffset resourceObservedAt)
    {
        if (observation.RunId != runId || observation.Kind != "auth-native-fixture-no-credential-files-v1" ||
            observation.BindingSha256 != binding.ComputeSha256() || observation.CreatedCredentialPaths.Length != 0 || observation.RemainingCredentialPaths.Length != 0 ||
            observation.ObservedAtUtc.Offset != TimeSpan.Zero || observation.ObservedAtUtc < resourceObservedAt ||
            observation.Files.Count is < 1 or > 8000 || observation.Files.Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != observation.Files.Count) { throw Invalid(); }
        // Every original observed slot is held and byte-checked; the fixed accepted fixtures have no credential-file writer.
        foreach (FileObservation item in observation.Files)
        {
            if (Path.GetFileName(item.Name) != item.Name || !item.Name.StartsWith($"auth-observed-{runId:N}-", StringComparison.Ordinal) ||
                !item.Name.EndsWith(".json", StringComparison.Ordinal) || item.Length is < 1 or > 512L * 1024 * 1024) { throw Invalid(); }
            using var input = SecureLocalFile.OpenReadShared(Path.Combine(directory, item.Name));
            string identity = SecureLocalFile.GetHandleIdentity(input);
            if (input.Length != item.Length || Convert.ToHexStringLower(SHA256.HashData(input)) != item.Sha256 ||
                SecureLocalFile.GetHandleIdentity(input) != identity || input.Position != item.Length) { throw Invalid(); }
        }
    }
    private sealed record Observed(Guid RunId, string CaseId, string Phase, DateTimeOffset ObservedAtUtc, CurrentAuthProofArtifact Artifact);
    private sealed record HostProcessObservation(CurrentAuthTypedHostCapacity Capacity, CurrentAuthTypedProcessFrame[] Processes);
    private sealed record ExecutedTestImage(string TestAssemblyPath, string TestAssemblySha256, string ConsoleAssemblyPath,
        string ConsoleAssemblySha256, string CoreAssemblyPath, string CoreAssemblySha256, int ProcessId, DateTimeOffset ProcessStartTimeUtc);
    private static T Decode<T>(byte[] bytes) => JsonSerializer.Deserialize<T>(bytes, Strict) ?? throw Invalid();
    private static string HashAssembly(string path) => CurrentAuthTypedHostProducer.ImageHash(path);
    private static string[] Strings(JsonElement row, string field) => [.. row.GetProperty(field).EnumerateArray().Select(x => x.GetString()!)];
    private static bool Match(string id, string testName) => id switch
    {
        "history-10.0.12" => testName.Contains("10.0.12", StringComparison.Ordinal), "history-10.0.10" => testName.Contains("10.0.10", StringComparison.Ordinal),
        "reject-expression" => testName.Contains("CREATE INDEX", StringComparison.Ordinal), "reject-extended-statistics" => testName.Contains("CREATE STATISTICS", StringComparison.Ordinal),
        "reject-statistics" => testName.Contains("ANALYZE", StringComparison.Ordinal), "reject-column" => testName.Contains("ADD COLUMN", StringComparison.Ordinal),
        "reject-partial" => testName.Contains("ALTER COLUMN", StringComparison.Ordinal), _ => testName.Contains(id, StringComparison.Ordinal)
    };
    internal static void RequireCapacity(CurrentAuthTypedHostCapacity[] frames, CurrentAuthTypedHostExit host)
    {
        if (frames.Length is < 2 or > 100000 || frames[0].ObservedAtUtc > host.ProcessStartTimeUtc || frames[^1].ObservedAtUtc < host.ExitedAtUtc) { throw Invalid(); }
        DateTimeOffset previous = frames[0].ObservedAtUtc;
        foreach (var frame in frames)
        {
            if (frame.ObservedAtUtc.Offset != TimeSpan.Zero || frame.ObservedAtUtc < previous || frame.ObservedAtUtc - previous > TimeSpan.FromSeconds(2)) { throw Invalid(); }
            CurrentAuthRepairCapacity.RequireValues(frame.AvailablePhysicalBytes, frame.OwnedRssBytes, admission: false); previous = frame.ObservedAtUtc;
        }
        CurrentAuthRepairCapacity.RequireValues(frames[0].AvailablePhysicalBytes, frames[0].OwnedRssBytes, admission: true);
    }
    private static MigrationExecutionException Invalid() => new("current_auth_typed_producer_invalid", "Genuine executed Auth proof observations are required.");
}
