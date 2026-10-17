using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal static class Production181CustomerDefinitionReader
{
    private const string Image = "ghcr.io/cloudnative-pg/postgresql:18.1-standard-bookworm@sha256:4d7755c0460bdac6143f49e5d16ba4865aeb61368fe773adfea8696380a69b7a";
    private static readonly string[] Required = ["start-1-false-1","start-1-false-9","start-69831-true-1","start-69831-true-9",
        "start-2000000000-true-1","start-2000000000-true-9","start-2000000000-false-1","start-2000000000-false-9",
        "reject-increment","reject-cache","reject-start","reject-generated","reject-owner"];
    internal static byte[] Payload(CustomerDefinitionProof proof)
    {
        return [.. "Legacy.Maliev.Production181.CustomerSequence.DefinitionPrecursor.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(proof with { Signature = null })];
    }

    internal static void Require(CurrentAppOwnedRepairCustody files, CustomerDefinitionProof proof, CustomerDefinitionSubject intended,
        IReceiptAttestationTrustStore trust, string keyId, string fingerprint, DateTimeOffset now)
    {
        if (proof.KeyId != keyId || string.IsNullOrWhiteSpace(proof.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(keyId, out string observed) || observed != fingerprint) { throw Invalid(); }
        try { if (!trust.Verify(keyId, Payload(proof), Convert.FromBase64String(proof.Signature))) { throw Invalid(); } }
        catch (FormatException) { throw Invalid(); }
        RequireBody(files, proof, intended, now);
    }
    internal static void RequireBody(CurrentAppOwnedRepairCustody files, CustomerDefinitionProof proof, CustomerDefinitionSubject intended, DateTimeOffset now)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        var definition = ApprovedCurrentCustomerSequenceDefinition.Create(intended.Source, intended.Owner, intended.Source.CommitSha, intended.Source.CatalogReportSha256, now);
        if (proof.Kind != "current-production181-customer-definition-precursor-v1" ||
            JsonSerializer.Serialize(proof.Subject) != JsonSerializer.Serialize(intended) || definition.ComputeSha256() != intended.DefinitionSha256 ||
            intended.ConsoleAssemblySha256 != AssemblyHash(typeof(MigrationConsole).Assembly.Location) ||
            intended.CoreAssemblySha256 != AssemblyHash(typeof(ApprovedCurrentCustomerSequenceDefinition).Assembly.Location) ||
            !CurrentAppOwnedRepairPermit.HashShape(intended.SourceSchemaPlanSha256) || !CurrentAppOwnedRepairPermit.HashShape(intended.IntendedNativeBeforeStateSha256) ||
            !CurrentAppOwnedRepairPermit.HashShape(intended.IntendedTargetObservationSha256) || !CurrentAppOwnedRepairPermit.HashShape(intended.IntendedRunBindingSha256) ||
            now.Offset != TimeSpan.Zero || proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > now || proof.ExpiresAtUtc <= now ||
            now - proof.BeganAtUtc > TimeSpan.FromHours(12) || proof.ExpiresAtUtc - proof.BeganAtUtc > TimeSpan.FromHours(12) ||
            !proof.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(Required.Order(StringComparer.Ordinal)) ||
            proof.Cases.Select(x => x.ExecutionId).Distinct(StringComparer.Ordinal).Count() != 13 ||
            !proof.Cases.Select(x => x.RunId).Distinct().Order().SequenceEqual(proof.Runs.Select(x => x.RunId).Order())) { throw Invalid(); }
        using var trxStream = new MemoryStream(Read(proof.Trx), false);
        using var xml = XmlReader.Create(trxStream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var counters = trx.Descendants(ns + "Counters").Single(); var results = trx.Descendants(ns + "UnitTestResult").ToArray();
        if ((string?)counters.Attribute("total") != "13" || (string?)counters.Attribute("passed") != "13" || (string?)counters.Attribute("failed") != "0" ||
            results.Length != 13 || results.Any(x => (string?)x.Attribute("outcome") != "Passed")) { throw Invalid(); }
        foreach (var item in proof.Cases)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false);
            var result = results.Single(x => (string?)x.Attribute("testId") == item.TestId && (string?)x.Attribute("executionId") == item.ExecutionId);
            var unit = trx.Descendants(ns + "UnitTest").Single(x => (string?)x.Attribute("id") == item.TestId);
            var method = unit.Element(ns + "TestMethod") ?? throw Invalid();
            string expected = item.CaseId.StartsWith("start-", StringComparison.Ordinal) ?
                "Start_definition_replacement_preserves_allocation_and_exact_other_facts_with_rollback_and_independent_readback" : "Unexpected_preimage_fails_before_candidate";
            if ((string?)result.Attribute("testName") != item.TestName || (string?)method.Attribute("name") != expected ||
                (string?)method.Attribute("className") != "Legacy.Maliev.DataMigration.Tests.Production181CustomerDefinitionNativeTests") { throw Invalid(); }
            RequireImageProvenance(item.ExecutedTestAssemblyPath, item.TestAssembly,
                (string?)method.Attribute("codeBase"), (string?)unit.Attribute("storage"));
            _ = Read(item.TestAssembly);
            using var enteredDocument = JsonDocument.Parse(Read(item.Entered)); using var exitedDocument = JsonDocument.Parse(Read(item.InvocationExit));
            JsonElement entered = enteredDocument.RootElement, exited = exitedDocument.RootElement;
            if (entered.GetProperty("run").GetGuid() != item.RunId || exited.GetProperty("run").GetGuid() != item.RunId ||
                entered.GetProperty("beganAtUtc").GetDateTimeOffset() != item.BeganAtUtc || exited.GetProperty("exitedAtUtc").GetDateTimeOffset() != item.InvocationExitedAtUtc ||
                entered.GetProperty("containerId").GetString() != proof.Runs.Single(x => x.RunId == item.RunId).ContainerId ||
                entered.GetProperty("coreAssemblySha256").GetString() != intended.CoreAssemblySha256 ||
                entered.GetProperty("consoleAssemblySha256").GetString() != intended.ConsoleAssemblySha256 ||
                entered.GetProperty("testAssemblySha256").GetString() != item.TestAssembly.Sha256 ||
                exited.GetProperty("containerId").GetString() != entered.GetProperty("containerId").GetString()) { throw Invalid(); }
            if (item.Committed)
            {
                string actual = "start-" + entered.GetProperty("last").GetInt64().ToString(CultureInfo.InvariantCulture) + "-" +
                    entered.GetProperty("called").GetBoolean().ToString().ToLowerInvariant() + "-" + entered.GetProperty("idOrdinal").GetInt32().ToString(CultureInfo.InvariantCulture);
                if (actual != item.CaseId || item.Rejection is not null) { throw Invalid(); }
            }
            else
            {
                using var rejected = JsonDocument.Parse(Read(item.Rejection ?? throw Invalid())); JsonElement rejection = rejected.RootElement;
                if (Production181CustomerDefinitionAssembler.NegativeCase(entered.GetProperty("changed").GetString() ?? throw Invalid()) != item.CaseId ||
                    rejection.GetProperty("run").GetGuid() != item.RunId || rejection.GetProperty("code").GetString() != item.RejectionCode ||
                    rejection.GetProperty("observedAtUtc").GetDateTimeOffset() < item.BeganAtUtc || rejection.GetProperty("observedAtUtc").GetDateTimeOffset() > item.InvocationExitedAtUtc) { throw Invalid(); }
            }
            var before = Decode<CurrentCustomerSequenceObservation>(Read(item.Before)); var candidate = Decode<CurrentCustomerSequenceObservation>(Read(item.Candidate));
            var after = Decode<CurrentCustomerSequenceObservation>(Read(item.After));
            RequireNativeCase(item.CaseId, before, candidate, after, item.RolledBack is null ? null : Decode<CurrentCustomerSequenceObservation>(Read(item.RolledBack)), item.Committed, item.RejectionCode);
            if (item.Committed)
            {
                var commitCandidate = Decode<CurrentCustomerSequenceObservation>(Read(item.CommitCandidate ?? throw Invalid()));
                ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, commitCandidate, "postgres");
                // The rollback and committed replacements have different physical relfilenodes.
                // Each is independently checked against before; only the committed candidate equals readback.
                if (commitCandidate.State != after.State || commitCandidate.Snapshot.Sha256 != after.Snapshot.Sha256) { throw Invalid(); }
            }
            else if (item.CommitCandidate is not null) { throw Invalid(); }
            if (item.BeganAtUtc.Offset != TimeSpan.Zero || item.InvocationExitedAtUtc.Offset != TimeSpan.Zero || item.BeganAtUtc < proof.BeganAtUtc ||
                item.InvocationExitedAtUtc < item.BeganAtUtc || item.InvocationExitedAtUtc > proof.CompletedAtUtc) { throw Invalid(); }
        }
        foreach (var run in proof.Runs)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false);
            using var attempt = JsonDocument.Parse(Read(run.Attempt)); using var container = JsonDocument.Parse(Read(run.Container));
            using var creationAttempt = JsonDocument.Parse(Read(run.CreationAttempt));
            using var volume = JsonDocument.Parse(Read(run.VolumeMetadata)); using var disposed = JsonDocument.Parse(Read(run.Disposed));
            JsonElement a = attempt.RootElement, c = container.RootElement, v = volume.RootElement, d = disposed.RootElement;
            DateTimeOffset began = a.GetProperty("began").GetDateTimeOffset(), lease = a.GetProperty("expires").GetDateTimeOffset(),
                removed = d.GetProperty("removedAtUtc").GetDateTimeOffset(), completed = d.GetProperty("completedAtUtc").GetDateTimeOffset();
            DateTimeOffset attempted = creationAttempt.RootElement.GetProperty("attemptedAtUtc").GetDateTimeOffset();
            if (run.RunId == Guid.Empty || run.ContainerId.Length != 64 || !run.ContainerId.All(char.IsAsciiHexDigitLower) || run.Port is < 1 or > 65535 ||
                run.Name != Production181EngineContract.Name(run.RunId) || a.GetProperty("run").GetGuid() != run.RunId ||
                a.GetProperty("name").GetString() != run.Name || a.GetProperty("persistent").GetBoolean() ||
                d.GetProperty("run").GetGuid() != run.RunId || d.GetProperty("containerId").GetString() != run.ContainerId ||
                !d.GetProperty("removed").GetBoolean() || !d.GetProperty("disposed").GetBoolean() || d.GetProperty("cleanupFailure").GetBoolean() ||
                began.Offset != TimeSpan.Zero || began < proof.BeganAtUtc || lease - began != TimeSpan.FromMinutes(8) ||
                attempted.Offset != TimeSpan.Zero || attempted < began || attempted > lease ||
                creationAttempt.RootElement.GetProperty("run").GetGuid() != run.RunId || creationAttempt.RootElement.GetProperty("name").GetString() != run.Name ||
                creationAttempt.RootElement.GetProperty("expires").GetDateTimeOffset() != lease || completed > proof.CompletedAtUtc || completed > lease.AddMinutes(1)) { throw Invalid(); }
            var members = proof.Cases.Where(x => x.RunId == run.RunId).ToArray();
            if (members.Any(x => x.BeganAtUtc < began || x.InvocationExitedAtUtc > lease)) { throw Invalid(); }
            DateTimeOffset exited = members.Max(x => x.InvocationExitedAtUtc);
            JsonElement host = c.GetProperty("HostConfig"), config = c.GetProperty("Config");
            DateTimeOffset created = c.GetProperty("Created").GetDateTimeOffset();
            DateTimeOffset started = c.GetProperty("State").GetProperty("StartedAt").GetDateTimeOffset();
            if (c.GetProperty("Id").GetString() != run.ContainerId || c.GetProperty("Name").GetString() != "/" + run.Name || config.GetProperty("Image").GetString() != Image ||
                created < attempted.AddSeconds(-1) || created > started || started > members.Min(x => x.BeganAtUtc) || !c.GetProperty("State").GetProperty("Running").GetBoolean() ||
                config.GetProperty("PgData").GetString() != "/var/lib/postgresql/18/docker" ||
                host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 ||
                host.GetProperty("NanoCpus").GetInt64() != 750000000 || !Empty(host, "Binds") || !Empty(host, "VolumesFrom") || !Production181SemanticResource.DeclaredMount(host, run.Volume) || !EmptyObject(host, "Tmpfs")) { throw Invalid(); }
            var mounts = c.GetProperty("Mounts").EnumerateArray().ToArray(); var ports = c.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray().ToArray();
            if (mounts.Length != 1 || mounts[0].GetProperty("Type").GetString() != "volume" || mounts[0].GetProperty("Name").GetString() != run.Volume ||
                !mounts[0].GetProperty("RW").GetBoolean() || mounts[0].GetProperty("Destination").GetString() != "/var/lib/postgresql" ||
                v.GetProperty("Name").GetString() != run.Volume || v.GetProperty("Driver").GetString() != "local" || v.GetProperty("Scope").GetString() != "local" ||
                run.Volume != Production181EngineContract.Name(run.RunId) || !Production181SemanticResource.NamedLabels(v, run.RunId) || !EmptyObject(v, "Options") ||
                v.GetProperty("CreatedAt").GetDateTimeOffset() < began.AddSeconds(-1) || v.GetProperty("CreatedAt").GetDateTimeOffset() > lease ||
                ports.Length != 1 || ports[0].GetProperty("HostIp").GetString() != "127.0.0.1" || ports[0].GetProperty("HostPort").GetString() != run.Port.ToString(CultureInfo.InvariantCulture)) { throw Invalid(); }
            if (config.GetProperty("Labels").GetProperty("codex.repair.purpose").GetString() != Production181EngineContract.Purpose ||
                config.GetProperty("Labels").GetProperty("codex.repair.operation").GetString() != run.RunId.ToString("D") ||
                config.GetProperty("Labels").GetProperty("codex.repair.run").GetString() != run.RunId.ToString("D") ||
                Decode<string[]>(Read(run.PreviousContainerNames)).Any(x => x == run.Name || x == "/" + run.Name) ||
                Decode<string[]>(Read(run.PreviousVolumes)).Contains(run.Volume, StringComparer.Ordinal) ||
                !Decode<string[]>(Read(run.VolumeConsumers)).SequenceEqual([run.ContainerId], StringComparer.Ordinal)) { throw Invalid(); }
            var absence = Decode<CustomerDefinitionAbsence>(Read(run.Absence));
            RequireCleanup(exited, removed, absence.ObservedAtUtc, completed, lease);
            if (absence.RunId != run.RunId || !absence.ContainersObserved || !absence.VolumesObserved || !absence.ListenersObserved ||
                absence.ContainerIds.Contains(run.ContainerId, StringComparer.Ordinal) || absence.ContainerNames.Any(x => x == run.Name || x == "/" + run.Name) ||
                absence.VolumeNames.Contains(run.Volume, StringComparer.Ordinal) || absence.ListeningPorts.Contains(run.Port)) { throw Invalid(); }
        }
        files.Require();
        byte[] Read(CustomerDefinitionArtifact artifact)
        {
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 8_000_000);
            return CurrentAppOwnedRepairPermit.Hash(bytes) != artifact.Sha256 ? throw Invalid() : bytes;
        }
    }
    internal static void RequireNativeCase(string id, CurrentCustomerSequenceObservation before, CurrentCustomerSequenceObservation candidate,
        CurrentCustomerSequenceObservation after, CurrentCustomerSequenceObservation? rolled, bool committed, string? code)
    {
        if (!Required.Contains(id, StringComparer.Ordinal)) { throw Invalid(); }
        if (id.StartsWith("start-", StringComparison.Ordinal))
        {
            string[] parts = id.Split('-');
            if (before.State.LastValue != long.Parse(parts[1], CultureInfo.InvariantCulture) || before.State.IsCalled != bool.Parse(parts[2]) ||
                before.State.AttributeNumber != short.Parse(parts[3], CultureInfo.InvariantCulture) || !committed || code is not null || rolled is null ||
                (before.State.IsCalled && before.State.LogCount <= 0) || before.State != rolled.State || before.Snapshot.Sha256 != rolled.Snapshot.Sha256) { throw Invalid(); }
            ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, candidate, "postgres");
            ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, after, "postgres");
        }
        else
        {
            bool shape = id switch
            {
                "reject-increment" => before.State.Increment == 2,
                "reject-cache" => before.State.Cache == 2,
                "reject-start" => before.State.Start == 1000,
                "reject-generated" => before.State.Identity == "a",
                "reject-owner" => before.State.Owner == "other_owner",
                _ => false
            };
            if (!shape || committed || code != "current_customer_sequence_definition_preparation_invalid" || rolled is not null || before.State != candidate.State || before.State != after.State ||
                before.Snapshot.Sha256 != candidate.Snapshot.Sha256 || before.Snapshot.Sha256 != after.Snapshot.Sha256) { throw Invalid(); }
            bool rejected = false; try { ApprovedCurrentCustomerSequenceDefinition.RequireBefore(before, "postgres"); } catch (MigrationExecutionException) { rejected = true; }
            if (!rejected) { throw Invalid(); }
        }
    }
    internal static void RequireCleanup(DateTimeOffset exited, DateTimeOffset removed, DateTimeOffset absence, DateTimeOffset disposed, DateTimeOffset lease)
    { if (new[] { exited, removed, absence, disposed, lease }.Any(x => x.Offset != TimeSpan.Zero) || exited > lease || removed < exited || absence < removed || absence > lease || disposed < absence || disposed > lease.AddMinutes(1)) { throw Invalid(); } }
    private static bool Empty(JsonElement host, string name)
    {
        return !host.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null || (value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 0);
    }

    private static bool EmptyObject(JsonElement value, string name)
    {
        return !value.TryGetProperty(name, out var member) || member.ValueKind == JsonValueKind.Null || (member.ValueKind == JsonValueKind.Object && !member.EnumerateObject().Any());
    }

    internal static void RequireImageProvenance(string executedPath, CustomerDefinitionArtifact heldImage, string? codeBase, string? storage)
    {
        if (!Path.IsPathFullyQualified(heldImage.Path) || !CurrentAppOwnedRepairPermit.HashShape(heldImage.Sha256)) { throw Invalid(); }
        CurrentCustomerSequenceClosedProofReader.RequireExecutedAssemblyPath(executedPath, heldImage.SourcePath ?? heldImage.Path, codeBase, storage);
    }

    private static T Decode<T>(byte[] value)
    {
        return MigrationConsole.DecodeCustomerSequence<T>(value);
    }

    private static string AssemblyHash(string path) { using var stream = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    private static MigrationExecutionException Invalid()
    {
        return new("customer_definition_precursor_invalid", "Actual definition precursor proof is required; this grants no operational authority.");
    }
}

internal static class Production181CustomerDefinitionAssembler
{
    // Both authorities retain the original/copy as immediate-root owner-only immutable files.
    // No external path is opened directly and no shared custody rule is changed.
    internal static async Task<CustomerDefinitionArtifact> ImportActualAsync(CurrentAppOwnedRepairCustody sourceFiles,
        CurrentAppOwnedRepairCustody destinationFiles, string sourcePath, string flatDestinationPath, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        sourceFiles.Require(); destinationFiles.Require();
        byte[] bytes = sourceFiles.Read(sourcePath, sharedReader: true, maximumBytes: 8_000_000);
        await destinationFiles.WriteNewAsync(flatDestinationPath, bytes, ct).ConfigureAwait(false);
        byte[] observed = destinationFiles.Read(flatDestinationPath, sharedReader: true, maximumBytes: 8_000_000);
        if (!bytes.AsSpan().SequenceEqual(observed)) { throw Invalid(); }
        sourceFiles.Require(); destinationFiles.Require();
        CurrentCustomerSequenceCapacity.Require(admission: false);
        return new(Path.GetFullPath(flatDestinationPath), CurrentAppOwnedRepairPermit.Hash(observed), Path.GetFullPath(sourcePath));
    }

    // This is an artifact reader, not a test runner. It accepts only already held genuine outputs.
    internal static CustomerDefinitionProof AssembleAfterActualRun(CurrentAppOwnedRepairCustody files,
        CustomerDefinitionSubject intended, string trxPath, string testAssemblyPath, string ledgerDirectory, string keyId,
        DateTimeOffset began, DateTimeOffset completed, DateTimeOffset expires, DateTimeOffset now, string? executedTestAssemblyPath = null)
    {
        CustomerDefinitionArtifact trxArtifact = Artifact(trxPath), assembly = Artifact(testAssemblyPath);
        string executedImage = executedTestAssemblyPath ?? testAssemblyPath;
        assembly = assembly with { SourcePath = Path.GetFullPath(executedImage) };
        using var trxStream = new MemoryStream(files.Read(trxPath, sharedReader: true, maximumBytes: 8_000_000), false);
        using var xml = XmlReader.Create(trxStream,
            new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var cases = new List<CustomerDefinitionCase>(); var runs = new List<CustomerDefinitionRun>();
        foreach (var result in trx.Descendants(ns + "UnitTestResult"))
        {
            string stdout = (string?)result.Element(ns + "Output")?.Element(ns + "StdOut") ?? throw Invalid();
            Guid run = RequireReportedRun(stdout);
            string prefix = Path.Combine(ledgerDirectory, run.ToString("N"));
            CustomerDefinitionArtifact enteredArtifact = Phase("definition-entered");
            using var enteredDocument = JsonDocument.Parse(files.Read(enteredArtifact.Path, sharedReader: true, maximumBytes: 8_000_000));
            JsonElement entered = enteredDocument.RootElement;
            if (entered.GetProperty("run").GetGuid() != run) { throw Invalid(); }
            string id; bool committed = entered.TryGetProperty("last", out var last);
            id = committed
                ? "start-" + last.GetInt64().ToString(CultureInfo.InvariantCulture) + "-" +
                    entered.GetProperty("called").GetBoolean().ToString().ToLowerInvariant() + "-" +
                    entered.GetProperty("idOrdinal").GetInt32().ToString(CultureInfo.InvariantCulture)
                : NegativeCase(entered.GetProperty("changed").GetString() ?? throw Invalid());
            using var exitedDocument = JsonDocument.Parse(files.Read(Phase("definition-invocation-exited").Path, sharedReader: true, maximumBytes: 8_000_000));
            JsonElement exited = exitedDocument.RootElement;
            if (exited.GetProperty("run").GetGuid() != run || exited.GetProperty("containerId").GetString() != entered.GetProperty("containerId").GetString()) { throw Invalid(); }
            string? rejection = null;
            if (!committed)
            {
                using var rejected = JsonDocument.Parse(files.Read(Phase("native-negative-rejection").Path, sharedReader: true, maximumBytes: 8_000_000));
                if (rejected.RootElement.GetProperty("run").GetGuid() != run) { throw Invalid(); }
                rejection = rejected.RootElement.GetProperty("code").GetString();
            }
            CustomerDefinitionArtifact before = Phase(committed ? "native-before" : "native-negative-before");
            // A rejected preimage never ran candidate DDL. Candidate aliases the held actual before frame.
            cases.Add(new CustomerDefinitionCase(id, RequiredAttribute(result, "testName"), RequiredAttribute(result, "testId"),
                RequiredAttribute(result, "executionId"), run, Path.GetFullPath(executedImage), assembly, enteredArtifact, Phase("definition-invocation-exited"),
                committed ? null : Phase("native-negative-rejection"), before,
                committed ? Phase("native-candidate") : before, Phase(committed ? "native-independent-after" : "native-negative-independent-after"),
                committed ? Phase("native-rolled-back") : null, committed ? Phase("native-commit-candidate") : null, entered.GetProperty("beganAtUtc").GetDateTimeOffset(),
                exited.GetProperty("exitedAtUtc").GetDateTimeOffset(), committed, rejection));
            using var container = JsonDocument.Parse(files.Read(Phase("proof-container").Path, sharedReader: true, maximumBytes: 8_000_000));
            using var disposed = JsonDocument.Parse(files.Read(Phase("disposed").Path, sharedReader: true, maximumBytes: 8_000_000));
            JsonElement c = container.RootElement, d = disposed.RootElement;
            string containerId = c.GetProperty("Id").GetString() ?? throw Invalid();
            string name = (c.GetProperty("Name").GetString() ?? throw Invalid()).TrimStart('/');
            string volume = d.GetProperty("volume").GetString() ?? throw Invalid();
            var portBindings = c.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray().ToArray();
            if (portBindings.Length != 1 || !int.TryParse(portBindings[0].GetProperty("HostPort").GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out int port)) { throw Invalid(); }
            runs.Add(new CustomerDefinitionRun(run, containerId, name, volume, port, Phase("attempt"), Phase("proof-container"),
                Phase("proof-volume-metadata"), Phase("disposed"), Phase("proof-absence"), Phase("proof-previous-volumes"), Phase("proof-volume-consumers"), Phase("creation-attempt"), Phase("proof-previous-container-names")));
            CustomerDefinitionArtifact Phase(string phase)
            {
                return Artifact(prefix + "-" + phase + ".json");
            }
        }
        var unsigned = new CustomerDefinitionProof("current-production181-customer-definition-precursor-v1", intended, began, completed, expires,
            trxArtifact, cases, runs, keyId, null);
        Production181CustomerDefinitionReader.RequireBody(files, unsigned, intended, now); return unsigned;
        CustomerDefinitionArtifact Artifact(string path)
        { byte[] bytes = files.Read(path, sharedReader: true, maximumBytes: 8_000_000); return new(path, CurrentAppOwnedRepairPermit.Hash(bytes)); }
    }
    internal static Guid RequireReportedRun(string stdout)
    {
        var runs = new HashSet<Guid>();
        foreach (string line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string value = line.Trim(); if (!value.StartsWith('{')) { continue; }
            try
            {
                using var json = JsonDocument.Parse(value); JsonElement root = json.RootElement;
                if (root.TryGetProperty("Purpose", out var purpose) && purpose.GetString() == Production181EngineContract.Purpose &&
                    root.TryGetProperty("run", out var run) && run.TryGetGuid(out Guid actual) && actual != Guid.Empty) { _ = runs.Add(actual); }
            }
            catch (JsonException) { throw Invalid(); }
        }
        return runs.Count != 1 ? throw Invalid() : runs.Single();
    }
    internal static string NegativeCase(string sql)
    {
        return sql switch
        {
            "ALTER SEQUENCE public.\"Customer_ID_seq\" INCREMENT BY 2;" => "reject-increment",
            "ALTER SEQUENCE public.\"Customer_ID_seq\" CACHE 2;" => "reject-cache",
            "ALTER SEQUENCE public.\"Customer_ID_seq\" START WITH 1000;" => "reject-start",
            "ALTER TABLE public.\"Customer\" ALTER COLUMN \"ID\" SET GENERATED ALWAYS;" => "reject-generated",
            "ALTER TABLE public.\"Customer\" OWNER TO other_owner;" => "reject-owner",
            _ => throw Invalid()
        };
    }

    private static string RequiredAttribute(XElement item, string name)
    {
        return (string?)item.Attribute(name) ?? throw Invalid();
    }

    private static MigrationExecutionException Invalid()
    {
        return new("customer_definition_precursor_invalid", "Genuine held definition invocation artifacts are required.");
    }

    internal static CustomerDefinitionProof SignAfterReadback(CurrentAppOwnedRepairCustody files, CustomerDefinitionProof unsigned,
        CustomerDefinitionSubject intended, P256MigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust, string fingerprint, DateTimeOffset now)
    {
        if (unsigned.Signature is not null || unsigned.KeyId != signer.KeyId) { throw new MigrationExecutionException("customer_definition_precursor_invalid", "Unsigned genuine evidence is required."); }
        // No signing occurs until real held native/TRX/cleanup evidence has been independently checked.
        Production181CustomerDefinitionReader.RequireBody(files, unsigned, intended, now);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Production181CustomerDefinitionReader.Payload(unsigned))) };
        Production181CustomerDefinitionReader.Require(files, signed, intended, trust, signer.KeyId, fingerprint, now); return signed;
    }
}
