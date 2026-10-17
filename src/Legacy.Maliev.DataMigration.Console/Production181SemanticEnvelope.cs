using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record Production181SemanticRun(Guid RunId, CustomerDefinitionArtifact Engine, CustomerDefinitionArtifact Initializer, CustomerDefinitionArtifact Checksum, CustomerDefinitionArtifact HostEntry);
internal sealed record Production181SemanticEnvelope(string Kind, string Phase, CustomerDefinitionSubject Subject, CustomerDefinitionArtifact Component, CustomerDefinitionArtifact HostExit,
    IReadOnlyList<Production181SemanticRun> Runs, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);
internal sealed record Production181ValidatedComponent(string Phase, string EnvelopeSha256);

// A semantic compatibility component is still not a production scope or permit.
internal static class Production181SemanticEnvelopeReader
{
    internal static byte[] Payload(Production181SemanticEnvelope proof)
    {
        return [.. System.Text.Encoding.UTF8.GetBytes("Legacy.Maliev.Production181.CustomerSemantic." + proof.Phase + ".v1\0"), .. JsonSerializer.SerializeToUtf8Bytes(proof with { Signature = null })];
    }

    internal static Production181ValidatedComponent Require(CurrentAppOwnedRepairCustody files, Production181SemanticEnvelope proof, CustomerDefinitionSubject intended,
        IReceiptAttestationTrustStore trust, string keyId, string fingerprint, DateTimeOffset now)
    {
        if (proof.Kind != "current-production181-customer-semantic-component-v1" || proof.Phase is not ("definition" or "provider" or "maintenance") || proof.KeyId != keyId || proof.Signature is null ||
            !trust.TryGetPublicKeyFingerprintSha256(keyId, out string measured) || measured != fingerprint || !trust.Verify(keyId, Payload(proof), Convert.FromBase64String(proof.Signature))) { throw Invalid(); }
        RequireBody(files, proof, intended, trust, keyId, fingerprint, now); return new(proof.Phase, CurrentAppOwnedSnapshotSerialization.Sha256(proof));
    }
    internal static void RequireBody(CurrentAppOwnedRepairCustody files, Production181SemanticEnvelope proof, CustomerDefinitionSubject intended,
        IReceiptAttestationTrustStore trust, string keyId, string fingerprint, DateTimeOffset now)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        if (JsonSerializer.Serialize(proof.Subject) != JsonSerializer.Serialize(intended) || proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > now || proof.ExpiresAtUtc <= now || proof.ExpiresAtUtc <= proof.CompletedAtUtc || proof.ExpiresAtUtc - proof.BeganAtUtc > TimeSpan.FromHours(12) ||
            proof.Runs.Count != Production181EngineContract.RequiredCases(proof.Phase).Count || proof.Runs.Select(x => x.RunId).Distinct().Count() != proof.Runs.Count) { throw Invalid(); }
        byte[] Read(CustomerDefinitionArtifact artifact, int cap = 8_000_000)
        {
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: cap); return CurrentCustomerSequenceRepairPermit.Hash(bytes) != artifact.Sha256 ? throw Invalid() : bytes;
        }
        Dictionary<Guid, CurrentCustomerSequenceObservation> nativeBefore = [];
        Dictionary<Guid, CustomerDefinitionRun> resources; Dictionary<Guid, (DateTimeOffset Begin, DateTimeOffset End)> invocation;
        DateTimeOffset componentExpires;
        if (proof.Phase == "definition")
        {
            var body = MigrationConsole.DecodeCustomerSequence<CustomerDefinitionProof>(Read(proof.Component));
            Production181CustomerDefinitionReader.Require(files, body, intended, trust, keyId, fingerprint, now);
            resources = body.Runs.ToDictionary(x => x.RunId); invocation = body.Cases.ToDictionary(x => x.RunId, x => (x.BeganAtUtc, x.InvocationExitedAtUtc)); componentExpires = body.ExpiresAtUtc;
            foreach (var item in body.Cases.Where(x => x.CaseId.StartsWith("start-", StringComparison.Ordinal))) { nativeBefore.Add(item.RunId, MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceObservation>(Read(item.Before, 32 * 1024 * 1024))); }
        }
        else
        {
            var body = MigrationConsole.DecodeCustomerSequence<Production181GuardedBootstrapProof>(Read(proof.Component));
            string expected = proof.Phase == "provider" ? "current-production181-customer-native-bootstrap-precursor-v1" : "current-production181-customer-maintenance-bootstrap-precursor-v1";
            if (body.Kind != expected) { throw Invalid(); }
            Production181CustomerGuardedReader.Require(files, body, intended, trust, keyId, fingerprint, now);
            resources = body.Cases.ToDictionary(x => x.RunId, x => x.Resource);
            invocation = body.Cases.ToDictionary(x => x.RunId, x =>
            { using var start = JsonDocument.Parse(Read(x.Entered)); using var end = JsonDocument.Parse(Read(x.Exit)); return (GuardedInvocationBegin(start.RootElement), end.RootElement.GetProperty("exitedAtUtc").GetDateTimeOffset()); }); componentExpires = body.ExpiresAtUtc;
            foreach (var item in body.Cases) { nativeBefore.Add(item.RunId, MigrationConsole.DecodeCustomerSequence<CurrentCustomerSequenceObservation>(Read(item.CustomerBefore, 32 * 1024 * 1024))); }
        }
        if (proof.ExpiresAtUtc > componentExpires || !resources.Keys.Order().SequenceEqual(proof.Runs.Select(x => x.RunId).Order())) { throw Invalid(); }
        var hostExit = MigrationConsole.DecodeCustomerSequence<CustomerGuardedBootstrapHostExit>(Read(proof.HostExit));
        Production181CustomerGuardedReader.RequireHostExit(hostExit, proof.BeganAtUtc, proof.CompletedAtUtc, proof.Runs.Select(x => x.RunId).ToArray());
        foreach (var run in proof.Runs)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false); var resource = resources[run.RunId]; var (Begin, End) = invocation[run.RunId];
            using var entered = JsonDocument.Parse(Read(run.HostEntry, 65536)); var host = entered.RootElement;
            if (host.GetProperty("run").GetGuid() != run.RunId || host.GetProperty("processId").GetInt32() != hostExit.ProcessId || host.GetProperty("processStartTimeUtc").GetDateTimeOffset() != hostExit.ProcessStartTimeUtc ||
                host.GetProperty("executable").GetString() != hostExit.Executable || host.GetProperty("executableSha256").GetString() != hostExit.ExecutableSha256 || host.GetProperty("testAssemblySha256").GetString() != hostExit.TestAssemblySha256 ||
                host.GetProperty("jobNonce").GetString() != hostExit.JobNonce || !host.GetProperty("nativeJobMembershipObserved").GetBoolean() || host.GetProperty("observedAtUtc").GetDateTimeOffset() > Begin) { throw Invalid(); }
            var captured = MigrationConsole.DecodeCustomerSequence<Production181RunCapture>(Read(run.Engine, 32 * 1024 * 1024)); var raw = captured.Actual; Production181RawCaptureReader.RequireEngine(raw.Engine);
            RequireCaptureChronology(captured.ObservedAtUtc, Begin, End);
            if (captured.RunId != run.RunId || (nativeBefore.TryGetValue(run.RunId, out var before) && (raw.Customer.State != before.State || raw.Customer.Snapshot.Sha256 != before.Snapshot.Sha256))) { throw Invalid(); }
            using var original = JsonDocument.Parse(Read(resource.Container, 2 * 1024 * 1024)); var main = original.RootElement;
            using var init = JsonDocument.Parse(Read(run.Initializer, 2 * 1024 * 1024)); var initial = init.RootElement;
            using var checkedFile = JsonDocument.Parse(Read(run.Checksum, 2 * 1024 * 1024)); var check = checkedFile.RootElement; var checker = check.GetProperty("checkerContainer");
            using var disposed = JsonDocument.Parse(Read(resource.Disposed, 65536)); using var absence = JsonDocument.Parse(Read(resource.Absence, 65536));
            string binding = main.GetProperty("Config").GetProperty("Labels").GetProperty("codex.repair.run-binding").GetString() ?? throw Invalid();
            RequireContainer(initial.GetProperty("container"), Production181DisposablePlans.Initializer(run.RunId, binding));
            RequireContainer(checker, Production181DisposablePlans.Checksum(run.RunId, binding)); RequireContainer(main, Production181DisposablePlans.Database(run.RunId, binding));
            if (initial.GetProperty("container").GetProperty("State").GetProperty("Running").GetBoolean() || initial.GetProperty("container").GetProperty("State").GetProperty("OOMKilled").GetBoolean() || initial.GetProperty("container").GetProperty("State").GetProperty("ExitCode").GetInt32() != 0 || initial.GetProperty("runId").GetGuid() != run.RunId || initial.GetProperty("exitCode").GetInt32() != 0 || !initial.GetProperty("removed").GetBoolean() || !initial.GetProperty("absenceObserved").GetBoolean() ||
                initial.GetProperty("volumeConsumersAfterRemoval").GetArrayLength() != 0 || initial.GetProperty("exitedAtUtc").GetDateTimeOffset() > main.GetProperty("Created").GetDateTimeOffset() ||
                check.GetProperty("runId").GetGuid() != run.RunId || check.GetProperty("mainContainerId").GetString() != resource.ContainerId || check.GetProperty("fullVolume").GetString() != resource.Volume ||
                check.GetProperty("beganAtUtc").GetDateTimeOffset() < End || check.GetProperty("mainExitedAtUtc").GetDateTimeOffset() < End ||
                check.GetProperty("mainExitedAtUtc").GetDateTimeOffset() > checker.GetProperty("Created").GetDateTimeOffset() || check.GetProperty("exitCode").GetInt32() != 0 ||
                checker.GetProperty("State").GetProperty("Running").GetBoolean() || checker.GetProperty("State").GetProperty("OOMKilled").GetBoolean() || checker.GetProperty("State").GetProperty("ExitCode").GetInt32() != 0 ||
                check.GetProperty("exitedAtUtc").GetDateTimeOffset() < check.GetProperty("beganAtUtc").GetDateTimeOffset() || check.GetProperty("exitedAtUtc").GetDateTimeOffset() > disposed.RootElement.GetProperty("removedAtUtc").GetDateTimeOffset() ||
                check.GetProperty("exitedAtUtc").GetDateTimeOffset() > proof.CompletedAtUtc || !NoBadChecksums(check.GetProperty("stdout").GetString() ?? string.Empty) ||
                absence.RootElement.GetProperty("ContainerIds").EnumerateArray().Any(x => x.GetString() == checker.GetProperty("Id").GetString() || x.GetString() == initial.GetProperty("containerId").GetString())) { throw Invalid(); }
        }
        files.Require();
    }
    internal static DateTimeOffset GuardedInvocationBegin(JsonElement frame)
    {
        return frame.GetProperty("enteredAtUtc").GetDateTimeOffset();
    }

    internal static void RequireCaptureChronology(DateTimeOffset capture, DateTimeOffset begin, DateTimeOffset end)
    {
        if (capture.Offset != TimeSpan.Zero || begin.Offset != TimeSpan.Zero || end.Offset != TimeSpan.Zero || begin > end || capture < begin || capture > end) { throw Invalid(); }
    }
    internal static bool NoBadChecksums(string text)
    {
        if (text.Length is <= 0 or > 65536) { return false; }
        string[] counts = text.Split('\n').Select(x => x.Trim()).Where(x => x.StartsWith("Bad checksums:", StringComparison.Ordinal)).ToArray();
        return counts.Length == 1 && counts[0] is "Bad checksums: 0" or "Bad checksums:  0";
    }
    private static void RequireContainer(JsonElement c, Docker.DotNet.Models.CreateContainerParameters plan)
    {
        var config = c.GetProperty("Config"); var host = c.GetProperty("HostConfig"); var mounts = c.GetProperty("Mounts").EnumerateArray().ToArray();
        var plannedHost = plan.HostConfig ?? throw Invalid();
        var plannedMounts = plannedHost.Mounts ?? throw Invalid();
        if (plannedMounts.Count != 1) { throw Invalid(); }
        string volume = plannedMounts[0].Source ?? throw Invalid();
        if (string.IsNullOrWhiteSpace(volume)) { throw Invalid(); }
        if (c.GetProperty("Name").GetString() != "/" + plan.Name || c.GetProperty("Image").GetString() != Production181EngineContract.Config || config.GetProperty("Image").GetString() != Production181EngineContract.Image || config.GetProperty("User").GetString() != plan.User ||
            !config.GetProperty("Entrypoint").EnumerateArray().Select(x => x.GetString()).SequenceEqual(plan.Entrypoint) || !config.GetProperty("Cmd").EnumerateArray().Select(x => x.GetString()).SequenceEqual(plan.Cmd) ||
            config.GetProperty("Labels").EnumerateObject().Count() != 4 || plan.Labels.Any(x => config.GetProperty("Labels").GetProperty(x.Key).GetString() != x.Value) ||
            host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("NanoCpus").GetInt64() != 750000000 || host.GetProperty("Privileged").GetBoolean() ||
            !Production181SemanticResource.DeclaredMount(host, volume) || mounts.Length != 1 || mounts[0].GetProperty("Name").GetString() != volume || mounts[0].GetProperty("Destination").GetString() != "/var/lib/postgresql" || !mounts[0].GetProperty("RW").GetBoolean()) { throw Invalid(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentCustomerSequenceRepairPermit.Invalid();
    }
}
