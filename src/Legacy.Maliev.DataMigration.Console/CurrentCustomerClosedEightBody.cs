using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal static partial class CurrentCustomerClosedEightReadback
{
    internal static async Task RequireBodyAsync(CurrentAppOwnedRepairCustody files, CustomerClosedEightReport report,
        DateTimeOffset now, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        var subject = CustomerClosedCompletedReadback.Require(report.CompletedComponents, now);
        if (report.ExpiresAtUtc > CustomerClosedCompletedReadback.MaximumExpires(report.CompletedComponents) || CurrentAppOwnedSnapshotSerialization.Sha256(subject) != CurrentAppOwnedSnapshotSerialization.Sha256(report.IntendedSubject) || report.TestAssembly.SourcePath != report.CompletedComponents.TestAssemblyPath ||
            report.TestAssembly.Sha256 != report.CompletedComponents.TestAssemblySha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        await RequireArtifactAsync(files, report.TestAssembly, ct).ConfigureAwait(false);
        byte[] Read(CustomerDefinitionArtifact a, int cap = 8_000_000)
        { byte[] b = files.Read(a.Path, sharedReader: true, maximumBytes: cap); return CurrentCustomerSequenceRepairPermit.Hash(b) == a.Sha256 ? b : throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var exit = CustomerClosedCompletedReadback.Decode<CustomerNamedClosedHostExit>(Read(report.HostExit, 65536));
        if (exit.Kind != "current-customer-sequence-named-closed-testhost-exit-v1" || exit.ExitCode != 0 || !exit.ProcessExitObserved ||
            !exit.NativeMembershipObserved || !exit.EmptyJobObservedAfterExit || exit.TestAssemblySha256 != report.TestAssembly.Sha256 ||
            exit.ProcessStartTimeUtc < report.BeganAtUtc || exit.MembershipObservedAtUtc < exit.ProcessStartTimeUtc || exit.MembershipObservedAtUtc > exit.ExitedAtUtc ||
            exit.ExitedAtUtc > report.CompletedAtUtc || !exit.RunIds.Order().SequenceEqual(report.Cases.Select(x => x.OperationId).Order()))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        using var cleanup = JsonDocument.Parse(Read(report.HostCleanup, 65536)); var h = cleanup.RootElement;
        var absence = CustomerClosedCompletedReadback.Decode<CustomerNamedClosedAbsence>(Read(report.HostAbsence, 65536));
        var baseline = CustomerClosedCompletedReadback.Decode<CustomerNamedClosedDockerBaseline>(Read(report.HostBaseline, 65536));
        if (h.GetProperty("nonce").GetString() != exit.JobNonce || h.GetProperty("cleanupFailure").GetBoolean() ||
            !h.GetProperty("launched").GetBoolean() || !h.GetProperty("allMemberExitObserved").GetBoolean() || !h.GetProperty("waitingChildExited").GetBoolean() ||
            !h.GetProperty("streamsSettled").GetBoolean() || h.GetProperty("completedAtUtc").GetDateTimeOffset() < exit.ExitedAtUtc ||
            h.GetProperty("completedAtUtc").GetDateTimeOffset() > report.CompletedAtUtc ||
            !absence.ContainerInventorySucceeded || !absence.VolumeInventorySucceeded || !absence.ListenerInventorySucceeded ||
            absence.ObservedAtUtc < exit.ExitedAtUtc || absence.ObservedAtUtc > report.CompletedAtUtc ||
            !absence.Operations.Order().SequenceEqual(report.Cases.Select(x => x.OperationId).Order()) || baseline.ObservedAtUtc > exit.ProcessStartTimeUtc ||
            baseline.ObservedAtUtc < report.BeganAtUtc || baseline.Volumes.Any(x => !absence.VolumeNames.Contains(x, StringComparer.Ordinal)) ||
            report.Cases.Any(x => baseline.Volumes.Contains("legacy-delta-proof-" + x.OperationId.ToString("N"), StringComparer.Ordinal)))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        await RequireArtifactAsync(files, report.Trx, ct).ConfigureAwait(false);
        var trx = files.BorrowReadStream(report.Trx.Path, 32 * 1024 * 1024); trx.Position = 0;
        using var xml = XmlReader.Create(trx, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, CloseInput = false, MaxCharactersInDocument = 32 * 1024 * 1024 });
        XDocument document = XDocument.Load(xml); RequireTrx(document, report.Cases, report.TestAssembly.SourcePath);
        foreach (var item in report.Cases)
        {
            ct.ThrowIfCancellationRequested(); CurrentCustomerSequenceCapacity.Require(admission: false);
            if (item.Artifacts.Count is < 10 or > 256 || item.Artifacts.Any(x => x.SourcePath is null || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(x.SourcePath)), item.OriginalRoot)) ||
                item.Artifacts.Select(x => x.SourcePath).Distinct(StringComparer.Ordinal).Count() != item.Artifacts.Count ||
                item.Artifacts.Select(x => x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != item.Artifacts.Count)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            foreach (var a in item.Artifacts) { await RequireArtifactAsync(files, a, ct).ConfigureAwait(false); }
            string Resolve(string original)
            {
                return item.Artifacts.Single(x => x.SourcePath == original).Path;
            }

            CustomerDefinitionArtifact Named(string name)
            {
                return item.Artifacts.Single(x => Path.GetFileName(x.SourcePath) == name);
            }

            var actual = CustomerClosedCompletedReadback.Decode<CustomerClosedCase>(Read(item.Facts));
            var config = CustomerClosedCompletedReadback.Decode<CurrentCustomerSequenceRepairConfiguration>(Read(Named("closed-config.json")));
            var scope = CustomerClosedCompletedReadback.Decode<CurrentCustomerSequenceRepairScope>(Read(Named("closed-scope.json")));
            var source = CustomerClosedCompletedReadback.Decode<FreshSchemaPlan>(Read(Named("closed-source.json"), 32 * 1024 * 1024));
            var binding = CustomerClosedCompletedReadback.Decode<LocalExecutionBinding>(Read(Named("fixture-binding.json"), 65536));
            if (!StringComparer.OrdinalIgnoreCase.Equals(binding.ArtifactRootCanonicalPath, item.OriginalRoot) || binding.ComputeSha256() != actual.BindingSha256 || actual.OperationId != item.OperationId ||
                actual.CaseId != item.CaseId || actual.BeganAtUtc < report.BeganAtUtc || actual.CompletedAtUtc > exit.ExitedAtUtc ||
                item.TestBeganAtUtc.Offset != TimeSpan.Zero || item.TestExitedAtUtc.Offset != TimeSpan.Zero || item.TestBeganAtUtc < exit.ProcessStartTimeUtc ||
                actual.BeganAtUtc < item.TestBeganAtUtc || actual.CompletedAtUtc > item.TestExitedAtUtc || item.TestExitedAtUtc > exit.ExitedAtUtc ||
                scope.ClosedConsoleSeed?.CaseId != item.CaseId || scope.ProofAdmission != CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            using var entry = JsonDocument.Parse(Read(item.HostEntry, 65536)); var e = entry.RootElement;
            if (e.GetProperty("run").GetGuid() != item.OperationId || e.GetProperty("caseId").GetString() != item.CaseId ||
                e.GetProperty("jobNonce").GetString() != exit.JobNonce || !e.GetProperty("nativeJobMembershipObserved").GetBoolean() ||
                e.GetProperty("processId").GetInt32() != exit.ProcessId || e.GetProperty("processStartTimeUtc").GetDateTimeOffset() != exit.ProcessStartTimeUtc ||
                e.GetProperty("testAssemblySha256").GetString() != report.TestAssembly.Sha256 ||
                e.GetProperty("executableSha256").GetString() != exit.ExecutableSha256)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            CurrentCustomerClosedCaseEvidence.Require(files, actual, scope, Resolve, item.Artifacts);
            RequireOwnedTarget(item, scope, Read);
            await RequireEffectsAsync(files, actual, scope, config, source, now, ct, Resolve, item.Artifacts).ConfigureAwait(false);
            RequireCleanup(item, actual, scope, absence, Read);
        }
        files.Require();
    }
    private static void RequireOwnedTarget(CustomerClosedEightCase item, CurrentCustomerSequenceRepairScope scope, Func<CustomerDefinitionArtifact, int, byte[]> read)
    {
        var artifact = item.Artifacts.Single(x => (Path.GetFileName(x.SourcePath) ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).StartsWith("customer-closed-resource-" + item.OperationId.ToString("N") + "-", StringComparison.Ordinal) &&
            x.SourcePath!.EndsWith("-target.json", StringComparison.Ordinal));
        using var json = JsonDocument.Parse(read(artifact, 2 * 1024 * 1024)); var c = json.RootElement;
        string name = "legacy-delta-proof-" + item.OperationId.ToString("N"); string id = c.GetProperty("Id").GetString() ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        var config = c.GetProperty("Config"); var host = c.GetProperty("HostConfig"); var labels = config.GetProperty("Labels"); var mounts = c.GetProperty("Mounts").EnumerateArray().ToArray();
        if (id.Length != 64 || c.GetProperty("Name").GetString() != "/" + name || !LocalDockerGenerationGuard.IsGenerationFor(scope.TargetGeneration, id) ||
            scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire || scope.Target.AuthorityId != "aspire://legacy-postgres-main-local/disposable-" + id[..12] ||
            config.GetProperty("Image").GetString() != "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382" ||
            config.TryGetProperty("Env", out _) || config.GetProperty("PgData").GetString() != "/var/lib/postgresql/18/docker" ||
            labels.GetProperty("codex.repair.purpose").GetString() != "current-customer-sequence-proof" ||
            labels.GetProperty("codex.repair.operation").GetString() != item.OperationId.ToString("D") || labels.GetProperty("codex.repair.run-binding").GetString() != scope.RunBindingSha256 ||
            host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("NanoCpus").GetInt64() != 750_000_000 ||
            mounts.Length != 1 || mounts[0].GetProperty("Type").GetString() != "volume" || mounts[0].GetProperty("Name").GetString() != name ||
            mounts[0].GetProperty("Destination").GetString() != "/var/lib/postgresql" || !mounts[0].GetProperty("RW").GetBoolean())
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        foreach (string kind in new[] { "container", "volume" })
        {
            var start = item.Artifacts.Single(x => x.SourcePath!.EndsWith("-" + kind + "-creation-start.json", StringComparison.Ordinal));
            var finish = item.Artifacts.Single(x => x.SourcePath!.EndsWith("-" + kind + "-creation-end.json", StringComparison.Ordinal));
            using var first = JsonDocument.Parse(read(start, 65536)); using var last = JsonDocument.Parse(read(finish, 65536));
            if (!first.RootElement.GetProperty("absent").GetBoolean() || first.RootElement.GetProperty("operation").GetGuid() != item.OperationId ||
                last.RootElement.GetProperty("operation").GetGuid() != item.OperationId || first.RootElement.GetProperty("name").GetString() != name || last.RootElement.GetProperty("name").GetString() != name ||
                last.RootElement.GetProperty("completedAtUtc").GetDateTimeOffset() < first.RootElement.GetProperty("startedAtUtc").GetDateTimeOffset())
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            if (kind == "container")
            {
                var created = c.GetProperty("Created").GetDateTimeOffset();
                if (created < first.RootElement.GetProperty("startedAtUtc").GetDateTimeOffset().AddSeconds(-1) || created > last.RootElement.GetProperty("completedAtUtc").GetDateTimeOffset().AddSeconds(1))
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
        }
        var volumes = item.Artifacts.Where(x => x.SourcePath!.EndsWith("-volume.json", StringComparison.Ordinal)).ToArray();
        if (volumes.Length < 2) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string? generation = null; bool soleConsumerObserved = false;
        var volumeStart = item.Artifacts.Single(x => x.SourcePath!.EndsWith("-volume-creation-start.json", StringComparison.Ordinal));
        var volumeEnd = item.Artifacts.Single(x => x.SourcePath!.EndsWith("-volume-creation-end.json", StringComparison.Ordinal));
        using var volumeFirst = JsonDocument.Parse(read(volumeStart, 65536)); using var volumeLast = JsonDocument.Parse(read(volumeEnd, 65536));
        foreach (var volume in volumes)
        {
            using var v = JsonDocument.Parse(read(volume, 65536)); var x = v.RootElement;
            if (x.GetProperty("Name").GetString() != name || x.GetProperty("Driver").GetString() != "local" || x.GetProperty("Scope").GetString() != "local" ||
                x.GetProperty("existedBefore").GetBoolean() || x.GetProperty("consumers").GetArrayLength() > 1 || x.GetProperty("consumers").EnumerateArray().Any(y => y.GetString() != id) ||
                x.GetProperty("Labels").EnumerateObject().Count() != 3 || x.GetProperty("Labels").GetProperty("codex.repair.purpose").GetString() != "current-customer-sequence-proof" ||
                x.GetProperty("Labels").GetProperty("codex.repair.operation").GetString() != item.OperationId.ToString("D") ||
                x.GetProperty("Labels").GetProperty("codex.repair.run-binding").GetString() != scope.RunBindingSha256 ||
                (x.GetProperty("Options").ValueKind != JsonValueKind.Null && (x.GetProperty("Options").ValueKind != JsonValueKind.Object || x.GetProperty("Options").EnumerateObject().Any())))
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            soleConsumerObserved |= x.GetProperty("consumers").GetArrayLength() == 1;
            var volumeCreated = DateTimeOffset.Parse(x.GetProperty("CreatedAt").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
            if (volumeCreated < volumeFirst.RootElement.GetProperty("startedAtUtc").GetDateTimeOffset().AddSeconds(-1) ||
                volumeCreated > volumeLast.RootElement.GetProperty("completedAtUtc").GetDateTimeOffset().AddSeconds(1)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            string measured = string.Join(':', "docker", id, c.GetProperty("Created").GetDateTimeOffset().ToUnixTimeMilliseconds(),
                c.GetProperty("State").GetProperty("StartedAt").GetDateTimeOffset().ToUnixTimeMilliseconds(),
                DateTimeOffset.Parse(x.GetProperty("CreatedAt").GetString()!, System.Globalization.CultureInfo.InvariantCulture).ToUnixTimeMilliseconds());
            if (measured != scope.TargetGeneration || (generation is not null && generation != measured)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            generation = measured;
        }
        if (!soleConsumerObserved) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    internal static async Task RequireArtifactAsync(CurrentAppOwnedRepairCustody files, CustomerDefinitionArtifact artifact, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        if (!CurrentCustomerSequenceRepairPermit.HashShape(artifact.Sha256)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var stream = files.BorrowReadStream(artifact.Path, 512 * 1024 * 1024); stream.Position = 0;
        if (Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false)) != artifact.Sha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        files.Require();
    }
    internal static void RequireTrx(XDocument document, IReadOnlyList<CustomerClosedEightCase> cases, string executedAssembly)
    {
        XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var counters = document.Descendants(ns + "Counters").Single();
        foreach (string field in new[] { "total", "executed", "passed" }) { if ((string?)counters.Attribute(field) != "8") { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
        if ((string?)counters.Attribute("failed") != "0" || (string?)counters.Attribute("notExecuted") != "0") { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var results = document.Descendants(ns + "UnitTestResult").ToArray(); if (results.Length != 8) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        foreach (var item in cases)
        {
            var result = results.Single(x => (string?)x.Attribute("testId") == item.TestId && (string?)x.Attribute("executionId") == item.ExecutionId);
            var test = document.Descendants(ns + "UnitTest").Single(x => (string?)x.Attribute("id") == item.TestId);
            var method = test.Element(ns + "TestMethod") ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
            if ((string?)result.Attribute("outcome") != "Passed" || (string?)result.Attribute("testName") != item.TestName ||
                (string?)method.Attribute("className") != "Legacy.Maliev.DataMigration.Tests.CurrentCustomerClosedConsoleExecutionTests" ||
                (string?)method.Attribute("name") != "Genuine_named_closed_customer_console" ||
                DateTimeOffset.Parse((string?)result.Attribute("startTime") ?? "", System.Globalization.CultureInfo.InvariantCulture) != item.TestBeganAtUtc ||
                DateTimeOffset.Parse((string?)result.Attribute("endTime") ?? "", System.Globalization.CultureInfo.InvariantCulture) != item.TestExitedAtUtc ||
                !item.TestName.EndsWith("(caseId: \"" + item.CaseId + "\")", StringComparison.Ordinal) ||
                !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath((string?)test.Attribute("storage") ?? ""), Path.GetFullPath(executedAssembly)) ||
                !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath((string?)method.Attribute("codeBase") ?? ""), Path.GetFullPath(executedAssembly)))
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
    }
    private static void RequireCleanup(CustomerClosedEightCase item, CustomerClosedCase actual, CurrentCustomerSequenceRepairScope scope,
        CustomerNamedClosedAbsence host, Func<CustomerDefinitionArtifact, int, byte[]> read)
    {
        CustomerDefinitionArtifact Frame(string suffix)
        {
            return item.Artifacts.Single(x => (Path.GetFileName(x.SourcePath) ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).StartsWith("customer-closed-resource-" + item.OperationId.ToString("N") + "-", StringComparison.Ordinal) && x.SourcePath!.EndsWith(suffix, StringComparison.Ordinal));
        }

        using var disposed = JsonDocument.Parse(read(Frame("-disposed.json"), 65536)); var d = disposed.RootElement;
        using var absent = JsonDocument.Parse(read(Frame("-absent.json"), 65536)); var a = absent.RootElement;
        string volume = "legacy-delta-proof-" + item.OperationId.ToString("N");
        DateTimeOffset disposedAt = d.GetProperty("completedAtUtc").GetDateTimeOffset(), observed = a.GetProperty("observedAtUtc").GetDateTimeOffset();
        if (d.GetProperty("Operation").GetGuid() != item.OperationId || !d.GetProperty("removed").GetBoolean() || !d.GetProperty("sdkDisposed").GetBoolean() ||
            d.GetProperty("cleanupFailed").GetBoolean() || disposedAt < actual.CompletedAtUtc || observed < actual.CompletedAtUtc || observed > disposedAt ||
            observed > d.GetProperty("expiresAtUtc").GetDateTimeOffset() || disposedAt > host.ObservedAtUtc || disposedAt > item.TestExitedAtUtc ||
            !a.GetProperty("secretsAbsent").GetBoolean() || a.GetProperty("volume").GetString() != volume ||
            a.GetProperty("volumeNames").EnumerateArray().Any(x => x.GetString() == volume) ||
            a.GetProperty("containerNames").EnumerateArray().Any(x => x.GetString() == "/" + volume) ||
            host.VolumeNames.Contains(volume, StringComparer.Ordinal) || host.ContainerNames.Contains("/" + volume, StringComparer.Ordinal))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var target = Frame("-target.json"); using var targetJson = JsonDocument.Parse(read(target, 2 * 1024 * 1024));
        var maps = targetJson.RootElement.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray().ToArray();
        if (maps.Length != 1 || maps[0].GetProperty("HostIp").GetString() != "127.0.0.1" ||
            !int.TryParse(maps[0].GetProperty("HostPort").GetString(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int targetPort) ||
            targetPort is < 1 or > 65535 || host.ListeningPorts.Contains(targetPort) || a.GetProperty("listeningPorts").EnumerateArray().Any(x => x.GetInt32() == targetPort))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var starts = item.Artifacts.Where(x => x.SourcePath!.EndsWith("-proxy-started.json", StringComparison.Ordinal)).ToArray();
        foreach (var start in starts)
        { using var proxy = JsonDocument.Parse(read(start, 65536)); int port = proxy.RootElement.GetProperty("Port").GetInt32(); if (host.ListeningPorts.Contains(port)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } }
        if (scope.ClosedConsoleSeed!.ExpiresAtUtc < observed) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
}
