using System.Net;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CustomerNamedClosedDockerBaseline(DateTimeOffset ObservedAtUtc, IReadOnlyList<string> Volumes, IReadOnlyList<string> ContainerIds);
internal sealed record CustomerNamedClosedAbsence(DateTimeOffset ObservedAtUtc, IReadOnlyList<string> ContainerIds,
    IReadOnlyList<string> ContainerNames, IReadOnlyList<string> VolumeNames, IReadOnlyList<int> ListeningPorts,
    IReadOnlyList<Guid> Operations, bool ContainerInventorySucceeded, bool VolumeInventorySucceeded, bool ListenerInventorySucceeded);

internal static class CustomerNamedClosedHostDockerCleanup
{
    internal static async Task<CustomerNamedClosedDockerBaseline> ObserveBeforeAsync(CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        var containers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, timeout.Token).ConfigureAwait(false);
        var volumes = await docker.Volumes.ListAsync(timeout.Token).ConfigureAwait(false);
        return new(DateTimeOffset.UtcNow, (volumes.Volumes ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Select(x => x.Name).Order(StringComparer.Ordinal).ToArray(),
            containers.Select(x => x.ID).Order(StringComparer.Ordinal).ToArray());
    }
    // Called only after the exact native job/testhost has exited. It never kills
    // active owners. Fallback removal uses original held fresh-root creation
    // evidence, fixed name/labels/caps/mount and all-state sole-consumer checks.
    internal static async Task RequireCleanupAfterExitAsync(CurrentAppOwnedRepairCustody parentFiles, string root, string nonce, CustomerNamedClosedDockerBaseline baseline)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        using var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        var operations = new List<Guid>(); var ids = new HashSet<string>(StringComparer.Ordinal); var names = new HashSet<string>(StringComparer.Ordinal); var ports = new HashSet<int>();
        foreach (string entryPath in Directory.EnumerateFiles(root, "*-host-entry.json"))
        {
            using var entry = JsonDocument.Parse(parentFiles.Read(entryPath, sharedReader: true, maximumBytes: 65536)); var e = entry.RootElement;
            if (e.GetProperty("jobNonce").GetString() != nonce) { continue; }
            if (!e.GetProperty("nativeJobMembershipObserved").GetBoolean()) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            Guid op = e.GetProperty("run").GetGuid(); operations.Add(op); string name = "legacy-delta-proof-" + op.ToString("N"); _ = names.Add(name);
            if (baseline.Volumes.Contains(name, StringComparer.Ordinal)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            string caseRoot = Path.Combine(root, "customer-closed-case-" + op.ToString("N"));
            if (!Directory.Exists(caseRoot)) { await RequireAbsent(name).ConfigureAwait(false); continue; }
            string bindingPath = Path.Combine(caseRoot, "fixture-binding.json");
            var binding = CustomerClosedCompletedReadback.ReadProtected<LocalExecutionBinding>(bindingPath, 65536);
            if (binding.ArtifactRootCanonicalPath != caseRoot) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            using var authority = WindowsLocalRunAuthority.AcquireResume(caseRoot, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            CustomerClosedCompletedReadback.RequireExactBinding(files, bindingPath, binding);
            string[] attempts = Directory.GetFiles(caseRoot, "customer-closed-resource-" + op.ToString("N") + "-*-attempt.json");
            if (attempts.Length == 0) { await RequireAbsent(name).ConfigureAwait(false); continue; }
            if (attempts.Length != 1) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            using var attempt = JsonDocument.Parse(files.Read(attempts[0], sharedReader: true, maximumBytes: 2 * 1024 * 1024)); var a = attempt.RootElement;
            DateTimeOffset began = a.GetProperty("began").GetDateTimeOffset(), expires = a.GetProperty("expires").GetDateTimeOffset();
            if (a.GetProperty("operation").GetGuid() != op || a.GetProperty("name").GetString() != name || a.GetProperty("persistent").GetBoolean() ||
                began < baseline.ObservedAtUtc || expires - began != TimeSpan.FromMinutes(8) ||
                a.GetProperty("previousVolumes").EnumerateArray().Any(x => x.GetString() == name)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            ContainerInspectResponse? container = null;
            try { container = await docker.Containers.InspectContainerAsync(name, timeout.Token).ConfigureAwait(false); }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { }
            if (container is not null)
            {
                RequireCreationInterval("container", JsonSerializer.SerializeToElement(container).GetProperty("Created").GetDateTimeOffset());
                RequireContainer(container, op, name, binding.ComputeSha256(), began, expires);
                if (baseline.ContainerIds.Contains(container.ID, StringComparer.Ordinal)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                _ = ids.Add(container.ID);
                foreach (var mapping in (container.NetworkSettings ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Ports.Values.SelectMany(x => x ?? []))
                { if (int.TryParse(mapping.HostPort, out int port)) { _ = ports.Add(port); } }
                var ownedVolume = await docker.Volumes.InspectAsync(name, timeout.Token).ConfigureAwait(false);
                RequireCreationInterval("volume", DateTimeOffset.Parse(ownedVolume.CreatedAt ?? throw CurrentCustomerSequenceRepairPermit.Invalid(), System.Globalization.CultureInfo.InvariantCulture));
                await RequireVolume(name, op, binding.ComputeSha256(), began, expires, container.ID).ConfigureAwait(false);
                if ((container.State ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Running) { _ = await docker.Containers.StopContainerAsync(container.ID, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, timeout.Token).ConfigureAwait(false); }
                var stopped = await docker.Containers.InspectContainerAsync(container.ID, timeout.Token).ConfigureAwait(false);
                RequireContainer(stopped, op, name, binding.ComputeSha256(), began, expires);
                if ((stopped.State ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Running || stopped.ID != container.ID) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                await RequireVolume(name, op, binding.ComputeSha256(), began, expires, container.ID).ConfigureAwait(false);
                await docker.Containers.RemoveContainerAsync(container.ID, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, timeout.Token).ConfigureAwait(false);
            }
            await RequireAbsent(name).ConfigureAwait(false);
            bool present = true;
            try { await RequireVolume(name, op, binding.ComputeSha256(), began, expires, null).ConfigureAwait(false); }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { present = false; }
            if (present)
            {
                var ownedVolume = await docker.Volumes.InspectAsync(name, timeout.Token).ConfigureAwait(false);
                RequireCreationInterval("volume", DateTimeOffset.Parse(ownedVolume.CreatedAt ?? throw CurrentCustomerSequenceRepairPermit.Invalid(), System.Globalization.CultureInfo.InvariantCulture));
                await docker.Volumes.RemoveAsync(name, force: false, timeout.Token).ConfigureAwait(false);
            }
            foreach (string proxy in Directory.GetFiles(caseRoot, "customer-closed-" + op.ToString("N") + "-*-proxy-started.json"))
            { using var record = JsonDocument.Parse(files.Read(proxy, sharedReader: true, maximumBytes: 65536)); _ = ports.Add(record.RootElement.GetProperty("Port").GetInt32()); }
            files.Require();
            void RequireCreationInterval(string kind, DateTimeOffset created)
            {
                string start = Directory.GetFiles(caseRoot, "*-" + kind + "-creation-start.json").Single();
                string end = Directory.GetFiles(caseRoot, "*-" + kind + "-creation-end.json").Single();
                using var s = JsonDocument.Parse(files.Read(start, sharedReader: true, maximumBytes: 65536));
                using var f = JsonDocument.Parse(files.Read(end, sharedReader: true, maximumBytes: 65536));
                var first = s.RootElement; var last = f.RootElement;
                if (first.GetProperty("operation").GetGuid() != op || last.GetProperty("operation").GetGuid() != op ||
                    first.GetProperty("name").GetString() != name || last.GetProperty("name").GetString() != name || !first.GetProperty("absent").GetBoolean() ||
                    first.GetProperty("startedAtUtc").GetDateTimeOffset() < began || last.GetProperty("completedAtUtc").GetDateTimeOffset() > expires ||
                    created < first.GetProperty("startedAtUtc").GetDateTimeOffset().AddSeconds(-1) || created > last.GetProperty("completedAtUtc").GetDateTimeOffset().AddSeconds(1))
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
        }
        var allContainers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, timeout.Token).ConfigureAwait(false);
        var allVolumes = await docker.Volumes.ListAsync(timeout.Token).ConfigureAwait(false);
        string[] containerIds = [.. allContainers.Select(x => x.ID).Order(StringComparer.Ordinal)], containerNames = [.. allContainers.SelectMany(x => x.Names).Order(StringComparer.Ordinal)],
            volumeNames = [.. (allVolumes.Volumes ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Select(x => x.Name).Order(StringComparer.Ordinal)];
        int[] listeners = [.. System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().Order()];
        if (ids.Any(x => containerIds.Contains(x, StringComparer.Ordinal)) || names.Any(x => containerNames.Contains("/" + x, StringComparer.Ordinal) || volumeNames.Contains(x, StringComparer.Ordinal)) ||
            ports.Any(listeners.Contains) || baseline.Volumes.Any(x => !volumeNames.Contains(x, StringComparer.Ordinal))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        await parentFiles.WriteNewAsync(Path.Combine(root, "customer-named-host-" + nonce + "-absence.json"), JsonSerializer.SerializeToUtf8Bytes(
            new CustomerNamedClosedAbsence(DateTimeOffset.UtcNow, containerIds, containerNames, volumeNames, listeners, operations, true, true, true)), timeout.Token).ConfigureAwait(false);
        async Task RequireAbsent(string name)
        {
            try { _ = await docker.Containers.InspectContainerAsync(name, timeout.Token).ConfigureAwait(false); throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { }
        }
        async Task RequireVolume(string name, Guid operation, string hash, DateTimeOffset began, DateTimeOffset expires, string? sole)
        {
            var v = await docker.Volumes.InspectAsync(name, timeout.Token).ConfigureAwait(false);
            if (v.Name != name || v.Driver != "local" || v.Scope != "local" || v.Options is { Count: > 0 } || v.Labels.Count != 3 ||
                v.Labels["codex.repair.purpose"] != "current-customer-sequence-proof" || v.Labels["codex.repair.operation"] != operation.ToString("D") || v.Labels["codex.repair.run-binding"] != hash ||
                !DateTimeOffset.TryParse(v.CreatedAt, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var created) || created < began.AddSeconds(-1) || created > expires)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            var consumers = await docker.Containers.ListContainersAsync(new ContainersListParameters
            {
                All = true,
                Filters = new Dictionary<string, IDictionary<string, bool>> { ["volume"] = new Dictionary<string, bool> { [name] = true } }
            }, timeout.Token).ConfigureAwait(false);
            if (sole is null ? consumers.Count != 0 : consumers.Count != 1 || consumers[0].ID != sole) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
    }
    private static void RequireContainer(ContainerInspectResponse c, Guid operation, string name, string hash, DateTimeOffset began, DateTimeOffset expires)
    {
        var config = c.Config ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        var host = c.HostConfig ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        DateTimeOffset created = JsonSerializer.SerializeToElement(c).GetProperty("Created").GetDateTimeOffset();
        if (c.ID.Length != 64 || c.Name != "/" + name || config.Image != "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382" ||
            config.Labels["codex.repair.purpose"] != "current-customer-sequence-proof" || config.Labels["codex.repair.operation"] != operation.ToString("D") || config.Labels["codex.repair.run-binding"] != hash ||
            created < began.AddSeconds(-1) || created > expires || host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750_000_000 ||
            c.Mounts.Count != 1 || c.Mounts[0].Type != "volume" || c.Mounts[0].Name != name || c.Mounts[0].Destination != "/var/lib/postgresql" || !c.Mounts[0].RW ||
            host.Tmpfs is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } ||
            host.PortBindings.Count != 1 || !host.PortBindings.TryGetValue("5432/tcp", out var mappings) || mappings.Count != 1 || mappings[0].HostIP != "127.0.0.1")
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
}
