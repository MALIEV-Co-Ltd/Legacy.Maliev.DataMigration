using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record OwnerIsoHostDockerBaseline(DateTimeOffset ObservedAtUtc, IReadOnlyList<string> Volumes, IReadOnlyList<string> ContainerIds);
internal static class OwnerIsoGuardedBootstrapHostDockerCleanup
{
    internal static async Task<OwnerIsoHostDockerBaseline> ObserveBeforeAsync(CancellationToken ct)
    {
        CurrentOwnerIsoCapacity.Require(admission: false);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        var containers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, timeout.Token);
        var volumes = await docker.Volumes.ListAsync(timeout.Token);
        return new(DateTimeOffset.UtcNow, (volumes.Volumes ?? throw Invalid()).Select(x => x.Name).Order(StringComparer.Ordinal).ToArray(), containers.Select(x => x.ID).Order(StringComparer.Ordinal).ToArray());
    }
    // Called only after independently observed exact owned process handles and empty native job.
    internal static async Task RequireCleanupAfterExitAsync(CurrentAppOwnedRepairCustody parentFiles, string parentRoot, string caseRoot, string nonce, OwnerIsoHostDockerBaseline baseline)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        using var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        var ports = new HashSet<int>(); var ids = new HashSet<string>(StringComparer.Ordinal); var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (string entryPath in Directory.EnumerateFiles(caseRoot, "iso-component-*-host-entry.json", SearchOption.TopDirectoryOnly))
        {
            var entry = MigrationConsole.DecodeOwnerIso<IsoActualHostEntry>(Read(entryPath));
            if (entry.JobNonce != nonce) { continue; }
            if (!entry.NativeJobMembershipObserved || entry.RunId == Guid.Empty) { throw Invalid(); }
            string prefix = Path.Combine(caseRoot, "iso-component-" + entry.RunId.ToString("N"));
            string name = "iso-component-" + entry.RunId.ToString("N"); _ = names.Add(name);
            using var attempt = JsonDocument.Parse(Read(prefix + "-attempt.json"));
            var a = attempt.RootElement; DateTimeOffset began = a.GetProperty("began").GetDateTimeOffset(), expires = a.GetProperty("expires").GetDateTimeOffset();
            if (a.GetProperty("run").GetGuid() != entry.RunId || a.GetProperty("name").GetString() != name || a.GetProperty("persistent").GetBoolean() ||
                began < baseline.ObservedAtUtc || expires - began != TimeSpan.FromMinutes(8)) { throw Invalid(); }
            string? observedId = null;
            string observedPath = prefix + "-container.json";
            if (File.Exists(observedPath))
            {
                using var observed = JsonDocument.Parse(Read(observedPath));
                observedId = observed.RootElement.GetProperty("Id").GetString() ?? throw Invalid(); _ = ids.Add(observedId);
                foreach (var observedBinding in observed.RootElement.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray())
                { _ = ports.Add(int.Parse(observedBinding.GetProperty("HostPort").GetString() ?? throw Invalid(), System.Globalization.CultureInfo.InvariantCulture)); }
            }
            string proxyPath = prefix + "-proxy-observed.json";
            if (File.Exists(proxyPath)) { using var proxy = JsonDocument.Parse(Read(proxyPath)); if (proxy.RootElement.GetProperty("RunId").GetGuid() != entry.RunId) { throw Invalid(); } _ = ports.Add(proxy.RootElement.GetProperty("port").GetInt32()); }
            var matches = await docker.Containers.ListContainersAsync(new ContainersListParameters
            {
                All = true,
                Filters = new Dictionary<string, IDictionary<string, bool>> { ["label"] = new Dictionary<string, bool> { ["codex.repair.run=" + entry.RunId.ToString("D")] = true } }
            }, timeout.Token);
            if (matches.Count > 1) { throw Invalid(); }
            if (matches.Count == 0) { continue; }
            string id = matches[0].ID;
            if (baseline.ContainerIds.Contains(id, StringComparer.Ordinal) || (observedId is not null && id != observedId)) { throw Invalid(); }
            var actual = await docker.Containers.InspectContainerAsync(id, timeout.Token); RequireOwned(actual);
            var image = await docker.Images.InspectImageAsync(CurrentOwnerIsoBootstrapSubjectValidator.Image, timeout.Token);
            if (actual.Image != image.ID || image.RepoDigests is null || !image.RepoDigests.Contains("postgres@" + CurrentOwnerIsoBootstrapSubjectValidator.Image.Split('@')[1], StringComparer.Ordinal)) { throw Invalid(); }
            _ = ids.Add(id);
            var binding = (actual.NetworkSettings?.Ports ?? throw Invalid())["5432/tcp"].Single();
            int port = int.Parse(binding.HostPort ?? throw Invalid(), System.Globalization.CultureInfo.InvariantCulture); _ = ports.Add(port);
            if (IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Any(x => x.State == TcpState.Established && IPAddress.IsLoopback(x.RemoteEndPoint.Address) && x.RemoteEndPoint.Port == port)) { throw Invalid(); }
            if (actual.State?.Running == true) { _ = await docker.Containers.StopContainerAsync(id, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, timeout.Token); }
            actual = await docker.Containers.InspectContainerAsync(id, timeout.Token); RequireOwned(actual);
            if (actual.State?.Running != false || actual.Image != image.ID) { throw Invalid(); }
            await docker.Containers.RemoveContainerAsync(id, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, timeout.Token);
            try { _ = await docker.Containers.InspectContainerAsync(id, timeout.Token); throw Invalid(); }
            catch (DockerApiException missing) when (missing.StatusCode == HttpStatusCode.NotFound) { }
            await parentFiles.WriteNewAsync(Path.Combine(parentRoot, "iso-host-" + nonce + "-docker-cleaned-" + entry.RunId.ToString("N") + ".json"),
                JsonSerializer.SerializeToUtf8Bytes(new { nonce, entry.RunId, containerId = id, removedAtUtc = DateTimeOffset.UtcNow, exactAbsenceObserved = true, volumesRemoved = 0 }), timeout.Token);
            void RequireOwned(ContainerInspectResponse value)
            {
                var config = value.Config ?? throw Invalid(); var host = value.HostConfig ?? throw Invalid();
                DateTimeOffset created = JsonSerializer.SerializeToElement(value).GetProperty("Created").GetDateTimeOffset();
                if (value.ID != id || value.Name != "/" + name || created < began.AddSeconds(-1) || created > expires ||
                    config.Image != CurrentOwnerIsoBootstrapSubjectValidator.Image || config.Labels is not { } labels ||
                    !labels.TryGetValue("codex.repair.purpose", out string? purpose) || purpose != "current-owner-iso-guarded-component" ||
                    !labels.TryGetValue("codex.repair.run", out string? run) || run != entry.RunId.ToString("D") ||
                    !labels.TryGetValue("codex.repair.operation", out string? operation) || operation != run ||
                    value.Mounts is not { Count: 0 } || host.Mounts is { Count: > 0 } || host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } ||
                    host.Tmpfs is not { Count: 1 } tmpfs || !tmpfs.TryGetValue("/var/lib/postgresql", out string? options) || options != "rw,nosuid,size=384m" ||
                    host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750000000 ||
                    value.NetworkSettings?.Ports is not { Count: 1 } networkPorts || !networkPorts.TryGetValue("5432/tcp", out var networkBindings) ||
                    networkBindings is not { Count: 1 } || networkBindings[0].HostIP != "127.0.0.1") { throw Invalid(); }
            }
        }
        var all = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, timeout.Token);
        var volumeInventory = await docker.Volumes.ListAsync(timeout.Token);
        int[] listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().Order().ToArray();
        if (all.Any(x => ids.Contains(x.ID) || x.Names.Any(y => names.Contains(y.TrimStart('/')))) || ports.Any(listeners.Contains)) { throw Invalid(); }
        await parentFiles.WriteNewAsync(Path.Combine(parentRoot, "iso-host-" + nonce + "-post-exit-absence.json"), JsonSerializer.SerializeToUtf8Bytes(new
        {
            nonce,
            observedAtUtc = DateTimeOffset.UtcNow,
            containerInventorySucceeded = true,
            volumeInventorySucceeded = true,
            listenerInventorySucceeded = true,
            containerIds = all.Select(x => x.ID).ToArray(),
            containerNames = all.SelectMany(x => x.Names).ToArray(),
            volumeNames = (volumeInventory.Volumes ?? throw Invalid()).Select(x => x.Name).ToArray(),
            listeningPorts = listeners
        }), timeout.Token);
    }
    private static byte[] Read(string path)
    { using var held = SecureLocalFile.OpenReadShared(path); if (held.Length is < 1 or > 65536) { throw Invalid(); } byte[] bytes = new byte[(int)held.Length]; held.ReadExactly(bytes); return bytes; }
    private static MigrationExecutionException Invalid()
    {
        return new("iso_host_cleanup_invalid", "Exact disposable ownership and post-exit absence evidence is required.");
    }
}
