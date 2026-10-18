using System.Net;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CustomerHostDockerBaseline(DateTimeOffset ObservedAtUtc, IReadOnlyList<string> Volumes, IReadOnlyList<string> ContainerIds);

// Finite fallback after every testhost member exits. A missing fixture finally is not cleanup proof.
internal static class CustomerGuardedBootstrapHostDockerCleanup
{
    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    internal static async Task<CustomerHostDockerBaseline> ObserveBeforeAsync(CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        try
        {
            var containers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, timeout.Token).ConfigureAwait(false);
            var volumes = await docker.Volumes.ListAsync(timeout.Token).ConfigureAwait(false);
            return new(DateTimeOffset.UtcNow, (volumes.Volumes ?? throw Invalid()).Select(x => x.Name).Order(StringComparer.Ordinal).ToArray(), containers.Select(x => x.ID).Order(StringComparer.Ordinal).ToArray());
        }
        finally { await Task.Run(docker.Dispose, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); }
    }
    internal static async Task RequireCleanupAfterExitAsync(CurrentAppOwnedRepairCustody files, string root, string nonce, CustomerHostDockerBaseline baseline)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        try
        {
            var ownedPorts = new HashSet<int>();
            foreach (string path in Directory.EnumerateFiles(root, "*-host-entry.json", SearchOption.TopDirectoryOnly))
            {
                using var entry = JsonDocument.Parse(files.Read(path, sharedReader: true, maximumBytes: 65536)); JsonElement e = entry.RootElement;
                if (e.GetProperty("jobNonce").GetString() != nonce) { continue; }
                if (!e.GetProperty("nativeJobMembershipObserved").GetBoolean()) { throw Invalid(); }
                Guid run = e.GetProperty("run").GetGuid(); string name = "customer-sequence-guarded-provider-" + run.ToString("N");
                string proxyPath = Path.Combine(root, run.ToString("N") + "-proxy.json");
                if (File.Exists(proxyPath))
                { using var proxy = JsonDocument.Parse(files.Read(proxyPath, sharedReader: true, maximumBytes: 65536)); if (proxy.RootElement.GetProperty("operation").GetGuid() != run) { throw Invalid(); } _ = ownedPorts.Add(proxy.RootElement.GetProperty("port").GetInt32()); }
                string attemptPath = Path.Combine(root, run.ToString("N") + "-attempt.json");
                if (!File.Exists(attemptPath)) { continue; }
                using var attempt = JsonDocument.Parse(files.Read(attemptPath, sharedReader: true, maximumBytes: 65536)); JsonElement a = attempt.RootElement;
                DateTimeOffset began = a.GetProperty("began").GetDateTimeOffset(), expires = a.GetProperty("expires").GetDateTimeOffset();
                if (a.GetProperty("run").GetGuid() != run || a.GetProperty("name").GetString() != name || a.GetProperty("persistent").GetBoolean() ||
                    began < baseline.ObservedAtUtc || expires - began != TimeSpan.FromMinutes(8)) { throw Invalid(); }
                var matches = await docker.Containers.ListContainersAsync(new ContainersListParameters
                {
                    All = true,
                    Filters = new Dictionary<string, IDictionary<string, bool>> { ["label"] = new Dictionary<string, bool> { ["codex.repair.run=" + run.ToString("D")] = true } }
                }, timeout.Token).ConfigureAwait(false);
                if (matches.Count > 1) { throw Invalid(); }
                if (matches.Count == 0)
                {
                    await RequireAbsentAsync(name, null, null).ConfigureAwait(false);
                    string observedPath = Path.Combine(root, run.ToString("N") + "-proof-container.json");
                    if (File.Exists(observedPath))
                    {
                        using var observed = JsonDocument.Parse(files.Read(observedPath, sharedReader: true, maximumBytes: 65536)); string id = observed.RootElement.GetProperty("Id").GetString() ?? throw Invalid();
                        string volume = observed.RootElement.GetProperty("Mounts")[0].GetProperty("Name").GetString() ?? throw Invalid();
                        foreach (var port in observed.RootElement.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray())
                        { _ = ownedPorts.Add(int.Parse(port.GetProperty("HostPort").GetString() ?? throw Invalid(), System.Globalization.CultureInfo.InvariantCulture)); }
                        await RequireAbsentAsync(name, id, volume).ConfigureAwait(false);
                    }
                    else if (File.Exists(Path.Combine(root, run.ToString("N") + "-creation-attempt.json")))
                    {
                        var remaining = await docker.Volumes.ListAsync(timeout.Token).ConfigureAwait(false);
                        if ((remaining.Volumes ?? throw Invalid()).Any(x => !baseline.Volumes.Contains(x.Name, StringComparer.Ordinal))) { throw Invalid(); }
                    }
                    continue;
                }
                string ownedId = matches[0].ID;
                var actual = await docker.Containers.InspectContainerAsync(ownedId, timeout.Token).ConfigureAwait(false);
                var pinned = await docker.Images.InspectImageAsync(Image, timeout.Token).ConfigureAwait(false);
                if (actual.Image != pinned.ID || pinned.RepoDigests is null || !pinned.RepoDigests.Contains("postgres@" + Image.Split('@')[1], StringComparer.Ordinal)) { throw Invalid(); }
                string ownedVolume = RequireOwned(actual, run, name, began, expires, baseline);
                _ = ownedPorts.Add(int.Parse(((actual.NetworkSettings ?? throw Invalid()).Ports ?? throw Invalid())["5432/tcp"][0].HostPort ?? throw Invalid(), System.Globalization.CultureInfo.InvariantCulture));
                await RequireVolumeAsync(ownedVolume, ownedId, began, expires).ConfigureAwait(false);
                if ((actual.State ?? throw Invalid()).Running)
                { _ = await docker.Containers.StopContainerAsync(ownedId, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, timeout.Token).ConfigureAwait(false); }
                actual = await docker.Containers.InspectContainerAsync(ownedId, timeout.Token).ConfigureAwait(false);
                if (RequireOwned(actual, run, name, began, expires, baseline) != ownedVolume || actual.Image != pinned.ID || (actual.State ?? throw Invalid()).Running) { throw Invalid(); }
                await RequireVolumeAsync(ownedVolume, ownedId, began, expires).ConfigureAwait(false);
                await docker.Containers.RemoveContainerAsync(ownedId, new ContainerRemoveParameters { Force = false, RemoveVolumes = true }, timeout.Token).ConfigureAwait(false);
                await RequireAbsentAsync(name, ownedId, ownedVolume).ConfigureAwait(false);
                await files.WriteNewAsync(Path.Combine(root, "customer-host-" + nonce + "-docker-cleaned-" + run.ToString("N") + ".json"),
                    JsonSerializer.SerializeToUtf8Bytes(new { nonce, run, containerId = ownedId, volume = ownedVolume, removedAtUtc = DateTimeOffset.UtcNow, exactAbsenceObserved = true }), timeout.Token).ConfigureAwait(false);
            }
            int[] listeners = [];
            for (int attempt = 0; attempt < 50; attempt++)
            {
                listeners = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
                .Where(x => IPAddress.IsLoopback(x.Address) || x.Address.Equals(IPAddress.Any) || x.Address.Equals(IPAddress.IPv6Any)).Select(x => x.Port).Distinct().Order().ToArray();
                if (!ownedPorts.Any(listeners.Contains)) { break; }
                await Task.Delay(100, timeout.Token).ConfigureAwait(false);
            }
            if (ownedPorts.Any(listeners.Contains)) { throw Invalid(); }
            await files.WriteNewAsync(Path.Combine(root, "customer-host-" + nonce + "-listener-absence.json"), JsonSerializer.SerializeToUtf8Bytes(new
            { nonce, observedAtUtc = DateTimeOffset.UtcNow, ownedPorts = ownedPorts.Order().ToArray(), listeningPorts = listeners, actualAbsenceObserved = true }), timeout.Token).ConfigureAwait(false);
            async Task RequireVolumeAsync(string volume, string id, DateTimeOffset began, DateTimeOffset expires)
            {
                var actual = await docker.Volumes.InspectAsync(volume, timeout.Token).ConfigureAwait(false);
                if (actual.Name != volume || actual.Driver != "local" || actual.Scope != "local" || actual.Options is { Count: > 0 } ||
                    (actual.Labels is { Count: > 0 } && (actual.Labels.Count != 1 || !actual.Labels.TryGetValue("com.docker.volume.anonymous", out string? label) || label != string.Empty)) ||
                    !DateTimeOffset.TryParse(actual.CreatedAt, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var created) || created < began.AddSeconds(-1) || created > expires) { throw Invalid(); }
                var consumers = await docker.Containers.ListContainersAsync(new ContainersListParameters
                {
                    All = true,
                    Filters = new Dictionary<string, IDictionary<string, bool>>
                    { ["volume"] = new Dictionary<string, bool> { [volume] = true } }
                }, timeout.Token).ConfigureAwait(false);
                if (consumers.Count != 1 || consumers[0].ID != id) { throw Invalid(); }
            }
            async Task RequireAbsentAsync(string name, string? id, string? volume)
            {
                string[] keys = id is null ? [name] : [name, id];
                foreach (string key in keys)
                { try { _ = await docker.Containers.InspectContainerAsync(key, timeout.Token).ConfigureAwait(false); throw Invalid(); } catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound) { } }
                if (volume is not null)
                { try { _ = await docker.Volumes.InspectAsync(volume, timeout.Token).ConfigureAwait(false); throw Invalid(); } catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound) { } }
            }
        }
        finally { await Task.Run(docker.Dispose, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); }
    }
    private static string RequireOwned(ContainerInspectResponse actual, Guid run, string name, DateTimeOffset began, DateTimeOffset expires, CustomerHostDockerBaseline baseline)
    {
        var config = actual.Config ?? throw Invalid(); var host = actual.HostConfig ?? throw Invalid(); var mounts = actual.Mounts ?? throw Invalid();
        var state = actual.State ?? throw Invalid(); var ports = (actual.NetworkSettings ?? throw Invalid()).Ports ?? throw Invalid();
        DateTimeOffset created = JsonSerializer.SerializeToElement(actual.Created).GetDateTimeOffset();
        return actual.ID is null || !Hex(actual.ID) || baseline.ContainerIds.Contains(actual.ID, StringComparer.Ordinal) || actual.Name != "/" + name || config.Image != Image ||
            config.Labels is null || !config.Labels.TryGetValue("codex.repair.run", out string? r) || r != run.ToString("D") ||
            !config.Labels.TryGetValue("codex.repair.operation", out string? op) || op != run.ToString("D") ||
            !config.Labels.TryGetValue("codex.repair.purpose", out string? purpose) || purpose != "current-customer-sequence-guarded-native-proof" ||
            host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750000000 || host.Binds is { Count: > 0 } ||
            host.Mounts is { Count: > 0 } || host.Tmpfs is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } || mounts.Count != 1 || mounts[0].Type != "volume" ||
            !Hex(mounts[0].Name) || baseline.Volumes.Contains(mounts[0].Name, StringComparer.Ordinal) || mounts[0].Destination != "/var/lib/postgresql" || !mounts[0].RW ||
            config.Env is null || config.Env.Count(x => x == "PGDATA=/var/lib/postgresql/18/docker") != 1 ||
            !ports.TryGetValue("5432/tcp", out var mapped) || mapped is null || mapped.Count != 1 || mapped[0].HostIP != "127.0.0.1" ||
            !int.TryParse(mapped[0].HostPort, out int port) || port is < 1 or > 65535 || ports.Any(x => x.Key != "5432/tcp" && x.Value is { Count: > 0 }) ||
            created < began.AddSeconds(-1) || created > expires ||
            (state.Running && JsonSerializer.SerializeToElement(state.StartedAt).GetDateTimeOffset() < created)
            ? throw Invalid()
            : mounts[0].Name ?? throw Invalid();
    }
    private static bool Hex(string? value)
    {
        return value is { Length: 64 } && value.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static MigrationExecutionException Invalid()
    {
        return new("customer_guarded_host_docker_cleanup_uncertain", "Exact run-owned disposable Docker cleanup could not be proven; uncertain resources preserved.");
    }
}
