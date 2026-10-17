using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;

namespace Legacy.Maliev.DataMigration.Console;

// Fallback only after all actual job members exited. It never invents successful case evidence.
internal static class Production181HostDockerCleanup
{
    internal static async Task<CustomerHostDockerBaseline> ObserveBeforeAsync(CurrentAppOwnedRepairCustody files, string root, string nonce, CancellationToken ct)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct); bounded.CancelAfter(TimeSpan.FromSeconds(30));
        var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        CustomerHostDockerBaseline result; bool disposed = false;
        try
        {
            var containers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, bounded.Token).ConfigureAwait(false);
            var volumes = await docker.Volumes.ListAsync(bounded.Token).ConfigureAwait(false);
            result = new(DateTimeOffset.UtcNow, (volumes.Volumes ?? throw Invalid()).Select(x => x.Name).Order(StringComparer.Ordinal).ToArray(), containers.Select(x => x.ID).Order(StringComparer.Ordinal).ToArray());
        }
        finally { disposed = await RetainDisposal(files, root, nonce, "baseline", docker).ConfigureAwait(false); }
        return !disposed ? throw Invalid() : result;
    }
    internal static async Task RequireCleanupAfterExitAsync(CurrentAppOwnedRepairCustody files, string root, string nonce, CustomerHostDockerBaseline baseline, string expectedBinding)
    {
        using var bounded = new CancellationTokenSource(TimeSpan.FromSeconds(60)); var ct = bounded.Token;
        var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        bool disposed = false;
        try
        {
            var ownedNames = new HashSet<string>(StringComparer.Ordinal); var ports = new HashSet<int>();
            foreach (string entryPath in Directory.EnumerateFiles(root, "*-host-entry.json", SearchOption.TopDirectoryOnly))
            {
                using var entry = JsonDocument.Parse(files.Read(entryPath, sharedReader: true, maximumBytes: 65536)); var e = entry.RootElement;
                if (e.GetProperty("jobNonce").GetString() != nonce) { continue; }
                if (!e.GetProperty("nativeJobMembershipObserved").GetBoolean()) { throw Invalid(); }
                Guid run = e.GetProperty("run").GetGuid(); string name = Production181EngineContract.Name(run); _ = ownedNames.Add(name);
                using var attempt = JsonDocument.Parse(files.Read(Path.Combine(root, run.ToString("N") + "-attempt.json"), sharedReader: true, maximumBytes: 65536));
                var a = attempt.RootElement; DateTimeOffset began = a.GetProperty("began").GetDateTimeOffset(), expiry = a.GetProperty("expires").GetDateTimeOffset();
                if (a.GetProperty("run").GetGuid() != run || a.GetProperty("name").GetString() != name || a.GetProperty("persistent").GetBoolean() || began < baseline.ObservedAtUtc || expiry - began != TimeSpan.FromMinutes(8) || baseline.Volumes.Contains(name, StringComparer.Ordinal)) { throw Invalid(); }
                foreach (string exactName in new[] { name + "-checksum", name, name + "-initialize" })
                {
                    var inventory = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, ct).ConfigureAwait(false);
                    var matches = inventory.Where(x => x.Names.Contains("/" + exactName, StringComparer.Ordinal)).ToArray();
                    if (matches.Length > 1) { throw Invalid(); }
                    if (matches.Length == 0) { continue; }
                    var c = await docker.Containers.InspectContainerAsync(matches[0].ID, ct).ConfigureAwait(false);
                    using var started = JsonDocument.Parse(files.Read(Path.Combine(root, run.ToString("N") + "-attempt-" + exactName + ".json"), sharedReader: true, maximumBytes: 65536));
                    DateTimeOffset created = JsonSerializer.SerializeToElement(c).GetProperty("Created").GetDateTimeOffset();
                    var config = c.Config ?? throw Invalid();
                    var labels = config.Labels ?? throw Invalid();
                    var host = c.HostConfig ?? throw Invalid();
                    var mounts = host.Mounts ?? throw Invalid();
                    var actualMounts = c.Mounts ?? throw Invalid();
                    var state = c.State ?? throw Invalid();
                    var network = c.NetworkSettings ?? throw Invalid();
                    var networkPorts = network.Ports ?? throw Invalid();
                    var entrypoint = config.Entrypoint ?? throw Invalid();
                    var command = config.Cmd ?? throw Invalid();
                    string binding = Label(labels, "codex.repair.run-binding") ?? throw Invalid(); if (binding != expectedBinding) { throw Invalid(); }
                    var plan = exactName == name ? Production181DisposablePlans.Database(run, binding) : exactName.EndsWith("-initialize", StringComparison.Ordinal) ? Production181DisposablePlans.Initializer(run, binding) : Production181DisposablePlans.Checksum(run, binding);
                    if (baseline.ContainerIds.Contains(c.ID, StringComparer.Ordinal) || c.Name != "/" + exactName || c.Image != Production181EngineContract.Config || config.Image != plan.Image ||
                        config.User != plan.User || !entrypoint.SequenceEqual(plan.Entrypoint) || !command.SequenceEqual(plan.Cmd) || labels.Count != 4 || plan.Labels.Any(x => Label(labels, x.Key) != x.Value) ||
                        host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750000000 || host.Privileged ||
                        host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } || host.Tmpfs is { Count: > 0 } ||
                        mounts.Count != 1 || mounts[0].Source != name || mounts[0].Target != "/var/lib/postgresql" || mounts[0].Type != "volume" || mounts[0].ReadOnly != false || mounts[0].VolumeOptions?.NoCopy != true ||
                        actualMounts.Count != 1 || actualMounts[0].Type != "volume" || actualMounts[0].Name != name || actualMounts[0].Destination != "/var/lib/postgresql" || !actualMounts[0].RW ||
                        started.RootElement.GetProperty("run").GetGuid() != run || started.RootElement.GetProperty("Name").GetString() != exactName || created < started.RootElement.GetProperty("at").GetDateTimeOffset().AddSeconds(-1) || created > expiry) { throw Invalid(); }
                    if (networkPorts.TryGetValue("5432/tcp", out var bindings) && bindings is not null)
                    { foreach (var p in bindings) { if (p.HostIP != "127.0.0.1" || !int.TryParse(p.HostPort, out int port) || port is < 1 or > 65535) { throw Invalid(); } _ = ports.Add(port); } }
                    await RequireVolume(run, name, binding, began, expiry).ConfigureAwait(false);
                    var consumersBeforeStop = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true, Filters = new Dictionary<string, IDictionary<string, bool>> { ["volume"] = new Dictionary<string, bool> { [name] = true } } }, ct).ConfigureAwait(false);
                    if (consumersBeforeStop.Count != 1 || consumersBeforeStop[0].ID != c.ID) { throw Invalid(); }
                    if (state.Running) { _ = await docker.Containers.StopContainerAsync(c.ID, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, ct).ConfigureAwait(false); }
                    var stopped = await docker.Containers.InspectContainerAsync(c.ID, ct).ConfigureAwait(false);
                    var stoppedState = stopped.State ?? throw Invalid();
                    if (stoppedState.Running || stopped.Image != c.Image || stopped.Name != c.Name) { throw Invalid(); }
                    await docker.Containers.RemoveContainerAsync(c.ID, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, ct).ConfigureAwait(false);
                }
                var volumes = await docker.Volumes.ListAsync(ct).ConfigureAwait(false);
                if ((volumes.Volumes ?? throw Invalid()).Any(x => x.Name == name))
                {
                    using var volumeAttempt = JsonDocument.Parse(files.Read(Path.Combine(root, run.ToString("N") + "-volume-creation-attempt.json"), sharedReader: true, maximumBytes: 65536));
                    var v = await docker.Volumes.InspectAsync(name, ct).ConfigureAwait(false); string binding = Label(v.Labels, "codex.repair.run-binding") ?? throw Invalid(); if (binding != expectedBinding) { throw Invalid(); }
                    await RequireVolume(run, name, binding, volumeAttempt.RootElement.GetProperty("attemptedAtUtc").GetDateTimeOffset(), expiry).ConfigureAwait(false);
                    var consumers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true, Filters = new Dictionary<string, IDictionary<string, bool>> { ["volume"] = new Dictionary<string, bool> { [name] = true } } }, ct).ConfigureAwait(false);
                    if (consumers.Count != 0) { throw Invalid(); }
                    await docker.Volumes.RemoveAsync(name, false, ct).ConfigureAwait(false);
                }
            }
            var remaining = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, ct).ConfigureAwait(false);
            var finalVolumes = await docker.Volumes.ListAsync(ct).ConfigureAwait(false); string[] names = (finalVolumes.Volumes ?? throw Invalid()).Select(x => x.Name).ToArray();
            int[] listeners = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().ToArray();
            if (remaining.Any(x => x.Names.Any(n => ownedNames.Any(o => n == "/" + o || n == "/" + o + "-initialize" || n == "/" + o + "-checksum"))) || ownedNames.Any(names.Contains) || baseline.Volumes.Any(x => !names.Contains(x, StringComparer.Ordinal)) || ports.Any(listeners.Contains)) { throw Invalid(); }
            await files.WriteNewAsync(Path.Combine(root, "customer-host-" + nonce + "-engine-docker-absence.json"), JsonSerializer.SerializeToUtf8Bytes(new { nonce, observedAtUtc = DateTimeOffset.UtcNow, containersObserved = true, volumesObserved = true, listenersObserved = true, containerIds = remaining.Select(x => x.ID).ToArray(), volumeNames = names, listeningPorts = listeners }), ct).ConfigureAwait(false);
            async Task RequireVolume(Guid run, string name, string binding, DateTimeOffset began, DateTimeOffset expiry)
            {
                var v = await docker.Volumes.InspectAsync(name, ct).ConfigureAwait(false);
                var labels = Production181DisposablePlans.Database(run, binding).Labels;
                if (v.Name != name || v.Driver != "local" || v.Scope != "local" || v.Options is { Count: > 0 } || v.Labels.Count != 4 || labels.Any(x => Label(v.Labels, x.Key) != x.Value) ||
                    !DateTimeOffset.TryParse(v.CreatedAt, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var created) || created < began.AddSeconds(-1) || created > expiry) { throw Invalid(); }
            }
        }
        finally { disposed = await RetainDisposal(files, root, nonce, "cleanup", docker).ConfigureAwait(false); }
        if (!disposed) { throw Invalid(); }
    }
    private static async Task<bool> RetainDisposal(CurrentAppOwnedRepairCustody files, string root, string nonce, string phase, IDisposable docker)
    {
        var evidence = await Production181SdkDisposal.ObserveAsync(docker, nonce + "-" + phase).ConfigureAwait(false);
        using var bounded = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await files.WriteNewAsync(Path.Combine(root, "customer-host-" + nonce + "-" + phase + "-sdk-disposal.json"), JsonSerializer.SerializeToUtf8Bytes(evidence), bounded.Token).ConfigureAwait(false);
        return evidence.Disposed;
    }
    private static string? Label(IDictionary<string, string> labels, string key)
    {
        return labels.TryGetValue(key, out string? value) ? value : null;
    }

    private static MigrationExecutionException Invalid()
    {
        return new("production181_cleanup_uncertain", "Exact current-run resource ownership or absence was not proven; uncertain resources preserved.");
    }
}
