using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;

namespace Legacy.Maliev.DataMigration.Console;

internal static class OwnerIsoNamedClosedBootstrapHostDockerCleanup
{
    internal static Task<OwnerIsoHostDockerBaseline> ObserveBeforeAsync(CancellationToken ct)
    {
        return OwnerIsoGuardedBootstrapHostDockerCleanup.ObserveBeforeAsync(ct);
    }

    // Called only by the serialized host AFTER actual empty-job and waiting-child exit.
    // Every candidate comes from a durable parent entry written before Docker creation.
    internal static async Task RequireCleanupAfterExitAsync(CurrentAppOwnedRepairCustody parentFiles, string parentRoot, string caseRoot, string nonce, OwnerIsoHostDockerBaseline baseline)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(75));
        using var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        var removed = new List<string>(); var retainedIds = new HashSet<string>(StringComparer.Ordinal); var names = new HashSet<string>(StringComparer.Ordinal);
        var volumes = new HashSet<string>(StringComparer.Ordinal); var ports = new HashSet<int>();
        foreach (string path in Directory.EnumerateFiles(caseRoot, "iso-closed-host-*-entry.json", SearchOption.TopDirectoryOnly))
        {
            var entry = MigrationConsole.DecodeOwnerIso<IsoNamedClosedHostEntry>(Read(path, 65536)); if (entry.Host.JobNonce != nonce) { continue; }
            Guid operation = entry.Host.RunId; string name = "iso-closed-bootstrap-" + operation.ToString("N"), volumeName = "iso-closed-bootstrap-data-" + operation.ToString("N");
            if (operation == Guid.Empty || !entry.Host.NativeJobMembershipObserved || entry.BeganAtUtc < baseline.ObservedAtUtc || entry.ExpiresAtUtc - entry.BeganAtUtc != TimeSpan.FromMinutes(8) ||
                entry.FixtureRoot != Path.Combine(caseRoot, "iso-closed-case-" + operation.ToString("N")) || entry.FixtureBindingPath != Path.Combine(entry.FixtureRoot, "fixture-binding.json") || baseline.Volumes.Contains(volumeName, StringComparer.Ordinal)) { throw Invalid(); }
            var binding = MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(Read(entry.FixtureBindingPath, 65536));
            if (!StringComparer.OrdinalIgnoreCase.Equals(binding.ArtifactRootCanonicalPath, entry.FixtureRoot)) { throw Invalid(); }
            string bindingHash = binding.ComputeSha256(); _ = names.Add(name); _ = volumes.Add(volumeName);
            foreach (string proxyPath in Directory.EnumerateFiles(entry.FixtureRoot, "iso-closed-proxy-" + operation.ToString("N") + "-created.json", SearchOption.TopDirectoryOnly))
            { using var proxy = JsonDocument.Parse(Read(proxyPath, 65536)); if (proxy.RootElement.GetProperty("_operation").GetGuid() != operation || proxy.RootElement.GetProperty("loopbackAddress").GetString() != "127.0.0.1") { throw Invalid(); } _ = ports.Add(proxy.RootElement.GetProperty("port").GetInt32()); }
            foreach (string targetPath in Directory.EnumerateFiles(entry.FixtureRoot, "iso-closed-resource-" + operation.ToString("N") + "-*-target.json", SearchOption.TopDirectoryOnly))
            {
                using var observed = JsonDocument.Parse(Read(targetPath, 65536)); var metadata = observed.RootElement; string observedId = metadata.GetProperty("Id").GetString() ?? throw Invalid(); if (metadata.GetProperty("Name").GetString() != "/" + name || observedId.Length != 64) { throw Invalid(); }
                _ = retainedIds.Add(observedId);
                foreach (var port in metadata.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray()) { if (port.GetProperty("HostIp").GetString() != "127.0.0.1" || !int.TryParse(port.GetProperty("HostPort").GetString(), out int parsed)) { throw Invalid(); } _ = ports.Add(parsed); }
            }

            ContainerInspectResponse? container = null;
            try { container = await docker.Containers.InspectContainerAsync(name, timeout.Token).ConfigureAwait(false); }
            catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound) { }
            if (container is not null)
            {
                RequireContainer(container); _ = retainedIds.Add(container.ID);
                foreach (var port in container.HostConfig!.PortBindings!["5432/tcp"]) { if (!int.TryParse(port.HostPort, out int parsed) || parsed is < 1 or > 65535) { throw Invalid(); } _ = ports.Add(parsed); }
                await RequireVolumeAsync(requireConsumer: true, container.ID).ConfigureAwait(false);
                if (container.State?.Running == true) { if (IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Any(x => x.State is not (TcpState.TimeWait or TcpState.Closed) && (ports.Contains(x.LocalEndPoint.Port) || ports.Contains(x.RemoteEndPoint.Port)))) { throw Invalid(); } _ = await docker.Containers.StopContainerAsync(container.ID, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, timeout.Token).ConfigureAwait(false); }
                var stopped = await docker.Containers.InspectContainerAsync(container.ID, timeout.Token).ConfigureAwait(false); RequireContainer(stopped);
                if (stopped.State?.Running != false) { throw Invalid(); }
                await RequireVolumeAsync(requireConsumer: true, container.ID).ConfigureAwait(false);
                await docker.Containers.RemoveContainerAsync(container.ID, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, timeout.Token).ConfigureAwait(false);
                bool absent = false; try { _ = await docker.Containers.InspectContainerAsync(container.ID, timeout.Token).ConfigureAwait(false); } catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound) { absent = true; }
                if (!absent) { throw Invalid(); }
            }
            bool present = true; try { await RequireVolumeAsync(requireConsumer: false, null).ConfigureAwait(false); } catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound) { present = false; }
            if (present) { await docker.Volumes.RemoveAsync(volumeName, force: false, timeout.Token).ConfigureAwait(false); }
            bool volumeAbsent = false; try { _ = await docker.Volumes.InspectAsync(volumeName, timeout.Token).ConfigureAwait(false); } catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound) { volumeAbsent = true; }
            if (!volumeAbsent) { throw Invalid(); }
            CurrentOwnerIsoClosedSecretCleanup.RequireRemoved(entry.FixtureRoot, binding, operation); removed.Add(name);
            void RequireLabels(IDictionary<string, string>? labels)
            {
                if (labels is null || !labels.TryGetValue("codex.repair.purpose", out string? purpose) || purpose != "current-owner-iso-closed-bootstrap" ||
                !labels.TryGetValue("codex.repair.operation", out string? op) || op != operation.ToString("D") || !labels.TryGetValue("codex.repair.run-binding", out string? run) || run != bindingHash) { throw Invalid(); }
            }
            void RequireContainer(ContainerInspectResponse actual)
            {
                var config = actual.Config ?? throw Invalid(); var host = actual.HostConfig ?? throw Invalid();
                DateTimeOffset created = JsonSerializer.SerializeToElement(actual).GetProperty("Created").GetDateTimeOffset(); RequireLabels(config.Labels);
                if (actual.ID.Length != 64 || baseline.ContainerIds.Contains(actual.ID, StringComparer.Ordinal) || actual.Name != "/" + name ||
                    created < entry.BeganAtUtc.AddSeconds(-1) || created > entry.ExpiresAtUtc || config.Image != CurrentOwnerIsoNamedClosedTarget.Image ||
                    config.Env is null || config.Env.Count(x => x.StartsWith("PGDATA=", StringComparison.Ordinal)) != 1 || config.Env.Single(x => x.StartsWith("PGDATA=", StringComparison.Ordinal)) != "PGDATA=/var/lib/postgresql/18/docker" ||
                    host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750_000_000 || host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } || host.Tmpfs is { Count: > 0 } ||
                    actual.Mounts is not { Count: 1 } || actual.Mounts[0].Name != volumeName || actual.Mounts[0].Type != "volume" || actual.Mounts[0].Destination != "/var/lib/postgresql" || !actual.Mounts[0].RW ||
                    host.PortBindings is not { Count: 1 } || !host.PortBindings.TryGetValue("5432/tcp", out var mappings) || mappings is not { Count: 1 } || mappings[0].HostIP != "127.0.0.1") { throw Invalid(); }
            }
            async Task RequireVolumeAsync(bool requireConsumer, string? id)
            {
                var actual = await docker.Volumes.InspectAsync(volumeName, timeout.Token).ConfigureAwait(false); RequireLabels(actual.Labels);
                if (actual.Name != volumeName || actual.Driver != "local" || actual.Scope != "local" || actual.Options is { Count: > 0 } || !DateTimeOffset.TryParse(actual.CreatedAt, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var created) || created < entry.BeganAtUtc.AddSeconds(-1) || created > entry.ExpiresAtUtc) { throw Invalid(); }
                var consumers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true, Filters = new Dictionary<string, IDictionary<string, bool>> { ["volume"] = new Dictionary<string, bool> { [volumeName] = true } } }, timeout.Token).ConfigureAwait(false);
                if (requireConsumer ? consumers.Count != 1 || consumers[0].ID != id : consumers.Count != 0) { throw Invalid(); }
            }
        }
        var allContainers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, timeout.Token).ConfigureAwait(false); var allVolumes = await docker.Volumes.ListAsync(timeout.Token).ConfigureAwait(false);
        string[] ids = [.. allContainers.Select(x => x.ID).Order(StringComparer.Ordinal)], allNames = [.. allContainers.SelectMany(x => x.Names).Order(StringComparer.Ordinal)], volumeNames = [.. (allVolumes.Volumes ?? throw Invalid()).Select(x => x.Name).Order(StringComparer.Ordinal)];
        int[] listeners = [.. IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().Order()];
        if (retainedIds.Any(x => ids.Contains(x, StringComparer.Ordinal)) || names.Any(x => allNames.Contains("/" + x, StringComparer.Ordinal)) || volumes.Any(x => volumeNames.Contains(x, StringComparer.Ordinal)) || ports.Any(listeners.Contains)) { throw Invalid(); }
        await parentFiles.WriteNewAsync(Path.Combine(parentRoot, "iso-named-host-" + nonce + "-post-exit-absence.json"), JsonSerializer.SerializeToUtf8Bytes(new
        {
            nonce,
            observedAtUtc = DateTimeOffset.UtcNow,
            containerInventorySucceeded = true,
            volumeInventorySucceeded = true,
            listenerInventorySucceeded = true,
            containerIds = ids,
            containerNames = allNames,
            volumeNames,
            listeningPorts = listeners,
            removedNames = removed
        }), timeout.Token).ConfigureAwait(false); parentFiles.Require();
    }
    private static byte[] Read(string path, int maximum) { using var held = SecureLocalFile.OpenReadShared(path); if (held.Length is < 1 || held.Length > maximum) { throw Invalid(); } byte[] bytes = new byte[(int)held.Length]; held.ReadExactly(bytes); return bytes; }
    private static MigrationExecutionException Invalid()
    {
        return new("iso_named_host_cleanup_invalid", "Exact run-owned disposable resources and native job exit must be proven before cleanup.");
    }
}
