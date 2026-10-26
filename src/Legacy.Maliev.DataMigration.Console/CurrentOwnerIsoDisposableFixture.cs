using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Console;

internal static class IsoDisposableFixture
{
    internal static async Task RunAsync(Guid run, string caseId, IsoExecutedProofRecorder proof,
        Func<string, string, CancellationToken, Task> body, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || run != proof.RunId || caseId != proof.CaseId) { throw Invalid(); }
        proof.Capacity(admission: true);
        string name = "iso-component-" + run.ToString("N"); DateTimeOffset began = DateTimeOffset.UtcNow, expires = began.AddMinutes(8);
        using var life = CancellationTokenSource.CreateLinkedTokenSource(ct); life.CancelAfter(TimeSpan.FromMinutes(8));
        using DockerClient docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        var container = new PostgreSqlBuilder(CurrentOwnerIsoBootstrapSubjectValidator.Image)
            .WithDockerEndpoint("npipe://./pipe/docker_engine").WithName(name).WithCleanUp(false)
            .WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C").WithCommand("-c", "autovacuum=off")
            .WithLabel("codex.repair.purpose", "current-owner-iso-guarded-component")
            .WithLabel("codex.repair.operation", run.ToString("D")).WithLabel("codex.repair.run", run.ToString("D"))
            .WithCreateParameterModifier(p =>
            {
                var host = p.HostConfig ?? throw Invalid(); host.Memory = 512L * 1024 * 1024; host.MemorySwap = 512L * 1024 * 1024;
                host.NanoCPUs = 750000000; host.Tmpfs = new Dictionary<string, string> { ["/var/lib/postgresql"] = "rw,nosuid,size=384m" };
                foreach (var ports in (host.PortBindings ?? throw Invalid()).Values)
                { foreach (var port in ports ?? []) { port.HostIP = "127.0.0.1"; } }
            }).Build();
        string? id = null; int? port = null; bool removed = false, disposed = false;
        DateTimeOffset? removedAt = null; ExceptionDispatchInfo? primary = null; Exception? cleanupFailure = null;
        try
        {
            await proof.RecordAsync("attempt", new { run, name, caseId, began, expires, persistent = false }, life.Token).ConfigureAwait(false);
            await container.StartAsync(life.Token).ConfigureAwait(false);
            var metadata = await docker.Containers.InspectContainerAsync(name, life.Token).ConfigureAwait(false); Require(metadata, active: true);
            id = metadata.ID; port = container.GetMappedPublicPort(5432);
            var config = metadata.Config ?? throw Invalid(); var host = metadata.HostConfig ?? throw Invalid();
            var state = metadata.State ?? throw Invalid(); var network = metadata.NetworkSettings ?? throw Invalid();
            await proof.RecordAsync("container", new
            {
                Id = id,
                metadata.Name,
                Created = JsonSerializer.SerializeToElement(metadata).GetProperty("Created"),
                Config = new { config.Image, config.Labels, PgData = (config.Env ?? throw Invalid()).Single(x => x.StartsWith("PGDATA=", StringComparison.Ordinal))[7..] },
                State = new { state.Running, StartedAt = JsonSerializer.SerializeToElement(state).GetProperty("StartedAt") },
                HostConfig = new { host.Memory, host.MemorySwap, NanoCpus = host.NanoCPUs, host.Tmpfs, host.Binds, host.VolumesFrom, host.Mounts },
                Mounts = (metadata.Mounts ?? throw Invalid()).Select(x => new { x.Type, x.Name, x.Destination, x.RW }).ToArray(),
                NetworkSettings = new
                {
                    Ports = (network.Ports ?? throw Invalid()).ToDictionary(x => x.Key,
                    x => (x.Value ?? []).Select(y => new { HostIp = y.HostIP, y.HostPort }).ToArray(), StringComparer.Ordinal)
                },
            }, life.Token).ConfigureAwait(false);
            using (var capacityDeadline = CancellationTokenSource.CreateLinkedTokenSource(life.Token))
            {
                capacityDeadline.CancelAfter(TimeSpan.FromSeconds(5));
                var df = await container.ExecAsync(["df", "-B1", "/var/lib/postgresql"], capacityDeadline.Token).ConfigureAwait(false);
                string[] lines = df.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                string[] cells = lines.Length == 2 ? lines[1].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries) : [];
                if (df.ExitCode != 0 || !string.IsNullOrEmpty(df.Stderr) || cells.Length != 6 || cells[0] != "tmpfs" ||
                    !long.TryParse(cells[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long bytes) || bytes != 384L * 1024 * 1024) { throw Invalid(); }
                await proof.RecordAsync("capacity", new { run, containerId = id, capacityBytes = bytes }, life.Token).ConfigureAwait(false);
            }
            proof.Capacity(admission: false);
            await body(container.GetConnectionString(), id, life.Token).ConfigureAwait(false);
        }
        catch (Exception error) { primary = ExceptionDispatchInfo.Capture(error); }
        finally
        {
            await CleanupAsync().ConfigureAwait(false);
        }
        if (primary is not null) { if (cleanupFailure is not null) { primary.SourceException.Data["isoCleanupFailure"] = cleanupFailure; } primary.Throw(); }
        if (cleanupFailure is not null) { throw new MigrationExecutionException("iso_component_cleanup_failed", "Exact owned disposable cleanup did not complete."); }

        async Task CleanupAsync()
        {
            try
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
                var metadata = await docker.Containers.InspectContainerAsync(id ?? name, deadline.Token).ConfigureAwait(false);
                Require(metadata, active: metadata.State?.Running ?? throw Invalid()); id ??= metadata.ID;
                if (metadata.ID != id || (port is not null && IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
                    .Any(x => x.State == TcpState.Established && IPAddress.IsLoopback(x.RemoteEndPoint.Address) && x.RemoteEndPoint.Port == port))) { throw Invalid(); }
                _ = await docker.Containers.StopContainerAsync(id, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, deadline.Token).ConfigureAwait(false);
                var stopped = await docker.Containers.InspectContainerAsync(id, deadline.Token).ConfigureAwait(false); Require(stopped, active: false);
                await docker.Containers.RemoveContainerAsync(id, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, deadline.Token).ConfigureAwait(false);
                try { _ = await docker.Containers.InspectContainerAsync(id, deadline.Token).ConfigureAwait(false); }
                catch (DockerApiException missing) when (missing.StatusCode == HttpStatusCode.NotFound) { removed = true; removedAt = DateTimeOffset.UtcNow; }
                if (!removed) { throw Invalid(); }
                await container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), deadline.Token).ConfigureAwait(false); disposed = true;
                var containers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, deadline.Token).ConfigureAwait(false);
                var volumes = await docker.Volumes.ListAsync(new VolumesListParameters(), deadline.Token).ConfigureAwait(false);
                int[] listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Where(x => IPAddress.IsLoopback(x.Address)).Select(x => x.Port).Distinct().Order().ToArray();
                if (containers.Any(x => x.ID == id || x.Names.Any(n => n == name || n == "/" + name)) || (port is not null && listeners.Contains(port.Value))) { throw Invalid(); }
                await proof.RecordAsync("absence", new IsoDefinitionAbsence(run, DateTimeOffset.UtcNow, true, true, true,
                    containers.Select(x => x.ID).ToArray(), containers.SelectMany(x => x.Names).ToArray(),
                    (volumes.Volumes ?? []).Select(x => x.Name).ToArray(), listeners), deadline.Token).ConfigureAwait(false);
            }
            catch (Exception error) { cleanupFailure = error; }
            try
            {
                using var ledgerDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await proof.RecordAsync("disposed", new
                {
                    run,
                    containerId = id,
                    name,
                    began,
                    expires,
                    removed,
                    removedAtUtc = removedAt,
                    disposed,
                    cleanupFailed = cleanupFailure is not null || !removed || !disposed,
                    failureCode = cleanupFailure?.GetType().Name,
                    completedAtUtc = DateTimeOffset.UtcNow
                }, ledgerDeadline.Token).ConfigureAwait(false);
            }
            catch (Exception error) { cleanupFailure = cleanupFailure is null ? error : new AggregateException(cleanupFailure, error); }
        }
        void Require(ContainerInspectResponse value, bool active)
        {
            var config = value.Config ?? throw Invalid(); var host = value.HostConfig ?? throw Invalid(); var state = value.State ?? throw Invalid();
            DateTimeOffset created = JsonSerializer.SerializeToElement(value).GetProperty("Created").GetDateTimeOffset();
            if (value.ID is not { Length: 64 } || value.Name != "/" + name || created < began.AddSeconds(-1) || created > expires ||
                config.Image != CurrentOwnerIsoBootstrapSubjectValidator.Image || config.Labels is not { } labels ||
                !labels.TryGetValue("codex.repair.purpose", out string? purpose) || purpose != "current-owner-iso-guarded-component" ||
                !labels.TryGetValue("codex.repair.run", out string? labelRun) || labelRun != run.ToString("D") ||
                !labels.TryGetValue("codex.repair.operation", out string? operation) || operation != run.ToString("D") ||
                state.Running != active || value.Mounts is not { Count: 0 } || host.Mounts is { Count: > 0 } || host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } ||
                host.Tmpfs is not { Count: 1 } tmpfs || !tmpfs.TryGetValue("/var/lib/postgresql", out string? setting) || setting != "rw,nosuid,size=384m" ||
                host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750000000 ||
                host.PortBindings is null || host.PortBindings.Values.SelectMany(x => x ?? []).Any(x => x.HostIP != "127.0.0.1")) { throw Invalid(); }
        }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentOwnerIsoRepairPermit.Invalid();
    }
}
