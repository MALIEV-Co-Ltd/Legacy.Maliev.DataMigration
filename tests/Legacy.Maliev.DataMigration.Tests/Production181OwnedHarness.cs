using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;
using Npgsql;
using Xunit.Abstractions;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Internal trusted test owner only; no configured SQL or production endpoint is accepted.
internal static class Production181OwnedHarness
{
    internal static async Task RunAsync(Func<Guid, string, string, CancellationToken, Task> algorithm, ITestOutputHelper output, string ledger, string testAssembly)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true);
        string nonce = Environment.GetEnvironmentVariable("MALIEV_CUSTOMER_GUARDED_JOB_NONCE") ?? throw Invalid();
        CustomerGuardedBootstrapHostObservation.RequireCurrentMembership(nonce);
        string bindingPath = Environment.GetEnvironmentVariable("MALIEV_PRODUCTION181_BINDING") ?? throw Invalid();
        using var bindingStream = SecureLocalFile.OpenReadShared(bindingPath);
        var binding = JsonSerializer.Deserialize<LocalExecutionBinding>(bindingStream) ?? throw Invalid();
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(ledger), binding.ArtifactRootCanonicalPath) ||
            binding.ComputeSha256() != Environment.GetEnvironmentVariable("MALIEV_PRODUCTION181_BINDING_SHA256") ||
            !SecureLocalFile.HandleResolvesToApprovedPath(bindingStream, bindingPath)) { throw Invalid(); }
        // The actual parent host retains this root authority. Reacquiring its exclusive lock here would self-deadlock.
        SecureLocalFile.EnsureOwnerOnlyDirectory(ledger);
        Guid run = Guid.NewGuid(); string name = Production181EngineContract.Name(run), bindingHash = binding.ComputeSha256();
        DateTimeOffset began = DateTimeOffset.UtcNow, expires = began.AddMinutes(8);
        Write(run, "attempt", new { run, name, began, expires, persistent = false });
        using (var image = Production181ActualExecutableImage.OpenCurrent())
        {
            image.Require();
            Write(run, "host-entry", new
            {
                run,
                processId = image.ProcessId,
                processStartTimeUtc = image.ProcessStartTimeUtc,
                executable = image.Path,
                executableSha256 = image.Sha256,
                testAssemblySha256 = Hash(testAssembly),
                jobNonce = nonce,
                nativeJobMembershipObserved = true,
                observedAtUtc = began
            });
            image.Require();
        }
        using var lifetime = new CancellationTokenSource(TimeSpan.FromMinutes(8)); var ct = lifetime.Token;
        DockerClient docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        var attempts = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal); var known = new Dictionary<string, string>(StringComparer.Ordinal);
        bool volumeAttempted = false, removed = false, disposed = false, cleanupFailure = false; DateTimeOffset? volumeAttempt = null, volumeCreated = null, removedAt = null; int port = 0;
        HashSet<string> previousVolumes = [];
        ExceptionDispatchInfo? primaryFailure = null;
        var cleanupErrors = new List<Exception>();
        try
        {
            var containers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, ct);
            var volumes = await docker.Volumes.ListAsync(ct); previousVolumes = (volumes.Volumes ?? throw Invalid()).Select(x => x.Name).ToHashSet(StringComparer.Ordinal);
            if (previousVolumes.Contains(name) || containers.SelectMany(x => x.Names).Any(x => x == "/" + name || x == "/" + name + "-initialize" || x == "/" + name + "-checksum")) { throw Invalid(); }
            Write(run, "proof-previous-volumes", previousVolumes.Order(StringComparer.Ordinal).ToArray());
            Write(run, "proof-previous-container-names", containers.SelectMany(x => x.Names).Order(StringComparer.Ordinal).ToArray());
            var pinnedImage = await docker.Images.InspectImageAsync(Production181EngineContract.Image, ct);
            if (pinnedImage.ID != Production181EngineContract.Config || pinnedImage.RepoDigests is null || !pinnedImage.RepoDigests.Contains("ghcr.io/cloudnative-pg/postgresql@" + Production181EngineContract.Image.Split('@')[1], StringComparer.Ordinal)) { throw Invalid(); }
            // No pull or image upgrade here: the owner must preload this exact verified pinned image.
            volumeAttempt = DateTimeOffset.UtcNow; volumeAttempted = true;
            Write(run, "volume-creation-attempt", new { run, name, attemptedAtUtc = volumeAttempt, expires });
            _ = await docker.Volumes.CreateAsync(new VolumesCreateParameters { Name = name, Driver = "local", Labels = Labels() }, ct);
            await RequireVolume([], ct);
            string init = await Create(Production181DisposablePlans.Initializer(run, bindingHash), ct);
            var initial = await AwaitExit(init, TimeSpan.FromSeconds(30), ct);
            var initialState = initial.State ?? throw Invalid();
            if (initialState.ExitCode != 0 || initialState.OOMKilled) { throw Invalid(); }
            await Remove(init, ct);
            await RequireVolume([], ct);
            Write(run, "engine-initializer", new
            {
                runId = run,
                name = name + "-initialize",
                containerId = init,
                exitCode = initialState.ExitCode,
                exitedAtUtc = DateTimeOffset.UtcNow,
                removed = true,
                absenceObserved = true,
                volumeConsumersAfterRemoval = Array.Empty<string>(),
                container = Sanitize(initial)
            });
            Write(run, "creation-attempt", new { run, name, attemptedAtUtc = DateTimeOffset.UtcNow, expires });
            string main = await Create(Production181DisposablePlans.Database(run, bindingHash), ct);
            var metadata = await docker.Containers.InspectContainerAsync(main, ct); RequireContainer(metadata, name);
            var network = metadata.NetworkSettings ?? throw Invalid(); var portMap = network.Ports ?? throw Invalid();
            var mapped = (portMap["5432/tcp"] ?? throw Invalid()).Single(); if (mapped.HostIP != "127.0.0.1") { throw Invalid(); }
            port = int.Parse(mapped.HostPort, System.Globalization.CultureInfo.InvariantCulture);
            string admin = new NpgsqlConnectionStringBuilder { Host = "127.0.0.1", Port = port, Username = "postgres", Database = "postgres", Pooling = false, Timeout = 2, CommandTimeout = 30, IncludeErrorDetail = false }.ConnectionString;
            using (var readiness = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                readiness.CancelAfter(TimeSpan.FromSeconds(30)); bool ready = false;
                while (!ready)
                {
                    try { await using var connection = new NpgsqlConnection(admin); await connection.OpenAsync(readiness.Token); await using var query = new NpgsqlCommand("SELECT current_setting('server_version_num')::integer;", connection); if ((int)(await query.ExecuteScalarAsync(readiness.Token))! != 180001) { throw Invalid(); } ready = true; }
                    catch (NpgsqlException) { await Task.Delay(200, readiness.Token); }
                }
            }
            await RequireVolume([main], ct);
            Write(run, "proof-container", Sanitize(metadata));
            var image = await docker.Images.InspectImageAsync(Production181EngineContract.Image, ct);
            if (image.ID != Production181EngineContract.Config) { throw Invalid(); }
            Write(run, "proof-image", new { Id = image.ID, image.RepoDigests });
            Write(run, "observed", new { run, operation = run, name, containerId = main, volume = name, began, expires, persistent = false });
            output.WriteLine(JsonSerializer.Serialize(new { run, Production181EngineContract.Purpose, ContainerId = main, began, expires, Owned = true, Removed = false, PersistentData = false }));
            CurrentCustomerSequenceCapacity.Require(admission: false);
            await algorithm(run, main, admin, ct);
            // All real provider/proxy connections have completed before this offline boundary.
            await RequireVolume([main], ct);
            _ = await docker.Containers.StopContainerAsync(main, new ContainerStopParameters { WaitBeforeKillSeconds = 10 }, ct);
            var stopped = await AwaitExit(main, TimeSpan.FromSeconds(15), ct); var stoppedState = stopped.State ?? throw Invalid(); if (stoppedState.OOMKilled || stoppedState.ExitCode != 0) { throw Invalid(); }
            await Remove(main, ct); await RequireVolume([], ct);
            DateTimeOffset offlineBegan = DateTimeOffset.UtcNow;
            string checker = await Create(Production181DisposablePlans.Checksum(run, bindingHash), ct);
            var checkedContainer = await AwaitExit(checker, TimeSpan.FromSeconds(30), ct);
            var logs = new BoundedLogs(); await docker.Containers.GetContainerLogsAsync(checker, new ContainerLogsParameters { ShowStdout = true, ShowStderr = true, Follow = false, Tail = "200" }, logs, ct);
            var checkedState = checkedContainer.State ?? throw Invalid();
            if (checkedState.ExitCode != 0 || checkedState.OOMKilled || !Production181SemanticEnvelopeReader.NoBadChecksums(logs.Text)) { throw Invalid(); }
            Write(run, "engine-checksum", new
            {
                runId = run,
                mainContainerId = main,
                mainExitedAtUtc = offlineBegan,
                checkerContainer = Sanitize(checkedContainer),
                beganAtUtc = offlineBegan,
                exitedAtUtc = DateTimeOffset.UtcNow,
                exitCode = checkedState.ExitCode,
                stdout = logs.Text,
                fullVolume = name
            });
            await Remove(checker, ct); await RequireVolume([], ct);
        }
        catch (Exception error) { primaryFailure = ExceptionDispatchInfo.Capture(error); }
        finally { await CleanupAsync(); }
        if (primaryFailure is not null)
        {
            if (cleanupErrors.Count > 0) { primaryFailure.SourceException.Data["Production181CleanupFailures"] = new AggregateException(cleanupErrors); }
            primaryFailure.Throw();
        }
        if (cleanupErrors.Count > 0) { throw new AggregateException("Exact fixture cleanup did not complete", cleanupErrors); }
        if (cleanupFailure || !disposed) { throw new MigrationExecutionException("production181_sdk_disposal_unsettled", "SDK disposal did not succeed; exact host ownership is retained in the ledger and no proof is accepted."); }
        async Task CleanupAsync()
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(55));
            try
            {
                foreach (var candidate in attempts.Keys.Reverse())
                {
                    var inventory = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, cleanup.Token);
                    var exact = inventory.Where(x => x.Names.Contains("/" + candidate, StringComparer.Ordinal)).ToArray();
                    if (exact.Length > 1) { throw Invalid(); }
                    if (exact.Length == 1) { var actual = await docker.Containers.InspectContainerAsync(exact[0].ID, cleanup.Token); RequireContainer(actual, candidate); known[candidate] = actual.ID; await Remove(actual.ID, cleanup.Token); }
                    else if (known.TryGetValue(candidate, out string? id) && inventory.Any(x => x.ID == id)) { throw Invalid(); }
                }
                var volumes = await docker.Volumes.ListAsync(cleanup.Token);
                if ((volumes.Volumes ?? throw Invalid()).Any(x => x.Name == name))
                { if (!volumeAttempted) { throw Invalid(); } await RequireVolume([], cleanup.Token); await docker.Volumes.RemoveAsync(name, false, cleanup.Token); }
                removedAt = DateTimeOffset.UtcNow;
                var left = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, cleanup.Token);
                var leftVolumes = await docker.Volumes.ListAsync(cleanup.Token); var names = (leftVolumes.Volumes ?? throw Invalid()).Select(x => x.Name).ToArray();
                var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().ToArray();
                if (left.Any(x => known.ContainsValue(x.ID) || x.Names.Any(y => attempts.Keys.Any(z => y == "/" + z))) || names.Contains(name, StringComparer.Ordinal) || previousVolumes.Any(x => !names.Contains(x, StringComparer.Ordinal)) || (port != 0 && listeners.Contains(port))) { throw Invalid(); }
                removed = true;
                Write(run, "proof-absence", new CustomerDefinitionAbsence(run, DateTimeOffset.UtcNow, true, true, true, left.Select(x => x.ID).ToArray(), left.SelectMany(x => x.Names).ToArray(), names, listeners));
            }
            catch (Exception error) { cleanupFailure = true; cleanupErrors.Add(error); }
            finally
            {
                try
                {
                    var disposal = await Production181SdkDisposal.ObserveAsync(docker, run.ToString("D"));
                    disposed = disposal.Disposed; cleanupFailure |= !disposed;
                    Write(run, "sdk-disposal", disposal);
                }
                catch (Exception error) { cleanupFailure = true; cleanupErrors.Add(error); }
                try { Write(run, "disposed", new { run, containerId = known.GetValueOrDefault(name), volume = name, removed, disposed, cleanupFailure, cleanupErrorCount = cleanupErrors.Count, removedAtUtc = removedAt, completedAtUtc = DateTimeOffset.UtcNow }); }
                catch (Exception error) { cleanupFailure = true; cleanupErrors.Add(error); }
            }
        }
        async Task<string> Create(CreateContainerParameters plan, CancellationToken token)
        {
            var all = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, token); if (all.SelectMany(x => x.Names).Contains("/" + plan.Name, StringComparer.Ordinal)) { throw Invalid(); }
            string planName = plan.Name ?? throw Invalid();
            attempts.Add(planName, DateTimeOffset.UtcNow); Write(run, "attempt-" + planName, new { run, Name = planName, at = attempts[planName], expires });
            var created = await docker.Containers.CreateContainerAsync(plan, token); known.Add(planName, created.ID);
            var observed = await docker.Containers.InspectContainerAsync(created.ID, token); RequireContainer(observed, planName);
            return !await docker.Containers.StartContainerAsync(created.ID, new ContainerStartParameters(), token)
                ? throw Invalid()
                : created.ID;
        }
        async Task<ContainerInspectResponse> AwaitExit(string id, TimeSpan timeout, CancellationToken token)
        {
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(token); bounded.CancelAfter(timeout);
            while (true) { var state = await docker.Containers.InspectContainerAsync(id, bounded.Token); var actualState = state.State ?? throw Invalid(); if (!actualState.Running) { return state; } await Task.Delay(100, bounded.Token); }
        }
        async Task Remove(string id, CancellationToken token)
        {
            var state = await docker.Containers.InspectContainerAsync(id, token); RequireContainer(state, state.Name.TrimStart('/'));
            await RequireVolume([id], token);
            var actualState = state.State ?? throw Invalid();
            if (actualState.Running) { _ = await docker.Containers.StopContainerAsync(id, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, token); _ = await AwaitExit(id, TimeSpan.FromSeconds(10), token); }
            await docker.Containers.RemoveContainerAsync(id, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, token);
            var inventory = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, token); if (inventory.Any(x => x.ID == id)) { throw Invalid(); }
        }
        void RequireContainer(ContainerInspectResponse actual, string expectedName)
        {
            var plan = expectedName.EndsWith("-initialize", StringComparison.Ordinal) ? Production181DisposablePlans.Initializer(run, bindingHash) : expectedName.EndsWith("-checksum", StringComparison.Ordinal) ? Production181DisposablePlans.Checksum(run, bindingHash) : Production181DisposablePlans.Database(run, bindingHash);
            var config = actual.Config ?? throw Invalid(); var labels = config.Labels ?? throw Invalid();
            var entrypoint = config.Entrypoint ?? throw Invalid(); var command = config.Cmd ?? throw Invalid();
            var host = actual.HostConfig ?? throw Invalid(); var mounts = host.Mounts ?? throw Invalid();
            var actualMounts = actual.Mounts ?? throw Invalid();
            if (!attempts.TryGetValue(expectedName, out var attempt) || actual.Name != "/" + expectedName || config.Image != Production181EngineContract.Image || actual.Image != Production181EngineContract.Config ||
                config.User != plan.User || !entrypoint.SequenceEqual(plan.Entrypoint) || !command.SequenceEqual(plan.Cmd) || labels.Count != 4 ||
                Labels().Any(x => !labels.TryGetValue(x.Key, out string? value) || value != x.Value) || host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750000000 ||
                host.Privileged || host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } || host.Tmpfs is { Count: > 0 } ||
                mounts is not { Count: 1 } || mounts[0].Type != "volume" || mounts[0].Source != name || mounts[0].Target != "/var/lib/postgresql" || mounts[0].ReadOnly != false || mounts[0].VolumeOptions?.NoCopy != true || actualMounts.Count != 1 || actualMounts[0].Type != "volume" || actualMounts[0].Name != name || actualMounts[0].Destination != "/var/lib/postgresql" || !actualMounts[0].RW ||
                JsonSerializer.SerializeToElement(actual).GetProperty("Created").GetDateTimeOffset() < attempt.AddSeconds(-1) || JsonSerializer.SerializeToElement(actual).GetProperty("Created").GetDateTimeOffset() > expires) { throw Invalid(); }
        }
        async Task RequireVolume(string[] expectedConsumers, CancellationToken token)
        {
            var v = await docker.Volumes.InspectAsync(name, token); var labels = v.Labels ?? throw Invalid(); string createdAt = v.CreatedAt ?? throw Invalid(); if (v.Name != name || v.Driver != "local" || v.Scope != "local" || v.Options is { Count: > 0 } || labels.Count != 4 ||
                Labels().Any(x => !labels.TryGetValue(x.Key, out string? value) || value != x.Value) || previousVolumes.Contains(name) || !DateTimeOffset.TryParse(createdAt, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var created) ||
                volumeAttempt is null || created < volumeAttempt.Value.AddSeconds(-1) || created > expires || (volumeCreated is not null && volumeCreated != created)) { throw Invalid(); }
            volumeCreated ??= created;
            var consumers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true, Filters = new Dictionary<string, IDictionary<string, bool>> { ["volume"] = new Dictionary<string, bool> { [name] = true } } }, token);
            if (!consumers.Select(x => x.ID).Order(StringComparer.Ordinal).SequenceEqual(expectedConsumers.Order(StringComparer.Ordinal))) { throw Invalid(); }
            if (expectedConsumers.Length == 1 && expectedConsumers[0] == known.GetValueOrDefault(name))
            { Write(run, "proof-volume-metadata", new { v.Name, v.Driver, v.Scope, v.CreatedAt, v.Options, v.Labels }); Write(run, "proof-volume-consumers", expectedConsumers); }
        }
        Dictionary<string, string> Labels()
        {
            return new() { ["codex.repair.purpose"] = Production181EngineContract.Purpose, ["codex.repair.operation"] = run.ToString("D"), ["codex.repair.run"] = run.ToString("D"), ["codex.repair.run-binding"] = bindingHash };
        }
    }
    internal static async Task RetainEngineAsync(Guid run, string connectionString, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(connectionString); await connection.OpenAsync(ct);
        var actual = await Production181RawCaptureReader.CaptureAsync(connection, ct);
        Write(run, "engine-raw", new Production181RunCapture(run, DateTimeOffset.UtcNow, actual));
    }
    private static object Sanitize(ContainerInspectResponse c)
    {
        var host = c.HostConfig ?? throw Invalid(); var config = c.Config ?? throw Invalid();
        var network = c.NetworkSettings ?? throw Invalid(); var ports = network.Ports ?? throw Invalid();
        var state = c.State ?? throw Invalid(); var mounts = c.Mounts ?? throw Invalid();
        return new
        {
            Id = c.ID,
            c.Name,
            c.Image,
            c.Created,
            State = state,
            Mounts = mounts,
            HostConfig = new { host.Memory, host.MemorySwap, NanoCpus = host.NanoCPUs, host.Privileged, host.Mounts, host.Binds, host.VolumesFrom, host.Tmpfs },
            NetworkSettings = new { Ports = ports.ToDictionary(x => x.Key, x => x.Value?.Select(p => new { HostIp = p.HostIP, p.HostPort }).ToArray(), StringComparer.Ordinal) },
            Config = new { config.Image, config.User, config.Labels, config.Entrypoint, config.Cmd, PgData = Production181EngineContract.Data }
        };
    }
    private static void Write(Guid run, string phase, object value)
    {
        string root = Environment.GetEnvironmentVariable("MALIEV_PRODUCTION181_NATIVE_LEDGER") ?? throw Invalid(); SecureLocalFile.EnsureOwnerOnlyDirectory(root);
        string path = Path.Combine(root, run.ToString("N") + "-" + phase + ".json"); using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(file, path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw Invalid(); }
        JsonSerializer.Serialize(file, value); file.Flush(true);
    }
    private static string Hash(string path) { using var stream = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    private sealed class BoundedLogs : IProgress<string>
    { private readonly System.Text.StringBuilder _text = new(); public string Text => _text.ToString(); public void Report(string value) { if (_text.Length + value.Length > 65536) { throw Invalid(); } _ = _text.AppendLine(value); } }
    private static MigrationExecutionException Invalid()
    {
        return CurrentCustomerSequenceRepairPermit.Invalid();
    }
}
