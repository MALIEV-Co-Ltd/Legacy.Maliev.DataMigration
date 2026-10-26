using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Docker.DotNet;
using Docker.DotNet.Models;
using DotNet.Testcontainers.Configurations;
using Npgsql;
using Testcontainers.PostgreSql;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Resource mechanics only; Source is imported input, not independently certified SQL capture.
// No schema, archive provider, permission or execution proof is produced here.
// Fixed named disposable fixture only. It does not accept a database endpoint, arbitrary
// container image/name/mount, cleanup selector, SQL callback or persistent volume.
internal sealed class CurrentAuthArchiveFixtureTarget : IAsyncDisposable
{
    internal const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    private readonly DockerClient _docker;
    private readonly PostgreSqlContainer _container;
    private readonly HashSet<string> _previousVolumes;
    private readonly DateTimeOffset _began, _expires;
    private readonly CancellationTokenSource _lease;
    private string? _id, _volumeCreated, _imageId;
    private DateTimeOffset? _containerCreated;
    private int _port;
    private bool _volumeAttempted, _containerAttempted, _disposed;
    private int _frame;
    internal Guid Operation { get; }
    internal string Root { get; }
    internal LocalExecutionBinding Binding { get; }
    internal bool Comparison { get; }
    internal FreshSchemaPlan Source { get; }
    internal CurrentAuthArchiveFixtureTargetSettings Configuration { get; }
    internal string Name => Configuration.Name;
    internal string ContainerId => _id ?? throw CurrentAuthRepairPermit.Invalid();
    internal string AdminConnection => new NpgsqlConnectionStringBuilder(_container.GetConnectionString())
    { Host = "127.0.0.1", Database = "postgres", Username = "postgres", Password = field, Pooling = false, SslMode = SslMode.Disable, Timeout = 5, CommandTimeout = 30, IncludeErrorDetail = false }.ConnectionString;
    internal CancellationToken Token => _lease.Token;

    private CurrentAuthArchiveFixtureTarget(string root, Guid operation, LocalExecutionBinding binding,
        DockerClient docker, PostgreSqlContainer container, HashSet<string> previous, string password, DateTimeOffset began, bool comparison, FreshSchemaPlan source)
    {
        Root = root; Operation = operation; Binding = binding; Comparison = comparison; Source = source;
        Configuration = Settings(operation, comparison, binding.ComputeSha256(), began); _docker = docker; _container = container;
        _previousVolumes = previous; AdminConnection = password; _began = began; _expires = began.AddMinutes(8);
        _lease = new CancellationTokenSource(_expires - DateTimeOffset.UtcNow);
    }

    internal static CurrentAuthArchiveFixtureTargetSettings Settings(Guid operation, bool comparison, string binding, DateTimeOffset began)
    {
        if (operation == Guid.Empty || !CurrentAuthRepairPermit.HashShape(binding) || began.Offset != TimeSpan.Zero)
        { throw CurrentAuthRepairPermit.Invalid(); }
        string[] databases = comparison ? [.. ReviewedProductionRepairInventory.ExportProductionNames()] :
            [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
        return new("legacy-delta-proof-" + operation.ToString("N") + (comparison ? "-comparison" : ""), Image,
            new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["codex.repair.purpose"] = "current-auth-local-session-archive-proof",
                ["codex.repair.operation"] = operation.ToString("D"),
                ["codex.repair.run-binding"] = binding,
            }), Array.AsReadOnly(databases), 512L * 1024 * 1024, 750_000_000, began.AddMinutes(8));
    }
    internal static async Task<CurrentAuthArchiveFixtureTarget> CreateAsync(string parentRoot, CurrentAppOwnedRepairCustody hostFiles,
        CurrentAuthArchiveProofArtifact sourceArtifact, string acceptedCommit, Guid operation, bool comparison, CancellationToken ct, CurrentAuthArchiveFixtureFault fault = CurrentAuthArchiveFixtureFault.None)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(parentRoot) || !Directory.Exists(parentRoot)) { throw CurrentAuthRepairPermit.Invalid(); }
        CurrentAuthArchiveCapacity.Require(admission: true);
        FreshSchemaPlan source = CurrentAuthArchiveFixtureSource.Read(hostFiles, sourceArtifact, acceptedCommit, DateTimeOffset.UtcNow);
        ct.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(fault)) { throw CurrentAuthRepairPermit.Invalid(); }
        if (operation == Guid.Empty) { throw CurrentAuthRepairPermit.Invalid(); }
        string root = Path.Combine(parentRoot, "auth-archive-target-" + operation.ToString("N") + (comparison ? "-comparison" : ""));
        if (Directory.Exists(root)) { throw CurrentAuthRepairPermit.Invalid(); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root); LocalExecutionBinding binding;
        using (var authority = WindowsLocalRunAuthority.AcquireFresh(root))
        {
            binding = authority.Binding;
            using var files = new CurrentAppOwnedRepairCustody(authority);
            await files.WriteNewAsync(Path.Combine(root, "fixture-binding.json"), JsonSerializer.SerializeToUtf8Bytes(binding), ct).ConfigureAwait(false);
        }
        DateTimeOffset began = DateTimeOffset.UtcNow;
        CurrentAuthArchiveFixtureTargetSettings settings = Settings(operation, comparison, binding.ComputeSha256(), began);
        string name = settings.Name, password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        PostgreSqlContainer? container = null; CurrentAuthArchiveFixtureTarget? fixture = null;
        try
        {
            using var initialDeadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            initialDeadline.CancelAfter(settings.ExpiresAtUtc - DateTimeOffset.UtcNow);
            ct = initialDeadline.Token;
            var inventory = await docker.Volumes.ListAsync(ct).ConfigureAwait(false);
            var previous = (inventory.Volumes ?? throw CurrentAuthRepairPermit.Invalid()).Select(x => x.Name).ToHashSet(StringComparer.Ordinal);
            if (previous.Contains(name)) { throw CurrentAuthRepairPermit.Invalid(); }
            bool absent = false;
            try { _ = await docker.Containers.InspectContainerAsync(name, ct).ConfigureAwait(false); }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { absent = true; }
            if (!absent) { throw CurrentAuthRepairPermit.Invalid(); }
            container = new PostgreSqlBuilder(settings.Image).WithDockerEndpoint("npipe://./pipe/docker_engine").WithName(name)
                .WithDatabase("postgres").WithUsername("postgres").WithPassword(password).WithCleanUp(false)
                .WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C").WithCommand("-c", "autovacuum=off")
                .WithVolumeMount(name, "/var/lib/postgresql", AccessMode.ReadWrite)
                .WithLabel("codex.repair.purpose", "current-auth-local-session-archive-proof").WithLabel("codex.repair.operation", operation.ToString("D"))
                .WithLabel("codex.repair.run-binding", binding.ComputeSha256())
                .WithCreateParameterModifier(parameters =>
                {
                    parameters.HostConfig!.Memory = settings.MemoryBytes; parameters.HostConfig.MemorySwap = settings.MemoryBytes;
                    parameters.HostConfig.NanoCPUs = settings.NanoCpus;
                    foreach (var port in parameters.HostConfig.PortBindings!.Values) { foreach (var map in port) { map.HostIP = "127.0.0.1"; } }
                }).Build();
            fixture = new(root, operation, binding, docker, container, previous, password, began, comparison, source);
            await fixture.RecordAsync("attempt", new
            {
                operation,
                name,
                began,
                expires = fixture._expires,
                persistent = false,
                comparison,
                sourceArtifact,
                acceptedCommit,
                expectedDatabaseNames = settings.Databases,
                previousVolumes = previous.Order(StringComparer.Ordinal).ToArray()
            }, ct).ConfigureAwait(false);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, fixture.Token);
            fixture._volumeAttempted = true;
            _ = await docker.Volumes.CreateAsync(new VolumesCreateParameters
            {
                Name = name,
                Driver = "local",
                Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                { ["codex.repair.purpose"] = "current-auth-local-session-archive-proof", ["codex.repair.operation"] = operation.ToString("D"), ["codex.repair.run-binding"] = binding.ComputeSha256() }
            }, linked.Token).ConfigureAwait(false);
            await fixture.RequireVolumeAsync(requireConsumer: false, linked.Token).ConfigureAwait(false);
            fixture._containerAttempted = true;
            await container.StartAsync(linked.Token).ConfigureAwait(false);
            if (fault == CurrentAuthArchiveFixtureFault.CancelAfterStarted)
            {
                using var canceled = new CancellationTokenSource(); canceled.Cancel(); canceled.Token.ThrowIfCancellationRequested();
            }
            var actual = await docker.Containers.InspectContainerAsync(name, linked.Token).ConfigureAwait(false);
            fixture.RequireContainer(actual); fixture._id = actual.ID;
            if (fixture._port != container.GetMappedPublicPort(5432)) { throw CurrentAuthRepairPermit.Invalid(); }
            await fixture.RequireVolumeAsync(requireConsumer: true, linked.Token).ConfigureAwait(false);
            await using (var connection = new NpgsqlConnection(fixture.AdminConnection))
            {
                await connection.OpenAsync(linked.Token).ConfigureAwait(false);
                await using var command = new NpgsqlCommand("SELECT current_setting('server_version_num'),current_setting('autovacuum');", connection);
                await using var reader = await command.ExecuteReaderAsync(linked.Token).ConfigureAwait(false);
                if (!await reader.ReadAsync(linked.Token).ConfigureAwait(false) || reader.GetString(0) != "180004" || reader.GetString(1) != "off" ||
                    await reader.ReadAsync(linked.Token).ConfigureAwait(false)) { throw CurrentAuthRepairPermit.Invalid(); }
            }
            await fixture.RecordTargetAsync(linked.Token).ConfigureAwait(false); return fixture;
        }
        catch
        {
            if (fixture is not null) { await fixture.DisposeAsync().ConfigureAwait(false); }
            else { if (container is not null) { await container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); } docker.Dispose(); }
            throw;
        }
    }

    internal Task RecordAsync<T>(string phase, T value, CancellationToken ct)
    {
        return CurrentAuthArchiveFixtureFrame.RunAsync(async token =>
        {
            token.ThrowIfCancellationRequested();
            using var authority = WindowsLocalRunAuthority.AcquireResume(Root, Binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
            if (bytes.Length > 2 * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
            string path = Path.Combine(Root, $"auth-archive-resource-{Operation:N}-{Interlocked.Increment(ref _frame):D5}-{phase}.json");
            await files.WriteNewAsync(path, bytes, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (!files.Read(path, maximumBytes: 2 * 1024 * 1024).AsSpan().SequenceEqual(bytes)) { throw CurrentAuthRepairPermit.Invalid(); }
            files.Require(); token.ThrowIfCancellationRequested();
        }, TimeSpan.FromSeconds(5), ct);
    }
    private void RequireContainer(ContainerInspectResponse actual, bool requireRunningTransport = true)
    {
        var host = actual.HostConfig ?? throw CurrentAuthRepairPermit.Invalid(); var config = actual.Config ?? throw CurrentAuthRepairPermit.Invalid();
        DateTimeOffset created = JsonSerializer.SerializeToElement(actual).GetProperty("Created").GetDateTimeOffset();
        if (actual.ID.Length != 64 || !actual.ID.All(char.IsAsciiHexDigitLower) || (_id is not null && _id != actual.ID) ||
            (_containerCreated is not null && _containerCreated != created) || (_imageId is not null && _imageId != actual.Image) ||
            string.IsNullOrWhiteSpace(actual.Image) || actual.Name != "/" + Name || created < _began.AddSeconds(-1) || created > _expires ||
            config.Image != Image || config.Labels["codex.repair.purpose"] != "current-auth-local-session-archive-proof" || config.Labels["codex.repair.operation"] != Operation.ToString("D") ||
            config.Labels["codex.repair.run-binding"] != Binding.ComputeSha256() || host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750_000_000 ||
            host.Tmpfs is { Count: > 0 } || host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } ||
            actual.Mounts.Count != 1 || actual.Mounts.Single().Type != "volume" || actual.Mounts.Single().Name != Name || actual.Mounts.Single().Destination != "/var/lib/postgresql" || !actual.Mounts.Single().RW ||
            host.PortBindings.Count != 1 || !host.PortBindings.TryGetValue("5432/tcp", out var declaredPorts) || declaredPorts.Count != 1 || declaredPorts[0].HostIP != "127.0.0.1" ||
            actual.NetworkSettings is null || actual.NetworkSettings.Ports.Values.SelectMany(x => x ?? []).Any(port => port.HostIP != "127.0.0.1") ||
            (requireRunningTransport && (actual.NetworkSettings.Ports.Count != 1 || !actual.NetworkSettings.Ports.TryGetValue("5432/tcp", out var ports) || ports.Count != 1 || ports[0].HostIP != "127.0.0.1")))
        { throw CurrentAuthRepairPermit.Invalid(); }
        _port = RecoverTransport(JsonSerializer.SerializeToElement(actual), _port);
        _containerCreated ??= created; _imageId ??= actual.Image;
    }

    internal static int RecoverTransport(JsonElement actual, int retained)
    {
        if (retained is < 0 or > 65535) { throw CurrentAuthRepairPermit.Invalid(); }
        try
        {
            JsonElement state = actual.GetProperty("State");
            JsonElement declared = actual.GetProperty("HostConfig").GetProperty("PortBindings");
            if (declared.EnumerateObject().Count() != 1) { throw CurrentAuthRepairPermit.Invalid(); }
            JsonElement[] bindings = [.. declared.GetProperty("5432/tcp").EnumerateArray()];
            if (bindings.Length != 1 || Host(bindings[0]) != "127.0.0.1") { throw CurrentAuthRepairPermit.Invalid(); }
            string configured = bindings[0].GetProperty("HostPort").GetString() ?? throw CurrentAuthRepairPermit.Invalid();
            JsonElement ports = actual.GetProperty("NetworkSettings").GetProperty("Ports");
            if (ports.ValueKind != JsonValueKind.Object || ports.EnumerateObject().Any(x => x.Name != "5432/tcp"))
            { throw CurrentAuthRepairPermit.Invalid(); }
            JsonElement[] maps = ports.TryGetProperty("5432/tcp", out var published) && published.ValueKind != JsonValueKind.Null ?
                [.. published.EnumerateArray()] : [];
            return maps.Length switch
            {
                1 => Published(maps[0], retained, configured),
                0 => Stopped(state, retained, configured),
                _ => throw CurrentAuthRepairPermit.Invalid(),
            };
        }
        catch (Exception failure) when (failure is KeyNotFoundException or InvalidOperationException or FormatException)
        { throw CurrentAuthRepairPermit.Invalid(); }

        static int Published(JsonElement mapping, int previousPort, string declaredPort)
        {
            return Host(mapping) != "127.0.0.1" || !int.TryParse(mapping.GetProperty("HostPort").GetString(), out int port) ||
                port is < 1 or > 65535 || (previousPort != 0 && previousPort != port) ||
                (declaredPort.Length != 0 && declaredPort != "0" && declaredPort != port.ToString(System.Globalization.CultureInfo.InvariantCulture))
                ? throw CurrentAuthRepairPermit.Invalid()
                : port;
        }
        static int Stopped(JsonElement stoppedState, int previousPort, string declaredPort)
        {
            return stoppedState.GetProperty("Running").GetBoolean()
                ? throw CurrentAuthRepairPermit.Invalid()
                : previousPort > 0
                    ? declaredPort.Length != 0 && declaredPort != "0" && declaredPort != previousPort.ToString(System.Globalization.CultureInfo.InvariantCulture)
                        ? throw CurrentAuthRepairPermit.Invalid()
                        : previousPort
                    : stoppedState.GetProperty("Status").GetString() == "created" &&
                        DateTimeOffset.TryParse(stoppedState.GetProperty("StartedAt").GetString(), System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.None, out var started) && started.Year == 1 &&
                        (declaredPort.Length == 0 || declaredPort == "0")
                        ? 0
                        : throw CurrentAuthRepairPermit.Invalid();
        }

        static string Host(JsonElement binding)
        {
            bool canonical = binding.TryGetProperty("HostIp", out var first), sdk = binding.TryGetProperty("HostIP", out var second);
            return canonical == sdk ? throw CurrentAuthRepairPermit.Invalid() :
                (canonical ? first : second).GetString() ?? throw CurrentAuthRepairPermit.Invalid();
        }
    }
    private async Task RequireVolumeAsync(bool requireConsumer, CancellationToken ct)
    {
        var actual = await _docker.Volumes.InspectAsync(Name, ct).ConfigureAwait(false);
        if (_previousVolumes.Contains(Name) || actual.Name != Name || actual.Driver != "local" || actual.Scope != "local" || actual.Options is { Count: > 0 } ||
            actual.Labels.Count != 3 || actual.Labels["codex.repair.purpose"] != "current-auth-local-session-archive-proof" || actual.Labels["codex.repair.operation"] != Operation.ToString("D") ||
            actual.Labels["codex.repair.run-binding"] != Binding.ComputeSha256() || !DateTimeOffset.TryParse(actual.CreatedAt, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out var created) || created < _began.AddSeconds(-1) || created > _expires || (_volumeCreated is not null && _volumeCreated != actual.CreatedAt))
        { throw CurrentAuthRepairPermit.Invalid(); }
        var consumers = await _docker.Containers.ListContainersAsync(new ContainersListParameters
        { All = true, Filters = new Dictionary<string, IDictionary<string, bool>> { ["volume"] = new Dictionary<string, bool> { [Name] = true } } }, ct).ConfigureAwait(false);
        if (requireConsumer ? consumers.Count != 1 || consumers[0].ID != _id : consumers.Count != 0) { throw CurrentAuthRepairPermit.Invalid(); }
        _volumeCreated ??= actual.CreatedAt;
        await RecordAsync("volume", new
        {
            actual.Name,
            actual.Driver,
            actual.Scope,
            actual.CreatedAt,
            actual.Labels,
            actual.Options,
            existedBefore = false,
            consumers = consumers.Select(x => x.ID).ToArray()
        }, ct).ConfigureAwait(false);
    }

    internal async Task RequireHealthyAsync(CancellationToken ct)
    {
        if (_disposed || DateTimeOffset.UtcNow >= _expires) { throw CurrentAuthRepairPermit.Invalid(); }
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct, Token);
        lease.Token.ThrowIfCancellationRequested();
        var actual = await _docker.Containers.InspectContainerAsync(ContainerId, lease.Token).ConfigureAwait(false);
        if (actual.State is null || !actual.State.Running) { throw CurrentAuthRepairPermit.Invalid(); }
        RequireContainer(actual);
        await RequireVolumeAsync(requireConsumer: true, lease.Token).ConfigureAwait(false);
        await RecordTargetAsync(lease.Token).ConfigureAwait(false);
        lease.Token.ThrowIfCancellationRequested();
    }

    private async Task RecordTargetAsync(CancellationToken ct)
    {
        string raw = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(["inspect", "--type", "container", ContainerId], ct,
            value => RecordAsync("docker", value, CancellationToken.None)).ConfigureAwait(false);
        JsonArray array = JsonNode.Parse(raw)!.AsArray(); JsonObject item = array.Single()!.AsObject(), config = item["Config"]!.AsObject();
        string[] pgData = config["Env"]!.AsArray().Select(x => x!.GetValue<string>()).Where(x => x.StartsWith("PGDATA=", StringComparison.Ordinal)).ToArray();
        if (pgData.Length != 1 || pgData[0] != "PGDATA=/var/lib/postgresql/18/docker") { throw CurrentAuthRepairPermit.Invalid(); }
        _ = config.Remove("Env"); config["PgData"] = pgData[0][7..]; await RecordAsync("target", item, ct).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true; _lease.Cancel();
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(55)); bool removed = false, sdkDisposed = false, verifiedAbsence = false; DateTimeOffset? removedAtUtc = null;
        try
        {
            if (_containerAttempted)
            {
                ContainerInspectResponse? actual = null;
                try { actual = await _docker.Containers.InspectContainerAsync(_id ?? Name, cleanup.Token).ConfigureAwait(false); }
                catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound && _id is null) { }
                if (actual is not null)
                {
                    RequireContainer(actual, requireRunningTransport: false); _id ??= actual.ID;
                    await RequireVolumeAsync(requireConsumer: true, cleanup.Token).ConfigureAwait(false);
                    if ((actual.State ?? throw CurrentAuthRepairPermit.Invalid()).Running) { _ = await _docker.Containers.StopContainerAsync(_id, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, cleanup.Token).ConfigureAwait(false); }
                    actual = await _docker.Containers.InspectContainerAsync(_id, cleanup.Token).ConfigureAwait(false); RequireContainer(actual, requireRunningTransport: false);
                    if ((actual.State ?? throw CurrentAuthRepairPermit.Invalid()).Running) { throw CurrentAuthRepairPermit.Invalid(); }
                    await RequireVolumeAsync(requireConsumer: true, cleanup.Token).ConfigureAwait(false);
                    await _docker.Containers.RemoveContainerAsync(_id, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, cleanup.Token).ConfigureAwait(false);
                    await RequireContainerAbsentAsync(_id, cleanup.Token).ConfigureAwait(false);
                }
                await RequireContainerAbsentAsync(Name, cleanup.Token).ConfigureAwait(false);
            }
            if (_volumeAttempted)
            {
                bool present = true;
                try { await RequireVolumeAsync(requireConsumer: false, cleanup.Token).ConfigureAwait(false); }
                catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { present = false; }
                if (present) { await _docker.Volumes.RemoveAsync(Name, force: false, cleanup.Token).ConfigureAwait(false); }
                bool absent = false;
                try { _ = await _docker.Volumes.InspectAsync(Name, cleanup.Token).ConfigureAwait(false); }
                catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { absent = true; }
                if (!absent) { throw CurrentAuthRepairPermit.Invalid(); }
            }
            removed = true; removedAtUtc = DateTimeOffset.UtcNow;
            // No credential file is created by this resource-only helper.
            await _container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); sdkDisposed = true;
            var containers = await _docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, cleanup.Token).ConfigureAwait(false);
            var volumes = await _docker.Volumes.ListAsync(cleanup.Token).ConfigureAwait(false);
            string[] ids = [.. containers.Select(x => x.ID).Order(StringComparer.Ordinal)], names = [.. containers.SelectMany(x => x.Names).Order(StringComparer.Ordinal)],
                volumeNames = [.. (volumes.Volumes ?? throw CurrentAuthRepairPermit.Invalid()).Select(x => x.Name).Order(StringComparer.Ordinal)];
            int[] ports = [.. System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().Order()];
            if ((_id is not null && ids.Contains(_id, StringComparer.Ordinal)) || names.Contains("/" + Name, StringComparer.Ordinal) ||
                volumeNames.Contains(Name, StringComparer.Ordinal) || (_port > 0 && ports.Contains(_port))) { throw CurrentAuthRepairPermit.Invalid(); }
            await RecordAsync("absent", new
            {
                Operation,
                _id,
                volume = Name,
                observedPort = _port,
                removedAtUtc,
                observedAtUtc = DateTimeOffset.UtcNow,
                containerIds = ids,
                containerNames = names,
                volumeNames,
                listeningPorts = ports,
                credentialFilesCreated = 0
            }, cleanup.Token).ConfigureAwait(false);
            verifiedAbsence = true;
        }
        finally
        {
            try
            {
                await RecordAsync("disposed", new
                {
                    Operation,
                    _id,
                    volume = Name,
                    removed,
                    sdkDisposed,
                    removedAtUtc,
                    verifiedAbsence,
                    cleanupFailed = !removed || !sdkDisposed || !verifiedAbsence,
                    expiresAtUtc = _expires,
                    completedAtUtc = DateTimeOffset.UtcNow
                }, CancellationToken.None).ConfigureAwait(false);
            }
            finally { _lease.Dispose(); _docker.Dispose(); }
        }
    }

    private async Task RequireContainerAbsentAsync(string name, CancellationToken ct)
    {
        bool absent = false;
        try { _ = await _docker.Containers.InspectContainerAsync(name, ct).ConfigureAwait(false); }
        catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { absent = true; }
        if (!absent) { throw CurrentAuthRepairPermit.Invalid(); }
    }
}
internal sealed record CurrentAuthArchiveFixtureTargetSettings(string Name, string Image,
    IReadOnlyDictionary<string, string> Labels, IReadOnlyList<string> Databases, long MemoryBytes, long NanoCpus,
    DateTimeOffset ExpiresAtUtc);


internal enum CurrentAuthArchiveFixtureFault { None, CancelAfterStarted }
