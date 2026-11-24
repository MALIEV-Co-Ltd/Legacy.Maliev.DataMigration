using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;
using DotNet.Testcontainers.Configurations;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Console;

// Fixed named disposable fixture only. It does not accept a database endpoint, arbitrary
// container image/name/mount, cleanup selector, SQL callback or persistent volume.
internal sealed partial class DualTargetNativeProofClone : IAsyncDisposable
{
    internal const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    private readonly DockerClient _docker;
    private readonly PostgreSqlContainer _container;
    private readonly HashSet<string> _previousVolumes;
    private readonly DateTimeOffset _began;
    private readonly CancellationTokenSource _lease;
    private string? _id, _volumeCreated;
    private string? _containerLabelsSha256;
    private string? _systemSha256;
    private int _port;
    private bool _volumeAttempted, _containerAttempted, _disposed;
    private int _frame;
    private string? _operatorConnection;
    private bool _controlDropped;
    private bool _administratorCreated;
    internal string RestoreConnection => AdminConnection;
    internal string Connection => _operatorConnection ?? new NpgsqlConnectionStringBuilder(AdminConnection)
    { Username = _administratorCreated ? "clone_admin" : "postgres", Database = _controlDropped ? "postgres" : "clone_control" }.ConnectionString;
    internal void MarkControlDropped() { if (_controlDropped) { throw DualTargetNativeProofPreimage.Invalid(); } _controlDropped = true; }
    internal const string Administrator = "clone_admin";
    internal void RetireAdministrator(string maintenanceConnection)
    {
        if (_operatorConnection is not null || new NpgsqlConnectionStringBuilder(maintenanceConnection).Host != "127.0.0.1" ||
            new NpgsqlConnectionStringBuilder(maintenanceConnection).Port != _port) { throw DualTargetNativeProofPreimage.Invalid(); }
        _operatorConnection = maintenanceConnection;
    }
    internal Guid Operation { get; }
    internal string Root { get; }
    internal LocalExecutionBinding Binding { get; }
    internal string Name => "legacy-delta-proof-" + Operation.ToString("N");
    internal string ContainerId => _id ?? throw DualTargetNativeProofPreimage.Invalid();
    internal string AdminConnection => new NpgsqlConnectionStringBuilder(_container.GetConnectionString())
    { Host = "127.0.0.1", Database = "postgres", Username = "clone_admin", Password = field, Pooling = false, SslMode = SslMode.Disable, Timeout = 5, CommandTimeout = 30, IncludeErrorDetail = false }.ConnectionString;
    internal CancellationToken Token => _lease.Token;
    internal DateTimeOffset ExpiresAtUtc { get; }

    private DualTargetNativeProofClone(string root, Guid operation, LocalExecutionBinding binding,
        DockerClient docker, PostgreSqlContainer container, HashSet<string> previous, string password, DateTimeOffset began)
    {
        Root = root; Operation = operation; Binding = binding; _docker = docker; _container = container;
        _previousVolumes = previous; AdminConnection = password; _began = began; ExpiresAtUtc = began.AddMinutes(8);
        _lease = new CancellationTokenSource(ExpiresAtUtc - DateTimeOffset.UtcNow);
    }

    internal static async Task<DualTargetNativeProofClone> CreateAsync(string parentRoot, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(parentRoot) || !Directory.Exists(parentRoot)) { throw DualTargetNativeProofPreimage.Invalid(); }
        CurrentAuthArchiveCapacity.Require(admission: true);
        _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        Guid operation = Guid.NewGuid(); string root = Path.Combine(parentRoot, "native-proof-clone-" + operation.ToString("N"));
        if (Directory.Exists(root)) { throw DualTargetNativeProofPreimage.Invalid(); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root); LocalExecutionBinding binding;
        using (var authority = WindowsLocalRunAuthority.AcquireFresh(root))
        {
            binding = authority.Binding;
            using var files = new CurrentAppOwnedRepairCustody(authority);
            await files.WriteNewAsync(Path.Combine(root, "fixture-binding.json"), JsonSerializer.SerializeToUtf8Bytes(binding), ct).ConfigureAwait(false);
        }
        DateTimeOffset began = DateTimeOffset.UtcNow;
        string name = "legacy-delta-proof-" + operation.ToString("N"), password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        PostgreSqlContainer? container = null; DualTargetNativeProofClone? fixture = null;
        try
        {
            _ = await docker.Images.InspectImageAsync(Image, ct).ConfigureAwait(false);
            var inventory = await docker.Volumes.ListAsync(ct).ConfigureAwait(false);
            var previous = (inventory.Volumes ?? throw DualTargetNativeProofPreimage.Invalid()).Select(x => x.Name).ToHashSet(StringComparer.Ordinal);
            if (previous.Contains(name)) { throw DualTargetNativeProofPreimage.Invalid(); }
            bool absent = false;
            try { _ = await docker.Containers.InspectContainerAsync(name, ct).ConfigureAwait(false); }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { absent = true; }
            if (!absent) { throw DualTargetNativeProofPreimage.Invalid(); }
            container = new PostgreSqlBuilder(Image).WithDockerEndpoint("npipe://./pipe/docker_engine").WithName(name)
                .WithDatabase("clone_control").WithUsername("postgres").WithPassword(password).WithCleanUp(false)
                .WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C").WithCommand("-c", "autovacuum=off")
                .WithVolumeMount(name, "/var/lib/postgresql", AccessMode.ReadWrite)
                .WithLabel("codex.repair.purpose", "dual-target-native-proof-preimage").WithLabel("codex.repair.operation", operation.ToString("D"))
                .WithLabel("codex.repair.run-binding", binding.ComputeSha256())
                .WithCreateParameterModifier(parameters =>
                {
                    parameters.HostConfig!.Memory = 512L * 1024 * 1024; parameters.HostConfig.MemorySwap = 512L * 1024 * 1024;
                    parameters.HostConfig.NanoCPUs = 750_000_000;
                    foreach (var port in parameters.HostConfig.PortBindings!.Values) { foreach (var map in port) { map.HostIP = "127.0.0.1"; } }
                }).Build();
            fixture = new(root, operation, binding, docker, container, previous, password, began);
            await fixture.RecordAsync("attempt", new
            {
                operation,
                name,
                began,
                expires = fixture.ExpiresAtUtc,
                persistent = false,
                previousVolumes = previous.Order(StringComparer.Ordinal).ToArray(),
                previousContainerIds = (await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, ct).ConfigureAwait(false)).Select(x => x.ID).Order(StringComparer.Ordinal).ToArray()
            }, ct).ConfigureAwait(false);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, fixture.Token);
            fixture._volumeAttempted = true;
            _ = await docker.Volumes.CreateAsync(new VolumesCreateParameters
            {
                Name = name,
                Driver = "local",
                Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                { ["codex.repair.purpose"] = "dual-target-native-proof-preimage", ["codex.repair.operation"] = operation.ToString("D"), ["codex.repair.run-binding"] = binding.ComputeSha256() }
            }, linked.Token).ConfigureAwait(false);
            await fixture.RequireVolumeAsync(requireConsumer: false, linked.Token).ConfigureAwait(false);
            fixture._containerAttempted = true;
            await container.StartAsync(linked.Token).ConfigureAwait(false);
            var actual = await docker.Containers.InspectContainerAsync(name, linked.Token).ConfigureAwait(false);
            fixture.RequireContainer(actual); fixture._id = actual.ID; fixture._port = container.GetMappedPublicPort(5432);
            fixture._containerLabelsSha256 = LabelHash((actual.Config ?? throw DualTargetNativeProofPreimage.Invalid()).Labels);
            await fixture.RequireVolumeAsync(requireConsumer: true, linked.Token).ConfigureAwait(false);
            await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.AdminConnection) { Username = "postgres" }.ConnectionString))
            {
                await connection.OpenAsync(linked.Token).ConfigureAwait(false);
                await using var command = new NpgsqlCommand("SELECT current_setting('server_version_num'),current_setting('autovacuum'),encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", connection);
                await using (var reader = await command.ExecuteReaderAsync(linked.Token).ConfigureAwait(false))
                {
                    if (!await reader.ReadAsync(linked.Token).ConfigureAwait(false) || reader.GetString(0) != "180004" || reader.GetString(1) != "off")
                    { throw DualTargetNativeProofPreimage.Invalid(); }
                    fixture._systemSha256 = reader.GetString(2);
                    if (await reader.ReadAsync(linked.Token).ConfigureAwait(false)) { throw DualTargetNativeProofPreimage.Invalid(); }
                }
                await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, null,
                    "CREATE ROLE clone_admin LOGIN SUPERUSER PASSWORD '" + password + "';", linked.Token).ConfigureAwait(false);
                fixture._administratorCreated = true;
            }
            await fixture.RecordTargetAsync(linked.Token).ConfigureAwait(false); return fixture;
        }
        catch (Exception primary)
        {
            try
            {
                if (fixture is not null) { await fixture.DisposeAsync().ConfigureAwait(false); }
                else { if (container is not null) { await container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); } docker.Dispose(); }
            }
            catch (Exception cleanup) { primary.Data["DualProofCloneCleanup"] = cleanup; }
            throw;
        }
    }

    internal async Task RecordAsync<T>(string phase, T value, CancellationToken ct)
    {
        using var authority = WindowsLocalRunAuthority.AcquireResume(Root, Binding); using var files = new CurrentAppOwnedRepairCustody(authority);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value); if (bytes.Length > 2 * 1024 * 1024) { throw DualTargetNativeProofPreimage.Invalid(); }
        string path = Path.Combine(Root, $"native-proof-resource-{Operation:N}-{Interlocked.Increment(ref _frame):D5}-{phase}.json");
        await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false); files.Require();
    }

    private void RequireContainer(ContainerInspectResponse actual, bool requireRunningTransport = true)
    {
        var host = actual.HostConfig ?? throw DualTargetNativeProofPreimage.Invalid(); var config = actual.Config ?? throw DualTargetNativeProofPreimage.Invalid();
        var state = actual.State ?? throw DualTargetNativeProofPreimage.Invalid();
        DateTimeOffset created = JsonSerializer.SerializeToElement(actual).GetProperty("Created").GetDateTimeOffset();
        if (actual.ID.Length != 64 || (_id is not null && _id != actual.ID) || actual.Name != "/" + Name || created < _began.AddSeconds(-1) || created > ExpiresAtUtc ||
            config.Image != Image || (_containerLabelsSha256 is not null && LabelHash(config.Labels) != _containerLabelsSha256) ||
            config.Labels["codex.repair.purpose"] != "dual-target-native-proof-preimage" || config.Labels["codex.repair.operation"] != Operation.ToString("D") ||
            config.Labels["codex.repair.run-binding"] != Binding.ComputeSha256() || host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750_000_000 ||
            host.Tmpfs is { Count: > 0 } || host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } ||
            actual.Mounts.Count != 1 || actual.Mounts.Single().Type != "volume" || actual.Mounts.Single().Name != Name || actual.Mounts.Single().Destination != "/var/lib/postgresql" || !actual.Mounts.Single().RW ||
            host.PortBindings.Count != 1 || !host.PortBindings.TryGetValue("5432/tcp", out var declaredPorts) || declaredPorts.Count != 1 || declaredPorts[0].HostIP != "127.0.0.1" ||
            actual.NetworkSettings is null || actual.NetworkSettings.Ports.Values.SelectMany(x => x ?? []).Any(port => port.HostIP != "127.0.0.1") ||
            (requireRunningTransport && (!state.Running || actual.NetworkSettings.Ports.Count != 1 || !actual.NetworkSettings.Ports.TryGetValue("5432/tcp", out var ports) || ports.Count != 1 || ports[0].HostIP != "127.0.0.1")))
        { throw DualTargetNativeProofPreimage.Invalid(); }
    }

    private async Task RequireVolumeAsync(bool requireConsumer, CancellationToken ct)
    {
        var actual = await _docker.Volumes.InspectAsync(Name, ct).ConfigureAwait(false);
        if (_previousVolumes.Contains(Name) || actual.Name != Name || actual.Driver != "local" || actual.Scope != "local" || actual.Options is { Count: > 0 } ||
            actual.Labels.Count != 3 || actual.Labels["codex.repair.purpose"] != "dual-target-native-proof-preimage" || actual.Labels["codex.repair.operation"] != Operation.ToString("D") ||
            actual.Labels["codex.repair.run-binding"] != Binding.ComputeSha256() || !DateTimeOffset.TryParse(actual.CreatedAt, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out var created) || created < _began.AddSeconds(-1) || created > ExpiresAtUtc || (_volumeCreated is not null && _volumeCreated != actual.CreatedAt))
        { throw DualTargetNativeProofPreimage.Invalid(); }
        var consumers = await _docker.Containers.ListContainersAsync(new ContainersListParameters
        { All = true, Filters = new Dictionary<string, IDictionary<string, bool>> { ["volume"] = new Dictionary<string, bool> { [Name] = true } } }, ct).ConfigureAwait(false);
        if (requireConsumer ? consumers.Count != 1 || consumers[0].ID != _id : consumers.Count != 0) { throw DualTargetNativeProofPreimage.Invalid(); }
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

    internal static string LabelHash(IDictionary<string, string> labels)
    {
        return Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(labels.OrderBy(x => x.Key, StringComparer.Ordinal).ToArray())));
    }

    private async Task RecordTargetAsync(CancellationToken ct)
    {
        var actual = await _docker.Containers.InspectContainerAsync(ContainerId, ct).ConfigureAwait(false);
        RequireContainer(actual);
        var config = actual.Config ?? throw DualTargetNativeProofPreimage.Invalid();
        var state = actual.State ?? throw DualTargetNativeProofPreimage.Invalid();
        string[] pgData = (config.Env ?? throw DualTargetNativeProofPreimage.Invalid()).Where(x => x.StartsWith("PGDATA=", StringComparison.Ordinal)).ToArray();
        if (pgData.Length != 1 || pgData[0] != "PGDATA=/var/lib/postgresql/18/docker") { throw DualTargetNativeProofPreimage.Invalid(); }
        await RecordAsync("target", new
        {
            actual.ID,
            actual.Name,
            actual.Image,
            Created = JsonSerializer.SerializeToElement(actual).GetProperty("Created"),
            Config = new { config.Image, config.Labels, PgData = pgData[0][7..] },
            State = new { state.Running, StartedAt = JsonSerializer.SerializeToElement(state).GetProperty("StartedAt") },
            actual.Mounts,
            (actual.NetworkSettings ?? throw DualTargetNativeProofPreimage.Invalid()).Ports
        }, ct).ConfigureAwait(false);
    }

    internal async Task RequireOwnedAsync(CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); Token.ThrowIfCancellationRequested();
        if (DateTimeOffset.UtcNow >= ExpiresAtUtc) { throw DualTargetNativeProofPreimage.Invalid(); }
        RequireContainer(await _docker.Containers.InspectContainerAsync(ContainerId, ct).ConfigureAwait(false));
        await RequireVolumeAsync(requireConsumer: true, ct).ConfigureAwait(false);
        var image = await _docker.Images.InspectImageAsync(Image, ct).ConfigureAwait(false);
        var container = await _docker.Containers.InspectContainerAsync(ContainerId, ct).ConfigureAwait(false);
        if (image.ID != container.Image || !(image.RepoDigests ?? throw DualTargetNativeProofPreimage.Invalid()).Any(x => x.EndsWith(Image[Image.IndexOf('@')..], StringComparison.Ordinal)))
        { throw DualTargetNativeProofPreimage.Invalid(); }
        await using var connection = new NpgsqlConnection(Connection); await connection.OpenAsync(ct).ConfigureAwait(false);
        if (await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, null,
            "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", ct).ConfigureAwait(false) != _systemSha256)
        { throw DualTargetNativeProofPreimage.Invalid(); }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true;
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(55)); bool removed = false, sdkDisposed = false, verifiedAbsence = false; DateTimeOffset? removedAtUtc = null;
        Exception? primary = null;
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
                    if ((actual.State ?? throw DualTargetNativeProofPreimage.Invalid()).Running)
                    {
                        await using (var connection = new NpgsqlConnection(Connection))
                        {
                            await connection.OpenAsync(cleanup.Token).ConfigureAwait(false);
                            if (_systemSha256 is not null && await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, null,
                                "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", cleanup.Token).ConfigureAwait(false) != _systemSha256)
                            { throw DualTargetNativeProofPreimage.Invalid(); }
                            if (await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, null,
                                "SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid();", cleanup.Token).ConfigureAwait(false) != "0")
                            { throw DualTargetNativeProofPreimage.Invalid(); }
                        }
                        if (System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Any(x =>
                            (x.LocalEndPoint.Port == _port || x.RemoteEndPoint.Port == _port) && x.State == System.Net.NetworkInformation.TcpState.Established))
                        { throw DualTargetNativeProofPreimage.Invalid(); }
                        _ = await _docker.Containers.StopContainerAsync(_id, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, cleanup.Token).ConfigureAwait(false);
                    }
                    actual = await _docker.Containers.InspectContainerAsync(_id, cleanup.Token).ConfigureAwait(false); RequireContainer(actual, requireRunningTransport: false);
                    if ((actual.State ?? throw DualTargetNativeProofPreimage.Invalid()).Running) { throw DualTargetNativeProofPreimage.Invalid(); }
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
                if (!absent) { throw DualTargetNativeProofPreimage.Invalid(); }
            }
            removed = true; removedAtUtc = DateTimeOffset.UtcNow;
            // No original source credential is retained in the clone root.
            await _container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); sdkDisposed = true;
            var containers = await _docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, cleanup.Token).ConfigureAwait(false);
            var volumes = await _docker.Volumes.ListAsync(cleanup.Token).ConfigureAwait(false);
            string[] ids = [.. containers.Select(x => x.ID).Order(StringComparer.Ordinal)], names = [.. containers.SelectMany(x => x.Names).Order(StringComparer.Ordinal)],
                volumeNames = [.. (volumes.Volumes ?? throw DualTargetNativeProofPreimage.Invalid()).Select(x => x.Name).Order(StringComparer.Ordinal)];
            int[] ports = [.. System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().Order()];
            if ((_id is not null && ids.Contains(_id, StringComparer.Ordinal)) || names.Contains("/" + Name, StringComparer.Ordinal) ||
                volumeNames.Contains(Name, StringComparer.Ordinal) || (_port > 0 && ports.Contains(_port))) { throw DualTargetNativeProofPreimage.Invalid(); }
            await RecordAsync("absent", new
            {
                Operation,
                _id,
                volume = Name,
                removedAtUtc,
                observedAtUtc = DateTimeOffset.UtcNow,
                containerIds = ids,
                containerNames = names,
                volumeNames,
                listeningPorts = ports
            }, cleanup.Token).ConfigureAwait(false);
            verifiedAbsence = true;
        }
        catch (Exception failure) { primary = failure; }
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
                    expiresAtUtc = ExpiresAtUtc,
                    completedAtUtc = DateTimeOffset.UtcNow
                }, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ledgerFailure) { if (primary is null) { primary = ledgerFailure; } else { primary.Data["DualProofCloneCleanupLedger"] = ledgerFailure; } }
            finally { _lease.Dispose(); _docker.Dispose(); }
        }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
    }

    private async Task RequireContainerAbsentAsync(string name, CancellationToken ct)
    {
        bool absent = false;
        try { _ = await _docker.Containers.InspectContainerAsync(name, ct).ConfigureAwait(false); }
        catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { absent = true; }
        if (!absent) { throw DualTargetNativeProofPreimage.Invalid(); }
    }
}
