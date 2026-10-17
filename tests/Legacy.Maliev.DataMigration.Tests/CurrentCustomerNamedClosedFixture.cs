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

// Fixed named disposable fixture only. It does not accept a database endpoint, arbitrary
// container image/name/mount, cleanup selector, SQL callback or persistent volume.
internal sealed class CurrentCustomerNamedClosedFixture : IAsyncDisposable
{
    internal const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    private readonly DockerClient _docker;
    private readonly PostgreSqlContainer _container;
    private readonly HashSet<string> _previousVolumes;
    private readonly DateTimeOffset _expires;
    private readonly CancellationTokenSource _lease;
    private DateTimeOffset _volumeStart, _volumeEnd, _containerStart, _containerEnd;
    private string? _id, _volumeCreated;
    private int _port;
    private bool _volumeAttempted, _containerAttempted, _disposed;
    private int _frame;
    internal Guid Operation { get; }
    internal string Root { get; }
    internal LocalExecutionBinding Binding { get; }
    internal string Name => "legacy-delta-proof-" + Operation.ToString("N");
    internal string ContainerId => _id ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
    internal string AdminConnection => new NpgsqlConnectionStringBuilder(_container.GetConnectionString())
    { Host = "127.0.0.1", Database = "postgres", Username = "postgres", Password = field, Pooling = false, SslMode = SslMode.Disable, Timeout = 5, CommandTimeout = 30, IncludeErrorDetail = false }.ConnectionString;
    internal CancellationToken Token => _lease.Token;

    private CurrentCustomerNamedClosedFixture(string root, Guid operation, LocalExecutionBinding binding,
        DockerClient docker, PostgreSqlContainer container, HashSet<string> previous, string password, DateTimeOffset began)
    {
        Root = root; Operation = operation; Binding = binding; _docker = docker; _container = container;
        _previousVolumes = previous; AdminConnection = password; _expires = began.AddMinutes(8);
        _lease = new CancellationTokenSource(_expires - DateTimeOffset.UtcNow);
    }

    internal static async Task<CurrentCustomerNamedClosedFixture> CreateAsync(string parentRoot, Guid operation, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(parentRoot) || !Directory.Exists(parentRoot)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        CurrentCustomerSequenceCapacity.Require(admission: true);
        _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        if (operation == Guid.Empty) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string root = Path.Combine(parentRoot, "customer-closed-case-" + operation.ToString("N"));
        if (Directory.Exists(root)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root); LocalExecutionBinding binding;
        using (var authority = WindowsLocalRunAuthority.AcquireFresh(root))
        {
            binding = authority.Binding;
            root = binding.ArtifactRootCanonicalPath;
            using var files = new CurrentAppOwnedRepairCustody(authority);
            await files.WriteNewAsync(Path.Combine(root, "fixture-binding.json"), JsonSerializer.SerializeToUtf8Bytes(binding), ct).ConfigureAwait(false);
        }
        DateTimeOffset began = DateTimeOffset.UtcNow;
        string name = "legacy-delta-proof-" + operation.ToString("N"), password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        using var inventoryTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        inventoryTimeout.CancelAfter(TimeSpan.FromSeconds(30));
        PostgreSqlContainer? container = null; CurrentCustomerNamedClosedFixture? fixture = null;
        try
        {
            var inventory = await docker.Volumes.ListAsync(inventoryTimeout.Token).ConfigureAwait(false);
            var previous = (inventory.Volumes ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Select(x => x.Name).ToHashSet(StringComparer.Ordinal);
            if (previous.Contains(name)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            bool absent = false;
            try { _ = await docker.Containers.InspectContainerAsync(name, inventoryTimeout.Token).ConfigureAwait(false); }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { absent = true; }
            if (!absent) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            container = new PostgreSqlBuilder(Image).WithDockerEndpoint("npipe://./pipe/docker_engine").WithName(name)
                .WithDatabase("postgres").WithUsername("postgres").WithPassword(password).WithCleanUp(false)
                .WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C").WithCommand("-c", "autovacuum=off")
                .WithVolumeMount(name, "/var/lib/postgresql", AccessMode.ReadWrite)
                .WithLabel("codex.repair.purpose", "current-customer-sequence-proof").WithLabel("codex.repair.operation", operation.ToString("D"))
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
                expires = fixture._expires,
                persistent = false,
                previousVolumes = previous.Order(StringComparer.Ordinal).ToArray()
            }, ct).ConfigureAwait(false);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, fixture.Token);
            var freshVolumes = await docker.Volumes.ListAsync(linked.Token).ConfigureAwait(false);
            if ((freshVolumes.Volumes ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Any(x => x.Name == name)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            fixture._volumeStart = DateTimeOffset.UtcNow;
            await fixture.RecordAsync("volume-creation-start", new { operation, name, absent = true, startedAtUtc = fixture._volumeStart }, linked.Token).ConfigureAwait(false);
            fixture._volumeAttempted = true;
            try
            {
                _ = await docker.Volumes.CreateAsync(new VolumesCreateParameters
                {
                    Name = name,
                    Driver = "local",
                    Labels = new Dictionary<string, string>(StringComparer.Ordinal)
                    { ["codex.repair.purpose"] = "current-customer-sequence-proof", ["codex.repair.operation"] = operation.ToString("D"), ["codex.repair.run-binding"] = binding.ComputeSha256() }
                }, linked.Token).ConfigureAwait(false);
            }
            finally { fixture._volumeEnd = DateTimeOffset.UtcNow; }
            await fixture.RecordAsync("volume-creation-end", new { operation, name, completedAtUtc = fixture._volumeEnd }, linked.Token).ConfigureAwait(false);
            await fixture.RequireVolumeAsync(requireConsumer: false, linked.Token).ConfigureAwait(false);
            absent = false;
            try { _ = await docker.Containers.InspectContainerAsync(name, linked.Token).ConfigureAwait(false); }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { absent = true; }
            if (!absent) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            fixture._containerStart = DateTimeOffset.UtcNow;
            await fixture.RecordAsync("container-creation-start", new { operation, name, absent = true, startedAtUtc = fixture._containerStart }, linked.Token).ConfigureAwait(false);
            fixture._containerAttempted = true;
            try { await container.StartAsync(linked.Token).ConfigureAwait(false); }
            finally { fixture._containerEnd = DateTimeOffset.UtcNow; }
            await fixture.RecordAsync("container-creation-end", new { operation, name, completedAtUtc = fixture._containerEnd }, linked.Token).ConfigureAwait(false);
            var actual = await docker.Containers.InspectContainerAsync(name, linked.Token).ConfigureAwait(false);
            fixture.RequireContainer(actual); fixture._id = actual.ID; fixture._port = container.GetMappedPublicPort(5432);
            await fixture.RequireVolumeAsync(requireConsumer: true, linked.Token).ConfigureAwait(false);
            await using (var connection = new NpgsqlConnection(fixture.AdminConnection))
            {
                await connection.OpenAsync(linked.Token).ConfigureAwait(false);
                await using var command = new NpgsqlCommand("SELECT current_setting('server_version_num'),current_setting('autovacuum');", connection);
                await using var reader = await command.ExecuteReaderAsync(linked.Token).ConfigureAwait(false);
                if (!await reader.ReadAsync(linked.Token).ConfigureAwait(false) || reader.GetString(0) != "180004" || reader.GetString(1) != "off" ||
                    await reader.ReadAsync(linked.Token).ConfigureAwait(false)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
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

    internal async Task RecordAsync<T>(string phase, T value, CancellationToken ct)
    {
        using var authority = WindowsLocalRunAuthority.AcquireResume(Root, Binding); using var files = new CurrentAppOwnedRepairCustody(authority);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value); if (bytes.Length > 2 * 1024 * 1024) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string path = Path.Combine(Root, $"customer-closed-resource-{Operation:N}-{Interlocked.Increment(ref _frame):D5}-{phase}.json");
        await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false); files.Require();
    }

    private void RequireContainer(ContainerInspectResponse actual, bool requireRunningTransport = true)
    {
        var host = actual.HostConfig ?? throw CurrentCustomerSequenceRepairPermit.Invalid(); var config = actual.Config ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        DateTimeOffset created = JsonSerializer.SerializeToElement(actual).GetProperty("Created").GetDateTimeOffset();
        if (actual.ID.Length != 64 || (_id is not null && _id != actual.ID) || actual.Name != "/" + Name || _containerStart == default ||
            created < _containerStart.AddSeconds(-1) || created > (_containerEnd == default ? DateTimeOffset.UtcNow : _containerEnd).AddSeconds(1) || created > _expires ||
            config.Image != Image || config.Labels["codex.repair.purpose"] != "current-customer-sequence-proof" || config.Labels["codex.repair.operation"] != Operation.ToString("D") ||
            config.Labels["codex.repair.run-binding"] != Binding.ComputeSha256() || host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750_000_000 ||
            host.Tmpfs is { Count: > 0 } || (host.Binds is { Count: > 0 } && (host.Binds.Count != 1 || host.Binds[0] != Name + ":/var/lib/postgresql:rw")) || host.VolumesFrom is { Count: > 0 } ||
            actual.Mounts.Count != 1 || actual.Mounts.Single().Type != "volume" || actual.Mounts.Single().Name != Name || actual.Mounts.Single().Destination != "/var/lib/postgresql" || !actual.Mounts.Single().RW ||
            host.PortBindings.Count != 1 || !host.PortBindings.TryGetValue("5432/tcp", out var declaredPorts) || declaredPorts.Count != 1 || declaredPorts[0].HostIP != "127.0.0.1" ||
            actual.NetworkSettings is null || actual.NetworkSettings.Ports.Values.SelectMany(x => x ?? []).Any(port => port.HostIP != "127.0.0.1") ||
            (requireRunningTransport && (actual.NetworkSettings.Ports.Count != 1 || !actual.NetworkSettings.Ports.TryGetValue("5432/tcp", out var ports) || ports.Count != 1 || ports[0].HostIP != "127.0.0.1")))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }

    private async Task RequireVolumeAsync(bool requireConsumer, CancellationToken ct)
    {
        var actual = await _docker.Volumes.InspectAsync(Name, ct).ConfigureAwait(false);
        if (_previousVolumes.Contains(Name) || actual.Name != Name || actual.Driver != "local" || actual.Scope != "local" || actual.Options is { Count: > 0 } ||
            actual.Labels.Count != 3 || actual.Labels["codex.repair.purpose"] != "current-customer-sequence-proof" || actual.Labels["codex.repair.operation"] != Operation.ToString("D") ||
            actual.Labels["codex.repair.run-binding"] != Binding.ComputeSha256() || !DateTimeOffset.TryParse(actual.CreatedAt, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out var created) || _volumeStart == default || created < _volumeStart.AddSeconds(-1) ||
            created > (_volumeEnd == default ? DateTimeOffset.UtcNow : _volumeEnd).AddSeconds(1) || created > _expires || (_volumeCreated is not null && _volumeCreated != actual.CreatedAt))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var consumers = await _docker.Containers.ListContainersAsync(new ContainersListParameters
        { All = true, Filters = new Dictionary<string, IDictionary<string, bool>> { ["volume"] = new Dictionary<string, bool> { [Name] = true } } }, ct).ConfigureAwait(false);
        if (requireConsumer ? consumers.Count != 1 || consumers[0].ID != _id : consumers.Count != 0) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
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

    private async Task RecordTargetAsync(CancellationToken ct)
    {
        string raw = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "container", ContainerId], ct,
            value => RecordAsync("docker", value, CancellationToken.None)).ConfigureAwait(false);
        JsonArray array = JsonNode.Parse(raw)!.AsArray(); JsonObject item = array.Single()!.AsObject(), config = item["Config"]!.AsObject();
        string[] pgData = config["Env"]!.AsArray().Select(x => x!.GetValue<string>()).Where(x => x.StartsWith("PGDATA=", StringComparison.Ordinal)).ToArray();
        if (pgData.Length != 1 || pgData[0] != "PGDATA=/var/lib/postgresql/18/docker") { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        _ = config.Remove("Env"); config["PgData"] = pgData[0][7..]; await RecordAsync("target", item, ct).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true;
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(55)); bool removed = false, sdkDisposed = false;
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
                    if ((actual.State ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Running) { _ = await _docker.Containers.StopContainerAsync(_id, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, cleanup.Token).ConfigureAwait(false); }
                    actual = await _docker.Containers.InspectContainerAsync(_id, cleanup.Token).ConfigureAwait(false); RequireContainer(actual, requireRunningTransport: false);
                    if ((actual.State ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Running) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
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
                if (!absent) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            removed = true; DateTimeOffset removedAtUtc = DateTimeOffset.UtcNow;
            CurrentCustomerClosedSecretCleanup.RequireRemoved(Root, Binding, Operation);
            await _container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false); sdkDisposed = true;
            var containers = await _docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, cleanup.Token).ConfigureAwait(false);
            var volumes = await _docker.Volumes.ListAsync(cleanup.Token).ConfigureAwait(false);
            string[] ids = [.. containers.Select(x => x.ID).Order(StringComparer.Ordinal)], names = [.. containers.SelectMany(x => x.Names).Order(StringComparer.Ordinal)],
                volumeNames = [.. (volumes.Volumes ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Select(x => x.Name).Order(StringComparer.Ordinal)];
            int[] ports = [.. System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().Order()];
            if ((_id is not null && ids.Contains(_id, StringComparer.Ordinal)) || names.Contains("/" + Name, StringComparer.Ordinal) ||
                volumeNames.Contains(Name, StringComparer.Ordinal) || (_port > 0 && ports.Contains(_port))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
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
                listeningPorts = ports,
                secretsAbsent = true
            }, cleanup.Token).ConfigureAwait(false);
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
                    cleanupFailed = !removed || !sdkDisposed,
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
        if (!absent) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
}
