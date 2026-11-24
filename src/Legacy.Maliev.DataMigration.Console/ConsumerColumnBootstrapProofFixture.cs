using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;
using Testcontainers.PostgreSql;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>In-process nonserializable creation lease. Existing containers, volumes and DSNs cannot be adopted.</summary>
internal sealed partial class ConsumerColumnBootstrapProofFixture : IAsyncDisposable
{
    private readonly DockerClient _docker;
    private readonly PostgreSqlContainer _container;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly string _root;
    private readonly string _contractSha256;
    private readonly Dictionary<(string Database, ConsumerColumnBootstrapNativePhase Phase), ConsumerColumnBootstrapNativeWitness> _native = [];
    private ConsumerColumnBootstrapCleanupEvidence? _cleanup;
    private Dictionary<string, string>? _lastFleet;
    private bool _volumeCreated, _volumeCreateAttempted, _disposed;
    private string? _containerId;
    private int? _port;
    internal Guid OperationId { get; }
    internal DateTimeOffset BeganAtUtc { get; }
    internal DateTimeOffset ExpiresAtUtc { get; }
    internal ConsumerColumnBootstrapProofCohort Cohort { get; }
    internal string SourceIdentitySha256 { get; }
    internal string VolumeName => "legacy-delta-proof-" + OperationId.ToString("N");
    internal string ConnectionString => !_disposed && _containerId is not null && DateTimeOffset.UtcNow < ExpiresAtUtc
        ? new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Host = "127.0.0.1", Pooling = false, Timeout = 5 }.ConnectionString
        : throw ConsumerColumnBootstrapOperationalContract.Invalid();
    internal string ContainerId => _containerId ?? throw ConsumerColumnBootstrapOperationalContract.Invalid();
    internal string ExecutionBindingSha256 { get; }

    private ConsumerColumnBootstrapProofFixture(Guid operation, ConsumerColumnBootstrapProofCohort cohort,
        WindowsLocalRunAuthority authority, LocalExecutionBinding executionBinding, CurrentAppOwnedRepairCustody files, string contractSha256, string sourceIdentitySha256)
    {
        OperationId = operation; Cohort = cohort; _files = files; _root = authority.Binding.ArtifactRootCanonicalPath;
        ExecutionBindingSha256 = executionBinding.ComputeSha256(); BeganAtUtc = DateTimeOffset.UtcNow; ExpiresAtUtc = BeganAtUtc.AddMinutes(8);
        _contractSha256 = contractSha256;
        SourceIdentitySha256 = sourceIdentitySha256;
        _docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        _container = new PostgreSqlBuilder(cohort.ImageReference).WithDockerEndpoint("npipe://./pipe/docker_engine")
            .WithName(VolumeName).WithCleanUp(false).WithVolumeMount(VolumeName, "/var/lib/postgresql")
            .WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C")
            .WithCommand("-c", "autovacuum=off")
            .WithLabel("codex.repair.purpose", ConsumerColumnBootstrapOperationalContract.Purpose)
            .WithLabel("codex.repair.operation", operation.ToString("D"))
            .WithLabel("codex.repair.run-binding", ExecutionBindingSha256)
            .WithCreateParameterModifier(parameters =>
            {
                var host = parameters.HostConfig ?? throw ConsumerColumnBootstrapOperationalContract.Invalid();
                host.Memory = 384L * 1024 * 1024; host.MemorySwap = 384L * 1024 * 1024; host.NanoCPUs = 500000000;
                foreach (var ports in (host.PortBindings ?? throw ConsumerColumnBootstrapOperationalContract.Invalid()).Values)
                { foreach (var port in ports ?? []) { port.HostIP = "127.0.0.1"; } }
            }).Build();
    }

    internal static async Task<ConsumerColumnBootstrapProofFixture> CreateAsync(Guid operation, ConsumerColumnBootstrapProofCohort cohort,
        WindowsLocalRunAuthority authority, LocalExecutionBinding executionBinding,
        CurrentAppOwnedRepairCustody files, ConsumerColumnBootstrapSourceCapture sourceCapture,
        string independentlyExpectedSourceIdentitySha256, string acceptedCommit, CancellationToken ct)
    {
        if (operation == Guid.Empty || System.Reflection.Assembly.GetEntryAssembly() != typeof(ConsumerColumnBootstrapProofFixture).Assembly ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != acceptedCommit)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        sourceCapture.Require(acceptedCommit, independentlyExpectedSourceIdentitySha256, DateTimeOffset.UtcNow);
        cohort.Require(); authority.ValidateHeld(); files.Require(); CurrentAuthRepairCapacity.Require(admission: true);
        if (StringComparer.OrdinalIgnoreCase.Equals(authority.Binding.ArtifactRootCanonicalPath, executionBinding.ArtifactRootCanonicalPath))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        var lease = new ConsumerColumnBootstrapProofFixture(operation, cohort, authority, executionBinding, files,
            ConsumerColumnBootstrapContract.Create(sourceCapture.Plan, acceptedCommit, DateTimeOffset.UtcNow).ComputeSha256(), sourceCapture.SourceIdentitySha256);
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromMinutes(8));
            var containers = await lease._docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, deadline.Token).ConfigureAwait(false);
            var volumes = await lease._docker.Volumes.ListAsync(new VolumesListParameters(), deadline.Token).ConfigureAwait(false);
            if (containers.Any(container => container.Names.Any(name => name == lease.VolumeName || name == "/" + lease.VolumeName)) ||
                (volumes.Volumes ?? []).Any(volume => volume.Name == lease.VolumeName)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            await lease.RecordAsync("before-absence", new
            {
                operation,
                lease.BeganAtUtc,
                lease.ExpiresAtUtc,
                ContainerIds = containers.Select(container => container.ID).ToArray(),
                ContainerNames = containers.SelectMany(container => container.Names).ToArray(),
                VolumeNames = (volumes.Volumes ?? []).Select(volume => volume.Name).ToArray()
            }, deadline.Token).ConfigureAwait(false);
            lease._volumeCreateAttempted = true;
            _ = await lease._docker.Volumes.CreateAsync(new VolumesCreateParameters
            {
                Name = lease.VolumeName,
                Driver = "local",
                DriverOpts = new Dictionary<string, string>(),
                Labels = new Dictionary<string, string>
                {
                    ["codex.repair.purpose"] = ConsumerColumnBootstrapOperationalContract.Purpose,
                    ["codex.repair.operation"] = operation.ToString("D"),
                    ["codex.repair.run-binding"] = lease.ExecutionBindingSha256,
                },
            }, deadline.Token).ConfigureAwait(false);
            lease._volumeCreated = true;
            await lease._container.StartAsync(deadline.Token).ConfigureAwait(false);
            var actual = await lease._docker.Containers.InspectContainerAsync(lease.VolumeName, deadline.Token).ConfigureAwait(false);
            lease.RequireContainer(actual); lease._containerId = actual.ID; lease._port = lease._container.GetMappedPublicPort(5432);
            var disk = await lease._docker.Volumes.InspectAsync(lease.VolumeName, deadline.Token).ConfigureAwait(false); lease.RequireVolume(disk);
            await lease.RecordAsync("created", new
            {
                operation,
                ContainerId = actual.ID,
                actual.Image,
                CreatedAtUtc = DateTimeOffset.UtcNow,
                lease.VolumeName,
                Cohort = cohort,
                lease.BeganAtUtc,
                lease.ExpiresAtUtc,
                Port = lease._port,
                Binding = lease.ExecutionBindingSha256
            }, deadline.Token).ConfigureAwait(false);
            return lease;
        }
        catch (Exception primary)
        {
            try { await lease.DisposeAsync().ConfigureAwait(false); }
            catch (Exception cleanup) { throw new AggregateException("Owned bootstrap fixture creation and verified cleanup failed.", primary, cleanup); }
            throw;
        }
    }

    internal void Require(Guid operation, string binding, string containerId, string volume, string image)
    {
        if (_disposed || !_volumeCreated || DateTimeOffset.UtcNow >= ExpiresAtUtc || (operation != OperationId && FaultControl?.AcceptsOperation(operation) != true) || binding != ExecutionBindingSha256 ||
            containerId != _containerId || volume != VolumeName || image != Cohort.ImageReference) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }

    internal void RecordNative(ConsumerColumnBootstrapNativePhase phase, ConsumerColumnBootstrapPreservationObservation observation)
    {
        if (_disposed || DateTimeOffset.UtcNow >= ExpiresAtUtc || observation.ContractSha256 != _contractSha256 ||
            observation.ProviderVersion != Cohort.ServerVersion || !Enum.IsDefined(phase)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        int database = observation.LogicalDatabase == "CustomerIdentity" ? 0 : observation.LogicalDatabase == "Quotation" ? 1 : -1;
        if (database < 0 || _native.Count != (database * 3) + (int)phase - 1 ||
            !_native.TryAdd((observation.LogicalDatabase, phase), ConsumerColumnBootstrapNativeWitness.Capture(phase, observation)))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }

    internal async Task InstallMaintenanceHbaAsync(string operatorRole, CancellationToken ct)
    {
        if (_disposed || DateTimeOffset.UtcNow >= ExpiresAtUtc || _containerId is null || operatorRole.Length is < 1 or > 63 ||
            operatorRole.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '_') || operatorRole is "postgres" or "all")
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        var current = await _docker.Containers.InspectContainerAsync(_containerId, ct).ConfigureAwait(false); RequireContainer(current);
        string script = "printf '%s\\n' 'local all " + operatorRole + " scram-sha-256' 'host all " + operatorRole +
            " 0.0.0.0/0 scram-sha-256' 'host all " + operatorRole +
            " ::/0 scram-sha-256' 'local all all reject' 'host all all 0.0.0.0/0 reject' 'host all all ::/0 reject' > \"$PGDATA/pg_hba.conf\"";
        var result = await _container.ExecAsync(["sh", "-c", script], ct).ConfigureAwait(false);
        if (result.ExitCode != 0 || !string.IsNullOrEmpty(result.Stdout) || !string.IsNullOrEmpty(result.Stderr))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }

    internal void RecordFleet(IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> snapshots)
    {
        if (_disposed || !ReviewedProductionRepairInventory.MatchesKeys(DeltaTargetAuthorityKind.LocalAspire, snapshots.Select(snapshot => snapshot.Database)) ||
            snapshots.Select(snapshot => snapshot.Database).Distinct(StringComparer.Ordinal).Count() != snapshots.Count) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        _lastFleet = snapshots.ToDictionary(snapshot => snapshot.Database, snapshot => snapshot.Sha256, StringComparer.Ordinal);
    }

    internal (ConsumerColumnBootstrapCleanupEvidence Cleanup, IReadOnlyList<ConsumerColumnBootstrapNativeWitness> Native, IReadOnlyDictionary<string, string> FinalFleet) ReadCompleted()
    {
        return !_disposed || FaultControl is not null || _cleanup is null || _native.Count != 6 || _lastFleet is null
            ? throw ConsumerColumnBootstrapOperationalContract.Invalid()
            : ((ConsumerColumnBootstrapCleanupEvidence Cleanup, IReadOnlyList<ConsumerColumnBootstrapNativeWitness> Native, IReadOnlyDictionary<string, string> FinalFleet))(ConsumerColumnBootstrapOperationalContract.Copy(_cleanup), _native.Values.Select(value => ConsumerColumnBootstrapOperationalContract.Copy(value)).ToArray(),
            new Dictionary<string, string>(_lastFleet, StringComparer.Ordinal));
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true; using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(55));
        bool containerAbsent = false, volumeAbsent = false; Exception? failure = null;
        ConsumerColumnBootstrapCleanupEvidence? cleanup = null;
        try
        {
            ContainerInspectResponse? actual = null;
            try { actual = await _docker.Containers.InspectContainerAsync(_containerId ?? VolumeName, deadline.Token).ConfigureAwait(false); }
            catch (DockerApiException absent) when (absent.StatusCode == HttpStatusCode.NotFound) { containerAbsent = true; }
            if (actual is not null)
            {
                RequireContainer(actual);
                if (_containerId is not null && actual.ID != _containerId) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                if (_port is not null && IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Any(connection =>
                    connection.State == TcpState.Established && IPAddress.IsLoopback(connection.RemoteEndPoint.Address) && connection.RemoteEndPoint.Port == _port))
                { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                _ = await _docker.Containers.StopContainerAsync(actual.ID, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, deadline.Token).ConfigureAwait(false);
                await _docker.Containers.RemoveContainerAsync(actual.ID, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, deadline.Token).ConfigureAwait(false);
            }
            var remaining = await _docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, deadline.Token).ConfigureAwait(false);
            containerAbsent = !remaining.Any(container => container.ID == _containerId || container.Names.Any(name => name == VolumeName || name == "/" + VolumeName));
            if (!containerAbsent) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            if (_volumeCreateAttempted)
            {
                VolumeResponse? disk = null;
                try { disk = await _docker.Volumes.InspectAsync(VolumeName, deadline.Token).ConfigureAwait(false); }
                catch (DockerApiException absent) when (absent.StatusCode == HttpStatusCode.NotFound) { }
                if (disk is not null)
                {
                    RequireVolume(disk);
                    if (remaining.Any(container => container.Mounts?.Any(mount => mount.Name == VolumeName) == true)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                    await _docker.Volumes.RemoveAsync(VolumeName, force: false, deadline.Token).ConfigureAwait(false);
                }
            }
            var disks = await _docker.Volumes.ListAsync(new VolumesListParameters(), deadline.Token).ConfigureAwait(false);
            volumeAbsent = !(disks.Volumes ?? []).Any(volume => volume.Name == VolumeName);
            if (!volumeAbsent || (_port is not null && IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(endpoint => endpoint.Port == _port)))
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            await _container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), deadline.Token).ConfigureAwait(false);
            if (_containerId is not null && _port is not null)
            {
                var finalContainers = await _docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, deadline.Token).ConfigureAwait(false);
                var finalVolumes = await _docker.Volumes.ListAsync(new VolumesListParameters(), deadline.Token).ConfigureAwait(false);
                int[] listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Where(endpoint => IPAddress.IsLoopback(endpoint.Address)).Select(endpoint => endpoint.Port).Distinct().Order().ToArray();
                if (finalContainers.Any(container => container.ID == _containerId || container.Names.Any(name => name == VolumeName || name == "/" + VolumeName)) ||
                    (finalVolumes.Volumes ?? []).Any(volume => volume.Name == VolumeName) || listeners.Contains(_port.Value))
                { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                cleanup = new(OperationId, _containerId, VolumeName, _port.Value, DateTimeOffset.UtcNow,
                    finalContainers.Select(container => container.ID).ToArray(), finalContainers.SelectMany(container => container.Names).ToArray(),
                    (finalVolumes.Volumes ?? []).Select(volume => volume.Name).ToArray(), listeners);
            }
        }
        catch (Exception error) { failure = error; }
        finally
        {
            try
            {
                using var retention = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await RecordAsync("cleanup", new
                {
                    OperationId,
                    ContainerId = _containerId,
                    VolumeName,
                    containerAbsent,
                    volumeAbsent,
                    CleanupFailure = failure?.GetType().Name,
                    CompletedAtUtc = DateTimeOffset.UtcNow,
                    ActualAbsence = cleanup
                }, retention.Token).ConfigureAwait(false);
            }
            finally { _docker.Dispose(); }
        }
        if (failure is not null) { throw new MigrationExecutionException("consumer_bootstrap_fixture_cleanup_failed", "Verified owned fixture cleanup failed; proof cannot be published.", failure); }
        _cleanup = cleanup;
    }

    private void RequireContainer(ContainerInspectResponse container)
    {
        DateTimeOffset created = JsonSerializer.SerializeToElement(container).GetProperty("Created").GetDateTimeOffset();
        if (container.Config is null || container.HostConfig is null || container.ID is not { Length: 64 } || container.Name != "/" + VolumeName || container.Config.Image != Cohort.ImageReference ||
            created < BeganAtUtc.AddSeconds(-1) || created > ExpiresAtUtc ||
            !Labels(container.Config.Labels) || container.HostConfig.Memory != 384L * 1024 * 1024 || container.HostConfig.MemorySwap != 384L * 1024 * 1024 ||
            container.HostConfig.NanoCPUs != 500000000 || container.HostConfig.Privileged || container.HostConfig.Binds is { Count: > 0 } ||
            container.HostConfig.VolumesFrom is { Count: > 0 } || container.Mounts is not { Count: 1 } ||
            container.Mounts[0].Type != "volume" || container.Mounts[0].Name != VolumeName || container.Mounts[0].Destination != "/var/lib/postgresql" || !container.Mounts[0].RW)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }

    private void RequireVolume(VolumeResponse volume)
    {
        DateTimeOffset created = JsonSerializer.SerializeToElement(volume).GetProperty("CreatedAt").GetDateTimeOffset();
        if (volume.Name != VolumeName || volume.Driver != "local" || volume.Scope != "local" || volume.Options is { Count: > 0 } || !Labels(volume.Labels))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        if (created < BeganAtUtc.AddSeconds(-1) || created > ExpiresAtUtc) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }

    private bool Labels(IDictionary<string, string>? labels)
    {
        return labels is not null &&
        labels.TryGetValue("codex.repair.purpose", out string? purpose) && purpose == ConsumerColumnBootstrapOperationalContract.Purpose &&
        labels.TryGetValue("codex.repair.operation", out string? operation) && operation == OperationId.ToString("D") &&
        labels.TryGetValue("codex.repair.run-binding", out string? binding) && binding == ExecutionBindingSha256;
    }

    private async Task RecordAsync<T>(string phase, T value, CancellationToken ct)
    {
        string path = Path.Combine(_root, $"consumer-bootstrap-{OperationId:N}-fixture-{phase}.json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        await _files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
        if (!_files.Read(path, sharedReader: true, maximumBytes: 4 * 1024 * 1024).AsSpan().SequenceEqual(bytes))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }
}
