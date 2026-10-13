using System.Data;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ReviewedInventoryNativeGroup
{
    public const string Name = "Reviewed inventory disposable native observation";
}

/// <summary>Observer component regressions only, never closed repair or production authority.</summary>
[Collection(ReviewedInventoryNativeGroup.Name)]
public sealed class ReviewedProductionRepairInventoryNativeTests(ITestOutputHelper output)
{
    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    private const string Purpose = "reviewed-inventory-native-observer";

    [InventoryWindowsTheory]
    [InlineData("happy")]
    [InlineData("missing-shadow")]
    [InlineData("substituted-shadow")]
    [InlineData("missing-control")]
    [InlineData("disabled-shadow")]
    [InlineData("extra-disabled")]
    [InlineData("template1-disabled")]
    public async Task Genuine_49_database_profile_is_observed_without_production_authority(string fault)
    {
        await RunOwnedAsync(fault, disk: true, async (settings, ct) =>
        {
            string[] names = [.. ReviewedProductionRepairInventory.ExportProductionNames()];
            Assert.Equal(49, names.Length);
            string shadow = names.First(x => x.StartsWith("legacy_shadow_", StringComparison.Ordinal));
            Assert.Equal(23, names.Count(x => x.StartsWith("legacy_shadow_", StringComparison.Ordinal)));
            Assert.Contains("legacy_migration_control", names);
            await using var setup = new NpgsqlConnection(settings); await setup.OpenAsync(ct);
            Assert.Equal("180004", await ScalarAsync(setup, "SHOW server_version_num;", ct));
            Assert.Equal("off", await ScalarAsync(setup, "SHOW autovacuum;", ct));
            foreach (string name in names.Where(x => x != "postgres"))
            { await ExecuteAsync(setup, "CREATE DATABASE " + Quote(name) + ";", ct); }
            string system = await ScalarAsync(setup, "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", ct);
            Assert.Equal(51L, await CountAsync(setup, ct));
            await ObserveAsync(settings, system, names, true, DeltaTargetAuthorityKind.ProductionCloudNativePg, ct);
            string? mutation = fault switch
            {
                "happy" => null,
                "missing-shadow" => "DROP DATABASE " + Quote(shadow) + ";",
                "substituted-shadow" => "ALTER DATABASE " + Quote(shadow) + " RENAME TO inventory_substituted_shadow;",
                "missing-control" => "DROP DATABASE legacy_migration_control;",
                "disabled-shadow" => "ALTER DATABASE " + Quote(shadow) + " ALLOW_CONNECTIONS false;",
                "extra-disabled" => "CREATE DATABASE inventory_unreviewed ALLOW_CONNECTIONS false;",
                "template1-disabled" => "ALTER DATABASE template1 ALLOW_CONNECTIONS false;",
                _ => throw new InvalidOperationException("Unknown production inventory case.")
            };
            if (mutation is null) { await ObserveAsync(settings, system, names, true, DeltaTargetAuthorityKind.ProductionCloudNativePg, ct); }
            else
            {
                await ExecuteAsync(setup, mutation, ct);
                MigrationExecutionException rejected = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                    ObserveAsync(settings, system, names, true, DeltaTargetAuthorityKind.ProductionCloudNativePg, ct));
                Assert.Equal("reviewed_production_inventory_mismatch", rejected.Code);
            }
        });
    }

    [InventoryWindowsTheory]
    [InlineData("happy")]
    [InlineData("extra-disabled")]
    [InlineData("missing")]
    [InlineData("renamed")]
    [InlineData("disabled-required")]
    [InlineData("non-template-became-template")]
    [InlineData("template0-connectable")]
    [InlineData("template1-disabled")]
    [InlineData("wrong-system")]
    [InlineData("nonreadonly")]
    public async Task Actual_catalog_observer_rejects_changed_inventory_in_a_fresh_transaction(string fault)
    {
        await RunOwnedAsync(fault, disk: false, async (settings, ct) =>
        {
            string[] names = [.. DatabaseInventory.ActiveDatabases, "Auth", "postgres", "legacy_local"];
            Assert.Equal(26, names.Length);
            await using var setup = new NpgsqlConnection(settings);
            await setup.OpenAsync(ct);
            Assert.Equal("180004", await ScalarAsync(setup, "SHOW server_version_num;", ct));
            Assert.Equal("off", await ScalarAsync(setup, "SHOW autovacuum;", ct));
            foreach (string name in names.Where(x => x != "postgres"))
            {
                await ExecuteAsync(setup, "CREATE DATABASE " + Quote(name) + ";", ct);
            }
            string system = await ScalarAsync(setup,
                "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", ct);
            Assert.Equal(28L, await CountAsync(setup, ct));

            // First observation completes and its transaction/connection are disposed before mutation.
            await ObserveAsync(settings, system, names, true, DeltaTargetAuthorityKind.LocalAspire, ct);
            switch (fault)
            {
                case "happy": break;
                case "extra-disabled":
                    await ExecuteAsync(setup, "CREATE DATABASE inventory_unreviewed ALLOW_CONNECTIONS false;", ct); break;
                case "missing": await ExecuteAsync(setup, "DROP DATABASE \"legacy_local\";", ct); break;
                case "renamed": await ExecuteAsync(setup, "ALTER DATABASE \"legacy_local\" RENAME TO inventory_renamed;", ct); break;
                case "disabled-required": await ExecuteAsync(setup, "ALTER DATABASE \"Auth\" ALLOW_CONNECTIONS false;", ct); break;
                case "non-template-became-template": await ExecuteAsync(setup, "ALTER DATABASE \"Auth\" IS_TEMPLATE true;", ct); break;
                case "template0-connectable": await ExecuteAsync(setup, "ALTER DATABASE template0 ALLOW_CONNECTIONS true;", ct); break;
                case "template1-disabled": await ExecuteAsync(setup, "ALTER DATABASE template1 ALLOW_CONNECTIONS false;", ct); break;
                case "wrong-system": system = system[0] == '0' ? "1" + system[1..] : "0" + system[1..]; break;
                case "nonreadonly": break;
                default: throw new InvalidOperationException("Unknown native inventory case.");
            }
            if (fault == "happy")
            {
                await ObserveAsync(settings, system, names, true, DeltaTargetAuthorityKind.LocalAspire, ct);
            }
            else
            {
                MigrationExecutionException rejected = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                    ObserveAsync(settings, system, names, fault != "nonreadonly", DeltaTargetAuthorityKind.LocalAspire, ct));
                Assert.Equal(fault is "wrong-system" or "nonreadonly"
                    ? "reviewed_inventory_observation_unbound" : "reviewed_production_inventory_mismatch", rejected.Code);
            }
        });
    }

    private static async Task ObserveAsync(string settings, string system, string[] names, bool readOnly, string kind, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(settings);
        await connection.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using (var command = new NpgsqlCommand(readOnly ? "SET TRANSACTION READ ONLY;" : "SET TRANSACTION READ WRITE;", connection, transaction))
        { _ = await command.ExecuteNonQueryAsync(ct); }
        await ReviewedProductionRepairInventoryObservation.RequireAsync(connection, transaction,
            kind, system, names, ct);
        await transaction.RollbackAsync(ct);
    }

    private async Task RunOwnedAsync(string caseId, bool disk, Func<string, CancellationToken, Task> body)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows owned native fixture required."); }
        Guid run = Guid.NewGuid(); DateTimeOffset began = DateTimeOffset.UtcNow, expires = began.AddMinutes(8);
        string name = "reviewed-inventory-" + run.ToString("N");
        string? ledgerParent = Environment.GetEnvironmentVariable("MALIEV_REVIEWED_INVENTORY_NATIVE_LEDGER");
        if (string.IsNullOrWhiteSpace(ledgerParent) || !Path.IsPathFullyQualified(ledgerParent))
        { throw new InvalidOperationException("Existing owner-protected native ledger directory required before startup."); }
        SecureSnapshotFileCreation.ValidateRestrictedDirectory(ledgerParent);
        string root = Path.Combine(ledgerParent, run.ToString("N"));
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root);
        using var authority = WindowsLocalRunAuthority.AcquireFresh(root);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        string bindingSha = authority.Binding.ComputeSha256();
        await Ledger("attempt", new { run, name, caseId, began, expires, bindingSha, binding = authority.Binding, persistent = false });
        using var lifetime = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        using DockerClient docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        string volume = name + "-data";
        DateTimeOffset volumeStart = default, volumeEnd = default; string? volumeCreated = null;
        bool volumeAttempted = false, volumeRemoved = !disk;
        PostgreSqlBuilder builder = new PostgreSqlBuilder(Image).WithDockerEndpoint("npipe://./pipe/docker_engine")
            .WithDatabase("postgres").WithUsername("postgres").WithPassword(Guid.NewGuid().ToString("N"))
            .WithName(name).WithCleanUp(false).WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C")
            .WithCommand("-c", "autovacuum=off")
            .WithLabel("codex.repair.purpose", Purpose).WithLabel("codex.repair.operation", run.ToString("D")).WithLabel("codex.repair.run-binding", bindingSha)
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 512 * 1024 * 1024; parameters.HostConfig.MemorySwap = 512 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 750000000;
                if (disk) { parameters.HostConfig.Binds = [volume + ":/var/lib/postgresql:rw"]; }
                else { parameters.HostConfig.Tmpfs = new Dictionary<string, string> { ["/var/lib/postgresql"] = "rw,nosuid,size=384m" }; }
                foreach (IList<PortBinding> bindings in parameters.HostConfig.PortBindings!.Values)
                { foreach (PortBinding binding in bindings) { binding.HostIP = "127.0.0.1"; } }
            });
        PostgreSqlContainer container = builder.Build();
        string? ownedId = null; bool removed = false, disposed = false;
        Task? disposalTask = null;
        using Process owningHost = Process.GetCurrentProcess();
        int owningHostPid = owningHost.Id;
        DateTime owningHostStartUtc = owningHost.StartTime.ToUniversalTime();
        string owningHostImage = Environment.ProcessPath ?? throw new InvalidOperationException("Owning test host image unavailable.");
        try
        {
            if (disk)
            {
                var inventory = await docker.Volumes.ListAsync(lifetime.Token);
                if ((inventory.Volumes ?? throw new InvalidOperationException("Volume inventory unavailable.")).Any(x => x.Name == volume))
                { throw new InvalidOperationException("Disposable volume preexists."); }
                volumeStart = DateTimeOffset.UtcNow;
                await Ledger("volume-attempt", new { run, volume, volumeStart, expires, absent = true }); volumeAttempted = true;
                try
                {
                    _ = await docker.Volumes.CreateAsync(new VolumesCreateParameters
                    { Name = volume, Driver = "local", Labels = new Dictionary<string, string>
                        { ["codex.repair.purpose"] = Purpose, ["codex.repair.operation"] = run.ToString("D"), ["codex.repair.run-binding"] = bindingSha } }, lifetime.Token);
                }
                finally { volumeEnd = DateTimeOffset.UtcNow; }
                await RequireVolumeAsync(false, lifetime.Token);
            }
            bool absent = false;
            try { _ = await docker.Containers.InspectContainerAsync(name, lifetime.Token); }
            catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound) { absent = true; }
            if (!absent) { throw new InvalidOperationException("Disposable container name preexists."); }
            await container.StartAsync(lifetime.Token);
            ContainerInspectResponse metadata = await docker.Containers.InspectContainerAsync(name, lifetime.Token);
            RequireOwnership(metadata); ownedId = metadata.ID;
            if (disk) { await RequireVolumeAsync(true, lifetime.Token); }
            await Ledger("observed", new { run, name, containerId = ownedId, port = container.GetMappedPublicPort(5432), persistent = false });
            using var capacityDeadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            capacityDeadline.CancelAfter(TimeSpan.FromSeconds(5));
            var capacity = await container.ExecAsync(["df", "-B1", "/var/lib/postgresql"], capacityDeadline.Token);
            string[] lines = capacity.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            string[] cells = lines.Length == 2 ? lines[1].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries) : [];
            if (capacity.ExitCode != 0 || !string.IsNullOrEmpty(capacity.Stderr) || cells.Length != 6 ||
                !long.TryParse(cells[1], out long bytes) || !long.TryParse(cells[3], out long available) ||
                (disk ? cells[0] == "tmpfs" || available < 1024L * 1024 * 1024 : cells[0] != "tmpfs" || bytes != 384L * 1024 * 1024))
            { throw new InvalidOperationException("Actual disposable filesystem capacity mismatch."); }
            await Ledger("filesystem-capacity", new { run, containerId = ownedId, disk, capacityBytes = bytes, availableBytes = available });
            string settings = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
            { Host = "127.0.0.1", Pooling = false, Timeout = 10, CommandTimeout = 30, SslMode = SslMode.Disable }.ConnectionString;
            await body(settings, lifetime.Token);
        }
        finally { await CompleteCleanupAsync(); }

        async Task CompleteCleanupAsync()
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            try
            {
                ContainerInspectResponse metadata = await docker.Containers.InspectContainerAsync(ownedId ?? name, cleanup.Token);
                RequireOwnership(metadata); ownedId ??= metadata.ID;
                if (ownedId != metadata.ID) { throw new InvalidOperationException("Owned container identity changed."); }
                _ = await docker.Containers.StopContainerAsync(ownedId, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, cleanup.Token);
                metadata = await docker.Containers.InspectContainerAsync(ownedId, cleanup.Token); RequireOwnership(metadata);
                if ((metadata.State ?? throw new InvalidOperationException("Owned container state missing.")).Running) { throw new InvalidOperationException("Owned container did not stop."); }
                if (disk) { await RequireVolumeAsync(true, cleanup.Token); }
                await docker.Containers.RemoveContainerAsync(ownedId, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, cleanup.Token);
                try { _ = await docker.Containers.InspectContainerAsync(ownedId, cleanup.Token); }
                catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound) { removed = true; }
                if (!removed) { throw new InvalidOperationException("Owned container removal not verified."); }
            }
            catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound && ownedId is null) { removed = true; }
            finally { await CompleteVolumeAndDisposeAsync(cleanup.Token); }
        }

        async Task CompleteVolumeAndDisposeAsync(CancellationToken ct)
        {
            try
            {
                if (removed && disk && volumeAttempted)
                {
                    bool present = true;
                    try { await RequireVolumeAsync(false, ct); }
                    catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound) { present = false; }
                    if (present) { await docker.Volumes.RemoveAsync(volume, force: false, ct); }
                    try { _ = await docker.Volumes.InspectAsync(volume, ct); }
                    catch (DockerApiException error) when (error.StatusCode == HttpStatusCode.NotFound) { volumeRemoved = true; }
                    if (!volumeRemoved) { throw new InvalidOperationException("Owned volume removal not verified."); }
                }
                else if (disk && !volumeAttempted) { volumeRemoved = true; }
                if (removed && volumeRemoved)
                {
                    await Ledger("sdk-disposal-start", new
                    {
                        run, containerId = ownedId, volume, removed, volumeRemoved,
                        processId = owningHostPid, processStartTimeUtc = owningHostStartUtc, executable = owningHostImage,
                        expiresAtUtc = expires, parentExactOwnedWorkerCleanupRequiredIfUnsettled = true,
                        beganAtUtc = DateTimeOffset.UtcNow
                    });
                    disposalTask = container.DisposeAsync().AsTask();
                    await disposalTask.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);
                    disposed = true;
                }
            }
            finally { await Ledger("disposed", new { run, containerId = ownedId, volume, removed, volumeRemoved, disposed, cleanupFailed = !removed || !volumeRemoved || !disposed, sdkDisposalStarted = disposalTask is not null,
                sdkDisposalSettled = disposalTask?.IsCompleted ?? false, sdkDisposalStatus = disposalTask?.Status.ToString(),
                processId = owningHostPid, processStartTimeUtc = owningHostStartUtc, executable = owningHostImage,
                parentExactOwnedWorkerCleanupRequired = disposalTask is { IsCompleted: false }, expires, completedAtUtc = DateTimeOffset.UtcNow }); }
        }

        async Task RequireVolumeAsync(bool consumer, CancellationToken ct)
        {
            var actual = await docker.Volumes.InspectAsync(volume, ct);
            if (actual.Name != volume || actual.Driver != "local" || actual.Scope != "local" || actual.Options is { Count: > 0 } ||
                actual.Labels.Count != 3 || actual.Labels["codex.repair.purpose"] != Purpose || actual.Labels["codex.repair.operation"] != run.ToString("D") || actual.Labels["codex.repair.run-binding"] != bindingSha ||
                !DateTimeOffset.TryParse(actual.CreatedAt, out var created) || volumeStart == default || created < volumeStart.AddSeconds(-1) ||
                created > volumeEnd.AddSeconds(1) || created > expires || (volumeCreated is not null && volumeCreated != actual.CreatedAt))
            { throw new InvalidOperationException("Disposable volume ownership mismatch."); }
            var consumers = await docker.Containers.ListContainersAsync(new ContainersListParameters
            { All = true, Filters = new Dictionary<string, IDictionary<string, bool>> { ["volume"] = new Dictionary<string, bool> { [volume] = true } } }, ct);
            if (consumer ? consumers.Count != 1 || consumers[0].ID != ownedId : consumers.Count != 0)
            { throw new InvalidOperationException("Disposable volume consumer mismatch."); }
            if (volumeCreated is null)
            {
                volumeCreated = actual.CreatedAt;
                await Ledger("volume-observed", new { run, volume, actual.CreatedAt, actual.Driver, actual.Scope, actual.Labels, volumeStart, volumeEnd, expires, persistent = false });
            }
        }

        void RequireOwnership(ContainerInspectResponse metadata)
        {
            DateTimeOffset created = JsonSerializer.SerializeToElement(metadata).GetProperty("Created").GetDateTimeOffset();
            if (metadata.Config is not { } config || metadata.HostConfig is not { } host || metadata.NetworkSettings is not { } network ||
                metadata.ID.Length != 64 || metadata.Name != "/" + name || created < began.AddSeconds(-1) || created > expires ||
                config.Image != Image || config.Labels["codex.repair.purpose"] != Purpose || config.Labels["codex.repair.operation"] != run.ToString("D") || config.Labels["codex.repair.run-binding"] != bindingSha ||
                !StorageMatches(metadata) || host.VolumesFrom is { Count: > 0 } ||
                host.Memory != 512 * 1024 * 1024 || host.MemorySwap != 512 * 1024 * 1024 || host.NanoCPUs != 750000000 ||
                network.Ports.Values.SelectMany(x => x ?? []).Any(x => x.HostIP != "127.0.0.1"))
            { throw new InvalidOperationException("Disposable container ownership mismatch."); }
        }

        bool StorageMatches(ContainerInspectResponse metadata)
        {
            if (metadata.HostConfig is not { } host || metadata.Mounts is not { } mounts) { return false; }
            if (!disk) { return mounts.Count == 0 && host.Mounts is not { Count: > 0 } && host.Binds is not { Count: > 0 } &&
                host.Tmpfs is { Count: 1 } tmpfs && tmpfs.TryGetValue("/var/lib/postgresql", out string? value) && value == "rw,nosuid,size=384m"; }
            return host.Tmpfs is not { Count: > 0 } && mounts.Count == 1 && mounts[0].Type == "volume" &&
                mounts[0].Name == volume && mounts[0].Destination == "/var/lib/postgresql" && mounts[0].RW &&
                (host.Binds is not { Count: > 0 } || host.Binds.Count == 1 && host.Binds[0] == volume + ":/var/lib/postgresql:rw") &&
                host.Mounts is not { Count: > 0 };
        }

        async Task Ledger(string phase, object record)
        {
            string path = Path.Combine(root, run.ToString("N") + "-" + phase + ".json");
            await files.WriteNewAsync(path, JsonSerializer.SerializeToUtf8Bytes(record), CancellationToken.None);
            files.Require();
            output.WriteLine("Owned inventory fixture run={0}; phase={1}; ledger={2}", run, phase, path);
        }
    }
    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, connection) { CommandTimeout = 30 }; _ = await command.ExecuteNonQueryAsync(ct); }
    private static async Task<string> ScalarAsync(NpgsqlConnection connection, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, connection) { CommandTimeout = 30 }; return (string)(await command.ExecuteScalarAsync(ct))!; }
    private static async Task<long> CountAsync(NpgsqlConnection connection, CancellationToken ct)
    { await using var command = new NpgsqlCommand("SELECT count(*) FROM pg_database;", connection) { CommandTimeout = 30 }; return (long)(await command.ExecuteScalarAsync(ct))!; }
    private static string Quote(string name) => PostgreSqlShadowTarget.QuoteIdentifier(name);
}

public sealed class InventoryWindowsTheoryAttribute : TheoryAttribute
{
    public InventoryWindowsTheoryAttribute()
    { if (!OperatingSystem.IsWindows()) { Skip = "Requires the owned Windows Docker pipe and protected native ledger."; } }
}
