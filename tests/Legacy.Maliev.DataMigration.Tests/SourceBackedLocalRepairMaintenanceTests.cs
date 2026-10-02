using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Diagnostics;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Volumes;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ProvisionedOperatorComponentFactAttribute : FactAttribute
{
    public ProvisionedOperatorComponentFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("LEGACY_SOURCE_REPAIR_OPERATOR_COMPONENT_SCRIPT")))
        { Skip = "Requires the independently reviewed off-repository Windows operator provisioning component."; }
    }
}

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class SourceBackedLocalRepairMaintenanceTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "repair-maintenance-" + Guid.NewGuid().ToString("N"));
    private static readonly DateTimeOffset Now = new(2026, 10, 2, 0, 0, 0, TimeSpan.Zero);
    private static readonly HistoricalCurrentLocalObservation Identity = new(new string('a', 64),
        "docker:" + new string('a', 64) + ":1:2:3", "legacy-maliev-exact23-postgres-data", Now,
        "/var/lib/docker/volumes/test/_data", "/var/lib/postgresql", "/var/lib/postgresql/18/docker", new string('b', 64));
    private const string Role = "legacy_repair_operator_0123456789abcdef0123456789abcdef";

    [WindowsLocalRunTheory]
    [InlineData("legacy_local")]
    [InlineData("postgres")]
    [InlineData("legacy_repair_operator_0123456789abcdef0123456789abcdeF")]
    public void ProvisioningPins_OrdinaryOrMalformedRole_RejectsBeforeConnecting(string role)
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(_root);
        SourceBackedLocalRepairMaintenancePins pins = Pins(authority) with { OperatorRole = role };
        DeltaExecutionException failure = Assert.Throws<DeltaExecutionException>(() =>
            new SourceBackedLocalRepairMaintenance(Connection(role), pins, _ => Task.FromResult(Identity), TimeProvider.System, authority));
        Assert.Equal("delta_source_repair_maintenance_invalid", failure.Code);
    }

    [WindowsLocalRunFact]
    public void ProtectedEndpoint_SameSystemIdentifierDifferentPortOrRole_Rejects()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(_root);
        var provider = Provider(authority);
        provider.RequireConnection(Connection(Role));
        string wrongPort = new NpgsqlConnectionStringBuilder(Connection(Role)) { Port = 5441 }.ConnectionString;
        _ = Assert.Throws<DeltaExecutionException>(() => provider.RequireConnection(wrongPort));
        _ = Assert.Throws<DeltaExecutionException>(() => provider.RequireConnection(Connection("postgres")));
        Assert.False(SourceBackedLocalRepairMaintenance.AuthorizesExecution);
    }

    [WindowsLocalRunFact]
    public void DisposedCoordinator_RejectsEvenWhenProvisioningPinsRemainUnchanged()
    {
        WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(_root);
        var provider = Provider(authority);
        authority.Dispose();
        _ = Assert.Throws<ObjectDisposedException>(() => provider.RequireConnection(Connection(Role)));
    }

    [WindowsLocalRunFact]
    public async Task CancelledAcquire_DoesNotInvokeDockerOrObservation()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(_root);
        int observations = 0;
        var provider = new SourceBackedLocalRepairMaintenance(Connection(Role), Pins(authority), _ =>
        { observations++; return Task.FromResult(Identity); }, TimeProvider.System, authority);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provider.AcquireAsync(Identity, cancellation.Token));
        Assert.Equal(0, observations);
    }

    [WindowsLocalRunFact]
    public void RoleExpiry_OverFourHoursAndDifferentHeldRoot_Rejects()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(_root);
        SourceBackedLocalRepairMaintenancePins maximum = Pins(authority) with { RoleExpiresAtUtc = Now.AddHours(4) };
        _ = new SourceBackedLocalRepairMaintenance(Connection(Role), maximum,
            _ => Task.FromResult(Identity), TimeProvider.System, authority);
        SourceBackedLocalRepairMaintenancePins tooLong = maximum with { RoleExpiresAtUtc = Now.AddHours(4).AddTicks(10) };
        _ = Assert.Throws<DeltaExecutionException>(() => new SourceBackedLocalRepairMaintenance(Connection(Role),
            tooLong, _ => Task.FromResult(Identity), TimeProvider.System, authority));
        SourceBackedLocalRepairMaintenancePins wrongLock = Pins(authority) with { LocalExecutionBindingSha256 = new string('e', 64) };
        _ = Assert.Throws<DeltaExecutionException>(() => new SourceBackedLocalRepairMaintenance(Connection(Role),
            wrongLock, _ => Task.FromResult(Identity), TimeProvider.System, authority));
    }

    [WindowsLocalRunFact]
    public async Task RoleExpiry_AtFourHourBoundary_RejectsBeforeObservation()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(_root);
        int observations = 0;
        SourceBackedLocalRepairMaintenancePins pins = Pins(authority) with { RoleExpiresAtUtc = Now.AddHours(4) };
        var provider = new SourceBackedLocalRepairMaintenance(Connection(Role), pins,
            _ => { observations++; return Task.FromResult(Identity); }, new FixedClock(pins.RoleExpiresAtUtc), authority);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => provider.AcquireAsync(Identity, CancellationToken.None));
        Assert.Equal(0, observations);
    }

    [WindowsLocalRunFact]
    public void MissingInstalledPolicyLifecycle_RejectsLegacyPinsBeforeConnecting()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(_root);
        foreach (SourceBackedLocalRepairMaintenancePins pins in new[]
        {
            Pins(authority) with { PostmasterStartedAtUtc = default },
            Pins(authority) with { HbaFileStateSha256 = null },
            Pins(authority) with { PostmasterStartedAtUtc = Now.ToOffset(TimeSpan.FromHours(1)) },
        })
        {
            _ = Assert.Throws<DeltaExecutionException>(() => new SourceBackedLocalRepairMaintenance(
                Connection(Role), pins, _ => Task.FromResult(Identity), TimeProvider.System, authority));
        }
    }

    [WindowsLocalRunFact]
    public async Task NativeRestrictedOperator_ValidatesActualDockerHbaRoleAndRejectsDriftWithoutOpeningApplications()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        CancellationToken token = timeout.Token;
        string volumeName = "repair-maintenance-test-" + Guid.NewGuid().ToString("N");
        await using IVolume volume = new VolumeBuilder().WithName(volumeName).Build();
        await volume.CreateAsync(token);
        await using var container = new PostgreSqlBuilder("postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382")
            .WithVolumeMount(volume, "/var/lib/postgresql", AccessMode.ReadWrite)
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384 * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500000000;
                foreach (IList<Docker.DotNet.Models.PortBinding> bindings in parameters.HostConfig!.PortBindings!.Values)
                    foreach (Docker.DotNet.Models.PortBinding binding in bindings) { binding.HostIP = "127.0.0.1"; }
            }).Build();
        await container.StartAsync(token);
        string adminString = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        { Host = "127.0.0.1", Database = "postgres", Pooling = false }.ConnectionString;
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        DateTimeOffset issued = DateTimeOffset.UtcNow;
        DateTimeOffset expiry = issued.AddMinutes(55);
        expiry = new(expiry.Ticks - expiry.Ticks % 10, TimeSpan.Zero);
        string pgData, clientAddress, system;
        DateTimeOffset postmasterStarted;
        await using (var admin = new NpgsqlConnection(adminString))
        {
            await admin.OpenAsync(token);
            foreach (string database in DatabaseInventory.ActiveDatabases)
            {
                await using var create = new NpgsqlCommand("CREATE DATABASE " + PostgreSqlShadowTarget.QuoteIdentifier(database), admin);
                _ = await create.ExecuteNonQueryAsync(token);
            }
            await using (var sentinel = new NpgsqlCommand("""
                CREATE TABLE public.maintenance_restart_sentinel
                    (id bigint GENERATED ALWAYS AS IDENTITY (CACHE 9),value text NOT NULL);
                INSERT INTO public.maintenance_restart_sentinel(value) VALUES ('synthetic ไทย');
                SELECT setval(pg_get_serial_sequence('public.maintenance_restart_sentinel','id'),41,true);
                """, admin))
            { _ = await sentinel.ExecuteNonQueryAsync(token); }
            await using (var role = new NpgsqlCommand($"CREATE ROLE {Role} LOGIN SUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}' VALID UNTIL '{expiry.ToString("O", CultureInfo.InvariantCulture)}';", admin))
            { _ = await role.ExecuteNonQueryAsync(token); }
            await using var identityCommand = new NpgsqlCommand("SELECT current_setting('data_directory'),host(inet_client_addr()),system_identifier::text,pg_postmaster_start_time() FROM pg_control_system();", admin);
            await using NpgsqlDataReader reader = await identityCommand.ExecuteReaderAsync(token);
            Assert.True(await reader.ReadAsync(token));
            pgData = reader.GetString(0); clientAddress = reader.GetString(1); system = reader.GetString(2);
            postmasterStarted = reader.GetFieldValue<DateTimeOffset>(3);
        }
        // Only a fresh random fixture volume is ever provisioned. It cannot satisfy the
        // fixed canonical volume claim policy or become live execution evidence.
        LocalDockerResourceState docker = await new LocalDockerResourceObserver().ObserveAsync(container.Id, token);
        DockerObservedMount mount = docker.Mounts.Single(item => item.Name == volumeName);
        DateTimeOffset volumeCreated = DateTimeOffset.Parse(mount.Volume.CreatedAt, CultureInfo.InvariantCulture);
        string generation = string.Join(':', "docker", docker.ContainerId,
            DateTimeOffset.Parse(docker.CreatedAt, CultureInfo.InvariantCulture).ToUnixTimeMilliseconds(),
            DateTimeOffset.Parse(docker.StartedAt, CultureInfo.InvariantCulture).ToUnixTimeMilliseconds(), volumeCreated.ToUnixTimeMilliseconds());
        var identity = new HistoricalCurrentLocalObservation(container.Id, generation, volumeName, volumeCreated,
            mount.Source, mount.Destination, pgData, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(system))).ToLowerInvariant());
        string databases = string.Join(',', DatabaseInventory.ActiveDatabases.Append("postgres"));
        string hba = $"host {databases} {Role} {clientAddress}/32 scram-sha-256\n" +
            $"host {databases} {Role} ::1/128 scram-sha-256\n" +
            "host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n" +
            "host replication all 0.0.0.0/0 reject\nhost replication all ::/0 reject\nlocal all all trust\n";
        await container.CopyAsync(Encoding.UTF8.GetBytes(hba), pgData + "/pg_hba.conf", 0, 0,
            UnixFileModes.UserRead | UnixFileModes.UserWrite | UnixFileModes.GroupRead | UnixFileModes.OtherRead, token);
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(_root);
        string operatorString = new NpgsqlConnectionStringBuilder(adminString) { Username = Role, Password = password }.ConnectionString;
        await using (var operatorConnection = new NpgsqlConnection(operatorString))
        {
            await operatorConnection.OpenAsync(token);
            await using var custody = new NpgsqlCommand($"COMMENT ON ROLE {Role} IS '{SourceBackedLocalRepairMaintenance.RoleCustodyComment(authority.Binding.ComputeSha256())}';", operatorConnection);
            _ = await custody.ExecuteNonQueryAsync(token);
        }
        var pins = new SourceBackedLocalRepairMaintenancePins(Role, issued, expiry,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(hba))).ToLowerInvariant(), clientAddress,
            identity, docker.Image.Id, authority.Binding.ComputeSha256())
        {
            PostmasterStartedAtUtc = postmasterStarted,
            HbaFileStateSha256 = await HbaStateHashAsync(),
        };
        var provider = new SourceBackedLocalRepairMaintenance(operatorString, pins, _ => Task.FromResult(identity), TimeProvider.System, authority);
        // Disk now describes restrictive rules, but the postmaster still has the
        // original permissive rules loaded. No foreign session remains open.
        await using (var ordinary = new NpgsqlConnection(adminString))
        {
            await ordinary.OpenAsync(token);
        }
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => provider.AcquireAsync(identity, token));
        var reload = await container.ExecAsync(["psql", "-U", "postgres", "-d", "postgres", "-Atqc", "SELECT pg_reload_conf();"], token);
        Assert.Equal(0, reload.ExitCode);
        Assert.Equal("t", reload.Stdout.Trim());
        // Reload acknowledgement does not establish the required startup lifecycle.
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => provider.AcquireAsync(identity, token));
        string originalContainerId = container.Id;
        await container.StopAsync(token);
        await container.StartAsync(token);
        Assert.Equal(originalContainerId, container.Id);
        LocalDockerResourceState restarted = await new LocalDockerResourceObserver().ObserveAsync(container.Id, token);
        Assert.Equal(docker.Image.Id, restarted.Image.Id);
        Assert.Equal(mount.Source, restarted.Mounts.Single(item => item.Name == volumeName).Source);
        int restartedPort = restarted.Ports.Single(port => port.HostAddress == "127.0.0.1" && port.ContainerPort == 5432).HostPort;
        adminString = new NpgsqlConnectionStringBuilder(adminString) { Port = restartedPort }.ConnectionString;
        operatorString = new NpgsqlConnectionStringBuilder(operatorString) { Port = restartedPort }.ConnectionString;
        identity = identity with
        {
            DockerGeneration = string.Join(':', "docker", restarted.ContainerId,
                DateTimeOffset.Parse(restarted.CreatedAt, CultureInfo.InvariantCulture).ToUnixTimeMilliseconds(),
                DateTimeOffset.Parse(restarted.StartedAt, CultureInfo.InvariantCulture).ToUnixTimeMilliseconds(),
                volumeCreated.ToUnixTimeMilliseconds()),
        };
        await using (var observed = new NpgsqlConnection(operatorString))
        {
            await observed.OpenAsync(token);
            await using var command = new NpgsqlCommand("SELECT system_identifier::text,pg_postmaster_start_time() FROM pg_control_system();", observed);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(token);
            Assert.True(await reader.ReadAsync(token));
            Assert.Equal(system, reader.GetString(0));
            postmasterStarted = reader.GetFieldValue<DateTimeOffset>(1);
        }
        await using (var observed = new NpgsqlConnection(operatorString))
        {
            await observed.OpenAsync(token);
            await using var retained = new NpgsqlCommand("""
                SELECT (SELECT count(*)=1 AND bool_and(id=1 AND value='synthetic ไทย')
                    FROM public.maintenance_restart_sentinel)
                    AND (SELECT last_value=41 AND is_called FROM public.maintenance_restart_sentinel_id_seq)
                    AND (SELECT seqcache=9 FROM pg_sequence WHERE seqrelid='public.maintenance_restart_sentinel_id_seq'::regclass);
                """, observed);
            Assert.True((bool)(await retained.ExecuteScalarAsync(token) ?? false));
        }
        pins = pins with
        {
            TargetIdentity = identity,
            PostmasterStartedAtUtc = postmasterStarted,
            HbaFileStateSha256 = await HbaStateHashAsync(),
        };
        provider = new SourceBackedLocalRepairMaintenance(operatorString, pins,
            _ => Task.FromResult(identity), TimeProvider.System, authority);
        var forgedEpoch = new SourceBackedLocalRepairMaintenance(operatorString,
            pins with { PostmasterStartedAtUtc = pins.PostmasterStartedAtUtc.AddTicks(10) },
            _ => Task.FromResult(identity), TimeProvider.System, authority);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => forgedEpoch.AcquireAsync(identity, token));
        // A copied PostgreSQL system identifier is insufficient: the exact actual
        // container must publish THIS endpoint. No connection to the other port occurs.
        var otherPort = new NpgsqlConnectionStringBuilder(operatorString);
        otherPort.Port = otherPort.Port == 65535 ? 65534 : otherPort.Port + 1;
        var wrongEndpoint = new SourceBackedLocalRepairMaintenance(otherPort.ConnectionString, pins,
            _ => Task.FromResult(identity), TimeProvider.System, authority);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => wrongEndpoint.AcquireAsync(identity, token));
        HistoricalCurrentLocalObservation wrongVolume = identity with { VolumeName = volumeName + "-absent" };
        var wrongProvider = new SourceBackedLocalRepairMaintenance(operatorString,
            pins with { TargetIdentity = wrongVolume }, _ => Task.FromResult(wrongVolume), TimeProvider.System, authority);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => wrongProvider.AcquireAsync(wrongVolume, token));
        string otherRoot = _root + "-other";
        try
        {
            using WindowsLocalRunAuthority otherAuthority = WindowsLocalRunAuthority.AcquireFresh(otherRoot);
            var otherCoordinator = new SourceBackedLocalRepairMaintenance(operatorString,
                pins with { LocalExecutionBindingSha256 = otherAuthority.Binding.ComputeSha256() },
                _ => Task.FromResult(identity), TimeProvider.System, otherAuthority);
            _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => otherCoordinator.AcquireAsync(identity, token));
        }
        finally { if (Directory.Exists(otherRoot)) { Directory.Delete(otherRoot, true); } }
        await using ISourceBackedLocalRepairMaintenanceLease lease = await provider.AcquireAsync(identity, token);
        await lease.RequireStillQuiescentAsync(identity, token);
        await using (var ordinary = new NpgsqlConnection(adminString))
        {
            PostgresException rejected = await Assert.ThrowsAsync<PostgresException>(() => ordinary.OpenAsync(token));
            Assert.Equal("28000", rejected.SqlState);
        }
        await using (var operatorConnection = new NpgsqlConnection(operatorString))
        {
            await operatorConnection.OpenAsync(token);
            await using var change = new NpgsqlCommand($"ALTER ROLE {Role} INHERIT;", operatorConnection);
            _ = await change.ExecuteNonQueryAsync(token);
        }
        DeltaExecutionException drift = await Assert.ThrowsAsync<DeltaExecutionException>(() => lease.RequireStillQuiescentAsync(identity, token));
        Assert.Equal("delta_source_repair_maintenance_invalid", drift.Code);
        await lease.DisposeAsync();
        var hbaAfter = await container.ExecAsync(["sha256sum", pgData + "/pg_hba.conf"], token);
        Assert.Equal(pins.RestrictedHbaSha256, hbaAfter.Stdout.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0]);
        Assert.DoesNotContain(password, drift.Message, StringComparison.Ordinal);
        await using (var operatorConnection = new NpgsqlConnection(operatorString))
        {
            await operatorConnection.OpenAsync(token);
            await using var restore = new NpgsqlCommand($"ALTER ROLE {Role} NOINHERIT;", operatorConnection);
            _ = await restore.ExecuteNonQueryAsync(token);
        }
        await using ISourceBackedLocalRepairMaintenanceLease restoredLease = await provider.AcquireAsync(identity, token);
        await container.CopyAsync(Encoding.UTF8.GetBytes(hba), pgData + "/pg_hba.conf", 999, 999,
            UnixFileModes.UserRead | UnixFileModes.UserWrite, token);
        var unchangedBytes = await container.ExecAsync(["sha256sum", pgData + "/pg_hba.conf"], token);
        Assert.Equal(pins.RestrictedHbaSha256, unchangedBytes.Stdout.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0]);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => restoredLease.RequireStillQuiescentAsync(identity, token));
        string rewrittenState = await HbaStateHashAsync();
        Assert.NotEqual(pins.HbaFileStateSha256, rewrittenState);
        var forgedRewrittenState = new SourceBackedLocalRepairMaintenance(operatorString,
            pins with { HbaFileStateSha256 = rewrittenState }, _ => Task.FromResult(identity), TimeProvider.System, authority);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => forgedRewrittenState.AcquireAsync(identity, token));

        async Task<string> HbaStateHashAsync()
        {
            var state = await container.ExecAsync(["env", "TZ=UTC", "LC_ALL=C", "stat",
                "--printf=" + SourceBackedLocalRepairMaintenance.HbaStatFormat, "--", pgData + "/pg_hba.conf"], token);
            Assert.Equal(0, state.ExitCode);
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(state.Stdout))).ToLowerInvariant();
        }
    }

    [ProvisionedOperatorComponentFact]
    public async Task ReviewedProvisioner_RestartsSameDisposableSystemAndMintsActualMaintenanceLease()
    {
        string script = Environment.GetEnvironmentVariable("LEGACY_SOURCE_REPAIR_OPERATOR_COMPONENT_SCRIPT")!;
        Assert.Equal("3e0ebfcf582063120a2baad43c3e551b6ab3ae7dc5a19c13251fc93f80d9f897",
            Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(script))).ToLowerInvariant());
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        CancellationToken token = timeout.Token;
        string volumeName = "repair-provision-component-" + Guid.NewGuid().ToString("N");
        await using IVolume volume = new VolumeBuilder().WithName(volumeName).Build();
        await volume.CreateAsync(token);
        await using var container = new PostgreSqlBuilder("postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382")
            .WithUsername("legacy_local").WithVolumeMount(volume, "/var/lib/postgresql", AccessMode.ReadWrite)
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384 * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500000000;
                foreach (IList<Docker.DotNet.Models.PortBinding> bindings in parameters.HostConfig.PortBindings!.Values)
                    foreach (Docker.DotNet.Models.PortBinding binding in bindings) { binding.HostIP = "127.0.0.1"; }
            }).Build();
        await container.StartAsync(token);
        string adminString = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        { Host = "127.0.0.1", Database = "postgres", Pooling = false }.ConnectionString;
        string pgData, clientAddress, system;
        await using (var admin = new NpgsqlConnection(adminString))
        {
            await admin.OpenAsync(token);
            foreach (string database in DatabaseInventory.ActiveDatabases)
            {
                await using var create = new NpgsqlCommand("CREATE DATABASE " + PostgreSqlShadowTarget.QuoteIdentifier(database), admin);
                _ = await create.ExecuteNonQueryAsync(token);
            }
            await using var observe = new NpgsqlCommand("SELECT current_setting('data_directory'),host(inet_client_addr()),system_identifier::text FROM pg_control_system();", admin);
            await using NpgsqlDataReader reader = await observe.ExecuteReaderAsync(token);
            Assert.True(await reader.ReadAsync(token));
            pgData = reader.GetString(0); clientAddress = reader.GetString(1); system = reader.GetString(2);
        }
        string closed = "host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\nhost replication all 0.0.0.0/0 reject\nhost replication all ::/0 reject\nlocal all all trust\n";
        await container.CopyAsync(Encoding.UTF8.GetBytes(closed), pgData + "/pg_hba.conf", 999, 999,
            UnixFileModes.UserRead | UnixFileModes.UserWrite, token);
        var reload = await container.ExecAsync(["psql", "-U", "legacy_local", "-d", "postgres", "-Atqc", "SELECT pg_reload_conf();"], token);
        Assert.Equal(0, reload.ExitCode);
        var observer = new LocalDockerResourceObserver();
        LocalDockerResourceState before = await observer.ObserveAsync(container.Id, token);
        DockerObservedMount mount = before.Mounts.Single(item => item.Name == volumeName);
        DateTimeOffset volumeCreated = DateTimeOffset.Parse(mount.Volume.CreatedAt, CultureInfo.InvariantCulture);
        string generation = string.Join(':', "docker", before.ContainerId,
            DateTimeOffset.Parse(before.CreatedAt, CultureInfo.InvariantCulture).ToUnixTimeMilliseconds(),
            DateTimeOffset.Parse(before.StartedAt, CultureInfo.InvariantCulture).ToUnixTimeMilliseconds(), volumeCreated.ToUnixTimeMilliseconds());
        var identity = new HistoricalCurrentLocalObservation(container.Id, generation, volumeName, volumeCreated,
            mount.Source, mount.Destination, pgData, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(system))).ToLowerInvariant());
        LocalExecutionBinding binding;
        using (WindowsLocalRunAuthority initial = WindowsLocalRunAuthority.AcquireFresh(_root))
        {
            binding = initial.Binding;
            await File.WriteAllTextAsync(Path.Combine(_root, "binding.json"), JsonSerializer.Serialize(binding), token);
            await File.WriteAllTextAsync(Path.Combine(_root, "identity.json"), JsonSerializer.Serialize(identity), token);
        }
        var start = new ProcessStartInfo("pwsh")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in new[] { "-NoProfile", "-File", script, "-RunDirectory", _root, "-BindingPath", Path.Combine(_root, "binding.json"),
            "-ExpectedHbaSha256", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(closed))).ToLowerInvariant(),
            "-ServerClientAddress", clientAddress, "-TargetIdentityPath", Path.Combine(_root, "identity.json"), "-ExpectedContainerId", container.Id, "-DisposableProof" })
        { start.ArgumentList.Add(argument); }
        using Process process = Process.Start(start)!;
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(token);
        Task<string> stderr = process.StandardError.ReadToEndAsync(token);
        await process.WaitForExitAsync(token);
        string output = await stdout;
        string error = await stderr;
        Assert.True(process.ExitCode == 0, "Reviewed operator component failed: " + error);
        Assert.Contains("local_repair_operator_provisioned_provider_verification_required", output, StringComparison.Ordinal);
        var pins = JsonSerializer.Deserialize<SourceBackedLocalRepairMaintenancePins>(await File.ReadAllTextAsync(Path.Combine(_root, "repair-maintenance-pins.json"), token))!;
        var updated = JsonSerializer.Deserialize<HistoricalCurrentLocalObservation>(await File.ReadAllTextAsync(Path.Combine(_root, "repair-operator-target-identity.json"), token))!;
        Assert.Equal(pins.TargetIdentity, updated);
        Assert.Equal(identity with { DockerGeneration = updated.DockerGeneration }, updated);
        Assert.NotEqual(identity.DockerGeneration, updated.DockerGeneration);
        Assert.Equal(identity, JsonSerializer.Deserialize<HistoricalCurrentLocalObservation>(await File.ReadAllTextAsync(Path.Combine(_root, "identity.json"), token)));
        LocalDockerResourceState after = await observer.ObserveAsync(container.Id, token);
        int actualPort = after.Ports.Single(port => port.HostAddress == "127.0.0.1" && port.ContainerPort == 5432).HostPort;
        string connection = await File.ReadAllTextAsync(Path.Combine(_root, "repair-operator-connection.txt"), token);
        Assert.Equal(actualPort, new NpgsqlConnectionStringBuilder(connection).Port);
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(_root, binding);
        var provider = new SourceBackedLocalRepairMaintenance(connection, pins, _ => Task.FromResult(updated), TimeProvider.System, authority);
        await using ISourceBackedLocalRepairMaintenanceLease lease = await provider.AcquireAsync(updated, token);
        await lease.RequireStillQuiescentAsync(updated, token);
    }

    private static SourceBackedLocalRepairMaintenance Provider(WindowsLocalRunAuthority authority)
    {
        return new(Connection(Role), Pins(authority), _ => Task.FromResult(Identity), TimeProvider.System, authority);
    }

    private static SourceBackedLocalRepairMaintenancePins Pins(WindowsLocalRunAuthority authority)
    {
        return new(Role, Now, Now.AddMinutes(55), new string('c', 64), "172.18.0.1", Identity,
            "sha256:" + new string('d', 64), authority.Binding.ComputeSha256())
        {
            PostmasterStartedAtUtc = Now,
            HbaFileStateSha256 = new string('f', 64),
        };
    }

    private static string Connection(string role)
    {
        return new NpgsqlConnectionStringBuilder
        {
            Host = "127.0.0.1",
            Port = 5440,
            Database = "postgres",
            Username = role,
            Password = "disposable-test-secret"
        }.ConnectionString;
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) { Directory.Delete(_root, true); }
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
