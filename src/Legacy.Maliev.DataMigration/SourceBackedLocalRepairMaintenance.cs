using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Globalization;
using System.Text.RegularExpressions;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Owner-protected provisioning pins, established before plan/preimage observation.</summary>
internal sealed record SourceBackedLocalRepairMaintenancePins(string OperatorRole,
    DateTimeOffset RoleIssuedAtUtc, DateTimeOffset RoleExpiresAtUtc, string RestrictedHbaSha256,
    string ServerClientAddress, HistoricalCurrentLocalObservation TargetIdentity,
    string ImageId, string LocalExecutionBindingSha256)
{
    public DateTimeOffset PostmasterStartedAtUtc { get; init; }
    public string? HbaFileStateSha256 { get; init; }
}

/// <summary>
/// Verifies an already installed exact operator allowlist. Never creates roles, rewrites HBA,
/// opens application access or rotates application credentials. Docker/volume reobservation
/// and the protected operator connection are supplied only by trusted operator composition.
/// Unix-control access still requires exclusive operator ownership throughout the run.
/// </summary>
internal sealed partial class SourceBackedLocalRepairMaintenance : ISourceBackedLocalRepairMaintenance
{
    private readonly string _connectionString;
    private readonly SourceBackedLocalRepairMaintenancePins _pins;
    private readonly Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> _observe;
    private readonly TimeProvider _clock;
    private readonly WindowsLocalRunAuthority _authority;
    private readonly LocalDockerResourceObserver _docker = new();
    internal const string HbaStatFormat = "%d|%i|%f|%u|%g|%h|%s|%y|%z";

    internal SourceBackedLocalRepairMaintenance(string connectionString,
        SourceBackedLocalRepairMaintenancePins pins,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observe, TimeProvider clock,
        WindowsLocalRunAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(pins);
        ArgumentNullException.ThrowIfNull(observe);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(authority);
        var endpoint = LocalPostgreSqlResourceAuthority.Connection(connectionString);
        if (endpoint.Username != pins.OperatorRole || !RoleName(pins.OperatorRole) ||
            !Hash(pins.RestrictedHbaSha256) || !Hash(pins.LocalExecutionBindingSha256) ||
            !Hash(pins.HbaFileStateSha256 ?? string.Empty) || pins.PostmasterStartedAtUtc == default ||
            pins.PostmasterStartedAtUtc.Offset != TimeSpan.Zero || pins.PostmasterStartedAtUtc.Ticks % 10 != 0 ||
            !pins.ImageId.StartsWith("sha256:", StringComparison.Ordinal) || !Hash(pins.ImageId[7..]) ||
            pins.RoleIssuedAtUtc.Offset != TimeSpan.Zero ||
            pins.RoleExpiresAtUtc.Offset != TimeSpan.Zero || pins.RoleExpiresAtUtc <= pins.RoleIssuedAtUtc ||
            pins.RoleExpiresAtUtc - pins.RoleIssuedAtUtc > TimeSpan.FromHours(4) ||
            pins.RoleExpiresAtUtc.Ticks % 10 != 0 ||
            !IPAddress.TryParse(pins.ServerClientAddress, out IPAddress? address) ||
            address.AddressFamily != AddressFamily.InterNetwork || address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.Broadcast)) { throw Invalid(); }
        _connectionString = endpoint.ConnectionString;
        _pins = pins;
        _observe = observe;
        _clock = clock;
        _authority = authority;
        RequireOwnership();
    }

    internal static bool AuthorizesExecution => false;

    /// <summary>The sole verified endpoint; database selection is performed after admission.</summary>
    internal string ConnectionString => _connectionString;

    internal static string RoleCustodyComment(string bindingSha256)
    {
        if (!Hash(bindingSha256)) { throw Invalid(); }
        return "legacy-maliev-source-repair-operator-v1:" + bindingSha256;
    }

    internal void RequireConnection(string connectionString)
    {
        RequireOwnership();
        string canonical = LocalPostgreSqlResourceAuthority.Connection(connectionString).ConnectionString;
        if (canonical != _connectionString) { throw Invalid(); }
    }

    public async Task<ISourceBackedLocalRepairMaintenanceLease> AcquireAsync(
        HistoricalCurrentLocalObservation identity, CancellationToken cancellationToken)
    {
        await VerifyAsync(identity, cancellationToken).ConfigureAwait(false);
        return new Lease(this);
    }

    private async Task VerifyAsync(HistoricalCurrentLocalObservation identity, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequireOwnership();
        if (identity != _pins.TargetIdentity || _clock.GetUtcNow() < _pins.RoleIssuedAtUtc ||
            _clock.GetUtcNow() >= _pins.RoleExpiresAtUtc ||
            await _observe(cancellationToken).ConfigureAwait(false) != identity) { throw Invalid(); }
        await using var connection = new NpgsqlConnection(_connectionString);
        LocalDockerResourceState docker = await _docker.ObserveAsync(identity.ContainerId,
            cancellationToken, _pins.ImageId).ConfigureAwait(false);
        BackupProcessResult writers = await new ReadOnlyDockerProcess().RunAsync(
            ["--host", docker.DockerHost, "ps", "--no-trunc", "--filter", "volume=" + identity.VolumeName,
                "--format", "{{.ID}}"], cancellationToken).ConfigureAwait(false);
        if (writers.ExitCode != 0 || writers.StandardOutput.Trim() != identity.ContainerId) { throw Invalid(); }
        var endpoint = new NpgsqlConnectionStringBuilder(_connectionString);
        DockerObservedMount? mount = docker.Mounts.SingleOrDefault(item => item.Name == identity.VolumeName);
        string generation = string.Join(':', "docker", docker.ContainerId,
            DateTimeOffset.Parse(docker.CreatedAt, System.Globalization.CultureInfo.InvariantCulture).ToUnixTimeMilliseconds(),
            DateTimeOffset.Parse(docker.StartedAt, System.Globalization.CultureInfo.InvariantCulture).ToUnixTimeMilliseconds(),
            mount is null ? 0 : DateTimeOffset.Parse(mount.Volume.CreatedAt,
                System.Globalization.CultureInfo.InvariantCulture).ToUnixTimeMilliseconds());
        if (generation != identity.DockerGeneration || mount is null || !mount.ReadWrite ||
            mount.Source != identity.VolumeMountpoint || mount.Destination != identity.VolumeDestination ||
            !(identity.PgData == mount.Destination || identity.PgData.StartsWith(mount.Destination + "/", StringComparison.Ordinal)) ||
            DateTimeOffset.Parse(mount.Volume.CreatedAt, System.Globalization.CultureInfo.InvariantCulture) != identity.VolumeCreatedAtUtc ||
            docker.Ports.Count(port => port.HostAddress == "127.0.0.1" && port.HostPort == endpoint.Port && port.ContainerPort == 5432) != 1 ||
            docker.Ports.Where(port => port.ContainerPort == 5432).Any(port => port.HostAddress != "127.0.0.1")) { throw Invalid(); }
        FileSystemObjectIdentity dataDirectory = await _docker.StatAsync(docker.DockerHost, docker.ContainerId,
            identity.PgData, "directory", cancellationToken).ConfigureAwait(false);
        FileSystemObjectIdentity controlFile = await _docker.StatAsync(docker.DockerHost, docker.ContainerId,
            identity.PgData + "/global/pg_control", "regular file", cancellationToken).ConfigureAwait(false);
        if (dataDirectory.Device != mount.FileSystemIdentity.Device || controlFile.Device != dataDirectory.Device)
        { throw Invalid(); }
        await RequireHbaStartupStateAsync(docker, dataDirectory.Device, cancellationToken).ConfigureAwait(false);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        const string identitySql = """
            SELECT system_identifier::text,current_user,session_user,host(inet_client_addr()),
                current_database(),current_setting('data_directory'),current_setting('hba_file'),pg_backend_pid(),
                encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex'),
                host(inet_server_addr()),inet_server_port(),pg_postmaster_start_time()
            FROM pg_control_system();
            """;
        await using (var command = new NpgsqlCommand(identitySql, connection))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
                !string.Equals(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(reader.GetString(0)))), identity.SystemIdentifierSha256, StringComparison.OrdinalIgnoreCase) ||
                reader.GetString(1) != _pins.OperatorRole || reader.GetString(2) != _pins.OperatorRole ||
                reader.GetString(3) != _pins.ServerClientAddress || reader.GetString(4) != "postgres" ||
                reader.GetString(5) != identity.PgData || reader.GetString(6) != identity.PgData + "/pg_hba.conf" ||
                reader.GetInt32(7) != connection.ProcessID || reader.GetString(8) != _pins.RestrictedHbaSha256 ||
                !docker.Networks.Any(network => network.Address == reader.GetString(9)) || reader.GetInt32(10) != 5432 ||
                reader.GetFieldValue<DateTimeOffset>(11) != _pins.PostmasterStartedAtUtc)
            { throw Invalid(); }
        }
        BackupProcessResult hbaFile = await new ReadOnlyDockerProcess().RunAsync(
            ["--host", docker.DockerHost, "exec", docker.ContainerId, "sha256sum", identity.PgData + "/pg_hba.conf"],
            cancellationToken).ConfigureAwait(false);
        string[] digest = hbaFile.StandardOutput.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (hbaFile.ExitCode != 0 || digest.Length < 2 || digest[0] != _pins.RestrictedHbaSha256) { throw Invalid(); }
        // Password bytes never leave PostgreSQL; inspect only its algorithm and role capability.
        const string roleSql = """
            SELECT rolcanlogin AND rolsuper AND NOT rolinherit AND NOT rolcreatedb AND NOT rolcreaterole
                AND NOT rolreplication AND NOT rolbypassrls AND rolpassword LIKE 'SCRAM-SHA-256$%'
                AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid)
                AND shobj_description(r.oid,'pg_authid')=$2
                AND NOT EXISTS(SELECT 1 FROM pg_db_role_setting s WHERE s.setrole=r.oid),rolvaliduntil
            FROM pg_authid r WHERE rolname=$1;
            """;
        await using (var command = new NpgsqlCommand(roleSql, connection))
        {
            _ = command.Parameters.AddWithValue(_pins.OperatorRole);
            _ = command.Parameters.AddWithValue(RoleCustodyComment(_authority.Binding.ComputeSha256()));
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(0) || !reader.GetBoolean(0) ||
                reader.IsDBNull(1) || reader.GetFieldValue<DateTimeOffset>(1) != _pins.RoleExpiresAtUtc) { throw Invalid(); }
        }
        string[] databases = [.. DatabaseInventory.ActiveDatabases, "postgres"];
        const string rulesSql = """
            SELECT type,database,user_name,address,netmask,auth_method,options,error
            FROM pg_hba_file_rules WHERE rule_number<=6 ORDER BY rule_number;
            """;
        await using (var command = new NpgsqlCommand(rulesSql, connection))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            string[] addresses = [_pins.ServerClientAddress, "::1", "0.0.0.0", "::", "0.0.0.0", "::"];
            string[] masks = ["255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "0.0.0.0", "::", "0.0.0.0", "::"];
            for (int ordinal = 0; ordinal < 6; ordinal++)
            {
                string[] expectedDatabases = ordinal < 2 ? databases : ordinal < 4 ? ["all"] : ["replication"];
                string[] expectedUsers = ordinal < 2 ? [_pins.OperatorRole] : ["all"];
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.GetString(0) != "host" ||
                    !reader.GetFieldValue<string[]>(1).SequenceEqual(expectedDatabases, StringComparer.Ordinal) ||
                    !reader.GetFieldValue<string[]>(2).SequenceEqual(expectedUsers, StringComparer.Ordinal) ||
                    reader.GetString(3) != addresses[ordinal] || reader.GetString(4) != masks[ordinal] ||
                    reader.GetString(5) != (ordinal < 2 ? "scram-sha-256" : "reject") ||
                    !reader.IsDBNull(6) || !reader.IsDBNull(7)) { throw Invalid(); }
            }
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) { throw Invalid(); }
        }
        const string sessionsSql = """
            SELECT NOT EXISTS(SELECT 1 FROM pg_hba_file_rules WHERE error IS NOT NULL)
                AND NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid<>pg_backend_pid()
                  AND backend_type IN ('client backend','walsender')
                  AND (backend_type='walsender' OR usename IS DISTINCT FROM $1
                    OR client_addr IS DISTINCT FROM $2::inet));
            """;
        await using (var command = new NpgsqlCommand(sessionsSql, connection))
        {
            _ = command.Parameters.AddWithValue(_pins.OperatorRole);
            _ = command.Parameters.AddWithValue(_pins.ServerClientAddress);
            if (await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not true) { throw Invalid(); }
        }
        await RequireHbaStartupStateAsync(docker, dataDirectory.Device, cancellationToken).ConfigureAwait(false);
        await using (var epoch = new NpgsqlCommand("SELECT pg_postmaster_start_time();", connection))
        {
            if (await epoch.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not DateTime started ||
                new DateTimeOffset(started) != _pins.PostmasterStartedAtUtc) { throw Invalid(); }
        }
        if (await _observe(cancellationToken).ConfigureAwait(false) != identity ||
            _clock.GetUtcNow() >= _pins.RoleExpiresAtUtc) { throw Invalid(); }
        RequireOwnership();
    }

    private async Task RequireHbaStartupStateAsync(LocalDockerResourceState docker, string expectedDevice,
        CancellationToken cancellationToken)
    {
        string path = _pins.TargetIdentity.PgData + "/pg_hba.conf";
        FileSystemObjectIdentity file = await _docker.StatAsync(docker.DockerHost, docker.ContainerId,
            path, "regular file", cancellationToken).ConfigureAwait(false);
        BackupProcessResult state = await new ReadOnlyDockerProcess().RunAsync(
            ["--host", docker.DockerHost, "exec", docker.ContainerId, "env", "TZ=UTC", "LC_ALL=C",
                "stat", "--printf=" + HbaStatFormat, "--", path], cancellationToken).ConfigureAwait(false);
        string[] fields = state.StandardOutput.Split('|');
        if (state.ExitCode != 0 || fields.Length != 9 || file.Device != expectedDevice ||
            fields[0] != file.Device || fields[1] != file.Inode ||
            !uint.TryParse(fields[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint mode) ||
            (mode & 0xf000) != 0x8000 || !uint.TryParse(fields[3], out _) || !uint.TryParse(fields[4], out _) ||
            fields[5] != "1" || !long.TryParse(fields[6], out long size) || size <= 0 ||
            !string.Equals(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(state.StandardOutput))), _pins.HbaFileStateSha256, StringComparison.OrdinalIgnoreCase) ||
            !BeforeEpoch(fields[7], _pins.PostmasterStartedAtUtc) || !BeforeEpoch(fields[8], _pins.PostmasterStartedAtUtc))
        { throw Invalid(); }
    }

    private static bool BeforeEpoch(string timestamp, DateTimeOffset epoch)
    {
        Match match = HbaTimestamp().Match(timestamp);
        if (!match.Success || !DateTimeOffset.TryParseExact(match.Groups["seconds"].Value + " +00:00",
            "yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset seconds) ||
            !uint.TryParse(match.Groups["nanos"].Value, out uint nanos)) { return false; }
        long epochSecond = epoch.UtcTicks - epoch.UtcTicks % TimeSpan.TicksPerSecond;
        return seconds.UtcTicks < epochSecond || seconds.UtcTicks == epochSecond &&
            nanos < epoch.UtcTicks % TimeSpan.TicksPerSecond * 100;
    }

    [GeneratedRegex(@"^(?<seconds>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(?<nanos>\d{9}) \+0000$", RegexOptions.CultureInvariant)]
    private static partial Regex HbaTimestamp();

    private void RequireOwnership()
    {
        _authority.ValidateHeld();
        if (_authority.Binding.ComputeSha256() != _pins.LocalExecutionBindingSha256) { throw Invalid(); }
    }

    private static bool RoleName(string value)
    {
        const string prefix = "legacy_repair_operator_";
        return value.StartsWith(prefix, StringComparison.Ordinal) && value.Length == prefix.Length + 32 &&
            value[prefix.Length..].All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static bool Hash(string value)
    {
        return value is { Length: 64 } && value.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_source_repair_maintenance_invalid", "Protected LOCAL operator identity, expiring role, exact HBA exclusion and maintained quiescence must match.");
    }

    private sealed class Lease(SourceBackedLocalRepairMaintenance owner) : ISourceBackedLocalRepairMaintenanceLease
    {
        private bool _disposed;
        public Task RequireStillQuiescentAsync(HistoricalCurrentLocalObservation identity, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return owner.VerifyAsync(identity, cancellationToken);
        }
        public ValueTask DisposeAsync()
        {
            // Catalog/role/HBA cleanup changes signed preservation state. It is a separately
            // recorded post-terminal lifecycle operation, never an automatic lease side effect.
            _disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}
