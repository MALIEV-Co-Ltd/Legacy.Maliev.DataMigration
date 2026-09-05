using System.Globalization;
using System.Text.RegularExpressions;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

// Exact local resource proof, not an authorization to use a remote/canonical database.
internal sealed partial class LocalPostgreSqlResourceAuthority(LocalPostgreSqlArchiveVerificationOptions options)
{
    private readonly LocalDockerResourceObserver _docker = new();
    private readonly ReadOnlyDockerProcess _process = new();

    internal static NpgsqlConnectionStringBuilder Connection(string connectionString)
    {
        var value = new NpgsqlConnectionStringBuilder(connectionString);
        Require(value.Host == "127.0.0.1" && value.Port is > 0 and <= 65535 && value.Database == "postgres" &&
            !string.IsNullOrWhiteSpace(value.Username) && !string.IsNullOrEmpty(value.Password) && string.IsNullOrEmpty(value.Options) &&
            !value.Multiplexing, "connection");
        // Construct a minimal single-endpoint connection; no passfile/service/role/search-path overrides.
        return new()
        {
            Host = "127.0.0.1",
            Port = value.Port,
            Database = "postgres",
            Username = value.Username,
            Password = value.Password,
            SslMode = value.SslMode,
            Pooling = false,
            Enlist = false,
            IncludeErrorDetail = false,
            Timeout = 15
        };
    }

    internal async Task<LocalPostgreSqlResourceProof> ObserveAsync(NpgsqlConnection admin, CancellationToken token)
    {
        Require(Hash().IsMatch(options.ContainerId ?? "") && Image().IsMatch(options.ImageId ?? "") &&
            ulong.TryParse(options.SystemIdentifier, NumberStyles.None, CultureInfo.InvariantCulture, out ulong expected) && expected > 0, "expected_identity");
        LocalDockerResourceState docker = await _docker.ObserveAsync(options.ContainerId!, token, options.ImageId).ConfigureAwait(false);
        var endpoint = new NpgsqlConnectionStringBuilder(admin.ConnectionString);
        Require(docker.Ports.Count(port => port.HostAddress == "127.0.0.1" && port.HostPort == endpoint.Port && port.ContainerPort == 5432) == 1 &&
            docker.Ports.Where(port => port.ContainerPort == 5432).All(port => port.HostAddress == "127.0.0.1"), "published_endpoint");
        if (admin.State != System.Data.ConnectionState.Open) { await admin.OpenAsync(token).ConfigureAwait(false); }
        const string sql = "SELECT system_identifier::text, current_setting('data_directory'), host(inet_server_addr()), inet_server_port(), current_setting('server_version_num')::integer, current_database(), current_user, session_user FROM pg_control_system();";
        string systemId, data, address;
        await using (var command = new NpgsqlCommand(sql, admin))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false))
        {
            Require(await reader.ReadAsync(token).ConfigureAwait(false), "postgres_identity");
            systemId = reader.GetString(0); data = reader.GetString(1); address = reader.GetString(2);
            Require(systemId == options.SystemIdentifier, "postgres_system_identifier");
            Require(LocalDockerResourceObserver.IsAbsoluteLinuxPath(data), "postgres_data_path");
            Require(docker.Networks.Any(network => network.Address == address) && reader.GetInt32(3) == 5432, "postgres_endpoint");
            Require(reader.GetInt32(4) is >= 180000 and < 190000 && reader.GetString(5) == "postgres" &&
                reader.GetString(6) == endpoint.Username && reader.GetString(7) == endpoint.Username, "postgres_identity");
        }
        FileSystemObjectIdentity directory = await _docker.StatAsync(docker.DockerHost, docker.ContainerId, data, "directory", token).ConfigureAwait(false);
        FileSystemObjectIdentity control = await _docker.StatAsync(docker.DockerHost, docker.ContainerId, data + "/global/pg_control", "regular file", token).ConfigureAwait(false);
        DockerObservedMount? mount = docker.Mounts.Where(item => data == item.Destination || data.StartsWith(item.Destination + "/", StringComparison.Ordinal))
            .OrderByDescending(item => item.Destination.Length).FirstOrDefault();
        Require(directory.Device == (mount?.FileSystemIdentity ?? docker.Root).Device && control.Device == directory.Device, "postgres_storage");
        BackupProcessResult result = await _process.RunAsync(["--host", docker.DockerHost, "exec", "--env", "LC_ALL=C", docker.ContainerId, "pg_controldata", "--pgdata=" + data], token).ConfigureAwait(false);
        MatchCollection matches = SystemIdentifierLine().Matches(result.StandardOutput);
        Require(result.ExitCode == 0 && matches.Count == 1 && matches[0].Groups[1].Value == systemId, "container_system_identifier");
        return new(ObservationDigest.Compute("LocalPostgreSqlDocker.v1", docker), systemId, data, address, directory, control);
    }

    internal static async Task ValidateRestoreRoleAsync(NpgsqlConnection admin, string role, string? localDatabase, CancellationToken token)
    {
        const string sql = """
            SELECT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls
              AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid)
              AND NOT EXISTS(SELECT 1 FROM pg_database d WHERE d.datdba=r.oid)
              AND NOT EXISTS(SELECT 1 FROM pg_database d WHERE d.datallowconn AND d.datname IS DISTINCT FROM $2
                  AND has_database_privilege(r.oid,d.oid,'CONNECT'))
              AND NOT EXISTS(SELECT 1 FROM pg_db_role_setting s WHERE s.setrole=r.oid)
            FROM pg_roles r WHERE r.rolname=$1;
            """;
        await using var command = new NpgsqlCommand(sql, admin);
        _ = command.Parameters.AddWithValue(role);
        _ = command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Text, (object?)localDatabase ?? DBNull.Value);
        Require(true.Equals(await command.ExecuteScalarAsync(token).ConfigureAwait(false)), "restore_role");
    }

    internal static void Require(bool condition, string boundary)
    {
        if (!condition) { throw new MigrationExecutionException("local_archive_" + boundary, "Local archive verification could not establish the required " + boundary + " boundary."); }
    }

    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Hash();
    [GeneratedRegex("^sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Image();
    [GeneratedRegex("^Database system identifier:\\s+([0-9]+)\\s*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)] private static partial Regex SystemIdentifierLine();
}

internal sealed record LocalPostgreSqlResourceProof(string DockerSha256, string SystemIdentifier, string DataDirectory,
    string ServerAddress, FileSystemObjectIdentity Directory, FileSystemObjectIdentity ControlFile);
