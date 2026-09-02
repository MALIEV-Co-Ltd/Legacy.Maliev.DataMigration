using Npgsql;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public sealed partial class RemotePostgreSqlHostBoundary
{
    private readonly NpgsqlConnectionStringBuilder _settings;
    private readonly CloudNativePgTargetObservation _authorizedTarget;
    private readonly CloudNativePgTargetObserver _observer;
    private readonly string _caDigest;

    public RemotePostgreSqlHostBoundary(string connectionString, CloudNativePgTargetObservation authorizedTarget, CloudNativePgTargetObserver observer)
    {
        ArgumentNullException.ThrowIfNull(authorizedTarget);
        ArgumentNullException.ThrowIfNull(observer);
        _settings = ValidateSettings(connectionString);
        if (!authorizedTarget.IsHealthy || !ulong.TryParse(authorizedTarget.SystemId, NumberStyles.None, CultureInfo.InvariantCulture, out ulong identity) || identity == 0)
        { throw new MigrationExecutionException("host_postgres_target_invalid", "Host SQL requires the verified signed healthy CloudNativePG target identity."); }
        _authorizedTarget = authorizedTarget;
        _observer = observer;
        _caDigest = AuthorityDigest(_settings.RootCertificate!);
    }

    // Validate on the actual journal/control/target connection before any operation.
    // Role/access/ownership validators remain independently mandatory; this adds identity.
    public async Task VerifyOpenConnectionAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        var actual = new NpgsqlConnectionStringBuilder(connection.ConnectionString);
        if (connection.State != System.Data.ConnectionState.Open || actual.Host != _settings.Host || actual.Port != _settings.Port ||
            actual.Username != _settings.Username || actual.SslMode != SslMode.VerifyFull || actual.RootCertificate != _settings.RootCertificate ||
            AuthorityDigest(actual.RootCertificate!) != _caDigest)
        { throw new MigrationExecutionException("host_postgres_connection_invalid", "The opened SQL connection does not use the protected authenticated host boundary."); }
        ValidateDatabase(actual.Database!);
        CloudNativePgTargetObservation observed = await _observer.ObserveAsync(_authorizedTarget.Namespace, _authorizedTarget.Cluster, cancellationToken).ConfigureAwait(false);
        if (!observed.IsHealthy || observed.Uid != _authorizedTarget.Uid || observed.Generation != _authorizedTarget.Generation ||
            observed.SystemId != _authorizedTarget.SystemId)
        { throw new MigrationExecutionException("host_postgres_target_drift", "The authenticated CloudNativePG target no longer matches signed authority."); }
        try
        {
            const string sql = "SELECT system_identifier::text, COALESCE((SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid()),false) FROM pg_catalog.pg_control_system();";
            await using var command = new NpgsqlCommand(sql, connection);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || !reader.GetBoolean(1) ||
                reader.GetString(0) != observed.SystemId || await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            { throw new MigrationExecutionException("host_postgres_identity_mismatch", "The actual authenticated SQL server is not the signed CloudNativePG target."); }
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.InsufficientPrivilege)
        { throw new MigrationExecutionException("host_postgres_identity_permission_required", "The existing runtime role cannot execute the narrow SQL identity observation; no privileges were changed."); }
    }

    public async Task VerifyEndpointAsync(string database, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(ConnectionStringFor(database));
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await VerifyOpenConnectionAsync(connection, cancellationToken).ConfigureAwait(false);
    }

    internal string ConnectionStringFor(string database)
    {
        ValidateDatabase(database);
        return AuthorityDigest(_settings.RootCertificate!) != _caDigest
            ? throw HostRuntimeTrust.Invalid()
            : new NpgsqlConnectionStringBuilder(_settings.ConnectionString) { Database = database, Pooling = false, GssEncryptionMode = GssEncryptionMode.Disable }.ConnectionString;
    }

    private void ValidateDatabase(string database)
    {
        if (database != _settings.Database && !ShadowName().IsMatch(database ?? string.Empty))
        { throw new MigrationExecutionException("host_postgres_database_invalid", "The requested database is outside the configured control/administrative or shadow boundary."); }
    }

    internal static NpgsqlConnectionStringBuilder ValidateSettings(string connectionString)
    {
        NpgsqlConnectionStringBuilder settings;
        try { settings = new(connectionString); }
        catch (ArgumentException) { throw HostRuntimeTrust.Invalid(); }
        PgDumpSource.ValidateConnectionOptions(settings);
        if (Uri.CheckHostName(settings.Host) != UriHostNameType.Dns || string.IsNullOrWhiteSpace(settings.Database) ||
            string.IsNullOrWhiteSpace(settings.Username) || string.IsNullOrEmpty(settings.Password) || settings.SslMode != SslMode.VerifyFull ||
            string.IsNullOrWhiteSpace(settings.RootCertificate) || settings.Timeout <= 0)
        { throw HostRuntimeTrust.Invalid(); }
        _ = AuthorityDigest(settings.RootCertificate);
        return settings;
    }

    private static string AuthorityDigest(string path)
    {
        X509Certificate2Collection roots = HostRuntimeTrust.ReadAuthorities(path);
        try
        {
            string framed = string.Join('|', roots.Cast<X509Certificate2>().Select(root => Convert.ToHexString(SHA256.HashData(root.RawData))));
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(framed)));
        }
        finally { foreach (X509Certificate2 root in roots) { root.Dispose(); } }
    }

    [System.Text.RegularExpressions.GeneratedRegex("^legacy_shadow_[a-z0-9_]+_[0-9a-f]{32}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex ShadowName();
}
