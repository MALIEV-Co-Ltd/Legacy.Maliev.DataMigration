using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Npgsql;
using static Legacy.Maliev.DataMigration.LocalPostgreSqlResourceAuthority;

namespace Legacy.Maliev.DataMigration;

/// <summary>Expectations only; every resource and PostgreSQL identity is independently observed before CREATE.</summary>
public sealed record LocalPostgreSqlArchiveVerificationOptions(string AdministrativeConnectionString,
    string RestoreConnectionString, string ContainerId, string ImageId, string SystemIdentifier, string PgRestorePath);

/// <summary>Restores only to a new exact-owned local database, using an existing isolated unprivileged restore login.</summary>
/// <remarks>Accepts authenticated pipeline-generated archives, not arbitrary SQL. A PostgreSQL login can still
/// change its own password/default settings; the restricted login is not an arbitrary-SQL sandbox.</remarks>
public sealed class LocalPostgreSqlArchiveVerifier : ILocalDatabaseArchiveVerifier
{
    private readonly LocalPostgreSqlArchiveVerificationOptions _options;
    private readonly FreshSchemaPlan _plan;
    private readonly DatabaseMigrationCheckpointVerifier _checkpoints;

    public LocalPostgreSqlArchiveVerifier(LocalPostgreSqlArchiveVerificationOptions options,
        DatabaseMigrationCheckpointVerificationOptions checkpointOptions)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        ArgumentNullException.ThrowIfNull(checkpointOptions);
        _plan = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(checkpointOptions.SchemaPlan))!;
        _checkpoints = new(checkpointOptions with { SchemaPlan = _plan });
    }

    /// <summary>Observes local resource and isolated-role prerequisites without creating a database. Not cached authority.</summary>
    public async Task PreflightAsync(CancellationToken cancellationToken)
    {
        (NpgsqlConnectionStringBuilder adminSettings, NpgsqlConnectionStringBuilder restoreSettings) = Connections();
        await using var admin = new NpgsqlConnection(adminSettings.ConnectionString);
        _ = await new LocalPostgreSqlResourceAuthority(_options).ObserveAsync(admin, cancellationToken).ConfigureAwait(false);
        await ValidateRestoreRoleAsync(admin, restoreSettings.Username!, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Authenticates execution credentials using only a new exact-owned local probe database.</summary>
    public Task VerifyExecutionReadinessAsync(CancellationToken cancellationToken)
    {
        return OnTemporaryDatabaseAsync(async (local, token) =>
        {
            await using var connection = new NpgsqlConnection(local.RestoreConnectionString);
            await connection.OpenAsync(token).ConfigureAwait(false);
            await using var command = new NpgsqlCommand("SELECT current_database(), current_user, session_user, host(inet_server_addr()), inet_server_port(), (SELECT oid FROM pg_database WHERE datname=current_database());", connection);
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            Require(await reader.ReadAsync(token).ConfigureAwait(false) && reader.GetString(0) == local.Name &&
                reader.GetString(1) == local.RestoreRole && reader.GetString(2) == local.RestoreRole &&
                reader.GetString(3) == local.ServerAddress && reader.GetInt32(4) == 5432 && reader.GetFieldValue<uint>(5) == local.Oid,
                "readiness_session");
        }, cancellationToken);
    }

    public async Task VerifyAsync(Stream authenticatedPlaintext, DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticatedPlaintext);
        DatabaseMigrationCheckpoint frozen = JsonSerializer.Deserialize<DatabaseMigrationCheckpoint>(MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint))!;
        _checkpoints.Validate(frozen, frozen.Shadow);
        DatabaseSchemaPlan plan = _plan.Databases.Single(database => database.Database == frozen.Database.Database);
        await OnTemporaryDatabaseAsync(async (local, token) =>
        {
            await LocalPgRestoreProcess.RestoreAsync(BuildStartInfo(_options.PgRestorePath, new(local.RestoreConnectionString)), authenticatedPlaintext, token).ConfigureAwait(false);
            await local.ValidateAsync(token).ConfigureAwait(false);
            await InspectAsync(local.AdministrativeConnectionString, local.Name, frozen, plan, token).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    private async Task OnTemporaryDatabaseAsync(Func<TemporaryDatabase, CancellationToken, Task> operation, CancellationToken cancellationToken)
    {
        (NpgsqlConnectionStringBuilder adminSettings, NpgsqlConnectionStringBuilder restoreSettings) = Connections();
        var authority = new LocalPostgreSqlResourceAuthority(_options);
        await using var admin = new NpgsqlConnection(adminSettings.ConnectionString);
        LocalPostgreSqlResourceProof original = await authority.ObserveAsync(admin, cancellationToken).ConfigureAwait(false);
        await ValidateRestoreRoleAsync(admin, restoreSettings.Username!, null, cancellationToken).ConfigureAwait(false);
        string database = "local_archive_verify_" + Guid.NewGuid().ToString("N");
        string marker = "MALIEV-local-archive-v1:" + Guid.NewGuid().ToString("N");
        uint? oid = null;
        bool created = false;
        Exception? primary = null;
        try
        {
            await ExecuteAsync(admin, $"CREATE DATABASE {Quote(database)} TEMPLATE template0 ALLOW_CONNECTIONS false;", cancellationToken).ConfigureAwait(false);
            created = true;
            oid = await DatabaseOidAsync(admin, database, cancellationToken).ConfigureAwait(false);
            // This is invocation-local ownership, never the remote checkpoint marker.
            await ExecuteAsync(admin, $"COMMENT ON DATABASE {Quote(database)} IS '{marker}'; REVOKE ALL ON DATABASE {Quote(database)} FROM PUBLIC; GRANT CONNECT, CREATE ON DATABASE {Quote(database)} TO {Quote(restoreSettings.Username!)}; ALTER DATABASE {Quote(database)} ALLOW_CONNECTIONS true;", cancellationToken).ConfigureAwait(false);
            await AssertOwnedAsync(admin, database, oid.Value, marker, cancellationToken).ConfigureAwait(false);
            adminSettings.Database = database;
            await using (var local = new NpgsqlConnection(adminSettings.ConnectionString))
            {
                await local.OpenAsync(cancellationToken).ConfigureAwait(false);
                await ExecuteAsync(local, $"GRANT USAGE, CREATE ON SCHEMA public TO {Quote(restoreSettings.Username!)};", cancellationToken).ConfigureAwait(false);
            }
            await ValidateRestoreRoleAsync(admin, restoreSettings.Username!, database, cancellationToken).ConfigureAwait(false);
            await ValidateAsync(cancellationToken).ConfigureAwait(false);
            restoreSettings.Database = database;
            await operation(new(database, oid.Value, adminSettings.ConnectionString, restoreSettings.ConnectionString,
                restoreSettings.Username!, original.ServerAddress, ValidateAsync), cancellationToken).ConfigureAwait(false);
            await ValidateAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) { primary = error; }
        Exception? cleanup = null;
        if (created)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try
            {
                await ValidateAsync(deadline.Token).ConfigureAwait(false);
                await ExecuteAsync(admin, $"DROP DATABASE {Quote(database)} WITH (FORCE);", deadline.Token).ConfigureAwait(false);
            }
            catch (Exception error) { cleanup = error; }
        }
        PgDumpProcessTermination.ThrowPrimaryOrAggregate(primary, cleanup, "Local archive verification failed and exact temporary database cleanup also failed.");

        async Task ValidateAsync(CancellationToken token)
        {
            Require(original == await authority.ObserveAsync(admin, token).ConfigureAwait(false), "resource_changed");
            Require(oid.HasValue, "cleanup_ownership");
            await AssertOwnedAsync(admin, database, oid!.Value, marker, token).ConfigureAwait(false);
        }
    }

    private (NpgsqlConnectionStringBuilder Admin, NpgsqlConnectionStringBuilder Restore) Connections()
    {
        NpgsqlConnectionStringBuilder admin = Connection(_options.AdministrativeConnectionString);
        NpgsqlConnectionStringBuilder restore = Connection(_options.RestoreConnectionString);
        Require(admin.Port == restore.Port && admin.Username != restore.Username && admin.SslMode == restore.SslMode &&
            Path.IsPathFullyQualified(_options.PgRestorePath) && File.Exists(_options.PgRestorePath), "configuration");
        return (admin, restore);
    }

    private static async Task InspectAsync(string connectionString, string localDatabase, DatabaseMigrationCheckpoint checkpoint,
        DatabaseSchemaPlan plan, CancellationToken token)
    {
        var connection = new NpgsqlConnection(connectionString);
        NpgsqlTransaction transaction = await PostgreSqlShadowTransactionGate.BeginAsync(connection, localDatabase, true, TimeSpan.FromSeconds(30), token).ConfigureAwait(false);
        // Internal composition is deliberately separate from remote role/naming/ownership validation.
        var session = new PostgreSqlShadowRecoverySession(connection, transaction, new(localDatabase, "local-verification", plan.Database));
        Exception? primary = null;
        try
        {
            PostgreSqlShadowRecoveryInspection observed = await session.InspectAsync(plan, token).ConfigureAwait(false);
            Require(!observed.IsVerifiedEmpty && observed.Tables.Count == checkpoint.Reconciliation.Tables.Count, "restore_coverage");
            ReconciliationDiagnostics.CompareSchema(plan.Database, checkpoint.Reconciliation.TargetSchemaSha256, observed.TargetSchemaSha256!);
            foreach (TableReconciliationEvidence expected in checkpoint.Reconciliation.Tables)
            {
                ReconciliationDiagnostics.CompareTable(plan.Database, expected, observed.Tables.Single(table => table.Table == expected.Table));
            }
            ReconciliationDiagnostics.CompareSequences(plan, checkpoint.Reconciliation.SequenceNextValues, observed.SequenceNextValues);
        }
        catch (Exception error) { primary = error; }
        Exception? cleanup = null;
        try { await session.DisposeAsync().ConfigureAwait(false); }
        catch (Exception error) { cleanup = error; }
        PgDumpProcessTermination.ThrowPrimaryOrAggregate(primary, cleanup, "Local archive inspection and transaction disposal both failed.");
    }

    internal static ProcessStartInfo BuildStartInfo(string executable, NpgsqlConnectionStringBuilder target)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string name in start.Environment.Keys.Where(key => key.StartsWith("PG", StringComparison.OrdinalIgnoreCase)).ToArray()) { _ = start.Environment.Remove(name); }
        foreach (string arg in new[] { "--dbname", target.Database!, "--format=custom", "--exit-on-error", "--no-owner", "--no-privileges", "--no-comments", "--single-transaction", "--no-password" }) { start.ArgumentList.Add(arg); }
        start.Environment["PGHOST"] = target.Host;
        start.Environment["PGPORT"] = target.Port.ToString(CultureInfo.InvariantCulture);
        start.Environment["PGUSER"] = target.Username;
        start.Environment["PGPASSWORD"] = target.Password;
        start.Environment["PGSSLMODE"] = target.SslMode switch
        {
            SslMode.Disable => "disable",
            SslMode.Allow => "allow",
            SslMode.Prefer => "prefer",
            SslMode.Require => "require",
            SslMode.VerifyCA => "verify-ca",
            SslMode.VerifyFull => "verify-full",
            _ => throw new ArgumentOutOfRangeException(nameof(target), "Unsupported PostgreSQL SSL mode."),
        };
        return start;
    }

    private static async Task<uint> DatabaseOidAsync(NpgsqlConnection connection, string database, CancellationToken token)
    {
        await using var command = new NpgsqlCommand("SELECT oid FROM pg_database WHERE datname=$1;", connection);
        _ = command.Parameters.AddWithValue(database);
        return (uint)(await command.ExecuteScalarAsync(token).ConfigureAwait(false) ?? throw new InvalidOperationException("Temporary database identity unavailable."));
    }

    private static async Task AssertOwnedAsync(NpgsqlConnection connection, string database, uint oid, string marker, CancellationToken token)
    {
        await using var command = new NpgsqlCommand("SELECT oid=$2 AND pg_get_userbyid(datdba)=current_user AND shobj_description(oid,'pg_database')=$3 FROM pg_database WHERE datname=$1;", connection);
        _ = command.Parameters.AddWithValue(database); _ = command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Oid, oid); _ = command.Parameters.AddWithValue(marker);
        Require(true.Equals(await command.ExecuteScalarAsync(token).ConfigureAwait(false)), "cleanup_ownership");
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, CancellationToken token)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
    }

    private static string Quote(string identifier)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(identifier);
    }

    private sealed record TemporaryDatabase(string Name, uint Oid, string AdministrativeConnectionString,
        string RestoreConnectionString, string RestoreRole, string ServerAddress, Func<CancellationToken, Task> ValidateAsync);
}
