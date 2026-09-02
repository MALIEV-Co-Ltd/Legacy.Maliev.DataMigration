using System.Text.RegularExpressions;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public sealed record PostgreSqlMigrationRuntimeBoundary(
    string ControlDatabase,
    string ControlRole,
    string ShadowAdministrativeDatabase,
    string ShadowAdminRole);

public sealed class PostgreSqlMigrationBoundaryException(string code, string message, Exception? innerException = null)
    : Exception(message, innerException)
{
    public string Code { get; } = code;
}

public static partial class PostgreSqlMigrationRuntimeBoundaryValidator
{
    public const string ControlDatabase = "legacy_migration_control";
    private static readonly string[] DangerousPredefinedRoles =
    [
        "pg_checkpoint",
        "pg_create_subscription",
        "pg_execute_server_program",
        "pg_maintain",
        "pg_monitor",
        "pg_read_all_data",
        "pg_read_all_settings",
        "pg_read_all_stats",
        "pg_read_server_files",
        "pg_signal_backend",
        "pg_signal_autovacuum_worker",
        "pg_stat_scan_tables",
        "pg_use_reserved_connections",
        "pg_write_all_data",
        "pg_write_server_files",
    ];

    public static async Task<PostgreSqlMigrationRuntimeBoundary> ValidateAsync(
        string controlConnectionString,
        string shadowAdministrativeConnectionString,
        string expectedControlRole,
        string expectedShadowAdminRole,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(controlConnectionString) ||
            string.IsNullOrWhiteSpace(shadowAdministrativeConnectionString) ||
            !RoleName().IsMatch(expectedControlRole ?? string.Empty) ||
            !RoleName().IsMatch(expectedShadowAdminRole ?? string.Empty))
        {
            throw Error("migration_postgres_boundary_configuration_invalid", "The PostgreSQL migration role boundary configuration is invalid.");
        }

        if (string.Equals(expectedControlRole, expectedShadowAdminRole, StringComparison.Ordinal))
        {
            throw Error("migration_postgres_role_boundary_invalid", "The journal and shadow administration roles must be distinct.");
        }

        try
        {
            await using var controlConnection = new NpgsqlConnection(controlConnectionString);
            await controlConnection.OpenAsync(cancellationToken).ConfigureAwait(false);
            RoleObservation control = await ValidateControlConnectionAsync(controlConnection, expectedControlRole!, cancellationToken).ConfigureAwait(false);

            await using var shadowConnection = new NpgsqlConnection(shadowAdministrativeConnectionString);
            await shadowConnection.OpenAsync(cancellationToken).ConfigureAwait(false);
            RoleObservation shadow = await ValidateShadowConnectionAsync(shadowConnection, expectedShadowAdminRole!, cancellationToken).ConfigureAwait(false);

            return new(control.Database, control.Role, shadow.Database, shadow.Role);
        }
        catch (PostgreSqlMigrationBoundaryException)
        {
            throw;
        }
        catch (Exception exception) when (exception is NpgsqlException or TimeoutException or InvalidOperationException)
        {
            throw Error("migration_postgres_boundary_unavailable", "The PostgreSQL migration role boundary could not be verified.", exception);
        }
    }

    internal static async Task ValidateOperationalControlConnectionAsync(
        NpgsqlConnection connection,
        string expectedRole,
        CancellationToken cancellationToken)
    {
        _ = await ValidateControlConnectionAsync(connection, expectedRole, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task ValidateOperationalShadowConnectionAsync(
        NpgsqlConnection connection,
        string expectedRole,
        CancellationToken cancellationToken)
    {
        _ = await ValidateShadowConnectionAsync(connection, expectedRole, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task ValidateOwnedShadowConnectionAsync(
        NpgsqlConnection connection,
        string expectedRole,
        string expectedDatabase,
        string administrativeDatabase,
        CancellationToken cancellationToken)
    {
        RoleObservation shadow = await ObserveAsync(connection, cancellationToken).ConfigureAwait(false);
        Require(string.Equals(shadow.Database, expectedDatabase, StringComparison.Ordinal) && ShadowDatabaseName().IsMatch(shadow.Database),
            "migration_shadow_database_invalid", "Recovery and COPY must use the exact owned shadow database.");
        Require(string.Equals(shadow.Role, expectedRole, StringComparison.Ordinal),
            "migration_shadow_role_invalid", "The actual target role does not match the reviewed configuration.");
        // Unlike the administrative database, the exact-owned target necessarily grants
        // CREATE to its owner. Keep the administrative/control validators unchanged.
        Require(!shadow.Superuser && !shadow.CreateRole && !shadow.CreateDatabase && !shadow.Replication && !shadow.BypassRowLevelSecurity &&
            shadow.CanConnectCurrentDatabase && shadow.CanCreateInCurrentDatabase && !shadow.CanConnectControlDatabase,
            "migration_shadow_role_overprivileged", "The actual target role does not match the reviewed owner boundary.");
        Require(!shadow.HasDangerousInheritedRole, "migration_shadow_privileged_membership", "The actual target role inherits a privileged PostgreSQL role.");
        Require(shadow.PubliclyConnectableDatabases.Count == 0, "migration_database_public_connect_invalid", "PUBLIC can connect inside the migration boundary.");
        Require(shadow.ConnectableDatabases.All(database =>
                string.Equals(database.Database, administrativeDatabase, StringComparison.Ordinal) ||
                (ShadowDatabaseName().IsMatch(database.Database) && string.Equals(database.Owner, expectedRole, StringComparison.Ordinal))),
            "migration_shadow_database_access_invalid", "The actual target role can connect to an unexpected or non-owned database.");
    }

    private static async Task<RoleObservation> ValidateControlConnectionAsync(
        NpgsqlConnection connection,
        string expectedRole,
        CancellationToken cancellationToken)
    {
        RoleObservation control = await ObserveAsync(connection, cancellationToken).ConfigureAwait(false);
        Require(string.Equals(control.Database, ControlDatabase, StringComparison.Ordinal), "migration_control_database_invalid", "The journal must use the dedicated migration-control database.");
        Require(string.Equals(control.Role, expectedRole, StringComparison.Ordinal), "migration_control_role_invalid", "The observed migration-control role does not match the reviewed configuration.");
        Require(!control.Superuser && !control.CreateRole && !control.CreateDatabase && !control.Replication && !control.BypassRowLevelSecurity && control.CanConnectCurrentDatabase && control.CanCreateInCurrentDatabase,
            "migration_control_role_overprivileged", "The migration-control role is missing required database-local access or has cluster-wide privileges.");
        Require(!control.HasDangerousInheritedRole, "migration_control_privileged_membership", "The migration-control role inherits a privileged PostgreSQL role.");
        Require(control.PubliclyConnectableDatabases.Count == 0, "migration_database_public_connect_invalid", "PUBLIC can connect to a PostgreSQL database inside the migration boundary.");
        Require(control.ConnectableDatabases.Count == 1 && string.Equals(control.ConnectableDatabases[0].Database, ControlDatabase, StringComparison.Ordinal),
            "migration_control_database_access_invalid", "The migration-control role can connect outside its dedicated database.");
        return control;
    }

    private static async Task<RoleObservation> ValidateShadowConnectionAsync(
        NpgsqlConnection connection,
        string expectedRole,
        CancellationToken cancellationToken)
    {
        RoleObservation shadow = await ObserveAsync(connection, cancellationToken).ConfigureAwait(false);
        Require(!string.Equals(shadow.Database, ControlDatabase, StringComparison.Ordinal), "migration_shadow_database_invalid", "The shadow administrator cannot use the migration-control database.");
        Require(string.Equals(shadow.Role, expectedRole, StringComparison.Ordinal), "migration_shadow_role_invalid", "The observed shadow-administration role does not match the reviewed configuration.");
        Require(!shadow.Superuser && !shadow.CreateRole && !shadow.CreateDatabase && !shadow.Replication && !shadow.BypassRowLevelSecurity && shadow.CanConnectCurrentDatabase && !shadow.CanCreateInCurrentDatabase && !shadow.CanConnectControlDatabase,
            "migration_shadow_role_overprivileged", "The shadow administrator must have only the reviewed database-creation boundary.");
        Require(!shadow.HasDangerousInheritedRole, "migration_shadow_privileged_membership", "The shadow administrator inherits a privileged PostgreSQL role.");
        Require(shadow.PubliclyConnectableDatabases.Count == 0, "migration_database_public_connect_invalid", "PUBLIC can connect to a PostgreSQL database inside the migration boundary.");
        Require(shadow.ConnectableDatabases.All(database => IsAllowedShadowDatabase(database, shadow)), "migration_shadow_database_access_invalid", "The shadow administrator can connect to an unexpected or non-owned database.");
        return shadow;
    }

    private static async Task<RoleObservation> ObserveAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        const string sql = """
            WITH RECURSIVE inherited_roles(oid) AS (
                SELECT oid
                FROM pg_catalog.pg_roles
                WHERE rolname = current_user
                UNION
                SELECT membership.roleid
                FROM inherited_roles AS inherited
                JOIN pg_catalog.pg_auth_members AS membership ON membership.member = inherited.oid
            )
            SELECT current_database(), current_user,
                   role.rolsuper, role.rolcreaterole, role.rolcreatedb,
                   role.rolreplication, role.rolbypassrls,
                   has_database_privilege(current_user, current_database(), 'CONNECT'),
                   has_database_privilege(current_user, current_database(), 'CREATE'),
                   has_database_privilege(current_user, @control_database, 'CONNECT'),
                    ARRAY(
                       SELECT ARRAY[database.datname::text, pg_get_userbyid(database.datdba)::text]
                       FROM pg_catalog.pg_database AS database
                       WHERE database.datallowconn
                         AND has_database_privilege(current_user, database.oid, 'CONNECT')
                       ORDER BY database.datname
                    ),
                    ARRAY(
                        SELECT database.datname::text
                        FROM pg_catalog.pg_database AS database
                        WHERE database.datallowconn
                          AND EXISTS (
                              SELECT 1
                              FROM aclexplode(COALESCE(database.datacl, acldefault('d', database.datdba))) AS acl
                              WHERE acl.grantee = 0 AND acl.privilege_type = 'CONNECT')
                        ORDER BY database.datname
                    ),
                    EXISTS (
                       SELECT 1
                       FROM inherited_roles AS inherited
                       JOIN pg_catalog.pg_roles AS inherited_role ON inherited_role.oid = inherited.oid
                       WHERE inherited_role.oid <> role.oid
                         AND (inherited_role.rolsuper
                              OR inherited_role.rolcreaterole
                              OR inherited_role.rolcreatedb
                              OR inherited_role.rolreplication
                              OR inherited_role.rolbypassrls
                              OR inherited_role.rolname = ANY(@dangerous_roles))
                   )
            FROM pg_catalog.pg_roles AS role
            WHERE role.rolname = current_user;
            """;
        await using var command = new NpgsqlCommand(sql, connection);
        _ = command.Parameters.AddWithValue("control_database", ControlDatabase);
        _ = command.Parameters.AddWithValue("dangerous_roles", DangerousPredefinedRoles);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw Error("migration_postgres_role_unavailable", "The connected PostgreSQL role could not be observed uniquely.");
        }

        var observation = new RoleObservation(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetBoolean(2),
            reader.GetBoolean(3),
            reader.GetBoolean(4),
            reader.GetBoolean(5),
            reader.GetBoolean(6),
            reader.GetBoolean(7),
            reader.GetBoolean(8),
            reader.GetBoolean(9),
            ReadDatabaseAccess(reader, 10),
            reader.GetFieldValue<string[]>(11),
            reader.GetBoolean(12));
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? throw Error("migration_postgres_role_unavailable", "The connected PostgreSQL role could not be observed uniquely.")
            : observation;
    }

    private static PostgreSqlMigrationBoundaryException Error(string code, string message, Exception? exception = null)
    {
        return new(code, message, exception);
    }

    private static void Require(bool condition, string code, string message)
    {
        if (!condition)
        {
            throw Error(code, message);
        }
    }

    private static bool IsAllowedShadowDatabase(DatabaseAccess database, RoleObservation shadow)
    {
        return string.Equals(database.Database, shadow.Database, StringComparison.Ordinal) ||
            (ShadowDatabaseName().IsMatch(database.Database) &&
             string.Equals(database.Owner, shadow.Role, StringComparison.Ordinal));
    }

    private static DatabaseAccess[] ReadDatabaseAccess(NpgsqlDataReader reader, int ordinal)
    {
        string[,] values = reader.GetFieldValue<string[,]>(ordinal);
        var result = new DatabaseAccess[values.GetLength(0)];
        for (int index = 0; index < result.Length; index++)
        {
            result[index] = new(values[index, 0], values[index, 1]);
        }

        return result;
    }

    [GeneratedRegex("^[a-z][a-z0-9_]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex RoleName();

    [GeneratedRegex("^legacy_shadow_[a-z0-9_]+_[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ShadowDatabaseName();

    private sealed record DatabaseAccess(string Database, string Owner);

    private sealed record RoleObservation(
        string Database,
        string Role,
        bool Superuser,
        bool CreateRole,
        bool CreateDatabase,
        bool Replication,
        bool BypassRowLevelSecurity,
        bool CanConnectCurrentDatabase,
        bool CanCreateInCurrentDatabase,
        bool CanConnectControlDatabase,
        IReadOnlyList<DatabaseAccess> ConnectableDatabases,
        IReadOnlyList<string> PubliclyConnectableDatabases,
        bool HasDangerousInheritedRole);
}
