using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class PostgreSqlMigrationRuntimeBoundaryTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task ValidateAsync_DedicatedLeastPrivilegeRoles_AcceptsBoundary()
    {
        PostgreSqlMigrationRuntimeBoundary observed = await PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
            fixture.ControlConnectionString,
            fixture.ShadowAdminConnectionString,
            fixture.ControlRole,
            fixture.ShadowAdminRole,
            CancellationToken.None);

        Assert.Equal(PostgreSqlMigrationRuntimeBoundaryValidator.ControlDatabase, observed.ControlDatabase);
        Assert.Equal(fixture.ControlRole, observed.ControlRole);
        Assert.Equal("postgres", observed.ShadowAdministrativeDatabase);
        Assert.Equal(fixture.ShadowAdminRole, observed.ShadowAdminRole);
    }

    [Fact]
    public async Task ShadowRuntimeCredential_CannotCreateArbitraryDatabase()
    {
        await using var connection = new NpgsqlConnection(fixture.ShadowAdminConnectionString);
        await connection.OpenAsync(CancellationToken.None);
        string forbidden = $"canonical_escape_{Guid.NewGuid():N}";
        await using var command = new NpgsqlCommand($"CREATE DATABASE {forbidden};", connection);

        PostgresException failure = await Assert.ThrowsAsync<PostgresException>(
            () => command.ExecuteNonQueryAsync(CancellationToken.None));

        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, failure.SqlState);
    }

    [Fact]
    public async Task ValidateAsync_WrongControlDatabase_FailsClosed()
    {
        PostgreSqlMigrationBoundaryException failure = await Assert.ThrowsAsync<PostgreSqlMigrationBoundaryException>(
            () => PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
                fixture.ShadowAdminConnectionString,
                fixture.ShadowAdminConnectionString,
                fixture.ControlRole,
                fixture.ShadowAdminRole,
                CancellationToken.None));

        Assert.Equal("migration_control_database_invalid", failure.Code);
    }

    [Fact]
    public async Task ValidateAsync_SameObservedRole_FailsClosed()
    {
        var sameRoleControl = new NpgsqlConnectionStringBuilder(fixture.ControlConnectionString)
        {
            Username = fixture.AdministratorUsername,
            Password = fixture.AdministratorPassword,
        };
        var sameRoleShadow = new NpgsqlConnectionStringBuilder(fixture.ConnectionString);

        PostgreSqlMigrationBoundaryException failure = await Assert.ThrowsAsync<PostgreSqlMigrationBoundaryException>(
            () => PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
                sameRoleControl.ConnectionString,
                sameRoleShadow.ConnectionString,
                fixture.AdministratorUsername,
                fixture.AdministratorUsername,
                CancellationToken.None));

        Assert.Equal("migration_postgres_role_boundary_invalid", failure.Code);
    }

    [Fact]
    public async Task ValidateAsync_PrivilegedControlRole_FailsClosed()
    {
        var privilegedControl = new NpgsqlConnectionStringBuilder(fixture.ControlConnectionString)
        {
            Username = fixture.AdministratorUsername,
            Password = fixture.AdministratorPassword,
        };

        PostgreSqlMigrationBoundaryException failure = await Assert.ThrowsAsync<PostgreSqlMigrationBoundaryException>(
            () => PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
                privilegedControl.ConnectionString,
                fixture.ShadowAdminConnectionString,
                fixture.AdministratorUsername,
                fixture.ShadowAdminRole,
                CancellationToken.None));

        Assert.Equal("migration_control_role_overprivileged", failure.Code);
    }

    [Fact]
    public async Task ValidateAsync_PrivilegedShadowRole_FailsClosed()
    {
        var privilegedShadow = new NpgsqlConnectionStringBuilder(fixture.ConnectionString);

        PostgreSqlMigrationBoundaryException failure = await Assert.ThrowsAsync<PostgreSqlMigrationBoundaryException>(
            () => PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
                fixture.ControlConnectionString,
                privilegedShadow.ConnectionString,
                fixture.ControlRole,
                fixture.AdministratorUsername,
                CancellationToken.None));

        Assert.Equal("migration_shadow_role_overprivileged", failure.Code);
    }

    [Fact]
    public async Task ValidateAsync_UnexpectedCanonicalDatabaseAccess_FailsClosed()
    {
        await ExecuteAsAdministratorAsync($"GRANT CONNECT ON DATABASE {fixture.CanonicalDatabase} TO {fixture.ShadowAdminRole};");
        try
        {
            PostgreSqlMigrationBoundaryException failure = await Assert.ThrowsAsync<PostgreSqlMigrationBoundaryException>(
                () => PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
                    fixture.ControlConnectionString,
                    fixture.ShadowAdminConnectionString,
                    fixture.ControlRole,
                    fixture.ShadowAdminRole,
                    CancellationToken.None));

            Assert.Equal("migration_shadow_database_access_invalid", failure.Code);
        }
        finally
        {
            await ExecuteAsAdministratorAsync($"REVOKE CONNECT ON DATABASE {fixture.CanonicalDatabase} FROM {fixture.ShadowAdminRole};");
        }
    }

    [Fact]
    public async Task ValidateAsync_TransitiveDangerousMembership_FailsClosed()
    {
        string inheritedRole = $"migration_test_{Guid.NewGuid():N}";
        await ExecuteAsAdministratorAsync($"CREATE ROLE {inheritedRole};");
        try
        {
            await ExecuteAsAdministratorAsync($"GRANT pg_read_all_data TO {inheritedRole};");
            await ExecuteAsAdministratorAsync($"GRANT {inheritedRole} TO {fixture.ShadowAdminRole};");

            PostgreSqlMigrationBoundaryException failure = await Assert.ThrowsAsync<PostgreSqlMigrationBoundaryException>(
                () => PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
                    fixture.ControlConnectionString,
                    fixture.ShadowAdminConnectionString,
                    fixture.ControlRole,
                    fixture.ShadowAdminRole,
                    CancellationToken.None));

            Assert.Equal("migration_shadow_privileged_membership", failure.Code);
        }
        finally
        {
            await ExecuteAsAdministratorAsync($"REVOKE {inheritedRole} FROM {fixture.ShadowAdminRole};");
            await ExecuteAsAdministratorAsync($"DROP ROLE {inheritedRole};");
        }
    }

    [Fact]
    public async Task ValidateAsync_PostgreSql18AutovacuumSignalMembership_FailsClosed()
    {
        await ExecuteAsAdministratorAsync($"GRANT pg_signal_autovacuum_worker TO {fixture.ShadowAdminRole};");
        try
        {
            PostgreSqlMigrationBoundaryException failure = await Assert.ThrowsAsync<PostgreSqlMigrationBoundaryException>(
                () => PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
                    fixture.ControlConnectionString,
                    fixture.ShadowAdminConnectionString,
                    fixture.ControlRole,
                    fixture.ShadowAdminRole,
                    CancellationToken.None));

            Assert.Equal("migration_shadow_privileged_membership", failure.Code);
        }
        finally
        {
            await ExecuteAsAdministratorAsync($"REVOKE pg_signal_autovacuum_worker FROM {fixture.ShadowAdminRole};");
        }
    }

    [Fact]
    public async Task ValidateAsync_PublicConnectOnOwnedShadow_FailsClosed()
    {
        string shadowName = $"legacy_shadow_order_{Guid.NewGuid():N}";
        await ExecuteAsAdministratorAsync($"CREATE DATABASE {shadowName} OWNER {fixture.ShadowAdminRole};");
        try
        {
            PostgreSqlMigrationBoundaryException failure = await Assert.ThrowsAsync<PostgreSqlMigrationBoundaryException>(
                () => PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
                    fixture.ControlConnectionString,
                    fixture.ShadowAdminConnectionString,
                    fixture.ControlRole,
                    fixture.ShadowAdminRole,
                    CancellationToken.None));

            Assert.Equal("migration_database_public_connect_invalid", failure.Code);
        }
        finally
        {
            await ExecuteAsAdministratorAsync($"DROP DATABASE {shadowName} WITH (FORCE);");
        }
    }

    [Fact]
    public async Task LeastPrivilegeBootstrap_DeniesCanonicalMutationAndAllowsOwnedShadowWork()
    {
        var canonical = new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
        {
            Database = fixture.CanonicalDatabase,
        };
        PostgresException denied = await Assert.ThrowsAsync<PostgresException>(async () =>
        {
            await using var connection = new NpgsqlConnection(canonical.ConnectionString);
            await connection.OpenAsync(CancellationToken.None);
        });
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);

        string shadowName = $"legacy_shadow_order_{Guid.NewGuid():N}";
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase? created = null;
        try
        {
            created = await target.CreateUniqueEmptyShadowAsync(
                "Order", shadowName, Guid.NewGuid().ToString("D"), CancellationToken.None);
            _ = await PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
                fixture.ControlConnectionString,
                fixture.ShadowAdminConnectionString,
                fixture.ControlRole,
                fixture.ShadowAdminRole,
                CancellationToken.None);

            var shadow = new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadowName };
            await using var connection = new NpgsqlConnection(shadow.ConnectionString);
            await connection.OpenAsync(CancellationToken.None);
            await using var command = new NpgsqlCommand("CREATE TABLE boundary_probe(id integer PRIMARY KEY); INSERT INTO boundary_probe VALUES (1);", connection);
            Assert.Equal(1, await command.ExecuteNonQueryAsync(CancellationToken.None));
        }
        finally
        {
            if (created is not null)
            {
                await target.DeleteRunOwnedShadowAsync(created, CancellationToken.None);
            }
        }
    }

    [Fact]
    public async Task ShadowPrivilegeDriftAfterPreflight_IsRejectedBeforeProvisioning()
    {
        _ = await PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
            fixture.ControlConnectionString,
            fixture.ShadowAdminConnectionString,
            fixture.ControlRole,
            fixture.ShadowAdminRole,
            CancellationToken.None);
        var provisioner = new RecordingProvisioner();
        var target = new PostgreSqlShadowTarget(new(
            fixture.ShadowAdminConnectionString,
            provisioner,
            fixture.ShadowAdminRole));
        await ExecuteAsAdministratorAsync($"ALTER ROLE {fixture.ShadowAdminRole} CREATEDB;");
        try
        {
            string shadowName = $"legacy_shadow_order_{Guid.NewGuid():N}";
            PostgreSqlMigrationBoundaryException failure = await Assert.ThrowsAsync<PostgreSqlMigrationBoundaryException>(
                () => target.CreateUniqueEmptyShadowAsync(
                    "Order", shadowName, Guid.NewGuid().ToString("D"), CancellationToken.None));

            Assert.Equal("migration_shadow_role_overprivileged", failure.Code);
            Assert.Equal(0, provisioner.ProvisionCalls);
        }
        finally
        {
            await ExecuteAsAdministratorAsync($"ALTER ROLE {fixture.ShadowAdminRole} NOCREATEDB;");
        }
    }

    [Fact]
    public async Task ControlPrivilegeDriftAfterPreflight_IsRejectedBeforeJournalSchemaWrite()
    {
        _ = await PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
            fixture.ControlConnectionString,
            fixture.ShadowAdminConnectionString,
            fixture.ControlRole,
            fixture.ShadowAdminRole,
            CancellationToken.None);
        string schema = $"drift_{Guid.NewGuid():N}";
        var journal = new PostgreSqlMigrationRunJournal(new(
            fixture.ControlConnectionString,
            schema,
            ExpectedControlRole: fixture.ControlRole));
        await ExecuteAsAdministratorAsync($"ALTER ROLE {fixture.ControlRole} CREATEDB;");
        try
        {
            PostgreSqlMigrationBoundaryException failure = await Assert.ThrowsAsync<PostgreSqlMigrationBoundaryException>(
                () => journal.TryBeginAsync(
                    new MigrationRunIdentity(Guid.NewGuid(), new string('a', 40), new string('b', 64), new string('c', 64), new string('d', 64), "generation"),
                    CancellationToken.None));

            Assert.Equal("migration_control_role_overprivileged", failure.Code);
            await using var connection = new NpgsqlConnection(fixture.ControlConnectionString);
            await connection.OpenAsync(CancellationToken.None);
            await using var command = new NpgsqlCommand("SELECT to_regnamespace($1) IS NULL;", connection);
            _ = command.Parameters.AddWithValue(schema);
            Assert.True((bool)(await command.ExecuteScalarAsync(CancellationToken.None))!);
        }
        finally
        {
            await ExecuteAsAdministratorAsync($"ALTER ROLE {fixture.ControlRole} NOCREATEDB;");
        }
    }

    private async Task ExecuteAsAdministratorAsync(string sql)
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync(CancellationToken.None);
        await using var command = new NpgsqlCommand(sql, connection);
        _ = await command.ExecuteNonQueryAsync(CancellationToken.None);
    }

    private sealed class RecordingProvisioner : IPostgreSqlShadowDatabaseProvisioner
    {
        public int ProvisionCalls { get; private set; }

        public Task ProvisionWithConnectionsDisabledAsync(ShadowDatabase shadow, string ownerRole, CancellationToken cancellationToken)
        {
            ProvisionCalls++;
            return Task.CompletedTask;
        }

        public Task EnableConnectionsAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task DeleteAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

}
