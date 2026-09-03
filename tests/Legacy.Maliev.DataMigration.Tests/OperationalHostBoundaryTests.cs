using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class OperationalHostBoundaryTests(RemotePostgreSqlHostFixture fixture) : IClassFixture<RemotePostgreSqlHostFixture>
{
    [Theory]
    [InlineData("journal-readonly")]
    [InlineData("journal-write")]
    [InlineData("target-create")]
    [InlineData("target-recovery")]
    [InlineData("target-copy")]
    [InlineData("target-empty")]
    [InlineData("target-delete")]
    public async Task OperationalOpen_RejectsActualWrongSqlIdentityBeforeAnyOperation(string operation)
    {
        string database = operation.StartsWith("journal", StringComparison.Ordinal)
            ? PostgreSqlMigrationRuntimeBoundaryValidator.ControlDatabase : HostKubernetesBoundaryTests.Shadow().Name;
        await using var admin = new NpgsqlConnection(fixture.AdminConnection);
        await admin.OpenAsync();
        await using var create = new NpgsqlCommand($"CREATE DATABASE {database} OWNER host_restricted", admin);
        _ = await create.ExecuteNonQueryAsync();
        string original = fixture.Tls.ResponseBody;
        fixture.Tls.ResponseBody = RemotePostgreSqlHostFixture.ClusterJson("123");
        try
        {
            using var observer = fixture.Observer();
            using RecoveryAuthorityTestData data = await RecoveryAuthorityTestData.CreateAsync();
            string connection = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = database }.ConnectionString;
            var boundary = new RemotePostgreSqlHostBoundary(connection, fixture.Target with { SystemId = "123" }, observer);
            var journal = new PostgreSqlMigrationRunJournal(new(new NpgsqlConnectionStringBuilder(connection)
            { Database = PostgreSqlMigrationRuntimeBoundaryValidator.ControlDatabase }.ConnectionString,
                RecoveryVerification: new(new(data.AdmissionPayload.Identity.SourceCommitSha, data.AdmissionPayload.Identity.RunnerDigestSha256),
                    RecoveryAuthorityTestData.Roles, data.Trust))
            { HostBoundary = boundary });
            var target = new PostgreSqlShadowTarget(new(connection, new RejectingProvisioner()) { HostBoundary = boundary });
            ShadowDatabase shadow = HostKubernetesBoundaryTests.Shadow() with { Name = database };
            var identity = new MigrationRunIdentity(Guid.NewGuid(), new string('a', 40), new string('b', 64), new string('c', 64), new string('d', 64), "1");
            Func<Task> action = operation switch
            {
                "journal-readonly" => async () => { _ = await journal.ReadRecoverySnapshotAsync(identity, default); }
                ,
                "journal-write" => async () => { _ = await journal.TryBeginAsync(identity, default); }
                ,
                "target-create" => async () => { _ = await target.CreateUniqueEmptyShadowAsync(shadow, default); }
                ,
                "target-recovery" => async () => { await using var session = await target.BeginReadOnlyRecoveryAsync(shadow, default); }
                ,
                "target-copy" => async () => { await using var transaction = await target.BeginWholeDatabaseTransactionAsync(shadow, default); }
                ,
                "target-empty" => async () => { _ = await target.IsEmptyAsync(shadow, default); }
                ,
                _ => () => target.DeleteRunOwnedShadowAsync(shadow, default),
            };
            MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(action);
            Assert.Equal("host_postgres_identity_mismatch", failure.Code);
            await using var inspected = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.AdminConnection) { Database = database, Pooling = false }.ConnectionString);
            await inspected.OpenAsync();
            await using var schema = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='legacy_migration_control')", inspected);
            Assert.False((bool)(await schema.ExecuteScalarAsync())!);
        }
        finally
        {
            fixture.Tls.ResponseBody = original;
            await using var drop = new NpgsqlCommand($"DROP DATABASE {database} WITH (FORCE)", admin);
            _ = await drop.ExecuteNonQueryAsync();
        }
    }

    private sealed class RejectingProvisioner : IPostgreSqlShadowDatabaseProvisioner
    {
        public Task ProvisionWithConnectionsDisabledAsync(ShadowDatabase shadow, string ownerRole, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Unexpected provision");
        }

        public Task EnableConnectionsAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Unexpected enable");
        }

        public Task DeleteAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Unexpected delete");
        }
    }
}
