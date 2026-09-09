namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ShadowMigrationRuntimeTests
{
    [Fact]
    public async Task Create_ComposesOnlyShadowTargetAndReadOnlySource()
    {
        ShadowMigrationRuntime runtime = ShadowMigrationRuntime.Create(new ShadowMigrationRuntimeOptions(
            new SqlServerMigrationSourceOptions(
                "Server=sql.example;Database=master;Integrated Security=True;Encrypt=True"),
            new PostgreSqlShadowTargetOptions(
                "Host=postgres.example;Database=postgres;Username=reviewer",
                new UnusedProvisioner()),
            new PostgreSqlMigrationRunJournalOptions(
                "Host=postgres.example;Database=legacy_migration_control;Username=control")));

        _ = Assert.IsType<SqlServerMigrationSource>(runtime.Source);
        _ = Assert.IsType<PostgreSqlShadowTarget>(runtime.ShadowTarget);
        _ = Assert.IsType<PostgreSqlMigrationRunJournal>(runtime.Journal);
        await runtime.DisposeAsync();
    }

    private sealed class UnusedProvisioner : IPostgreSqlShadowDatabaseProvisioner
    {
        public Task ProvisionWithConnectionsDisabledAsync(ShadowDatabase shadow, string ownerRole, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Provisioning is not used while composing the runtime.");
        }

        public Task EnableConnectionsAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Provisioning is not used while composing the runtime.");
        }

        public Task DeleteAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("Provisioning is not used while composing the runtime.");
        }
    }
}
