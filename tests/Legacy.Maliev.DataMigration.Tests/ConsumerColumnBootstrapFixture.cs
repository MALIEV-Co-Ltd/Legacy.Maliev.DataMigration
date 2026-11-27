using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ConsumerColumnBootstrapTestGroup : ICollectionFixture<ConsumerColumnBootstrapFixture>
{
    public const string Name = "Consumer column bootstrap characterization";
}

public sealed class ConsumerColumnBootstrapFixture : IAsyncLifetime
{
    private const string ShadowRole = "legacy_consumer_bootstrap_shadow";
    private const string ControlRole = "legacy_consumer_bootstrap_control";
    private readonly string _shadowPassword = Guid.NewGuid().ToString("N");
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres@sha256:68e33adb18d9962952f00d5e3b8644305e10e375f98dd652bf6ee6a1836314ba")
        .WithDatabase("postgres").WithUsername("postgres").WithPassword(Guid.NewGuid().ToString("N"))
        .WithCommand("-c", "autovacuum=off")
        .WithLabel("legacy.maliev.fixture", "consumer-column-bootstrap-characterization")
        .WithCreateParameterModifier(parameters =>
        {
            parameters.HostConfig!.Memory = 384L * 1024 * 1024;
            parameters.HostConfig.MemorySwap = 384L * 1024 * 1024;
            parameters.HostConfig.NanoCPUs = 500000000;
            foreach (var bindings in parameters.HostConfig.PortBindings!.Values)
            { foreach (var binding in bindings) { binding.HostIP = "127.0.0.1"; } }
        }).Build();

    public string ConnectionString => new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Pooling = false }.ConnectionString;

    internal PostgreSqlShadowTarget CreateShadowTarget()
    {
        return new(new PostgreSqlShadowTargetOptions(
        new NpgsqlConnectionStringBuilder(ConnectionString) { Username = ShadowRole, Password = _shadowPassword }.ConnectionString,
        new TestcontainerShadowDatabaseProvisioner(ConnectionString)));
    }

    public async Task InitializeAsync()
    {
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            await _container.StartAsync(deadline.Token);
            await using var connection = new NpgsqlConnection(ConnectionString);
            await connection.OpenAsync(deadline.Token);
            await using (var command = new NpgsqlCommand($"""
                CREATE ROLE {ShadowRole} LOGIN NOCREATEDB PASSWORD '{_shadowPassword}';
                CREATE ROLE {ControlRole} NOLOGIN;
                """, connection) { CommandTimeout = 30 })
            { _ = await command.ExecuteNonQueryAsync(deadline.Token); }
            await using (var command = new NpgsqlCommand(
                $"CREATE DATABASE {PostgreSqlMigrationRuntimeBoundaryValidator.ControlDatabase} OWNER {ControlRole};", connection)
            { CommandTimeout = 30 })
            { _ = await command.ExecuteNonQueryAsync(deadline.Token); }
            await using (var command = new NpgsqlCommand($"""
                REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
                REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
                REVOKE CONNECT ON DATABASE {PostgreSqlMigrationRuntimeBoundaryValidator.ControlDatabase} FROM PUBLIC;
                GRANT CONNECT ON DATABASE postgres TO {ShadowRole};
                """, connection) { CommandTimeout = 30 })
            { _ = await command.ExecuteNonQueryAsync(deadline.Token); }
            await using var observe = new NpgsqlCommand("SHOW autovacuum;", connection) { CommandTimeout = 30 };
            Assert.Equal("off", await observe.ExecuteScalarAsync(deadline.Token));
            await using var provider = new NpgsqlCommand("SELECT current_setting('server_version_num')='180007' AND current_setting('composite_type_mismatch')='error';", connection) { CommandTimeout = 30 };
            Assert.Equal(true, await provider.ExecuteScalarAsync(deadline.Token));
        }
        catch (Exception primary)
        {
            try { await DisposeAsync(); }
            catch (Exception cleanup) { throw new AggregateException("Bootstrap fixture initialization and cleanup failed.", primary, cleanup); }
            throw;
        }
    }

    public Task DisposeAsync()
    {
        return _container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(60));
    }
}
