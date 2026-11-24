using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public abstract class OrderSubtotalExpressionRepairScaleFixture(string image, int version) : IAsyncLifetime
{
    private const string ShadowRole = "legacy_order_scale_shadow";
    private const string ControlRole = "legacy_order_scale_control";
    private readonly string _shadowPassword = Guid.NewGuid().ToString("N");
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder(image)
        .WithDatabase("postgres").WithUsername("postgres").WithPassword(Guid.NewGuid().ToString("N"))
        .WithCommand("-c", "autovacuum=off")
        .WithLabel("legacy.maliev.fixture", "order-subtotal-full-model-scale-characterization")
        .WithCreateParameterModifier(parameters =>
        {
            parameters.HostConfig!.Memory = 512L * 1024 * 1024;
            parameters.HostConfig.MemorySwap = 512L * 1024 * 1024;
            parameters.HostConfig.NanoCPUs = 750000000;
            foreach (var bindings in parameters.HostConfig.PortBindings!.Values)
            { foreach (var binding in bindings) { binding.HostIP = "127.0.0.1"; } }
        }).Build();
    internal int ExpectedVersion { get; } = version;

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
            await using var provider = new NpgsqlCommand("SELECT current_setting('server_version_num')::integer;", connection) { CommandTimeout = 30 };
            Assert.Equal(ExpectedVersion, await provider.ExecuteScalarAsync(deadline.Token));
            if (ExpectedVersion >= 180007)
            {
                await using var defense = new NpgsqlCommand("SHOW composite_type_mismatch;", connection) { CommandTimeout = 30 };
                Assert.Equal("error", await defense.ExecuteScalarAsync(deadline.Token));
            }
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

public sealed class OrderSubtotalExpressionRepairScale184Fixture() : OrderSubtotalExpressionRepairScaleFixture(
    "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382", 180004);

public sealed class OrderSubtotalExpressionRepairScale187Fixture() : OrderSubtotalExpressionRepairScaleFixture(
    "postgres@sha256:68e33adb18d9962952f00d5e3b8644305e10e375f98dd652bf6ee6a1836314ba", 180007);

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class OrderSubtotalExpressionRepairScale184Group : ICollectionFixture<OrderSubtotalExpressionRepairScale184Fixture>
{
    public const string Name = "Order Subtotal full-model scale PostgreSQL18.4";
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class OrderSubtotalExpressionRepairScale187Group : ICollectionFixture<OrderSubtotalExpressionRepairScale187Fixture>
{
    public const string Name = "Order Subtotal full-model scale PostgreSQL18.7";
}