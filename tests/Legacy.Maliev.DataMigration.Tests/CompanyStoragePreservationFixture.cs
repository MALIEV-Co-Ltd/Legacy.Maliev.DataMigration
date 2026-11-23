using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CompanyStoragePreservationTestGroup : ICollectionFixture<CompanyStoragePreservationFixture>
{
    public const string Name = "Company storage preservation";
}

// Only this disposable collection opts out of automatic maintenance; explicit ANALYZE probes remain enabled.
public sealed class CompanyStoragePreservationFixture : PostgreSqlAdapterFixture, IAsyncLifetime
{
    public CompanyStoragePreservationFixture() : base(384, quiescent: true)
    {
    }

    async Task IAsyncLifetime.InitializeAsync()
    {
        try
        {
            await InitializeAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await using var connection = new NpgsqlConnection(ConnectionString);
            await connection.OpenAsync(deadline.Token);
            await using var command = new NpgsqlCommand("SHOW autovacuum;", connection) { CommandTimeout = 30 };
            Assert.Equal("off", await command.ExecuteScalarAsync(deadline.Token));
        }
        catch (Exception primary)
        {
            try { await DisposeAsync(); }
            catch (Exception cleanup)
            { throw new AggregateException("The quiescent Company fixture failed initialization and cleanup.", primary, cleanup); }
            throw;
        }
    }

    Task IAsyncLifetime.DisposeAsync()
    {
        return DisposeAsync();
    }
}
