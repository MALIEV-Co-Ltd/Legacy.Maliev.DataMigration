using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;
using Legacy.Maliev.DataMigration.Tests;

namespace Legacy.Maliev.DataMigration.SqlServer.Tests;

[Collection(SqlServerAdapterTestGroup.Name)]
public sealed class SqlServerLiveSourceObservationTests
{
    [SqlServerIntegrationFact]
    public async Task Live_observation_reads_all_23_snapshot_enabled_databases_and_rejects_disabled_isolation()
    {
        const string image = "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04";
        await using var container = new MsSqlBuilder(image)
            .WithPassword("MALIEV_test_Only!123456")
            .Build();
        await container.StartAsync();
        await using var connection = new SqlConnection(container.GetConnectionString());
        await connection.OpenAsync();
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            string name = database.Replace("]", "]]", StringComparison.Ordinal);
            await using var create = new SqlCommand($"CREATE DATABASE [{name}];", connection) { CommandTimeout = 120 };
            _ = await create.ExecuteNonQueryAsync();
            await using var enable = new SqlCommand(
                $"ALTER DATABASE [{name}] SET ALLOW_SNAPSHOT_ISOLATION ON;", connection)
            { CommandTimeout = 120 };
            _ = await enable.ExecuteNonQueryAsync();
        }

        string observed = await SqlServerLiveSourceObservation.ObserveSha256Async(
            container.GetConnectionString(), CancellationToken.None);
        Assert.Matches("^[0-9a-f]{64}$", observed);
        Assert.Equal(observed, await SqlServerLiveSourceObservation.ObserveSha256Async(
            container.GetConnectionString(), CancellationToken.None));

        await using var disable = new SqlCommand(
            "ALTER DATABASE [Country] SET ALLOW_SNAPSHOT_ISOLATION OFF;", connection)
        { CommandTimeout = 120 };
        _ = await disable.ExecuteNonQueryAsync();
        MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            SqlServerLiveSourceObservation.ObserveSha256Async(container.GetConnectionString(), CancellationToken.None));
        Assert.Equal("delta_live_source_observation_invalid", error.Code);
    }

    [Fact]
    public void Exact23_online_snapshot_inventory_has_a_stable_identity_digest()
    {
        var observed = DatabaseInventory.ActiveDatabases.ToDictionary(
            name => name,
            name => (Guid: GuidFromName(name), State: 0, SnapshotState: 1),
            StringComparer.Ordinal);

        string first = SqlServerLiveSourceObservation.ComputeSha256("source-a", "16", observed);
        string second = SqlServerLiveSourceObservation.ComputeSha256("source-a", "16", observed);

        Assert.Equal(first, second);
        Assert.Matches("^[0-9a-f]{64}$", first);
        Assert.NotEqual(first, SqlServerLiveSourceObservation.ComputeSha256("source-b", "16", observed));
        var changed = new Dictionary<string, (Guid Guid, int State, int SnapshotState)>(observed, StringComparer.Ordinal)
        {
            [DatabaseInventory.ActiveDatabases[0]] = (Guid.NewGuid(), 0, 1),
        };
        Assert.NotEqual(first, SqlServerLiveSourceObservation.ComputeSha256("source-a", "16", changed));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("offline")]
    [InlineData("snapshot-disabled")]
    [InlineData("invisible-guid")]
    public void Incomplete_or_unstable_live_source_fails_closed(string scenario)
    {
        var observed = DatabaseInventory.ActiveDatabases.ToDictionary(
            name => name,
            name => (Guid: GuidFromName(name), State: 0, SnapshotState: 1),
            StringComparer.Ordinal);
        string first = DatabaseInventory.ActiveDatabases[0];
        switch (scenario)
        {
            case "missing": _ = observed.Remove(first); break;
            case "offline": observed[first] = (observed[first].Guid, 1, 1); break;
            case "snapshot-disabled": observed[first] = (observed[first].Guid, 0, 0); break;
            case "invisible-guid": observed[first] = (Guid.Empty, 0, 1); break;
            default:
                break;
        }

        MigrationExecutionException error = Assert.Throws<MigrationExecutionException>(() =>
            SqlServerLiveSourceObservation.ComputeSha256("source-a", "16", observed));
        Assert.Equal("delta_live_source_observation_invalid", error.Code);
    }

    private static Guid GuidFromName(string name)
    {
        byte[] bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(name));
        return new Guid(bytes.AsSpan(0, 16));
    }
}
