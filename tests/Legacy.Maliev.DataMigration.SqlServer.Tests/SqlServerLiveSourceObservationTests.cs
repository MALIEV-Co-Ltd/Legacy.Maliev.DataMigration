namespace Legacy.Maliev.DataMigration.SqlServer.Tests;

public sealed class SqlServerLiveSourceObservationTests
{
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
