namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CanonicalAsyncDeltaPlannerTests
{
    [Fact]
    public async Task Async_stream_matches_canonical_planner_without_materializing_rows()
    {
        TableCopyPlan table = Table();
        MigrationRow[] source = [Row(1, "same"), Row(2, "changed"), Row(4, "insert")];
        MigrationRow[] target = [Row(1, "same"), Row(2, "old"), Row(3, "delete")];

        CanonicalTableDelta expected = CanonicalDeltaPlanner.Plan(table, source, target);
        CanonicalTableDelta actual = await CanonicalAsyncDeltaPlanner.PlanAsync(
            table, Stream(source), Stream(target), CancellationToken.None);

        Assert.Equal(expected.Table, actual.Table);
        Assert.Equal(expected.UnchangedCount, actual.UnchangedCount);
        Assert.Equal(expected.Operations, actual.Operations);
    }

    [Fact]
    public async Task Async_stream_rejects_out_of_order_source()
    {
        DeltaPlanningException error = await Assert.ThrowsAsync<DeltaPlanningException>(() =>
            CanonicalAsyncDeltaPlanner.PlanAsync(Table(), Stream([Row(2, "two"), Row(1, "one")]), Stream([]), CancellationToken.None));
        Assert.Equal("delta_key_order_invalid", error.Code);
    }

    [Fact]
    public async Task Async_stream_consumes_large_values_and_compares_their_canonical_content()
    {
        byte[] same = System.Text.Encoding.UTF8.GetBytes("ข้อความเดียวกัน");
        byte[] changed = System.Text.Encoding.UTF8.GetBytes("ข้อความใหม่");
        TableCopyPlan table = Table() with
        {
            SourceColumnTypes = new Dictionary<string, string>
            {
                ["id"] = "int",
                ["value"] = "nvarchar(max)",
            },
        };
        var sourceSame = new StreamingLob(StreamingLobKind.Text, same.Length,
            (destination, token) => destination.WriteAsync(same, token).AsTask());
        var sourceChanged = new StreamingLob(StreamingLobKind.Text, changed.Length,
            (destination, token) => destination.WriteAsync(changed, token).AsTask());
        MigrationRow[] source =
        [
            new(new Dictionary<string, object?> { ["id"] = 1, ["value"] = sourceSame }),
            new(new Dictionary<string, object?> { ["id"] = 2, ["value"] = sourceChanged }),
        ];
        MigrationRow[] target =
        [
            new(new Dictionary<string, object?> { ["id"] = 1, ["value"] = new BufferedStreamingLob(StreamingLobKind.Text, same) }),
            new(new Dictionary<string, object?> { ["id"] = 2, ["value"] = new BufferedStreamingLob(StreamingLobKind.Text, same) }),
        ];

        CanonicalTableDelta delta = await CanonicalAsyncDeltaPlanner.PlanAsync(
            table, Stream(source), Stream(target), CancellationToken.None);

        Assert.True(sourceSame.IsConsumed);
        Assert.True(sourceChanged.IsConsumed);
        Assert.Equal(1, delta.UnchangedCount);
        CanonicalDeltaOperation update = Assert.Single(delta.Operations);
        Assert.Equal(DeltaOperationKind.Update, update.Kind);
    }

    private static async IAsyncEnumerable<MigrationRow> Stream(IEnumerable<MigrationRow> rows)
    {
        foreach (MigrationRow row in rows)
        {
            await Task.Yield();
            yield return row;
        }
    }

    private static TableCopyPlan Table()
    {
        return new("dbo", "items", "public", "items", ["id", "value"], ["id"])
        {
            ColumnTypes = new Dictionary<string, string> { ["id"] = "integer", ["value"] = "text" },
            PrimaryKey = new("pk_items", ["id"]),
        };
    }

    private static MigrationRow Row(int id, string value)
    {
        return new(new Dictionary<string, object?>
        {
            ["id"] = id,
            ["value"] = value,
        });
    }
}
