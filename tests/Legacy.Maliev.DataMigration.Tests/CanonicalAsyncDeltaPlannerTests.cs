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
