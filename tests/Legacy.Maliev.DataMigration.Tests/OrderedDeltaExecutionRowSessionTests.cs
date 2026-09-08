using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class OrderedDeltaExecutionRowSessionTests
{
    [Fact]
    public async Task Resolves_each_ordered_stream_once_and_does_not_buffer_upsert_lob()
    {
        TableCopyPlan table = Table();
        byte[] content = Encoding.UTF8.GetBytes("streamed-value");
        var expected = new MigrationRow(new Dictionary<string, object?>
        {
            ["Id"] = 1,
            ["Value"] = new BufferedStreamingLob(StreamingLobKind.Text, content),
        });
        CanonicalDeltaOperation operation = Assert.Single(CanonicalDeltaPlanner.Plan(table, [expected], []).Operations);
        var lob = new StreamingLob(StreamingLobKind.Text, content.Length, async (destination, token) =>
            await destination.WriteAsync(content, token));
        var source = new CountingRows([Row(1, lob)]);
        var target = new CountingRows([]);
        var provider = new OrderedDeltaExecutionRowSessionProvider(source, target);
        await using IDeltaExecutionRowSession session = await provider.OpenAsync("db", table, CancellationToken.None);
        await using IAsyncEnumerator<ResolvedDeltaRow> rows = session.ResolveAsync(Plan(table, [operation]), CancellationToken.None)
            .GetAsyncEnumerator();

        Assert.True(await rows.MoveNextAsync());
        Assert.Same(lob, rows.Current.Source!.Values["Value"]);
        Assert.False(lob.IsConsumed);
        await lob.ConsumeAsync(Stream.Null, CancellationToken.None);
        DeltaExecutionCoordinator.VerifyRow(table, rows.Current.Source, operation.KeySha256, operation.SourceRowSha256, "source");
        Assert.False(await rows.MoveNextAsync());
        Assert.Equal(1, source.ReadCount);
        Assert.Equal(1, target.ReadCount);
    }

    [Fact]
    public async Task Rejects_duplicate_source_keys()
    {
        TableCopyPlan table = Table();
        MigrationRow row = Row(1, "one");
        CanonicalDeltaOperation operation = Assert.Single(CanonicalDeltaPlanner.Plan(table, [row], []).Operations);
        var provider = new OrderedDeltaExecutionRowSessionProvider(new CountingRows([row, row]), new CountingRows([]));
        await using IDeltaExecutionRowSession session = await provider.OpenAsync("db", table, CancellationToken.None);

        DeltaExecutionException exception = await Assert.ThrowsAsync<DeltaExecutionException>(async () =>
        {
            await foreach (ResolvedDeltaRow _ in session.ResolveAsync(Plan(table, [operation]), CancellationToken.None)) { }
        });

        Assert.Equal("delta_execution_duplicate_key", exception.Code);
    }

    [Fact]
    public async Task Rejects_out_of_order_source_keys()
    {
        TableCopyPlan table = Table();
        MigrationRow first = Row(2, "two");
        MigrationRow second = Row(1, "one");
        CanonicalDeltaOperation[] operations =
        [
            Assert.Single(CanonicalDeltaPlanner.Plan(table, [first], []).Operations),
            Assert.Single(CanonicalDeltaPlanner.Plan(table, [second], []).Operations),
        ];
        var provider = new OrderedDeltaExecutionRowSessionProvider(new CountingRows([first, second]), new CountingRows([]));
        await using IDeltaExecutionRowSession session = await provider.OpenAsync("db", table, CancellationToken.None);

        DeltaExecutionException exception = await Assert.ThrowsAsync<DeltaExecutionException>(async () =>
        {
            await foreach (ResolvedDeltaRow _ in session.ResolveAsync(Plan(table, operations), CancellationToken.None)) { }
        });

        Assert.Equal("delta_execution_key_order_invalid", exception.Code);
    }

    private static TableCopyPlan Table()
    {
        return new("dbo", "items", "public", "items", ["Id", "Value"], ["Id"])
        {
            ColumnTypes = new Dictionary<string, string> { ["Id"] = "integer", ["Value"] = "text" },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_items", ["Id"]),
        };
    }

    private static MigrationRow Row(int id, object value)
    {
        return new(new Dictionary<string, object?> { ["Id"] = id, ["Value"] = value });
    }

    private static DeltaTablePlan Plan(TableCopyPlan table, IReadOnlyList<CanonicalDeltaOperation> operations)
    {
        return new(
        $"{table.TargetSchema}.{table.TargetTable}",
        operations.LongCount(item => item.Kind == DeltaOperationKind.Insert),
        operations.LongCount(item => item.Kind == DeltaOperationKind.Update),
        operations.LongCount(item => item.Kind == DeltaOperationKind.Delete),
        0,
        DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(operations),
        operations);
    }

    private sealed class CountingRows(IReadOnlyList<MigrationRow> rows) : IDeltaOrderedRowSource
    {
        internal int ReadCount { get; private set; }

        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(
            string database,
            TableCopyPlan table,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            ReadCount++;
            foreach (MigrationRow row in rows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return row;
                await Task.Yield();
            }
        }
    }
}
