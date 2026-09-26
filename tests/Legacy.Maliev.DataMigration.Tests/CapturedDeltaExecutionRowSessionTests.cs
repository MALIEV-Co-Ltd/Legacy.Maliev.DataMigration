using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CapturedDeltaExecutionRowSessionTests
{
    [Fact]
    public async Task Local_preflight_replays_signed_rows_and_rejects_changed_target_preimage()
    {
        string directory = NewDirectory();
        try
        {
            TableCopyPlan table = Table();
            byte[] key = RandomNumberGenerator.GetBytes(32);
            var archive = new DeltaCapturedTableArchive(directory);
            DeltaCapturedTableArtifact full = await archive.CaptureAsync("Quotation", table,
                new('a', 64), Rows([Row(1, "new"), Row(2, "updated")]), key, CancellationToken.None);
            MigrationRow[] originalTarget = [Row(2, "old")];
            CanonicalTableDelta delta = await CanonicalAsyncDeltaPlanner.PlanAsync(table,
                archive.ReplayAsync(full, "Quotation", table, new('a', 64), key, CancellationToken.None),
                Rows(originalTarget), CancellationToken.None);
            var tablePlan = new DeltaTablePlan(delta.Table, delta.InsertCount, delta.UpdateCount,
                delta.DeleteCount, delta.UnchangedCount,
                DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(delta.Operations), delta.Operations);
            DeltaCapturedTableArtifact selected = await archive.CapturePlannedRowsAsync(full,
                "Quotation", table, new('a', 64), tablePlan, key, CancellationToken.None);
            using var captured = new DeltaCapturedTableRowSource(archive, [selected], new('a', 64), key);
            var database = new DeltaDatabasePlan("Quotation", [tablePlan]);
            var schema = new DatabaseSchemaPlan("Quotation", "1.0", new('b', 64), new('c', 64), [table]);

            Assert.Equal(2, await PairedLocalTransitionPreflight.VerifyCapturedRowsAsync(database,
                schema, captured, new InMemoryTarget(originalTarget), CancellationToken.None));
            DeltaExecutionException changed = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                PairedLocalTransitionPreflight.VerifyCapturedRowsAsync(database, schema, captured,
                    new InMemoryTarget([Row(2, "changed")]), CancellationToken.None));
            Assert.Equal("delta_execution_target_row_drift", changed.Code);
            DeltaExecutionException replayedInsert = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                PairedLocalTransitionPreflight.VerifyCapturedRowsAsync(database, schema, captured,
                    new InMemoryTarget([Row(1, "already there"), Row(2, "old")]), CancellationToken.None));
            Assert.Equal("delta_capture_target_drift", replayedInsert.Code);
            await File.AppendAllTextAsync(Path.Combine(directory, selected.CaptureId.ToString("N") + ".enc"),
                "tampered");
            DeltaPlanException changedCapture = await Assert.ThrowsAsync<DeltaPlanException>(() =>
                PairedLocalTransitionPreflight.VerifyCapturedRowsAsync(database, schema, captured,
                    new InMemoryTarget(originalTarget), CancellationToken.None));
            Assert.Equal("delta_capture_artifact_invalid", changedCapture.Code);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Resolves_only_signed_captured_rows_despite_later_source_insert()
    {
        string directory = NewDirectory();
        try
        {
            TableCopyPlan table = Table();
            byte[] key = RandomNumberGenerator.GetBytes(32);
            var liveRows = new List<MigrationRow> { Row(1, "insert"), Row(2, "updated"), Row(4, "same") };
            MigrationRow[] targetRows = [Row(2, "old"), Row(3, "delete"), Row(4, "same")];
            var archive = new DeltaCapturedTableArchive(directory);
            DeltaCapturedTableArtifact full = await archive.CaptureAsync("Quotation", table,
                new('a', 64), Rows(liveRows), key, CancellationToken.None);
            CanonicalTableDelta delta = await CanonicalAsyncDeltaPlanner.PlanAsync(table,
                archive.ReplayAsync(full, "Quotation", table, new('a', 64), key, CancellationToken.None),
                Rows(targetRows), CancellationToken.None);
            var plan = new DeltaTablePlan(delta.Table, delta.InsertCount, delta.UpdateCount,
                delta.DeleteCount, delta.UnchangedCount,
                DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(delta.Operations), delta.Operations);
            DeltaCapturedTableArtifact selected = await archive.CapturePlannedRowsAsync(full,
                "Quotation", table, new('a', 64), plan, key, CancellationToken.None);
            liveRows.Add(Row(5, "arrived after snapshot"));

            using var captured = new DeltaCapturedTableRowSource(archive, [selected], new('a', 64), key);
            var provider = new CapturedDeltaExecutionRowSessionProvider(captured, new InMemoryTarget(targetRows));
            await using IDeltaExecutionRowSession session = await provider.OpenAsync("Quotation", table, CancellationToken.None);
            var resolved = new List<ResolvedDeltaRow>();
            await foreach (ResolvedDeltaRow row in session.ResolveAsync(plan, CancellationToken.None))
            {
                resolved.Add(row);
            }

            Assert.Equal([DeltaOperationKind.Insert, DeltaOperationKind.Update, DeltaOperationKind.Delete],
                resolved.Select(row => row.Operation.Kind));
            Assert.Equal([1, 2], resolved.Take(2).Select(row => row.Source!.Values["ID"]));
            Assert.Equal(3, resolved[2].Target!.Values["ID"]);
            Assert.DoesNotContain(resolved, row => Equals(row.Source?.Values["ID"], 5));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Rejects_planned_target_drift_before_yielding_any_rows(bool insertCollision)
    {
        string directory = NewDirectory();
        try
        {
            TableCopyPlan table = Table();
            byte[] key = RandomNumberGenerator.GetBytes(32);
            var archive = new DeltaCapturedTableArchive(directory);
            DeltaCapturedTableArtifact full = await archive.CaptureAsync("Quotation", table,
                new('a', 64), Rows([Row(1, "new")]), key, CancellationToken.None);
            MigrationRow[] initialTarget = [Row(2, "old")];
            CanonicalTableDelta delta = await CanonicalAsyncDeltaPlanner.PlanAsync(table,
                archive.ReplayAsync(full, "Quotation", table, new('a', 64), key, CancellationToken.None),
                Rows(initialTarget), CancellationToken.None);
            var plan = new DeltaTablePlan(delta.Table, delta.InsertCount, delta.UpdateCount,
                delta.DeleteCount, delta.UnchangedCount,
                DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(delta.Operations), delta.Operations);
            DeltaCapturedTableArtifact selected = await archive.CapturePlannedRowsAsync(full,
                "Quotation", table, new('a', 64), plan, key, CancellationToken.None);
            MigrationRow[] drifted = insertCollision
                ? [Row(1, "collision"), Row(2, "old")]
                : [Row(2, "changed")];

            using var captured = new DeltaCapturedTableRowSource(archive, [selected], new('a', 64), key);
            var provider = new CapturedDeltaExecutionRowSessionProvider(captured, new InMemoryTarget(drifted));
            await using IDeltaExecutionRowSession session = await provider.OpenAsync("Quotation", table, CancellationToken.None);
            DeltaExecutionException error = await Assert.ThrowsAsync<DeltaExecutionException>(async () =>
            {
                await foreach (ResolvedDeltaRow _ in session.ResolveAsync(plan, CancellationToken.None)) { }
            });
            Assert.Equal(insertCollision ? "delta_capture_target_drift" : "delta_execution_target_row_drift", error.Code);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string NewDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "captured-exec-" + Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(path);
        return path;
    }

    private static TableCopyPlan Table()
    {
        return new("dbo", "Items", "public", "Items", ["ID", "Name"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "integer",
                ["Name"] = "text",
            },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Items", ["ID"]),
        };
    }

    private static MigrationRow Row(int id, string name)
    {
        return new(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = id,
            ["Name"] = name,
        });
    }

    private static async IAsyncEnumerable<MigrationRow> Rows(IEnumerable<MigrationRow> rows)
    {
        foreach (MigrationRow row in rows)
        {
            await Task.Yield();
            yield return row;
        }
    }

    private sealed class InMemoryTarget(IReadOnlyList<MigrationRow> rows) : IDeltaOrderedRowSource
    {
        public IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            CancellationToken cancellationToken)
        {
            return Rows(rows);
        }
    }
}
