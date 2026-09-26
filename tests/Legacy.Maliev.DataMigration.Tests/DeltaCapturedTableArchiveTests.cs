using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DeltaCapturedTableArchiveTests
{
    [Fact]
    public async Task Captured_rows_are_immutable_when_live_source_changes_after_snapshot()
    {
        string directory = NewDirectory();
        try
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            var source = new List<MigrationRow> { Row(1, "งานผลิต"), Row(2, "original") };
            var archive = new DeltaCapturedTableArchive(directory);
            DeltaCapturedTableArtifact artifact = await archive.CaptureAsync("Quotation", Table(),
                new('a', 64), Rows(source), key, CancellationToken.None);
            source[1] = Row(2, "changed after capture");
            source.Add(Row(3, "new after capture"));

            var replayed = new List<MigrationRow>();
            await foreach (MigrationRow row in archive.ReplayAsync(artifact, "Quotation", Table(), new('a', 64), key, CancellationToken.None))
            {
                replayed.Add(row);
            }

            Assert.Equal(2, artifact.RowCount);
            Assert.Equal(["งานผลิต", "original"], replayed.Select(row => row.Values["Name"]));
            Assert.Matches("^[0-9a-f]{64}$", artifact.EncryptedSha256);
            Assert.Matches("^[0-9a-f]{64}$", artifact.PlaintextSha256);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Ciphertext_table_schema_and_key_drift_fail_before_replay()
    {
        string directory = NewDirectory();
        try
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            var archive = new DeltaCapturedTableArchive(directory);
            DeltaCapturedTableArtifact artifact = await archive.CaptureAsync("Quotation", Table(),
                new('a', 64), Rows([Row(1, "safe")]), key, CancellationToken.None);

            _ = await Assert.ThrowsAnyAsync<Exception>(async () =>
            {
                await foreach (MigrationRow _ in archive.ReplayAsync(
                    artifact, "Quotation", Table() with { SourceTable = "Changed" }, new('a', 64), key, CancellationToken.None)) { }
            });
            _ = await Assert.ThrowsAnyAsync<Exception>(async () =>
            {
                await foreach (MigrationRow _ in archive.ReplayAsync(
                    artifact, "OtherDatabase", Table(), new('a', 64), key, CancellationToken.None)) { }
            });
            _ = await Assert.ThrowsAnyAsync<Exception>(async () =>
            {
                await foreach (MigrationRow _ in archive.ReplayAsync(
                    artifact, "Quotation", Table(), new('b', 64), key, CancellationToken.None)) { }
            });
            _ = await Assert.ThrowsAnyAsync<Exception>(async () =>
            {
                await foreach (MigrationRow _ in archive.ReplayAsync(
                    artifact, "Quotation", Table(), new('a', 64), RandomNumberGenerator.GetBytes(32), CancellationToken.None)) { }
            });
            DeltaPlanException wrongPlaintext = await Assert.ThrowsAsync<DeltaPlanException>(async () =>
            {
                await foreach (MigrationRow _ in archive.ReplayAsync(
                    artifact with { PlaintextSha256 = new('f', 64) }, "Quotation", Table(),
                    new('a', 64), key, CancellationToken.None)) { }
            });
            Assert.Equal("delta_capture_artifact_invalid", wrongPlaintext.Code);

            string path = Path.Combine(directory, $"{artifact.CaptureId:N}.enc");
            byte[] bytes = await File.ReadAllBytesAsync(path);
            bytes[40] ^= 0x01;
            await File.WriteAllBytesAsync(path, bytes);
            DeltaPlanException error = await Assert.ThrowsAsync<DeltaPlanException>(async () =>
            {
                await foreach (MigrationRow _ in archive.ReplayAsync(
                    artifact, "Quotation", Table(), new('a', 64), key, CancellationToken.None)) { }
            });
            Assert.Equal("delta_capture_artifact_invalid", error.Code);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Delta_planning_from_capture_ignores_later_live_source_inserts()
    {
        string directory = NewDirectory();
        try
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            var source = new List<MigrationRow> { Row(1, "captured") };
            var archive = new DeltaCapturedTableArchive(directory);
            DeltaCapturedTableArtifact artifact = await archive.CaptureAsync("Quotation", Table(),
                new('a', 64), Rows(source), key, CancellationToken.None);
            source.Add(Row(2, "later live write"));
            using var capturedRows = new DeltaCapturedTableRowSource(archive, [artifact], new('a', 64), key);

            CanonicalTableDelta delta = await CanonicalAsyncDeltaPlanner.PlanAsync(Table(),
                capturedRows.ReadOrderedAsync("Quotation", Table(), CancellationToken.None),
                Rows([]), CancellationToken.None);

            _ = Assert.Single(delta.Operations);
            Assert.Equal(DeltaOperationKind.Insert, delta.Operations[0].Kind);
            Assert.Equal(1, delta.InsertCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Selected_capture_contains_only_planned_changed_rows()
    {
        string directory = NewDirectory();
        try
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            var archive = new DeltaCapturedTableArchive(directory);
            TableCopyPlan table = Table();
            MigrationRow changed = Row(2, "updated");
            DeltaCapturedTableArtifact full = await archive.CaptureAsync("Quotation", table,
                new('a', 64), Rows([Row(1, "unchanged"), changed]), key, CancellationToken.None);
            CanonicalDeltaOperation operation = CanonicalDeltaPlanner.Create(
                DeltaOperationKind.Insert, table, changed, null);
            var plan = new DeltaTablePlan("public.Items", 1, 0, 0, 1,
                DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([operation]), [operation]);

            DeltaCapturedTableArtifact selected = await archive.CapturePlannedRowsAsync(full,
                "Quotation", table, new('a', 64), plan, key, CancellationToken.None);

            Assert.Equal(1, selected.RowCount);
            var replayed = new List<MigrationRow>();
            await foreach (MigrationRow row in archive.ReplayAsync(selected,
                "Quotation", table, new('a', 64), key, CancellationToken.None))
            {
                replayed.Add(row);
            }
            Assert.Equal("updated", Assert.Single(replayed).Values["Name"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Selected_capture_rejects_a_missing_or_changed_planned_row()
    {
        string directory = NewDirectory();
        try
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            var archive = new DeltaCapturedTableArchive(directory);
            TableCopyPlan table = Table();
            DeltaCapturedTableArtifact full = await archive.CaptureAsync("Quotation", table,
                new('a', 64), Rows([Row(1, "original")]), key, CancellationToken.None);
            CanonicalDeltaOperation changed = CanonicalDeltaPlanner.Create(
                DeltaOperationKind.Insert, table, Row(1, "different"), null);
            CanonicalDeltaOperation missing = CanonicalDeltaPlanner.Create(
                DeltaOperationKind.Insert, table, Row(2, "missing"), null);
            foreach (CanonicalDeltaOperation operation in new[] { changed, missing })
            {
                var plan = new DeltaTablePlan("public.Items", 1, 0, 0, 0,
                    DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256([operation]), [operation]);
                DeltaPlanException failure = await Assert.ThrowsAsync<DeltaPlanException>(() =>
                    archive.CapturePlannedRowsAsync(full, "Quotation", table, new('a', 64),
                        plan, key, CancellationToken.None));
                Assert.Equal("delta_capture_operation_mismatch", failure.Code);
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string NewDirectory()
    {
        string root = Path.Combine(Path.GetTempPath(), "legacy-delta-capture-tests", Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(root);
        return root;
    }

    private static TableCopyPlan Table()
    {
        return new TableCopyPlan("dbo", "Items", "public", "Items", ["ID", "Name"], ["ID"])
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
}
