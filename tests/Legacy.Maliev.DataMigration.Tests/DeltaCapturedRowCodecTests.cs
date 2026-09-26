using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DeltaCapturedRowCodecTests
{
    [Fact]
    public async Task EncryptedCapture_RoundTripsScalarsAndLargeValueWithoutPlaintextArtifact()
    {
        TableCopyPlan table = Table();
        byte[] large = RandomNumberGenerator.GetBytes(3 * 1024 * 1024);
        MigrationRow first = Row(1, "งานผลิตภาษาไทย", 12345.6789m,
            new DateTime(2026, 9, 26, 1, 2, 3, DateTimeKind.Unspecified),
            new StreamingLob(StreamingLobKind.Binary, large.Length,
                async (output, token) => await output.WriteAsync(large, token)),
            Guid.Parse("11111111-2222-3333-4444-555555555555"));
        MigrationRow second = Row(2, "English", 0.01m,
            new DateTime(2026, 9, 26, 1, 2, 4, DateTimeKind.Unspecified), null, null);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        SnapshotArchiveContext context = SnapshotArchiveContext.Create("delta-capture-test", "Quotation", new string('a', 64));
        using var encrypted = new MemoryStream();

        SnapshotEncryptionResult result = await DeltaCapturedRowCodec.EncryptAsync(table,
            Rows(first, second), encrypted, key, context, CancellationToken.None);
        Assert.True(result.PlaintextByteLength > large.Length);
        Assert.InRange(result.MaximumPlaintextChunkBytes, 1, 1024 * 1024);
        Assert.DoesNotContain(Encoding.UTF8.GetBytes("งานผลิตภาษาไทย"), encrypted.ToArray());

        encrypted.Position = 0;
        var restored = new List<MigrationRow>();
        await foreach (MigrationRow row in DeltaCapturedRowCodec.DecryptAsync(
            table, encrypted, key, context, CancellationToken.None))
        {
            if (row.Values["Payload"] is StreamingLob lob)
            {
                using var bytes = new MemoryStream();
                await lob.ConsumeAsync(bytes, CancellationToken.None);
                Assert.Equal(large, bytes.ToArray());
            }
            restored.Add(row);
        }
        Assert.Equal(2, restored.Count);
        Assert.Equal("งานผลิตภาษาไทย", restored[0].Values["Name"]);
        Assert.Equal(12345.6789m, restored[0].Values["Amount"]);
        Assert.Equal(first.Values["OccurredUtc"], restored[0].Values["OccurredUtc"]);
        Assert.Equal(first.Values["EventId"], restored[0].Values["EventId"]);
        Assert.Null(restored[1].Values["Payload"]);
        Assert.Null(restored[1].Values["EventId"]);
    }

    [Fact]
    public async Task ChangedCiphertextOrTableIdentity_FailsClosed()
    {
        TableCopyPlan table = Table();
        byte[] key = RandomNumberGenerator.GetBytes(32);
        SnapshotArchiveContext context = SnapshotArchiveContext.Create("delta-capture-test", "Quotation", new string('a', 64));
        using var encrypted = new MemoryStream();
        _ = await DeltaCapturedRowCodec.EncryptAsync(table,
            Rows(Row(1, "safe", 1m, DateTime.UnixEpoch, null, null)),
            encrypted, key, context, CancellationToken.None);
        byte[] damaged = encrypted.ToArray();
        damaged[40] ^= 0x01;
        _ = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await foreach (MigrationRow _ in DeltaCapturedRowCodec.DecryptAsync(
                table, new MemoryStream(damaged), key, context, CancellationToken.None)) { }
        });

        encrypted.Position = 0;
        _ = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await foreach (MigrationRow _ in DeltaCapturedRowCodec.DecryptAsync(
                table with { SourceTable = "Other" }, encrypted, key, context, CancellationToken.None)) { }
        });

        encrypted.Position = 0;
        TableCopyPlan changed = table with
        {
            ColumnTypes = table.ColumnTypes.ToDictionary(pair => pair.Key,
                pair => pair.Key == "Amount" ? "numeric(18,2)" : pair.Value, StringComparer.Ordinal),
        };
        _ = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await foreach (MigrationRow _ in DeltaCapturedRowCodec.DecryptAsync(
                changed, encrypted, key, context, CancellationToken.None)) { }
        });
    }

    [Fact]
    public async Task UnconsumedLargeValue_RejectsAdvancingTheCapture()
    {
        TableCopyPlan table = Table();
        byte[] key = RandomNumberGenerator.GetBytes(32);
        SnapshotArchiveContext context = SnapshotArchiveContext.Create("delta-capture-test", "Quotation", new string('a', 64));
        using var encrypted = new MemoryStream();
        _ = await DeltaCapturedRowCodec.EncryptAsync(table,
            Rows(Row(1, "one", 1m, DateTime.UnixEpoch,
                new StreamingLob(StreamingLobKind.Binary, 3,
                    async (output, token) => await output.WriteAsync(new byte[] { 1, 2, 3 }, token)), null)),
            encrypted, key, context, CancellationToken.None);
        encrypted.Position = 0;
        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(async () =>
        {
            await foreach (MigrationRow _ in DeltaCapturedRowCodec.DecryptAsync(
                table, encrypted, key, context, CancellationToken.None)) { }
        });
        Assert.Equal("delta_capture_lob_not_consumed", exception.Code);
    }

    [Fact]
    public async Task Capture_RoundTripsRemainingSqlScalarTypesAndStreamedThaiText()
    {
        string thai = string.Concat(Enumerable.Repeat("ทดสอบข้อมูลภาษาไทย", 30_000));
        byte[] thaiBytes = Encoding.UTF8.GetBytes(thai);
        string[] columns = ["ID", "Small", "Tiny", "Flag", "Real", "Float", "Offset", "Clock", "Day", "Text"];
        var table = new TableCopyPlan("dbo", "Types", "public", "Types", columns, ["ID"])
        {
            ColumnTypes = columns.ToDictionary(column => column, _ => "text", StringComparer.Ordinal),
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Types", ["ID"]),
        };
        var original = new MigrationRow(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = 1L,
            ["Small"] = (short)-25,
            ["Tiny"] = (byte)255,
            ["Flag"] = true,
            ["Real"] = 1.25f,
            ["Float"] = 3.14159d,
            ["Offset"] = new DateTimeOffset(2026, 9, 26, 7, 30, 0, TimeSpan.FromHours(7)),
            ["Clock"] = new TimeSpan(12, 34, 56),
            ["Day"] = new DateOnly(2026, 9, 26),
            ["Text"] = new StreamingLob(StreamingLobKind.Text, thaiBytes.Length,
                async (output, token) => await output.WriteAsync(thaiBytes, token)),
        });
        byte[] key = RandomNumberGenerator.GetBytes(32);
        SnapshotArchiveContext context = SnapshotArchiveContext.Create("type-capture", "Quotation", new string('b', 64));
        using var encrypted = new MemoryStream();
        _ = await DeltaCapturedRowCodec.EncryptAsync(table, Rows(original), encrypted, key, context, CancellationToken.None);
        encrypted.Position = 0;
        await foreach (MigrationRow row in DeltaCapturedRowCodec.DecryptAsync(
            table, encrypted, key, context, CancellationToken.None))
        {
            foreach (string column in columns.Except(["Text"], StringComparer.Ordinal))
            {
                Assert.Equal(original.Values[column], row.Values[column]);
            }
            var lob = Assert.IsType<StreamingLob>(row.Values["Text"]);
            using var bytes = new MemoryStream();
            await lob.ConsumeAsync(bytes, CancellationToken.None);
            Assert.Equal(thaiBytes, bytes.ToArray());
        }
    }

    [Fact]
    public async Task DuplicateKeysAndUnsupportedValues_RejectBeforePublishingCapture()
    {
        TableCopyPlan table = Table();
        using var output = new MemoryStream();
        MigrationRow first = Row(1, "one", 1m, DateTime.UnixEpoch, null, null);
        DeltaPlanningException duplicate = await Assert.ThrowsAsync<DeltaPlanningException>(() =>
            DeltaCapturedRowCodec.WriteAsync(table, Rows(first, first), output, CancellationToken.None));
        Assert.Equal("delta_capture_key_order_invalid", duplicate.Code);

        MigrationRow unsupported = first with
        {
            Values = new Dictionary<string, object?>(first.Values, StringComparer.Ordinal)
            {
                ["Name"] = new object(),
            },
        };
        using var secondOutput = new MemoryStream();
        DeltaPlanningException type = await Assert.ThrowsAsync<DeltaPlanningException>(() =>
            DeltaCapturedRowCodec.WriteAsync(table, Rows(unsupported), secondOutput, CancellationToken.None));
        Assert.Equal("delta_capture_type_unsupported", type.Code);

        MigrationRow oversized = Row(1, new string('a', (4 * 1024 * 1024) + 1), 1m,
            DateTime.UnixEpoch, null, null);
        using var thirdOutput = new MemoryStream();
        DeltaPlanningException bounded = await Assert.ThrowsAsync<DeltaPlanningException>(() =>
            DeltaCapturedRowCodec.WriteAsync(table, Rows(oversized), thirdOutput, CancellationToken.None));
        Assert.Equal("delta_capture_header_too_large", bounded.Code);
    }

    private static TableCopyPlan Table()
    {
        string[] columns = ["ID", "Name", "Amount", "OccurredUtc", "Payload", "EventId"];
        return new("dbo", "CaptureProbe", "public", "CaptureProbe", columns, ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "integer",
                ["Name"] = "text",
                ["Amount"] = "numeric(18,4)",
                ["OccurredUtc"] = "timestamp without time zone",
                ["Payload"] = "bytea",
                ["EventId"] = "uuid",
            },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_CaptureProbe", ["ID"]),
        };
    }

    private static MigrationRow Row(int id, string name, decimal amount, DateTime occurredUtc,
        StreamingLob? payload, Guid? eventId)
    {
        return new(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = id,
            ["Name"] = name,
            ["Amount"] = amount,
            ["OccurredUtc"] = occurredUtc,
            ["Payload"] = payload,
            ["EventId"] = eventId,
        });
    }

    private static async IAsyncEnumerable<MigrationRow> Rows(params MigrationRow[] rows)
    {
        foreach (MigrationRow row in rows)
        {
            await Task.Yield();
            yield return row;
        }
    }
}
