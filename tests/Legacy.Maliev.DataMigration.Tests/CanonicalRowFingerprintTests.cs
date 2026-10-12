using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CanonicalRowFingerprintTests
{
    [Fact]
    public void Compute_UuidArrayBindsEveryElementOrderLengthAndNullSeparately()
    {
        TableCopyPlan table = CreatePlan("uuid[]");
        Guid first = Guid.Parse("11111111-1111-1111-1111-111111111111");
        Guid second = Guid.Parse("22222222-2222-2222-2222-222222222222");
        Guid third = Guid.Parse("33333333-3333-3333-3333-333333333333");
        Guid[][] values = [[], [first], [second], [first, second], [second, first], [first, third], [first, second, second]];
        string[] hashes = [.. values.Select(value => CanonicalRowFingerprint.Compute(table, [Row(value)]))];
        Assert.Equal(values.Length, hashes.Distinct(StringComparer.Ordinal).Count());
        Assert.All(values, value => Assert.Equal(
            CanonicalRowFingerprint.Compute(table, [Row(value)]),
            CanonicalRowFingerprint.Compute(table, [Row(value.ToArray())])));
        Assert.DoesNotContain(CanonicalRowFingerprint.Compute(table, [Row(null)]), hashes);
        Assert.DoesNotContain(CanonicalRowFingerprint.Compute(table, [Row(DBNull.Value)]), hashes);
        Assert.Equal(CanonicalRowFingerprint.Compute(table, [Row(null)]), CanonicalRowFingerprint.Compute(table, [Row(DBNull.Value)]));
    }

    [Fact]
    public void Compute_UuidArrayRejectsValuesThatCannotRepresentItsExactProviderShape()
    {
        TableCopyPlan table = CreatePlan("uuid[]");
        Guid value = Guid.Parse("11111111-1111-1111-1111-111111111111");
        object[] incompatible = ["{11111111-1111-1111-1111-111111111111}", value, new object[] { value }, new string[] { value.ToString("D") }, new int[] { 1 }, new Guid[1, 1], new Guid?[] { value, null }];
        foreach (object input in incompatible)
        {
            _ = Assert.Throws<InvalidOperationException>(() => CanonicalRowFingerprint.Compute(table, [Row(input)]));
        }
    }

    [Fact]
    public void Compute_ThaiUnicodeNormalizationDifference_RemainsDetectableForExactParity()
    {
        TableCopyPlan table = CreatePlan("text");
        MigrationRow composed = Row("é");
        MigrationRow decomposed = Row("é".Normalize(NormalizationForm.FormD));

        Assert.NotEqual(
            CanonicalRowFingerprint.Compute(table, [composed]),
            CanonicalRowFingerprint.Compute(table, [decomposed]));
    }

    [Fact]
    public void Compute_NullAndLiteralNullMarker_ProduceDifferentSemanticHashes()
    {
        TableCopyPlan table = CreatePlan("text");

        Assert.NotEqual(
            CanonicalRowFingerprint.Compute(table, [Row(null)]),
            CanonicalRowFingerprint.Compute(table, [Row("<NULL>")]));
    }

    [Fact]
    public void Compute_TimestampWithoutTimeZone_TruncatesToPostgreSqlMicroseconds()
    {
        TableCopyPlan table = CreatePlan("timestamp without time zone");
        DateTime precise = new DateTime(2026, 8, 29, 12, 30, 0, DateTimeKind.Unspecified).AddTicks(1_234_567);
        DateTime truncated = new(precise.Ticks - (precise.Ticks % TimeSpan.TicksPerMicrosecond), DateTimeKind.Unspecified);

        Assert.Equal(
            CanonicalRowFingerprint.Compute(table, [Row(precise)]),
            CanonicalRowFingerprint.Compute(table, [Row(truncated)]));
    }

    [Fact]
    public void Compute_TimestampWithTimeZone_UnspecifiedSqlServerDateTime_FailsClosed()
    {
        TableCopyPlan table = CreatePlan("timestamp with time zone");
        DateTime unspecified = new(2026, 8, 29, 12, 30, 0, DateTimeKind.Unspecified);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            CanonicalRowFingerprint.Compute(table, [Row(unspecified)]));

        Assert.Equal(
            "A timestamp with time zone value must carry an explicit UTC offset.",
            exception.Message);
    }

    [Fact]
    public void Compute_TextEncodedDateTimeOffset_DifferentOriginalOffsetsRemainDifferent()
    {
        TableCopyPlan table = CreatePlan("text");

        Assert.NotEqual(
            CanonicalRowFingerprint.Compute(table, [Row("2026-08-29T17:45:12.1234567+07:00")]),
            CanonicalRowFingerprint.Compute(table, [Row("2026-08-29T10:45:12.1234567+00:00")]));
    }

    [Fact]
    public void Compute_ColumnTypeChanges_ChangeSemanticHash()
    {
        Assert.NotEqual(
            CanonicalRowFingerprint.Compute(CreatePlan("text"), [Row("1")]),
            CanonicalRowFingerprint.Compute(CreatePlan("integer"), [Row("1")]));
    }

    [Fact]
    public void Compute_MissingPlannedColumn_RejectsRowShape()
    {
        TableCopyPlan table = CreatePlan("text");
        var row = new MigrationRow(new Dictionary<string, object?>());

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            CanonicalRowFingerprint.Compute(table, [row]));

        Assert.Equal("Migration row does not exactly match the approved column shape.", exception.Message);
    }

    [Fact]
    public void Compute_UnknownColumn_RejectsRowShape()
    {
        TableCopyPlan table = CreatePlan("text");
        var row = new MigrationRow(new Dictionary<string, object?>
        {
            ["Value"] = "approved",
            ["Unexpected"] = "forbidden",
        });

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            CanonicalRowFingerprint.Compute(table, [row]));

        Assert.Equal("Migration row does not exactly match the approved column shape.", exception.Message);
    }

    [Fact]
    public async Task Compute_BufferedStreamingValue_PreservesStreamingEvidenceHash()
    {
        TableCopyPlan table = CreatePlan("text");
        byte[] content = "ข้อความทดสอบ"u8.ToArray();
        var streaming = new StreamingLob(
            StreamingLobKind.Text,
            content.LongLength,
            async (destination, cancellationToken) =>
                await destination.WriteAsync(content, cancellationToken));
        await streaming.ConsumeAsync(Stream.Null, CancellationToken.None);
        var buffered = new BufferedStreamingLob(StreamingLobKind.Text, content);

        Assert.Equal(
            CanonicalRowFingerprint.Compute(table, [Row(streaming)]),
            CanonicalRowFingerprint.Compute(table, [Row(buffered)]));
    }

    private static TableCopyPlan CreatePlan(string type)
    {
        return new(
        "dbo",
        "Example",
        "public",
        "Example",
        ["Value"],
        ["Value"])
        {
            SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Value"] = "nvarchar" },
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal) { ["Value"] = type },
        };
    }

    private static MigrationRow Row(object? value)
    {
        return new(new Dictionary<string, object?> { ["Value"] = value });
    }
}
