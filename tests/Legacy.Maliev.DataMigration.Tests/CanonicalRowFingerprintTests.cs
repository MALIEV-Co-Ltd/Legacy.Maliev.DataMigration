using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CanonicalRowFingerprintTests
{
    [Fact]
    public void Compute_ThaiUnicodeNormalization_ProducesSameSemanticHash()
    {
        TableCopyPlan table = CreatePlan("text");
        MigrationRow composed = Row("กำ");
        MigrationRow decomposed = Row("กำ".Normalize(NormalizationForm.FormD));

        Assert.Equal(
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
