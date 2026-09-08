using System.Collections.ObjectModel;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CanonicalDeltaPlannerTests
{
    [Fact]
    public void Classifies_insert_update_delete_and_unchanged_without_row_payloads()
    {
        TableCopyPlan table = Plan(["Id"], ["Id", "Name"]);
        MigrationRow[] source = [Row(1, "same"), Row(2, "changed"), Row(4, "new")];
        MigrationRow[] target = [Row(1, "same"), Row(2, "old"), Row(3, "removed")];

        CanonicalTableDelta result = CanonicalDeltaPlanner.Plan(table, source, target);

        Assert.Equal(1, result.InsertCount);
        Assert.Equal(1, result.UpdateCount);
        Assert.Equal(1, result.DeleteCount);
        Assert.Equal(1, result.UnchangedCount);
        Assert.Equal(
            [DeltaOperationKind.Update, DeltaOperationKind.Delete, DeltaOperationKind.Insert],
            result.Operations.Select(operation => operation.Kind));
        Assert.All(result.Operations, operation =>
        {
            Assert.Matches("^[0-9a-f]{64}$", operation.KeySha256);
            Assert.DoesNotContain("changed", operation.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("removed", operation.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("new", operation.ToString(), StringComparison.Ordinal);
        });
    }

    [Fact]
    public void Supports_composite_keys_and_canonical_values()
    {
        TableCopyPlan table = Plan(
            ["Tenant", "Id"],
            ["Tenant", "Id", "Thai", "Amount", "OccurredAt", "Payload"],
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Tenant"] = "integer",
                ["Id"] = "bigint",
                ["Thai"] = "text",
                ["Amount"] = "numeric(18,4)",
                ["OccurredAt"] = "timestamp without time zone",
                ["Payload"] = "bytea",
            });
        var timestamp = new DateTime(2026, 9, 8, 12, 46, 19, 589, DateTimeKind.Unspecified).AddTicks(390);
        MigrationRow row = new(new ReadOnlyDictionary<string, object?>(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["Tenant"] = 7,
            ["Id"] = 9L,
            ["Thai"] = "ทดสอบภาษาไทย",
            ["Amount"] = 1234.5600m,
            ["OccurredAt"] = timestamp,
            ["Payload"] = new byte[] { 0, 1, 254, 255 },
        }));

        CanonicalTableDelta result = CanonicalDeltaPlanner.Plan(table, [row], []);

        CanonicalDeltaOperation operation = Assert.Single(result.Operations);
        Assert.Equal(DeltaOperationKind.Insert, operation.Kind);
        Assert.Null(operation.TargetRowSha256);
        Assert.Matches("^[0-9a-f]{64}$", operation.SourceRowSha256);
    }

    [Fact]
    public void Treats_null_non_key_values_as_canonical_changes()
    {
        TableCopyPlan table = Plan(["Id"], ["Id", "Name"]);
        MigrationRow source = new(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = null });
        MigrationRow target = new(new Dictionary<string, object?> { ["Id"] = 1, ["Name"] = "previous" });

        CanonicalTableDelta result = CanonicalDeltaPlanner.Plan(table, [source], [target]);

        CanonicalDeltaOperation operation = Assert.Single(result.Operations);
        Assert.Equal(DeltaOperationKind.Update, operation.Kind);
        Assert.NotEqual(operation.SourceRowSha256, operation.TargetRowSha256);
    }

    [Fact]
    public void Compares_compatible_integral_key_types_without_false_changes()
    {
        TableCopyPlan table = Plan(["Id"], ["Id", "Name"]);
        MigrationRow source = Row(9, "same");
        MigrationRow target = Row(9L, "same");

        CanonicalTableDelta result = CanonicalDeltaPlanner.Plan(table, [source], [target]);

        Assert.Empty(result.Operations);
        Assert.Equal(1, result.UnchangedCount);
    }

    [Theory]
    [InlineData("missing-primary-key")]
    [InlineData("null-key")]
    [InlineData("missing-column")]
    [InlineData("duplicate-key")]
    [InlineData("out-of-order")]
    public void Fails_closed_for_unsafe_or_ambiguous_input(string scenario)
    {
        TableCopyPlan table = Plan(["Id"], ["Id", "Name"]);
        MigrationRow[] source = [Row(1, "private-source-value")];
        if (scenario == "missing-primary-key") { table = table with { PrimaryKey = null }; }
        if (scenario == "null-key") { source = [Row(null, "private-source-value")]; }
        if (scenario == "missing-column")
        {
            source = [new MigrationRow(new Dictionary<string, object?> { ["Id"] = 1 })];
        }
        if (scenario == "duplicate-key") { source = [Row(1, "private-source-value"), Row(1, "private-target-value")]; }
        if (scenario == "out-of-order") { source = [Row(2, "private-source-value"), Row(1, "private-target-value")]; }

        DeltaPlanningException exception = Assert.Throws<DeltaPlanningException>(
            () => CanonicalDeltaPlanner.Plan(table, source, []));

        Assert.DoesNotContain("private-source-value", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("private-target-value", exception.Message, StringComparison.Ordinal);
        Assert.StartsWith("delta_", exception.Code, StringComparison.Ordinal);
    }

    private static MigrationRow Row(object? id, string name)
    {
        return new(new ReadOnlyDictionary<string, object?>(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["Id"] = id,
            ["Name"] = name,
        }));
    }

    private static TableCopyPlan Plan(
        IReadOnlyList<string> keys,
        IReadOnlyList<string> columns,
        IReadOnlyDictionary<string, string>? types = null)
    {
        types ??= columns.ToDictionary(
            column => column,
            column => string.Equals(column, "Id", StringComparison.Ordinal) ? "integer" : "text",
            StringComparer.Ordinal);
        return new TableCopyPlan("dbo", "Source", "public", "target", columns, keys)
        {
            ColumnTypes = types,
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Source", keys),
        };
    }
}
