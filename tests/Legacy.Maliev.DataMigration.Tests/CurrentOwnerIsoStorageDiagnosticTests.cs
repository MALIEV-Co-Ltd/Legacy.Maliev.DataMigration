using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentOwnerIsoStorageDiagnosticTests
{
    [Theory]
    [InlineData(754u, 764u, 764u)]
    [InlineData(754u, 764u, 780u)]
    [InlineData(4294967290u, 4u, 5u)]
    public void Actual_rewrite_freeze_boundary_advances_only_within_observed_snapshot(uint before, uint after, uint horizon)
    {
        var left = Row(); left["relfrozenxid"] = before.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var right = Row(); right["relfrozenxid"] = after.ToString(System.Globalization.CultureInfo.InvariantCulture);
        CurrentOwnerIsoNativePreservation.RequireFrozenXidProgression(left, right, horizon);
    }

    [Theory]
    [InlineData(754u, 753u, 764u)]
    [InlineData(754u, 765u, 764u)]
    [InlineData(754u, 2u, 764u)]
    [InlineData(754u, 764u, 0u)]
    [InlineData(4u, 4294967290u, 5u)]
    public void Regressed_future_special_or_unobserved_freeze_boundary_is_rejected(uint before, uint after, uint horizon)
    {
        var left = Row(); left["relfrozenxid"] = before.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var right = Row(); right["relfrozenxid"] = after.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var error = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequireFrozenXidProgression(left, right, horizon));
        Assert.Equal("current_owner_iso_native_heap_freeze_boundary", error.Code);
    }

    [Fact]
    public void Diagnostic_binds_catalog_metadata_to_actual_selected_storage_without_changing_it()
    {
        var row = Row();
        string original = row.ToJsonString();
        var frame = CurrentOwnerIsoNativePreservation.DescribeStorage(row, new(42, 2, 8), 8, true, false);
        Assert.Equal("80", frame.ObjectId);
        Assert.Equal("Country", frame.Relation);
        Assert.Equal("r", frame.Kind);
        Assert.True(frame.Rebuilt);
        Assert.False(frame.Index);
        Assert.Equal("42", frame.CatalogFileNode);
        Assert.Equal(42u, frame.ActualFileNode);
        Assert.Equal(2, frame.ActualBlocks);
        Assert.Equal(8L, frame.ActualRows);
        Assert.Equal(8, frame.ExpectedTuples);
        Assert.Equal(1, frame.CatalogPages);
        Assert.Equal("8", frame.CatalogTuples);
        Assert.Equal(0, frame.CatalogAllVisible);
        Assert.Equal(0, frame.CatalogAllFrozen);
        Assert.Equal(original, row.ToJsonString());
        var rejection = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequireStorage(row, new(42, 2, 0), 8, true, true));
        Assert.Equal("current_owner_iso_native_physical_storage", rejection.Code);
        Assert.Contains("\"CatalogPages\":1", rejection.Message, StringComparison.Ordinal);
        Assert.Contains("\"ActualBlocks\":2", rejection.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("relpages")]
    [InlineData("reltuples")]
    public void Rebuilt_heap_requires_unchanged_pair_statistics_even_when_each_value_is_bounded(string field)
    {
        var before = Row(); before["relpages"] = 0; before["reltuples"] = -1;
        var after = (JsonObject)before.DeepClone(); after["relfilenode"] = 43;
        CurrentOwnerIsoNativePreservation.RequireStorage(after, new(43, 1, 8), 8, true, false);
        CurrentOwnerIsoNativePreservation.RequireHeapStatisticsPreserved(before, after);
        after[field] = field == "relpages" ? 1 : 0;
        CurrentOwnerIsoNativePreservation.RequireStorage(after, new(43, 1, 8), 8, true, false);
        var rejection = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequireHeapStatisticsPreserved(before, after));
        Assert.Equal("current_owner_iso_native_heap_statistics", rejection.Code);
    }

    [Fact]
    public void Index_diagnostic_does_not_label_the_capture_placeholder_as_a_measured_row_count()
    {
        var row = Row(); row["relname"] = "PK_Country"; row["relkind"] = "i";
        var frame = CurrentOwnerIsoNativePreservation.DescribeStorage(row, new(42, 2, 0), 8, true, true);
        Assert.Null(frame.ActualRows);
        Assert.Equal(8, frame.ExpectedTuples);
    }

    [Theory]
    [InlineData("NaN")]
    [InlineData("Infinity")]
    [InlineData("-Infinity")]
    public void Rejected_nonfinite_tuple_counts_remain_controlled_failures(string value)
    {
        var row = Row(); row["reltuples"] = value;
        var rejection = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequireStorage(row, new(42, 1, 8), 8, true, false));
        Assert.Equal("current_owner_iso_native_physical_storage", rejection.Code);
        Assert.Contains(value, rejection.Message, StringComparison.Ordinal);
    }

    private static JsonObject Row()
    {
        return new()
        {
            ["oid"] = 80,
            ["relname"] = "Country",
            ["relkind"] = "r",
            ["relfilenode"] = 42,
            ["relpages"] = 1,
            ["reltuples"] = 8,
            ["relallvisible"] = 0,
            ["relallfrozen"] = 0,
        };
    }
}
