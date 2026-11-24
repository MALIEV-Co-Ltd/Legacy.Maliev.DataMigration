using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CustomerCompanyAttributeVersionTests
{
    private static readonly int[] Changed = [2, 3, 4];
    private static readonly int[] Affected = [2, 3, 4, 5];

    [Fact]
    public void Reserved_versions_follow_three_ordered_type_changes_and_preserve_user_options()
    {
        var (before, after) = Rows();
        var actual = Require(before, after);
        Assert.Equal(4, actual.Count);
        Assert.True(actual.SetEquals(Affected));
    }

    [Fact]
    public void Preupgrade_null_options_are_zero_versions_and_can_acquire_reserved_versions()
    {
        var (before, after) = Rows();
        foreach (JsonObject row in before) { row["attoptions"] = null; }
        after[1]["attoptions"] = new JsonArray("pg_attver=210"); after[0]["attoptions"] = null;
        Assert.Equal(4, Require(before, after).Count);
    }

    [Theory]
    [InlineData("malformed")]
    [InlineData("duplicate")]
    [InlineData("backwards")]
    [InlineData("beyond_wal")]
    [InlineData("prior_beyond_wal")]
    [InlineData("user_option")]
    [InlineData("unaffected")]
    [InlineData("tail")]
    [InlineData("wrong_order")]
    [InlineData("missing")]
    [InlineData("zero")]
    [InlineData("leading_zero")]
    [InlineData("overflow")]
    public void Invalid_versions_or_any_unreserved_option_change_fail_closed(string fault)
    {
        var (before, after) = Rows();
        switch (fault)
        {
            case "malformed": after[1]["attoptions"] = new JsonArray("pg_attver=xyz", "n_distinct=-0.25"); break;
            case "duplicate": after[1]["attoptions"] = new JsonArray("pg_attver=210", "pg_attver=210", "n_distinct=-0.25"); break;
            case "backwards": after[1]["attoptions"] = new JsonArray("pg_attver=100", "n_distinct=-0.25"); break;
            case "beyond_wal": after[1]["attoptions"] = new JsonArray("pg_attver=301", "n_distinct=-0.25"); break;
            case "prior_beyond_wal": before[1]["attoptions"] = new JsonArray("pg_attver=201", "n_distinct=-0.25"); break;
            case "user_option": after[1]["attoptions"] = new JsonArray("pg_attver=210", "n_distinct=-0.5"); break;
            case "unaffected": after[0]["attoptions"] = new JsonArray("pg_attver=210"); break;
            case "tail": after[4]["attoptions"] = new JsonArray("pg_attver=240"); break;
            case "wrong_order": after[2]["attoptions"] = new JsonArray("pg_attver=230"); break;
            case "missing": after[1]["attoptions"] = new JsonArray("n_distinct=-0.25"); break;
            case "zero": after[1]["attoptions"] = new JsonArray("pg_attver=0", "n_distinct=-0.25"); break;
            case "leading_zero": after[1]["attoptions"] = new JsonArray("pg_attver=0210", "n_distinct=-0.25"); break;
            case "overflow": after[1]["attoptions"] = new JsonArray("pg_attver=18446744073709551616", "n_distinct=-0.25"); break;
            default: throw new InvalidOperationException();
        }
        _ = Assert.Throws<MigrationExecutionException>(() => Require(before, after));
    }

    [Theory]
    [InlineData("warning")]
    [InlineData("off")]
    [InlineData("")]
    public void Security_defense_must_remain_error(string defense)
    {
        var (before, after) = Rows();
        _ = Assert.Throws<MigrationExecutionException>(() => CustomerCompanyStorageNativePreservation.RequireCompanyAttributeVersions(before, after, "100", Changed, 180007, defense, 200, 300));
    }

    [Fact]
    public void Legacy_provider_does_not_normalize_any_attribute_option()
    {
        var (before, after) = Rows();
        Assert.Empty(CustomerCompanyStorageNativePreservation.RequireCompanyAttributeVersions(before, after, "100", Changed, 180006, string.Empty, 200, 300));
    }

    private static IReadOnlySet<int> Require(JsonObject[] before, JsonObject[] after)
    {
        return CustomerCompanyStorageNativePreservation.RequireCompanyAttributeVersions(before, after, "100", Changed, 180007, "error", 200, 300);
    }

    private static (JsonObject[] Before, JsonObject[] After) Rows()
    {
        JsonObject[] before = [.. Enumerable.Range(1, 5).Select(number => new JsonObject
        { ["attrelid"] = "100", ["attnum"] = number, ["attoptions"] = number == 2 ? new JsonArray("pg_attver=100", "n_distinct=-0.25") : new JsonArray("pg_attver=100") })];
        JsonObject[] after = [.. before.Select(row => (JsonObject)row.DeepClone())];
        after[1]["attoptions"] = new JsonArray("n_distinct=-0.25", "pg_attver=210");
        after[2]["attoptions"] = new JsonArray("pg_attver=220"); after[3]["attoptions"] = new JsonArray("pg_attver=230"); after[4]["attoptions"] = new JsonArray("pg_attver=230");
        return (before, after);
    }
}
