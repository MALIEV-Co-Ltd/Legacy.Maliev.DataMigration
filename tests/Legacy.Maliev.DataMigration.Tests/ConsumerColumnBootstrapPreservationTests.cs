using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsumerColumnBootstrapPreservationTests
{
    [Fact]
    public void New_security_version_is_one_canonical_reserved_option_within_the_creation_window()
    {
        ConsumerColumnBootstrapNativePreservation.RequireNewAttributeOptions(new JsonArray("pg_attver=210"), 180007, "error", 200, 300);
        ConsumerColumnBootstrapNativePreservation.RequireNewAttributeOptions(null, 180006, string.Empty, 200, 300);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("[\"pg_attver=0\"]")]
    [InlineData("[\"pg_attver=200\"]")]
    [InlineData("[\"pg_attver=301\"]")]
    [InlineData("[\"pg_attver=0210\"]")]
    [InlineData("[\"pg_attver=18446744073709551616\"]")]
    [InlineData("[\"pg_attver=xyz\"]")]
    [InlineData("[\"pg_attver=210\",\"pg_attver=210\"]")]
    [InlineData("[\"pg_attver=210\",\"n_distinct=-0.25\"]")]
    [InlineData("[210]")]
    [InlineData(/*lang=json,strict*/ "{\"pg_attver\":210}")]
    public void Any_missing_malformed_duplicate_user_option_or_out_of_window_creation_version_is_rejected(string json)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapNativePreservation.RequireNewAttributeOptions(JsonNode.Parse(json), 180007, "error", 200, 300));
    }

    [Theory]
    [InlineData("warning")]
    [InlineData("off")]
    [InlineData("")]
    public void Creation_version_cannot_disable_the_security_defense(string defense)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapNativePreservation.RequireNewAttributeOptions(new JsonArray("pg_attver=210"), 180007, defense, 200, 300));
    }

    [Fact]
    public void Legacy_provider_cannot_acquire_attribute_options_and_unknown_provider_is_rejected()
    {
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapNativePreservation.RequireNewAttributeOptions(new JsonArray("pg_attver=210"), 180006, string.Empty, 200, 300));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapNativePreservation.RequireNewAttributeOptions(new JsonArray("pg_attver=210"), 190000, "error", 200, 300));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(1, 2)]
    [InlineData(2, 2)]
    public void Only_observed_fixed_storage_transitions_are_supported(long before, long after)
    {
        ConsumerColumnBootstrapNativePreservation.RequireFixedStorage(2656, before, 2656, after, 2656);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    [InlineData(1, 3)]
    [InlineData(2, 1)]
    [InlineData(2, 3)]
    [InlineData(3, 3)]
    [InlineData(3, 4)]
    public void Arbitrary_growth_shrink_and_unobserved_preimages_are_rejected(long before, long after)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapNativePreservation.RequireFixedStorage(2656, before, 2656, after, 2656));
    }

    [Theory]
    [InlineData(2655U, 2656U)]
    [InlineData(2656U, 2655U)]
    [InlineData(2655U, 2655U)]
    public void Replaced_files_are_rejected_even_without_growth(uint before, uint after)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapNativePreservation.RequireFixedStorage(before, 1, after, 1, 2656));
    }

    [Fact]
    public void Catalog_inventory_is_detached_and_unique()
    {
        Assert.Equal(ConsumerColumnBootstrapNativePreservation.CatalogNames.Count, ConsumerColumnBootstrapNativePreservation.CatalogNames.Distinct(StringComparer.Ordinal).Count());
        Assert.Contains("pg_statistic_ext_data", ConsumerColumnBootstrapNativePreservation.CatalogNames);
        Assert.Contains("pg_shseclabel", ConsumerColumnBootstrapNativePreservation.CatalogNames);
        Assert.NotSame(ConsumerColumnBootstrapNativePreservation.CatalogNames, ConsumerColumnBootstrapNativePreservation.CatalogNames);
    }
}
