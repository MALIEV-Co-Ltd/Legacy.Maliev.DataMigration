namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsumerColumnBootstrapNativePreimageTests
{
    [Fact]
    public void Review_wal_is_monotonic_but_storage_and_settings_are_exact()
    {
        var before = Synthetic(); var provider = Provider(); DateTimeOffset now = ConsumerColumnBootstrapTestData.Now;
        var pin = ConsumerColumnBootstrapNativePreimage.Pin(before, provider, now);
        ConsumerColumnBootstrapNativePreimage.Require(pin, before with { WalUpper = 11 }, provider, now.AddMinutes(1));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapNativePreimage.Require(pin, before with { WalUpper = 9 }, provider, now));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapNativePreimage.Require(pin, before with
        { HeapStorage = new Dictionary<string, (uint File, long Blocks)> { ["synthetic-relation"] = (10, 2) } }, provider, now));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapNativePreimage.Require(pin, before,
            provider with { DatabaseSettingsSha256 = new string('b', 64) }, now));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapNativePreimage.Require(pin, before, provider, now.AddMinutes(16)));
    }

    [Fact]
    public void Cross_vendor_locale_provenance_does_not_replace_own_target_preimage()
    {
        var fixture = Provider(); var intended = fixture with
        { LocaleAndIcuProvenanceSha256 = new string('b', 64), DatabaseSettingsSha256 = new string('c', 64) };
        ConsumerColumnBootstrapProviderCompatibility.RequireCompatible(fixture, intended);
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapProviderCompatibility.RequireCompatible(fixture,
            intended with { EngineVersion = 180007, CompositeDefense = "error" }));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapProviderCompatibility.RequireCompatible(fixture,
            intended with { BuiltinTypeSemanticsSha256 = new string('d', 64) }));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapProviderCompatibility.RequireCompatible(fixture,
            intended with { CatalogVersion = 2 }));
    }

    // Hash-domain unit observations only. Empty synthetic catalogs are never native/proof authority.
    private static ConsumerColumnBootstrapPreservationObservation Synthetic()
    {
        var snapshot = new CurrentAppOwnedDatabaseSnapshot("CustomerIdentity", [], [], []);
        var native = new CurrentAppOwnedRetained31Observation(snapshot,
            new Dictionary<string, string[]> { ["pg_class"] = [/*lang=json,strict*/ "{\"oid\":123,\"relkind\":\"i\"}"] },
            new Dictionary<string, (uint FileNode, long Blocks)> { ["123"] = (400, 1) });
        return new(native, "CustomerIdentity", new string('a', 64), false,
            new("public", "AspNetUsers", 2, new string('a', 64)),
            new Dictionary<string, (uint File, long Blocks)> { ["synthetic-relation"] = (10, 1) }, 180004, string.Empty, 10);
    }

    private static ConsumerColumnBootstrapProviderObservation Provider()
    {
        return new(180004, 1, "UTF8", 8192, string.Empty,
        new string('a', 64), new string('a', 64), new string('a', 64));
    }
}
