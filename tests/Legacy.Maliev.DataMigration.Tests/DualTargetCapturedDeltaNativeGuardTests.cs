using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DualTargetCapturedDeltaNativeGuardTests
{
    [Theory]
    [InlineData("pg_proc")]
    [InlineData("pg_depend")]
    [InlineData("pg_authid")]
    [InlineData("pg_attribute")]
    public void Complete_catalog_multisets_reject_unrelated_rows_and_duplicates(string catalog)
    {
        var baseline = Observation();
        Require(baseline, Observation());
        _ = Assert.Throws<DeltaExecutionException>(() => Require(baseline, Observation(catalog)));
    }

    [Fact]
    public void Private_rows_and_unrelated_sequence_tuples_remain_exact()
    {
        var baseline = Observation();
        Require(baseline, Observation());
        _ = Assert.Throws<DeltaExecutionException>(() => Require(baseline, Observation(privateRows: 2)));
        _ = Assert.Throws<DeltaExecutionException>(() => Require(baseline, Observation(sequence: new string('c', 64))));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Preimage_digest_binds_existing_storage_fields(bool changeFile, bool changeBlocks)
    {
        var storage = new Dictionary<string, DualTargetCapturedStorage> { ["42"] = new(11, 5) };
        string before = DualTargetCapturedDeltaNativeGuard.PreimageHash(new string('a', 64), storage);
        var same = new Dictionary<string, DualTargetCapturedStorage> { ["42"] = new(11, 5) };
        Assert.Equal(before, DualTargetCapturedDeltaNativeGuard.PreimageHash(new string('a', 64), same));
        same["42"] = new(changeFile ? 12U : 11U, changeBlocks ? 6 : 5);
        Assert.NotEqual(before, DualTargetCapturedDeltaNativeGuard.PreimageHash(new string('a', 64), same));
    }

    private static void Require(CurrentAppOwnedRetained31Observation before, CurrentAppOwnedRetained31Observation after)
    {
        DualTargetCapturedDeltaNativeGuard.RequireNative(before, after,
            new("Customer", "1.0", new string('a', 64), new string('b', 64), []),
            new HashSet<string>(StringComparer.Ordinal), new HashSet<string>(StringComparer.Ordinal));
    }

    private static CurrentAppOwnedRetained31Observation Observation(string? changedCatalog = null, long privateRows = 1, string? sequence = null)
    {
        var tuples = ConsumerColumnBootstrapNativePreservation.CatalogNames.ToDictionary(x => x,
            x => x == changedCatalog ? new[] { new JsonObject { ["test"] = 1 }.ToJsonString() } : [], StringComparer.Ordinal);
        var snapshot = new CurrentAppOwnedDatabaseSnapshot("Customer", [],
            [new("legacy_migration_internal", "PrivateReceipt", privateRows, new string('a', 64))],
            [new("public", "PrivateSequence", "public.PrivateReceipt.Id", sequence ?? new string('b', 64))]);
        return new(snapshot, tuples, new Dictionary<string, (uint FileNode, long Blocks)>(StringComparer.Ordinal));
    }
}
