using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class OrderSubtotalExpressionRepairNativePreservationTests
{
    [Theory]
    [InlineData(760U, 760U, 761U, 761U, 761UL, 762UL)]
    [InlineData(760U, 760U, 762U, 762U, 761UL, 763UL)]
    public void Actual_frozen_xid_relations_are_supported(uint oldRoot, uint oldToast, uint newRoot, uint newToast, ulong lower, ulong upper)
    {
        OrderSubtotalExpressionRepairNativePreservation.RequireFrozenXids(oldRoot, oldToast, newRoot, newToast, lower, upper);
    }

    [Theory]
    [InlineData(2U, 2U, 761U, 761U, 761UL, 762UL)]
    [InlineData(760U, 759U, 761U, 761U, 761UL, 762UL)]
    [InlineData(762U, 762U, 763U, 763U, 761UL, 764UL)]
    [InlineData(760U, 760U, 760U, 760U, 760UL, 762UL)]
    [InlineData(760U, 760U, 761U, 762U, 761UL, 763UL)]
    [InlineData(760U, 760U, 761U, 761U, 762UL, 763UL)]
    [InlineData(760U, 760U, 762U, 762U, 761UL, 762UL)]
    [InlineData(760U, 760U, 761U, 761U, 2UL, 762UL)]
    [InlineData(4294967294U, 4294967294U, 3U, 3U, 4294967294UL, 4294967296UL)]
    [InlineData(760U, 760U, 761U, 761U, 4294968057UL, 4294968058UL)]
    public void Malformed_backwards_or_uncharacterized_epoch_xids_are_rejected(uint oldRoot, uint oldToast, uint newRoot, uint newToast, ulong lower, ulong upper)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalExpressionRepairNativePreservation.RequireFrozenXids(oldRoot, oldToast, newRoot, newToast, lower, upper));
    }
    [Theory]
    [InlineData("root", 348, 384, 180004, false)]
    [InlineData("root", 357, 384, 180007, true)]
    [InlineData("toast", 1073, 1073, 180004, true)]
    [InlineData("toast_index", 14, 14, 180007, false)]
    [InlineData("index:PK_Order", 38, 38, 180004, false)]
    [InlineData("dependent_index:IX_Order_Scale_Subtotal", 43, 43, 180007, true)]
    [InlineData("1249", 59, 60, 180004, true)]
    [InlineData("1249", 69, 70, 180007, false)]
    [InlineData("2658", 16, 17, 180007, true)]
    public void Exact_measured_storage_transitions_are_supported(string role, long before, long after, int version, bool alphabetical)
    {
        OrderSubtotalExpressionRepairNativePreservation.RequireCharacterizedStorage(role, before, after, version, alphabetical);
    }

    [Theory]
    [InlineData("root", 358, 384, 180004, false)]
    [InlineData("root", 348, 385, 180007, false)]
    [InlineData("root", 10000, 10000, 180004, true)]
    [InlineData("toast", 1072, 1073, 180004, true)]
    [InlineData("toast_index", 14, 15, 180007, true)]
    [InlineData("index:unreviewed", 38, 38, 180004, false)]
    [InlineData("1249", 70, 71, 180007, false)]
    [InlineData("2658", 17, 18, 180007, true)]
    [InlineData("2658", 16, 17, 180004, true)]
    [InlineData("2658", 16, 17, 180007, false)]
    [InlineData("root", 348, 384, 180008, false)]
    public void Unsupported_preimages_and_growth_are_rejected(string role, long before, long after, int version, bool alphabetical)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalExpressionRepairNativePreservation.RequireCharacterizedStorage(role, before, after, version, alphabetical));
    }

    [Theory]
    [InlineData(180004, "")]
    [InlineData(180007, "error")]
    public void Only_actual_provider_cohorts_are_supported(int version, string defense)
    {
        OrderSubtotalExpressionRepairNativePreservation.RequireProvider(version, defense);
    }

    [Theory]
    [InlineData(180004, "error")]
    [InlineData(180007, "off")]
    [InlineData(180008, "error")]
    [InlineData(170007, "")]
    public void Unobserved_provider_or_defense_is_rejected(int version, string defense)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalExpressionRepairNativePreservation.RequireProvider(version, defense));
    }
}

// Mutations use actual native observations in each scale case; no fake observation mints permission.
internal static class OrderSubtotalExpressionRepairNativeMutationTests
{
    internal static void RequireRejectedMutations(OrderSubtotalExpressionRepairNativeObservation before,
        OrderSubtotalExpressionRepairNativeObservation after, OrderSubtotalExpressionRepairContract contract)
    {
        static void Reject(OrderSubtotalExpressionRepairNativeObservation left, OrderSubtotalExpressionRepairNativeObservation right,
            OrderSubtotalExpressionRepairContract fixedContract)
        { _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalExpressionRepairNativePreservation.RequirePreserved(left, right, fixedContract)); }
        Reject(before, after with { ContractSha256 = new string('0', 64) }, contract);
        Reject(before, after with { WalLower = before.WalUpper - 1 }, contract);
        Reject(before, after with { SnapshotXmax = before.SnapshotXmin }, contract);
        Reject(before, after with { OriginalRows = after.OriginalRows with { RowSha256 = new string('0', 64) } }, contract);
        Reject(before, after with { ExpressionTree = "wrong expression tree" }, contract);
        var snapshot = after.Native.Snapshot;
        Reject(before, after with { Native = Replace(after, snapshot with { Sequences = [.. snapshot.Sequences.Select((x, i) => i == 0 ? x with { TupleSha256 = new string('0', 64) } : x)] }) }, contract);
        Reject(before, after with { Native = Replace(after, snapshot with { Relations = [.. snapshot.Relations.Select(x => x.Schema == "legacy_migration_internal" ? x with { Rows = x.Rows + 1 } : x)] }) }, contract);
        Reject(before, Change(after, "pg_attribute", rows => rows[0]["attoptions"] = new JsonArray("unreserved=changed")), contract);
        Reject(before, Change(after, "pg_depend", rows => rows.Add((JsonObject)rows[0].DeepClone())), contract);
        Reject(before, Change(after, "pg_namespace", rows => rows.RemoveAt(0)), contract);
        Reject(before, Change(after, "pg_index", rows => rows[0]["indisvalid"] = false), contract);
        Reject(before, Change(after, "pg_constraint", rows => rows[0]["convalidated"] = false), contract);
        Reject(before, Change(after, "pg_attribute", rows => rows[0]["attcollation"] = "100"), contract);
        string id = after.Storage.Keys.First(key => !after.Native.Read("pg_class").Any(x => x["oid"]?.ToString() == key && x["relname"]?.ToString() == "Order"));
        var changedStorage = after.Storage.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        changedStorage[id] = changedStorage[id] with { Blocks = changedStorage[id].Blocks + 100 };
        Reject(before, after with { Storage = changedStorage }, contract);
    }

    private static CurrentAppOwnedRetained31Observation Replace(OrderSubtotalExpressionRepairNativeObservation observation,
        CurrentAppOwnedDatabaseSnapshot snapshot, string? changedCatalog = null, Action<List<JsonObject>>? edit = null)
    {
        var tuples = new Dictionary<string, string[]>(StringComparer.Ordinal);
        foreach (string catalog in OrderSubtotalExpressionRepairNativePreservation.CatalogNames)
        {
            var rows = observation.Native.Read(catalog).ToList();
            if (catalog == changedCatalog) { edit!(rows); }
            tuples.Add(catalog, [.. rows.Select(x => x.ToJsonString())]);
        }
        var storage = observation.Native.Read("pg_class").Where(x => x["relkind"]?.ToString() == "i")
            .ToDictionary(x => x["oid"]!.ToString(), x => observation.Native.Storage(x["oid"]!.ToString()), StringComparer.Ordinal);
        return new(snapshot, tuples, storage);
    }

    private static OrderSubtotalExpressionRepairNativeObservation Change(OrderSubtotalExpressionRepairNativeObservation observation,
        string catalog, Action<List<JsonObject>> edit)
    {
        return observation with { Native = Replace(observation, observation.Native.Snapshot, catalog, edit) };
    }
}
