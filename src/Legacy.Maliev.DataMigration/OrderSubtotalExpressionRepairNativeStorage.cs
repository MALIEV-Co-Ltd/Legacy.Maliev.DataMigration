namespace Legacy.Maliev.DataMigration;

internal static partial class OrderSubtotalExpressionRepairNativePreservation
{
    private static void RequireStorage(OrderSubtotalExpressionRepairNativeObservation before,
        OrderSubtotalExpressionRepairNativeObservation after, Binding left, Binding right, OrderSubtotalStorageProfile? profile, bool characterize)
    {
        string[] oldIds = [.. before.Native.Read("pg_class").Where(x => V(x, "relkind") is "r" or "i" or "t").Select(x => V(x, "oid")).Order(StringComparer.Ordinal)];
        string[] newIds = [.. after.Native.Read("pg_class").Where(x => V(x, "relkind") is "r" or "i" or "t").Select(x => V(x, "oid")).Order(StringComparer.Ordinal)];
        if (!oldIds.SequenceEqual(before.Storage.Keys.Order(StringComparer.Ordinal)) || !newIds.SequenceEqual(after.Storage.Keys.Order(StringComparer.Ordinal)))
        { throw Invalid("storage_inventory"); }
        foreach (string id in oldIds)
        {
            string? role = left.Roles.GetValueOrDefault(id);
            string newId = role is null ? id : right.Roles.Single(x => x.Value == role).Key;
            var oldStorage = before.Storage[id];
            if (!after.Storage.TryGetValue(newId, out var newStorage)) { throw Invalid("storage_rebinding"); }
            if (role is not null)
            {
                if (oldStorage.FileNode == 0 || newStorage.FileNode == 0 || newStorage.FileNode == oldStorage.FileNode ||
                    before.Storage.Values.Any(x => x.FileNode == newStorage.FileNode)) { throw Invalid("rewritten_file_identity"); }
                if (characterize) { if (oldStorage.Blocks < 0 || newStorage.Blocks < 0) { throw Invalid("negative_characterization"); } }
                else if (profile is null) { RequireCharacterizedStorage(role, oldStorage.Blocks, newStorage.Blocks, before.ProviderVersion, left.Alphabetical); }
                else { profile.RequireStorage(role, oldStorage.Blocks, newStorage.Blocks, before.ProviderVersion, left.Alphabetical); }
            }
            else if (id is "1249" or "2658")
            {
                string expectedName = id == "1249" ? "pg_attribute" : "pg_attribute_relid_attnam_index";
                var relation = One(before.Native.Read("pg_class"), x => V(x, "oid") == id);
                var ns = One(before.Native.Read("pg_namespace"), x => V(x, "oid") == V(relation, "relnamespace"));
                if (V(relation, "relname") != expectedName || V(ns, "nspname") != "pg_catalog" ||
                    oldStorage.FileNode.ToString(System.Globalization.CultureInfo.InvariantCulture) != id || newStorage.FileNode != oldStorage.FileNode)
                { throw Invalid("catalog_storage_identity"); }
                if (oldStorage.Blocks != newStorage.Blocks)
                {
                    if (characterize) { if (oldStorage.Blocks < 0 || newStorage.Blocks < 0) { throw Invalid("negative_characterization"); } }
                    else if (profile is null) { RequireCharacterizedStorage(id, oldStorage.Blocks, newStorage.Blocks, before.ProviderVersion, left.Alphabetical); }
                    else { profile.RequireStorage(id, oldStorage.Blocks, newStorage.Blocks, before.ProviderVersion, left.Alphabetical); }
                }
            }
            else if (oldStorage != newStorage) { throw Invalid("unrelated_storage"); }
            var oldClass = One(before.Native.Read("pg_class"), x => V(x, "oid") == id);
            var matchingClass = One(after.Native.Read("pg_class"), x => V(x, "oid") == newId);
            if ((V(oldClass, "relfilenode") != "0" && U(oldClass, "relfilenode") != oldStorage.FileNode) ||
                (V(matchingClass, "relfilenode") != "0" && U(matchingClass, "relfilenode") != newStorage.FileNode))
            { throw Invalid("class_storage_capture"); }
            if ((role is "toast" or "toast_index") && newStorage.FileNode.ToString(System.Globalization.CultureInfo.InvariantCulture) != newId)
            { throw Invalid("toast_file_identity"); }
            if (V(oldClass, "relkind") == "i")
            {
                var newClass = One(after.Native.Read("pg_class"), x => V(x, "oid") == newId);
                var (FileNode, Blocks) = before.Native.Storage(id); var newNative = after.Native.Storage(newId);
                if (FileNode != oldStorage.FileNode || Blocks != oldStorage.Blocks ||
                    newNative.FileNode != newStorage.FileNode || newNative.Blocks != newStorage.Blocks ||
                    (V(oldClass, "relfilenode") != "0" && U(oldClass, "relfilenode") != oldStorage.FileNode) ||
                    (V(newClass, "relfilenode") != "0" && U(newClass, "relfilenode") != newStorage.FileNode))
                { throw Invalid("index_storage_capture"); }
            }
        }
    }

    // These are exact measured transitions, not generic growth bounds. In particular,
    // an arbitrary btree with 16 blocks is never authorized to grow merely by its size.
    internal static void RequireCharacterizedStorage(string role, long before, long after, int provider, bool alphabetical)
    {
        bool accepted = role switch
        {
            "root" => before == (alphabetical ? 357 : 348) && after == 384,
            "toast" => before == 1073 && after == 1073,
            "toast_index" => before == 14 && after == 14,
            "index:PK_Order" => before == 38 && after == 38,
            "dependent_index:IX_Order_Scale_Subtotal" => before == 43 && after == 43,
            "1249" => before == (provider == 180004 ? 59 : 69) && after == before + 1,
            "2658" => before == after || (provider == 180007 && alphabetical && before == 16 && after == 17),
            _ => false
        };
        if (provider is not (180004 or 180007) || !accepted) { throw Invalid("uncharacterized_storage_preimage_" + role); }
    }
}
