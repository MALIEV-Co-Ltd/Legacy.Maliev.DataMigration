using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record OrderSubtotalExpressionRepairStorage(uint FileNode, long Blocks);
internal sealed record OrderSubtotalExpressionRepairNativeObservation(
    CurrentAppOwnedRetained31Observation Native, string ContractSha256, bool After,
    CurrentAppOwnedRelationFact OriginalRows, CurrentAppOwnedRelationFact CorrectedRows,
    IReadOnlyDictionary<string, OrderSubtotalExpressionRepairStorage> Storage,
    string Expression, string ExpressionTree, int ProviderVersion, string CompositeDefense,
    ulong WalLower, ulong WalUpper, uint SnapshotXmin, uint SnapshotXmax);

/// <summary>
/// Preservation observation only: no permit, executor, fleet coverage or persistent admission.
/// Physical storage transitions are limited to the retained full-model scale witnesses.
/// Other actual target storage preimages require further characterization, never a restamp.
/// </summary>
internal static partial class OrderSubtotalExpressionRepairNativePreservation
{
    internal static IReadOnlyList<string> CatalogNames => ConsumerColumnBootstrapNativePreservation.CatalogNames;

    internal static async Task<OrderSubtotalExpressionRepairNativeObservation> CaptureAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, OrderSubtotalExpressionRepairContract contract, bool after, CancellationToken ct)
    {
        if (transaction.Connection != connection || transaction.IsolationLevel is not
            (System.Data.IsolationLevel.RepeatableRead or System.Data.IsolationLevel.Serializable)) { throw Invalid("isolation"); }
        int provider; string defense; ulong lower; uint xmin, xmax;
        await using (var command = new NpgsqlCommand("""
            SELECT current_setting('server_version_num')::integer,
              coalesce(current_setting('composite_type_mismatch',true),''),pg_current_wal_insert_lsn()::text,
              pg_snapshot_xmin(pg_current_snapshot())::text,
              greatest(pg_snapshot_xmax(pg_current_snapshot())::text::bigint,coalesce(pg_current_xact_id_if_assigned()::text::bigint+1,0))::text,
              current_setting('server_encoding')='UTF8' AND (current_schemas(true))[1]='pg_catalog';
            """, connection, transaction))
        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(ct).ConfigureAwait(false) || !reader.GetBoolean(5)) { throw Invalid("provider"); }
            provider = reader.GetInt32(0); defense = reader.GetString(1); lower = Wal(reader.GetString(2));
            xmin = uint.Parse(reader.GetString(3), CultureInfo.InvariantCulture); xmax = uint.Parse(reader.GetString(4), CultureInfo.InvariantCulture);
            RequireProvider(provider, defense);
        }
        var native = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        var original = await RowsAsync(connection, transaction, "to_jsonb(x)-'Subtotal'", ct).ConfigureAwait(false);
        var corrected = await RowsAsync(connection, transaction,
            "(to_jsonb(x)-'Subtotal')||jsonb_build_object('Subtotal'," + OrderSubtotalExpressionRepairContract.CorrectedExpression + ")", ct).ConfigureAwait(false);
        string expression, tree;
        await using (var command = new NpgsqlCommand("""
            SELECT pg_get_expr(d.adbin,d.adrelid),d.adbin::text FROM pg_attribute a
            JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
            WHERE a.attrelid='public."Order"'::regclass AND a.attname='Subtotal' AND a.attgenerated='s' AND NOT a.attisdropped;
            """, connection, transaction))
        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw Invalid("expression"); }
            expression = reader.GetString(0); tree = reader.GetString(1);
            if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw Invalid("expression_multiplicity"); }
        }
        var storage = new Dictionary<string, OrderSubtotalExpressionRepairStorage>(StringComparer.Ordinal);
        await using (var command = new NpgsqlCommand("""
            SELECT oid::text,coalesce(pg_relation_filenode(oid),0::oid),pg_relation_size(oid)/current_setting('block_size')::bigint
            FROM pg_class WHERE relkind IN ('r','i','t') ORDER BY oid;
            """, connection, transaction))
        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            { storage.Add(reader.GetString(0), new(reader.GetFieldValue<uint>(1), reader.GetInt64(2))); }
        }
        await using var wal = new NpgsqlCommand("SELECT pg_current_wal_insert_lsn()::text;", connection, transaction);
        ulong upper = Wal((string)(await wal.ExecuteScalarAsync(ct).ConfigureAwait(false))!);
        var result = new OrderSubtotalExpressionRepairNativeObservation(native, contract.ComputeSha256(), after, original, corrected,
            storage, expression, tree, provider, defense, lower, upper, xmin, xmax);
        _ = Bind(result, contract);
        return result;
    }

    internal static void RequirePreserved(OrderSubtotalExpressionRepairNativeObservation before,
        OrderSubtotalExpressionRepairNativeObservation after, OrderSubtotalExpressionRepairContract contract)
    {
        RequireProvider(before.ProviderVersion, before.CompositeDefense); RequireProvider(after.ProviderVersion, after.CompositeDefense);
        if (before.After || !after.After || before.ContractSha256 != contract.ComputeSha256() || before.ContractSha256 != after.ContractSha256 ||
            before.Native.Snapshot.Database != after.Native.Snapshot.Database || before.ProviderVersion != after.ProviderVersion ||
            before.CompositeDefense != after.CompositeDefense || before.WalLower > before.WalUpper || after.WalLower > after.WalUpper ||
            after.WalLower < before.WalUpper || before.SnapshotXmin > before.SnapshotXmax || after.SnapshotXmin > after.SnapshotXmax ||
            after.SnapshotXmax < before.SnapshotXmax) { throw Invalid("binding"); }
        Binding left = Bind(before, contract), right = Bind(after, contract);
        if (left.Table != right.Table || left.Ordinal != right.Ordinal || left.Alphabetical != right.Alphabetical ||
            before.OriginalRows != after.OriginalRows || before.CorrectedRows != after.CorrectedRows ||
            after.Native.Snapshot.Relations.Single(x => x.Schema == "public" && x.Name == "Order") != before.CorrectedRows ||
            !before.Native.Snapshot.Sequences.SequenceEqual(after.Native.Snapshot.Sequences) ||
            !before.Native.Snapshot.Relations.Where(x => x.Schema != "public" || x.Name != "Order").SequenceEqual(
                after.Native.Snapshot.Relations.Where(x => x.Schema != "public" || x.Name != "Order"))) { throw Invalid("rows_or_sequences"); }
        if (!left.Roles.Values.Order(StringComparer.Ordinal).SequenceEqual(right.Roles.Values.Order(StringComparer.Ordinal))) { throw Invalid("graph_inventory"); }
        foreach (var pair in left.Roles)
        {
            string role = pair.Value, oldId = pair.Key, newId = right.Roles.Single(x => x.Value == role).Key;
            bool recreated = role is "toast" or "toast_index" or "subtotal_default" || role.StartsWith("dependent_", StringComparison.Ordinal);
            if (recreated ? oldId == newId || left.Roles.ContainsKey(newId) : oldId != newId) { throw Invalid("graph_rebinding"); }
        }
        RequireStorage(before, after, left, right);
        RequireFrozenXids(
            U(One(before.Native.Read("pg_class"), x => V(x, "oid") == left.Table), "relfrozenxid"),
            U(One(before.Native.Read("pg_class"), x => V(x, "oid") == left.Toast), "relfrozenxid"),
            U(One(after.Native.Read("pg_class"), x => V(x, "oid") == right.Table), "relfrozenxid"),
            U(One(after.Native.Read("pg_class"), x => V(x, "oid") == right.Toast), "relfrozenxid"),
            before.SnapshotXmin, after.SnapshotXmax);
        foreach (string catalog in CatalogNames)
        {
            if (!Normalize(before, left, catalog).SequenceEqual(Normalize(after, right, catalog), StringComparer.Ordinal))
            { throw Invalid("catalog_" + catalog); }
        }
    }

    private static async Task<CurrentAppOwnedRelationFact> RowsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string expression, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT count(*),encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h COLLATE \"C\"),''),'UTF8')),'hex') FROM " +
            "(SELECT encode(sha256(convert_to((" + expression + ")::text,'UTF8')),'hex') h FROM public.\"Order\" x) rows;", connection, transaction)
        { CommandTimeout = 120 };
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return !await reader.ReadAsync(ct).ConfigureAwait(false)
            ? throw Invalid("rows")
            : new("public", "Order", reader.GetInt64(0), reader.GetString(1));
    }

    // Current observations store epoch-zero snapshot bounds. A wrapped/epoch-bearing
    // xid8 cannot be coerced to these uint fields by CaptureAsync; no modulo comparison is used.
    internal static void RequireFrozenXids(uint oldRoot, uint oldToast, uint newRoot, uint newToast,
        ulong beforeSnapshotXmin, ulong afterSnapshotXmax)
    {
        if (beforeSnapshotXmin < 3 || afterSnapshotXmax > uint.MaxValue || beforeSnapshotXmin > afterSnapshotXmax ||
            oldRoot < 3 || oldRoot != oldToast || oldRoot > beforeSnapshotXmin || newRoot != newToast ||
            newRoot <= oldRoot || newRoot < beforeSnapshotXmin || newRoot >= afterSnapshotXmax)
        { throw Invalid("rewrite_xid"); }
    }
    internal static void RequireProvider(int version, string defense)
    {
        if (version is not (180004 or 180007) || (version == 180007 && defense != "error") || (version == 180004 && defense.Length != 0)) { throw Invalid("provider"); }
    }
    private static ulong Wal(string value)
    {
        string[] parts = value.Split('/'); return parts.Length != 2
            ? throw Invalid("wal")
            : ((ulong)uint.Parse(parts[0], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture) << 32) |
            uint.Parse(parts[1], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
    }
    private static JsonObject One(IEnumerable<JsonObject> rows, Func<JsonObject, bool> predicate)
    { JsonObject[] found = rows.Where(predicate).ToArray(); return found.Length == 1 ? found[0] : throw Invalid("catalog_identity"); }
    private static string V(JsonObject row, string key)
    {
        return row[key]?.ToString() ?? "null";
    }

    private static uint U(JsonObject row, string key)
    {
        return uint.Parse(V(row, key), CultureInfo.InvariantCulture);
    }

    private static string Canonical(JsonObject row)
    {
        return new JsonObject([.. row.OrderBy(x => x.Key, StringComparer.Ordinal)
        .Select(x => new KeyValuePair<string, JsonNode?>(x.Key, x.Value?.DeepClone()))]).ToJsonString();
    }

    private static MigrationExecutionException Invalid(string detail)
    {
        return new("order_subtotal_native_preservation_invalid", "Closed Order rewrite observation rejected: " + detail);
    }
}
