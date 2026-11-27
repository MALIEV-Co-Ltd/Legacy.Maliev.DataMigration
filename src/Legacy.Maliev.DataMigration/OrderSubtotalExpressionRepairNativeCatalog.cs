using System.Globalization;
using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration;

internal static partial class OrderSubtotalExpressionRepairNativePreservation
{
    private sealed record Binding(string Table, string Toast, string ToastIndex, int Ordinal, bool Alphabetical,
        IReadOnlyDictionary<string, string> Roles);

    private static Binding Bind(OrderSubtotalExpressionRepairNativeObservation observation, OrderSubtotalExpressionRepairContract contract)
    {
        var native = observation.Native;
        JsonObject space = One(native.Read("pg_namespace"), x => V(x, "nspname") == "public");
        JsonObject root = One(native.Read("pg_class"), x => V(x, "relnamespace") == V(space, "oid") && V(x, "relname") == "Order" && V(x, "relkind") == "r");
        string table = V(root, "oid"), toast = V(root, "reltoastrelid");
        if (toast == "0" || V(root, "relam") != "2" || V(root, "relpersistence") != "p" ||
            V(root, "relallvisible") != "0" || V(root, "relallfrozen") != "0") { throw Invalid("root_preimage"); }
        JsonObject[] attributes = [.. native.Read("pg_attribute").Where(x => V(x, "attrelid") == table && int.Parse(V(x, "attnum"), CultureInfo.InvariantCulture) > 0)
            .OrderBy(x => int.Parse(V(x, "attnum"), CultureInfo.InvariantCulture))];
        TableCopyPlan model = contract.BeforePhysical().Tables.Single(x => x.TargetSchema == "public" && x.TargetTable == "Order");
        string[] actualOrder = [.. attributes.Select(x => V(x, "attname"))];
        bool alphabetical = actualOrder.SequenceEqual(model.OrderedColumns.Order(StringComparer.Ordinal), StringComparer.Ordinal);
        if (attributes.Length != 27 || (!alphabetical && !actualOrder.SequenceEqual(model.OrderedColumns, StringComparer.Ordinal)) ||
            attributes.Any(x => V(x, "attisdropped") != "false" || V(x, "atthasmissing") != "false" || x["attmissingval"] is not null))
        { throw Invalid("physical_layout_or_fast_default"); }
        JsonObject subtotal = One(attributes, x => V(x, "attname") == "Subtotal" && V(x, "attgenerated") == "s" && V(x, "atttypid") == "1700" && V(x, "atttypmod") == "1179654");
        int ordinal = int.Parse(V(subtotal, "attnum"), CultureInfo.InvariantCulture);
        JsonObject definition = One(native.Read("pg_attrdef"), x => V(x, "adrelid") == table && V(x, "adnum") == V(subtotal, "attnum"));
        string expectedExpression = observation.After ? OrderSubtotalExpressionRepairContract.CorrectedExpression : contract.ObservedHistoricalExpression;
        if ((!observation.After && observation.Expression != contract.ObservedHistoricalExpression) ||
            PostgreSqlGeneratedExpressionCanonicalizer.Canonicalize(observation.Expression) != PostgreSqlGeneratedExpressionCanonicalizer.Canonicalize(expectedExpression) ||
            V(definition, "adbin") != observation.ExpressionTree) { throw Invalid("bound_expression"); }
        JsonObject toastRow = One(native.Read("pg_class"), x => V(x, "oid") == toast && V(x, "relkind") == "t");
        JsonObject toastSpace = One(native.Read("pg_namespace"), x => V(x, "oid") == V(toastRow, "relnamespace"));
        if (V(toastSpace, "nspname") != "pg_toast" || V(toastRow, "relname") != "pg_toast_" + table) { throw Invalid("toast_identity"); }
        JsonObject toastIndex = One(native.Read("pg_index"), x => V(x, "indrelid") == toast);
        string toastIndexId = V(toastIndex, "indexrelid");
        JsonObject toastIndexRow = One(native.Read("pg_class"), x => V(x, "oid") == toastIndexId && V(x, "relkind") == "i");
        if (V(toastIndexRow, "relname") != "pg_toast_" + table + "_index") { throw Invalid("toast_index_identity"); }
        var roles = new Dictionary<string, string>(StringComparer.Ordinal)
        { [table] = "root", [toast] = "toast", [toastIndexId] = "toast_index", [V(definition, "oid")] = "subtotal_default" };
        foreach (JsonObject index in native.Read("pg_index").Where(x => V(x, "indrelid") == table))
        {
            string id = V(index, "indexrelid");
            JsonObject relation = One(native.Read("pg_class"), x => V(x, "oid") == id && V(x, "relkind") == "i");
            bool dependent = native.Read("pg_depend").Any(x => V(x, "classid") == "1259" && V(x, "objid") == id &&
                V(x, "refclassid") == "1259" && V(x, "refobjid") == table && V(x, "refobjsubid") == V(subtotal, "attnum"));
            if (V(relation, "relam") != "403" || V(index, "indisvalid") != "true" || V(index, "indisready") != "true" || V(index, "indislive") != "true")
            { throw Invalid("index_preimage"); }
            if (dependent && (index["indkey"] is not JsonArray { Count: 1 } key || key[0]?.ToString() != V(subtotal, "attnum") ||
                index["indexprs"] is not null || index["indpred"] is not null || V(index, "indisunique") != "false" || V(index, "indisprimary") != "false"))
            { throw Invalid("dependent_index_shape"); }
            roles.Add(id, (dependent ? "dependent_index:" : "index:") + V(relation, "relname"));
        }
        foreach (JsonObject constraint in native.Read("pg_constraint").Where(x => V(x, "conrelid") == table &&
            x["conkey"] is JsonArray keys && keys.Any(key => key?.ToString() == V(subtotal, "attnum"))))
        {
            if (V(constraint, "contype") != "c" || constraint["conkey"] is not JsonArray { Count: 1 }) { throw Invalid("dependent_constraint_shape"); }
            roles.Add(V(constraint, "oid"), "dependent_constraint:" + V(constraint, "conname"));
        }
        if (roles.Values.Distinct(StringComparer.Ordinal).Count() != roles.Count ||
            native.Read("pg_statistic_ext").Any(x => V(x, "stxrelid") == table) ||
            native.Read("pg_depend").Any(x => V(x, "refclassid") == "1259" && V(x, "refobjid") == table &&
                V(x, "refobjsubid") == V(subtotal, "attnum") && V(x, "classid") is not ("1259" or "2604" or "2606")))
        { throw Invalid("unsupported_dependency"); }
        JsonObject[] statistics = [.. native.Read("pg_statistic").Where(x => V(x, "starelid") == table && V(x, "staattnum") == V(subtotal, "attnum"))];
        return statistics.Length > (observation.After ? 0 : 1)
            ? throw Invalid("statistics_multiplicity")
            : new(table, toast, toastIndexId, ordinal, alphabetical, roles);
    }

    private static string[] Normalize(OrderSubtotalExpressionRepairNativeObservation observation, Binding binding, string catalog)
    {
        var result = new List<string>();
        foreach (JsonObject row in observation.Native.Read(catalog))
        {
            if (catalog == "pg_statistic" && V(row, "starelid") == binding.Table && V(row, "staattnum") == binding.Ordinal.ToString(CultureInfo.InvariantCulture))
            { if (observation.After) { throw Invalid("remaining_subtotal_statistics"); } continue; }
            if (catalog == "pg_class" && binding.Roles.TryGetValue(V(row, "oid"), out string? role) && role != "subtotal_default" && !role.StartsWith("dependent_constraint:", StringComparison.Ordinal))
            {
                row["relfilenode"] = "<rewritten-file>";
                if (role == "root")
                {
                    if (observation.After && (V(row, "relpages") != "0" || V(row, "reltuples") != "-1")) { throw Invalid("post_rewrite_estimates"); }
                    row["relpages"] = 0; row["reltuples"] = -1;
                }
                if (role is "root" or "toast") { row["relfrozenxid"] = "<rewrite-xid>"; }
                Rebind(row, "oid", binding); Rebind(row, "reltoastrelid", binding);
            }
            else if (catalog == "pg_attribute") { Rebind(row, "attrelid", binding); }
            else if (catalog == "pg_attrdef" && V(row, "adrelid") == binding.Table && V(row, "adnum") == binding.Ordinal.ToString(CultureInfo.InvariantCulture))
            { row["adbin"] = "<fixed-approved-subtotal-expression>"; Rebind(row, "oid", binding); }
            else if (catalog == "pg_index") { Rebind(row, "indexrelid", binding); Rebind(row, "indrelid", binding); }
            else if (catalog == "pg_constraint") { Rebind(row, "oid", binding); Rebind(row, "conindid", binding); }
            else if (catalog == "pg_depend")
            {
                if (V(row, "classid") is "1259" or "2604" or "2606") { Rebind(row, "objid", binding); }
                if (V(row, "refclassid") is "1259" or "2604" or "2606") { Rebind(row, "refobjid", binding); }
            }
            result.Add(Canonical(row));
        }
        return [.. result.Order(StringComparer.Ordinal)];
    }

    private static void Rebind(JsonObject row, string field, Binding binding)
    { if (binding.Roles.TryGetValue(V(row, field), out string? role)) { row[field] = "<" + role + ">"; } }
}
