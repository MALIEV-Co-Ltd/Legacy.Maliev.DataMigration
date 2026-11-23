using System.Text.Json.Nodes;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Strict fixed PG18 native observation only; supplies no executor, permit or persistent-write authority.</summary>
internal static class CustomerCompanyStorageNativePreservation
{
    private static readonly string[] OperandColumns = ["Name", "TaxNumber", "Registrar"];
    private static readonly string[] Catalogs =
    [
        "pg_class", "pg_type", "pg_namespace", "pg_constraint", "pg_attrdef", "pg_trigger", "pg_proc",
        "pg_collation", "pg_policy", "pg_rewrite", "pg_extension", "pg_event_trigger", "pg_authid",
        "pg_database", "pg_tablespace", "pg_language", "pg_operator", "pg_cast", "pg_opclass", "pg_opfamily",
        "pg_am", "pg_conversion", "pg_attribute", "pg_index", "pg_depend", "pg_shdepend", "pg_description",
        "pg_shdescription", "pg_auth_members", "pg_default_acl", "pg_init_privs", "pg_inherits",
        "pg_partitioned_table", "pg_sequence", "pg_statistic", "pg_statistic_ext", "pg_statistic_ext_data",
        "pg_amop", "pg_amproc", "pg_range", "pg_transform", "pg_seclabel", "pg_shseclabel",
    ];

    internal sealed record Observation(CurrentAppOwnedRetained31Observation Native, string ContractSha256, bool After);

    internal static async Task<Observation> CaptureAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        ApprovedCustomerCompanyStorageRepair contract, bool after, CancellationToken ct)
    {
        await using (var settings = new NpgsqlCommand("""
            SELECT current_setting('server_encoding')='UTF8'
                AND current_setting('server_version_num')::integer BETWEEN 180000 AND 189999
                AND (current_schemas(true))[1]='pg_catalog';
            """, connection, transaction))
        {
            if (await settings.ExecuteScalarAsync(ct).ConfigureAwait(false) is not true) { throw Invalid("provider"); }
        }
        DatabaseSchemaPlan plan = after ? contract.After() : contract.Before();
        await using (var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false))
        {
            if (await inspector.InspectSchemaAsync(plan, ct).ConfigureAwait(false) != plan.TargetSchemaSha256)
            { throw Invalid("physical_profile"); }
        }
        var native = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        _ = Bind(native, after);
        return new(native, contract.ComputeSha256(), after);
    }

    internal static void RequirePreserved(Observation before, Observation after, ApprovedCustomerCompanyStorageRepair contract)
    {
        if (before.After || !after.After || before.ContractSha256 != contract.ComputeSha256() ||
            before.ContractSha256 != after.ContractSha256 || before.Native.Snapshot.Database != after.Native.Snapshot.Database)
        { throw Invalid("binding"); }
        if (!before.Native.Snapshot.Relations.SequenceEqual(after.Native.Snapshot.Relations) ||
            !before.Native.Snapshot.Sequences.SequenceEqual(after.Native.Snapshot.Sequences))
        { throw Invalid("rows_or_sequences"); }
        Binding old = Bind(before.Native, false), current = Bind(after.Native, true);
        if (old.Table != current.Table || old.Namespace != current.Namespace || old.Owner != current.Owner ||
            !old.Columns.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(current.Columns.OrderBy(x => x.Key, StringComparer.Ordinal)) ||
            !old.Indexes.Keys.Order(StringComparer.Ordinal).SequenceEqual(current.Indexes.Keys.Order(StringComparer.Ordinal)))
        { throw Invalid("operand_identity"); }
        if (current.Checks.Values.Any(id => before.Native.Read("pg_constraint").Any(x => V(x, "oid") == id)) ||
            before.Native.Read("pg_proc").Any(x => V(x, "oid") == current.Function) ||
            before.Native.Read("pg_trigger").Any(x => V(x, "oid") == current.Trigger) ||
            current.Indexes.Values.Any(id => before.Native.Read("pg_class").Any(x => V(x, "oid") == id)))
        { throw Invalid("new_object_oid"); }
        JsonObject oldNotNull = One(before.Native.Read("pg_constraint").Where(x => V(x, "oid") == old.NotNull));
        JsonObject newNotNull = One(after.Native.Read("pg_constraint").Where(x => V(x, "oid") == current.NotNull));
        if (old.NotNull == current.NotNull) { throw Invalid("notnull_oid"); }
        newNotNull["oid"] = oldNotNull["oid"]!.DeepClone();
        Equal(oldNotNull, newNotNull, "notnull_replacement");
        foreach ((string name, string oldId) in old.Indexes)
        {
            string newId = current.Indexes[name];
            if (oldId == newId || before.Native.Storage(oldId) != after.Native.Storage(newId))
            { throw Invalid("index_file_reuse"); }
            JsonObject oldClass = One(before.Native.Read("pg_class").Where(x => V(x, "oid") == oldId));
            JsonObject newClass = One(after.Native.Read("pg_class").Where(x => V(x, "oid") == newId));
            if (V(newClass, "relpages") != "0" || V(newClass, "reltuples") != "0" ||
                V(oldClass, "relfilenode") != V(newClass, "relfilenode"))
            { throw Invalid("index_metadata_reset"); }
        }
        foreach (string catalog in Catalogs)
        {
            string[] expected = Normalize(before.Native, old, catalog, false);
            string[] observed = Normalize(after.Native, current, catalog, true);
            if (!expected.SequenceEqual(observed, StringComparer.Ordinal))
            { throw Invalid("catalog_" + catalog + "_" + DifferenceFacet(expected, observed)); }
        }
        foreach (JsonObject index in before.Native.Read("pg_index").Where(x => !old.Indexes.ContainsValue(V(x, "indexrelid"))))
        {
            string id = V(index, "indexrelid");
            if (before.Native.Storage(id) != after.Native.Storage(id))
            {
                string catalogNamespace = V(One(before.Native.Read("pg_namespace").Where(x => V(x, "nspname") == "pg_catalog")), "oid");
                string category = V(One(before.Native.Read("pg_class").Where(x => V(x, "oid") == id)), "relnamespace") == catalogNamespace
                    ? "pg_catalog" : "user_or_private";
                string facet = before.Native.Storage(id).FileNode != after.Native.Storage(id).FileNode ? "file" : "blocks";
                if (category == "pg_catalog")
                {
                    JsonObject ns = One(before.Native.Read("pg_namespace").Where(x => V(x, "oid") == catalogNamespace));
                    JsonObject table = One(before.Native.Read("pg_class").Where(x => V(x, "oid") == V(index, "indrelid")));
                    JsonObject oldClass = One(before.Native.Read("pg_class").Where(x => V(x, "oid") == id));
                    JsonObject newClass = One(after.Native.Read("pg_class").Where(x => V(x, "oid") == id));
                    JsonObject newIndex = One(after.Native.Read("pg_index").Where(x => V(x, "indexrelid") == id));
                    string name = V(oldClass, "relname");
                    if (name == "pg_proc_proname_args_nsp_index")
                    {
                        RequireProcedureIndexStorage(ns, table, oldClass, newClass, index, newIndex,
                            before.Native.Storage(id), after.Native.Storage(id),
                            before.Native.Read("pg_proc"), after.Native.Read("pg_proc"),
                            One(after.Native.Read("pg_proc").Where(x => V(x, "oid") == current.Function)), current.Function!);
                    }
                    else if (name is "pg_trigger_tgconstraint_index" or "pg_trigger_tgrelid_tgname_index" or "pg_trigger_oid_index")
                    {
                        RequireTriggerIndexStorage(ns, table, oldClass, newClass, index, newIndex,
                            before.Native.Storage(id), after.Native.Storage(id),
                            before.Native.Read("pg_trigger"), after.Native.Read("pg_trigger"),
                            One(after.Native.Read("pg_trigger").Where(x => V(x, "oid") == current.Trigger)), current.Trigger!);
                    }
                    else { throw Invalid("unreviewed_system_index_storage_" + name + "_" + facet); }
                    continue;
                }
                throw Invalid("unrelated_index_storage_" + category + "_" + facet);
            }
        }
    }

    // The three ordinary pg_trigger btrees reuse their files while recording exactly the bound trigger insertion.
    internal static void RequireTriggerIndexStorage(JsonObject catalogNamespace, JsonObject triggerTable,
        JsonObject beforeClass, JsonObject afterClass, JsonObject beforeIndex, JsonObject afterIndex,
        (uint FileNode, long Blocks) beforeStorage, (uint FileNode, long Blocks) afterStorage,
        JsonObject[] beforeTriggers, JsonObject[] afterTriggers, JsonObject reviewedTrigger, string boundTriggerOid)
    {
        if (V(catalogNamespace, "nspname") != "pg_catalog" || V(catalogNamespace, "oid") != "11")
        { throw Invalid("trigger_index_namespace"); }
        if (V(triggerTable, "relname") != "pg_trigger" || V(triggerTable, "oid") != "2620" ||
            V(triggerTable, "relnamespace") != V(catalogNamespace, "oid"))
        { throw Invalid("trigger_index_table_binding"); }
        string expectedId = V(beforeClass, "relname") switch
        {
            "pg_trigger_tgconstraint_index" => "2699",
            "pg_trigger_tgrelid_tgname_index" => "2701",
            "pg_trigger_oid_index" => "2702",
            _ => throw Invalid("trigger_index_name"),
        };
        if (V(beforeClass, "oid") != expectedId || V(beforeClass, "relnamespace") != V(catalogNamespace, "oid") ||
            V(beforeClass, "relkind") != "i" || V(beforeClass, "relam") != "403")
        { throw Invalid("trigger_index_class_binding"); }
        if (V(beforeIndex, "indrelid") != V(triggerTable, "oid") || V(beforeIndex, "indexrelid") != expectedId ||
            V(beforeIndex, "indisvalid") != "true" || V(beforeIndex, "indisready") != "true" || V(beforeIndex, "indislive") != "true")
        { throw Invalid("trigger_index_definition_binding"); }
        if (beforeStorage.FileNode == 0 || beforeStorage.FileNode != afterStorage.FileNode ||
            V(beforeClass, "relfilenode") != beforeStorage.FileNode.ToString(System.Globalization.CultureInfo.InvariantCulture))
        { throw Invalid("trigger_index_physical_file"); }
        if (beforeStorage.Blocks < 0 || afterStorage.Blocks < beforeStorage.Blocks || afterStorage.Blocks - beforeStorage.Blocks > 1)
        { throw Invalid("trigger_index_block_delta"); }
        if (V(reviewedTrigger, "oid") != boundTriggerOid || V(reviewedTrigger, "tgname") != "NormalizeCompanySource" ||
            beforeTriggers.Any(x => V(x, "oid") == boundTriggerOid) || afterTriggers.Length != beforeTriggers.Length + 1)
        { throw Invalid("trigger_index_trigger_insertion"); }
        Equal(beforeClass, afterClass, "trigger_index_class");
        Equal(beforeIndex, afterIndex, "trigger_index_definition");
        string[] expected = [.. beforeTriggers.Select(Canonical), Canonical(reviewedTrigger)];
        if (!expected.Order(StringComparer.Ordinal).SequenceEqual(afterTriggers.Select(Canonical).Order(StringComparer.Ordinal), StringComparer.Ordinal))
        { throw Invalid("trigger_index_trigger_set"); }
    }

    // Called only after every logical catalog transition has passed. Pure for bounded negative coverage.
    internal static void RequireProcedureIndexStorage(JsonObject catalogNamespace, JsonObject procedureTable,
        JsonObject beforeClass, JsonObject afterClass, JsonObject beforeIndex, JsonObject afterIndex,
        (uint FileNode, long Blocks) beforeStorage, (uint FileNode, long Blocks) afterStorage,
        JsonObject[] beforeFunctions, JsonObject[] afterFunctions, JsonObject reviewedFunction, string boundFunctionOid)
    {
        if (V(catalogNamespace, "nspname") != "pg_catalog" || V(catalogNamespace, "oid") != "11")
        { throw Invalid("procedure_index_namespace"); }
        if (V(procedureTable, "relname") != "pg_proc" || V(procedureTable, "oid") != "1255" ||
            V(procedureTable, "relnamespace") != V(catalogNamespace, "oid"))
        { throw Invalid("procedure_index_table_binding"); }
        if (V(beforeClass, "relname") != "pg_proc_proname_args_nsp_index" ||
            V(beforeClass, "oid") != "2691" ||
            V(beforeClass, "relnamespace") != V(catalogNamespace, "oid") ||
            V(beforeClass, "relkind") != "i" || V(beforeClass, "relam") != "403")
        { throw Invalid("procedure_index_class_binding"); }
        if (V(beforeIndex, "indrelid") != V(procedureTable, "oid") ||
            V(beforeIndex, "indexrelid") != V(beforeClass, "oid") ||
            V(beforeIndex, "indisvalid") != "true" || V(beforeIndex, "indisready") != "true" ||
            V(beforeIndex, "indislive") != "true")
        { throw Invalid("procedure_index_definition_binding"); }
        if (beforeStorage.FileNode == 0 || beforeStorage.FileNode != afterStorage.FileNode)
        { throw Invalid("procedure_index_physical_file"); }
        if (beforeStorage.Blocks < 0 || afterStorage.Blocks < beforeStorage.Blocks ||
            afterStorage.Blocks - beforeStorage.Blocks > 1)
        { throw Invalid("procedure_index_block_delta"); }
        // PG18's fixed built-in index is relation-mapped: catalog zero, independently captured physical file nonzero.
        if (V(beforeClass, "relfilenode") != "0") { throw Invalid("procedure_index_mapped_catalog_file"); }
        if (V(reviewedFunction, "oid") != boundFunctionOid || V(reviewedFunction, "proname") != "NormalizeCompanySource" ||
            beforeFunctions.Any(x => V(x, "oid") == boundFunctionOid))
        { throw Invalid("procedure_index_function_identity"); }
        if (afterFunctions.Length != beforeFunctions.Length + 1)
        { throw Invalid("procedure_index_function_count"); }
        Equal(beforeClass, afterClass, "procedure_index_class");
        Equal(beforeIndex, afterIndex, "procedure_index_definition");
        string[] expected = [.. beforeFunctions.Select(Canonical), Canonical(reviewedFunction)];
        if (!expected.Order(StringComparer.Ordinal).SequenceEqual(afterFunctions.Select(Canonical).Order(StringComparer.Ordinal), StringComparer.Ordinal))
        { throw Invalid("procedure_index_function_insertion"); }
    }

    private sealed record Binding(string Table, string Namespace, string Owner, string Database, string Language,
        Dictionary<string, int> Columns, string NotNull, Dictionary<string, string> Indexes,
        Dictionary<string, string> Checks, string? Function, string? Trigger);

    private static Binding Bind(CurrentAppOwnedRetained31Observation native, bool after)
    {
        string ns = V(One(native.Read("pg_namespace").Where(x => V(x, "nspname") == "public")), "oid");
        JsonObject table = One(native.Read("pg_class").Where(x => V(x, "relnamespace") == ns && V(x, "relname") == "Company"));
        string tableId = V(table, "oid"), owner = V(table, "relowner");
        if (V(table, "relkind") != "r" || V(table, "relpersistence") != "p" || V(table, "relrowsecurity") != "false" ||
            V(table, "relforcerowsecurity") != "false" || V(table, "relhastriggers") != (after ? "true" : "false"))
        { throw Invalid("table_kind"); }
        var columns = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (string name in new[] { "Name", "TaxNumber", "Registrar" })
        {
            JsonObject attribute = One(native.Read("pg_attribute").Where(x => V(x, "attrelid") == tableId && V(x, "attname") == name));
            if (V(attribute, "atttypid") != (after ? "25" : "1043") || V(attribute, "atttypmod") != (after ? "-1" : "260") ||
                V(attribute, "attnotnull") != (name == "Name" ? "true" : "false") || V(attribute, "attisdropped") != "false")
            { throw Invalid("attribute"); }
            columns.Add(name, Number(attribute, "attnum"));
        }
        var numbers = columns.Values.ToHashSet();
        var indexes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (JsonObject index in native.Read("pg_index").Where(x => V(x, "indrelid") == tableId))
        {
            if (!Vector(index, "indkey").Any(numbers.Contains)) { continue; }
            string id = V(index, "indexrelid");
            JsonObject relation = One(native.Read("pg_class").Where(x => V(x, "oid") == id));
            string name = V(relation, "relname");
            string column = name switch { "IX_Company_Name" => "Name", "IX_Company_TaxNumber" => "TaxNumber", _ => throw Invalid("index_name_unsupported") };
            if (!Vector(index, "indkey").SequenceEqual([columns[column]]) || V(index, "indnatts") != "1" ||
                V(index, "indnkeyatts") != "1" || V(index, "indisunique") != "false" ||
                V(index, "indisvalid") != "true" || V(index, "indisready") != "true" || V(index, "indislive") != "true" ||
                index["indexprs"] is not null || index["indpred"] is not null || V(relation, "relam") != "403" ||
                V(relation, "relowner") != owner || V(relation, "relnamespace") != ns ||
                !Vector(index, "indclass").SequenceEqual([3126]) || !Vector(index, "indoption").SequenceEqual([0]) ||
                native.Read("pg_constraint").Any(x => V(x, "conindid") == id))
            { throw Invalid("index_shape_unsupported"); }
            JsonObject indexAttribute = One(native.Read("pg_attribute").Where(x => V(x, "attrelid") == id && Number(x, "attnum") > 0));
            JsonObject tableAttribute = One(native.Read("pg_attribute").Where(x => V(x, "attrelid") == tableId && V(x, "attname") == column));
            if (Number(indexAttribute, "attnum") != 1 || V(indexAttribute, "attname") != column ||
                V(indexAttribute, "atttypid") != (after ? "25" : "1043") ||
                V(indexAttribute, "atttypmod") != (after ? "-1" : "260") ||
                V(indexAttribute, "attcollation") != V(tableAttribute, "attcollation") ||
                !Vector(index, "indcollation").SequenceEqual([Number(tableAttribute, "attcollation")]) ||
                V(relation, "relkind") != "i" || V(relation, "relnatts") != "1" ||
                V(index, "indisprimary") != "false" || V(index, "indisexclusion") != "false")
            { throw Invalid("index_attribute"); }
            indexes.Add(name, id);
        }
        RequireOperandStatistics(native.Read("pg_statistic"), tableId, numbers, after);
        if (native.Read("pg_statistic_ext").Any(x => V(x, "stxrelid") == tableId))
        { throw Invalid("statistics_unsupported"); }
        JsonObject notNull = One(native.Read("pg_constraint").Where(x => V(x, "conrelid") == tableId &&
            V(x, "contype") == "n" && Vector(x, "conkey").SequenceEqual([columns["Name"]])));
        var checks = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string column in columns.Keys)
        {
            JsonObject[] found = [.. native.Read("pg_constraint").Where(x => V(x, "conrelid") == tableId && V(x, "conname") == $"CK_Company_{column}_SourceLength")];
            if (after) { checks.Add(column, V(One(found), "oid")); }
            else if (found.Length != 0) { throw Invalid("existing_check"); }
        }
        JsonObject[] functions = [.. native.Read("pg_proc").Where(x => V(x, "pronamespace") == ns && V(x, "proname") == "NormalizeCompanySource")];
        JsonObject[] triggers = [.. native.Read("pg_trigger").Where(x => V(x, "tgrelid") == tableId)];
        if (!after && (functions.Length != 0 || triggers.Length != 0)) { throw Invalid("existing_normalizer"); }
        if (native.Read("pg_default_acl").Any(x => V(x, "defaclrole") == owner && V(x, "defaclobjtype") == "f" &&
            (V(x, "defaclnamespace") == "0" || V(x, "defaclnamespace") == ns)))
        { throw Invalid("function_default_acl_unsupported"); }
        var binding = new Binding(tableId, ns, owner,
            V(One(native.Read("pg_database").Where(x => V(x, "datname") == native.Snapshot.Database)), "oid"),
            V(One(native.Read("pg_language").Where(x => V(x, "lanname") == "plpgsql")), "oid"),
            columns, V(notNull, "oid"), indexes, checks,
            after ? V(One(functions), "oid") : null, after ? V(One(triggers), "oid") : null);
        if (after) { RequireNewObjects(native, binding); }
        else
        {
            foreach (JsonObject dependency in native.Read("pg_depend").Where(x => V(x, "refclassid") == "1259" &&
                V(x, "refobjid") == tableId && numbers.Contains(Number(x, "refobjsubid"))))
            {
                bool allowed = Canonical(dependency) == Canonical(Dependency("2606", binding.NotNull, "1259", tableId, columns["Name"], "a")) ||
                    indexes.Values.Any(id => Canonical(dependency) == Canonical(Dependency("1259", id, "1259", tableId, Number(dependency, "refobjsubid"), "a")));
                if (!allowed) { throw Invalid("operand_dependency_unsupported"); }
            }
        }
        return binding;
    }

    private static void RequireNewObjects(CurrentAppOwnedRetained31Observation native, Binding binding)
    {
        foreach ((string column, string id) in binding.Checks)
        {
            JsonObject expected = Template(CheckTemplate);
            expected["oid"] = id; expected["conname"] = $"CK_Company_{column}_SourceLength";
            expected["connamespace"] = binding.Namespace; expected["conrelid"] = binding.Table;
            expected["conkey"] = new JsonArray(JsonValue.Create(binding.Columns[column]));
            string expression = V(expected, "conbin").Replace(":varattno 2 ", $":varattno {binding.Columns[column]} ", StringComparison.Ordinal)
                .Replace(":varattnosyn 2 ", $":varattnosyn {binding.Columns[column]} ", StringComparison.Ordinal);
            string collation = V(One(native.Read("pg_attribute").Where(x => V(x, "attrelid") == binding.Table && V(x, "attname") == column)), "attcollation");
            expression = expression.Replace(":varcollid 950 ", $":varcollid {collation} ", StringComparison.Ordinal);
            int firstInput = expression.IndexOf(":inputcollid 950 ", StringComparison.Ordinal);
            if (firstInput < 0) { throw Invalid("check_expression_binding"); }
            expression = expression[..firstInput] + $":inputcollid {collation} " + expression[(firstInput + ":inputcollid 950 ".Length)..];
            expected["conbin"] = expression;
            Equal(expected, One(native.Read("pg_constraint").Where(x => V(x, "oid") == id)), "new_check");
        }
        JsonObject function = Template(FunctionTemplate);
        function["oid"] = binding.Function; function["pronamespace"] = binding.Namespace;
        function["proowner"] = binding.Owner; function["prolang"] = binding.Language;
        function["prosrc"] = CustomerCompanyStorageManifest.TriggerBody.Replace("\r\n", "\n", StringComparison.Ordinal);
        JsonObject observedFunction = One(native.Read("pg_proc").Where(x => V(x, "oid") == binding.Function));
        observedFunction["prosrc"] = V(observedFunction, "prosrc").Replace("\r\n", "\n", StringComparison.Ordinal);
        Equal(function, observedFunction, "new_function");
        JsonObject trigger = Template(TriggerTemplate);
        trigger["oid"] = binding.Trigger; trigger["tgrelid"] = binding.Table; trigger["tgfoid"] = binding.Function;
        trigger["tgattr"] = new JsonArray(OperandColumns.Select(x => (JsonNode?)JsonValue.Create(binding.Columns[x])).ToArray());
        Equal(trigger, One(native.Read("pg_trigger").Where(x => V(x, "oid") == binding.Trigger)), "new_trigger");
    }

    private static string[] Normalize(CurrentAppOwnedRetained31Observation native, Binding binding, string catalog, bool after)
    {
        var rows = new List<JsonObject>(native.Read(catalog));
        if (catalog == "pg_statistic" && !after)
        {
            // Native evidence proves invalidation of these exact ordinary rows; every other row remains compared.
            _ = rows.RemoveAll(x => V(x, "starelid") == binding.Table && binding.Columns.ContainsValue(Number(x, "staattnum")));
        }
        if (catalog == "pg_constraint")
        {
            if (after) { _ = rows.RemoveAll(x => binding.Checks.ContainsValue(V(x, "oid"))); }
            foreach (JsonObject row in rows.Where(x => V(x, "oid") == binding.NotNull)) { row["oid"] = "@CompanyNameNotNull"; }
        }
        if (catalog == "pg_proc" && after) { _ = rows.RemoveAll(x => V(x, "oid") == binding.Function); }
        if (catalog == "pg_trigger" && after) { _ = rows.RemoveAll(x => V(x, "oid") == binding.Trigger); }
        if (catalog == "pg_attribute")
        {
            foreach (JsonObject row in rows)
            {
                if ((V(row, "attrelid") == binding.Table && binding.Columns.ContainsValue(Number(row, "attnum"))) ||
                    (binding.Indexes.ContainsValue(V(row, "attrelid")) && Number(row, "attnum") == 1))
                { row["atttypid"] = "@CompanyTextType"; row["atttypmod"] = "@CompanyTextTypmod"; }
                RemapIndex(row, "attrelid", binding);
            }
        }
        if (catalog == "pg_index") { foreach (JsonObject row in rows) { RemapIndex(row, "indexrelid", binding); } }
        if (catalog == "pg_class")
        {
            JsonObject table = One(rows.Where(x => V(x, "oid") == binding.Table));
            table["relchecks"] = Number(table, "relchecks") - (after ? 3 : 0); table["relhastriggers"] = false;
            foreach ((string name, string id) in binding.Indexes)
            {
                JsonObject row = One(rows.Where(x => V(x, "oid") == id));
                row["oid"] = "@index/" + name;
                if (after)
                {
                    // Exact zero reset was checked separately; the existing physical file and block count must be identical.
                    row["relpages"] = "@index-statistics"; row["reltuples"] = "@index-statistics";
                }
                else { row["relpages"] = "@index-statistics"; row["reltuples"] = "@index-statistics"; }
            }
        }
        if (catalog == "pg_depend")
        {
            if (after)
            {
                var expected = new List<JsonObject>();
                foreach ((string column, string id) in binding.Checks)
                {
                    expected.Add(Dependency("2606", id, "1259", binding.Table, binding.Columns[column], "a"));
                    expected.Add(Dependency("2606", id, "1259", binding.Table, binding.Columns[column], "n"));
                }
                expected.Add(Dependency("1255", binding.Function!, "2615", binding.Namespace, 0, "n"));
                expected.Add(Dependency("1255", binding.Function!, "2612", binding.Language, 0, "n"));
                expected.Add(Dependency("2620", binding.Trigger!, "1255", binding.Function!, 0, "n"));
                expected.Add(Dependency("2620", binding.Trigger!, "1259", binding.Table, 0, "a"));
                foreach (int column in binding.Columns.Values) { expected.Add(Dependency("2620", binding.Trigger!, "1259", binding.Table, column, "n")); }
                foreach (JsonObject dependency in expected) { RemoveExact(rows, dependency, "new_dependency"); }
            }
            foreach (JsonObject row in rows)
            {
                if (V(row, "classid") == "2606" && V(row, "objid") == binding.NotNull) { row["objid"] = "@CompanyNameNotNull"; }
                if (V(row, "classid") == "1259") { RemapIndex(row, "objid", binding); }
            }
        }
        if (catalog == "pg_shdepend" && after && binding.Owner != "10")
        {
            JsonObject dependency = Dependency("1255", binding.Function!, "1260", binding.Owner, 0, "o");
            _ = dependency.Remove("refobjsubid"); dependency["dbid"] = binding.Database;
            RemoveExact(rows, dependency, "function_owner_dependency");
        }
        return [.. rows.Select(Canonical).Order(StringComparer.Ordinal)];
    }

    internal static void RequireOperandStatistics(JsonObject[] rows, string table, IReadOnlySet<int> columns, bool after)
    {
        JsonObject[] operands = [.. rows.Where(x => V(x, "starelid") == table && columns.Contains(Number(x, "staattnum")))];
        if ((after && operands.Length != 0) ||
            operands.Any(x => V(x, "stainherit") != "false") ||
            operands.GroupBy(x => Number(x, "staattnum")).Any(group => group.Count() != 1))
        { throw Invalid("operand_statistics"); }
    }

    private static void RemapIndex(JsonObject row, string field, Binding binding)
    {
        foreach ((string name, string id) in binding.Indexes) { if (V(row, field) == id) { row[field] = "@index/" + name; return; } }
    }
    private static void RemoveExact(List<JsonObject> rows, JsonObject expected, string code)
    {
        int index = rows.FindIndex(x => Canonical(x) == Canonical(expected));
        if (index < 0) { throw Invalid(code); }
        rows.RemoveAt(index);
    }
    private static JsonObject Dependency(string classId, string objectId, string refClass, string refId, int column, string type)
    {
        return new()
        {
            ["classid"] = classId,
            ["objid"] = objectId,
            ["objsubid"] = 0,
            ["refclassid"] = refClass,
            ["refobjid"] = refId,
            ["refobjsubid"] = column,
            ["deptype"] = type,
        };
    }

    private static JsonObject Template(string value)
    {
        return JsonNode.Parse(value)!.AsObject();
    }

    private static string V(JsonObject row, string key)
    {
        return row[key]?.ToString() ?? throw Invalid("catalog_field");
    }

    private static int Number(JsonObject row, string key)
    {
        return int.Parse(V(row, key), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static int[] Vector(JsonObject row, string key)
    {
        return row[key] is JsonArray array
            ? [.. array.Select(x => int.Parse(x!.ToString(), System.Globalization.CultureInfo.InvariantCulture))]
            : [.. V(row, key).Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(x => int.Parse(x, System.Globalization.CultureInfo.InvariantCulture))];
    }

    private static JsonObject One(IEnumerable<JsonObject> rows)
    {
        JsonObject[] values = [.. rows];
        return values.Length == 1 ? values[0] : throw Invalid("catalog_binding");
    }
    private static string Canonical(JsonObject row)
    {
        return new JsonObject(row.OrderBy(x => x.Key, StringComparer.Ordinal)
        .Select(x => new KeyValuePair<string, JsonNode?>(x.Key, x.Value?.DeepClone()))).ToJsonString();
    }

    private static void Equal(JsonObject expected, JsonObject observed, string code)
    { if (Canonical(expected) != Canonical(observed)) { throw Invalid(code); } }
    // Diagnostics contain only catalog field names, never tuple values or object identifiers.
    private static string DifferenceFacet(string[] expected, string[] observed)
    {
        string? missing = expected.FirstOrDefault(x => !observed.Contains(x, StringComparer.Ordinal));
        if (missing is null) { return "added_or_duplicate_tuple"; }
        JsonObject left = Template(missing);
        JsonObject? right = observed.Select(Template).FirstOrDefault(row =>
            (left["oid"] is not null && JsonNode.DeepEquals(left["oid"], row["oid"])) ||
            (left["attrelid"] is not null && JsonNode.DeepEquals(left["attrelid"], row["attrelid"]) &&
                JsonNode.DeepEquals(left["attnum"], row["attnum"])));
        return right is null ? "missing_or_rebound_tuple" :
            "fields_" + string.Join('_', left.Where(x => !JsonNode.DeepEquals(x.Value, right[x.Key])).Select(x => x.Key));
    }
    private static MigrationExecutionException Invalid(string code)
    {
        return new("customer_company_native_preservation_" + code,
        "The Company transition is outside the exact supported native catalog and storage closure (" + code + ").");
    }

    // PG18 x64 catalog templates captured from the independently executed fixed owner SQL on 2026-11-24.
    // Only explicitly bound OIDs, column ordinals/collations and the approved CRLF/LF body spelling vary.
    private const string CheckTemplate = /*lang=json,strict*/ """
        {"conbin":"{OPEXPR :opno 523 :opfuncid 149 :opresulttype 16 :opretset false :opcollid 0 :inputcollid 0 :args ({OPEXPR :opno 551 :opfuncid 177 :opresulttype 23 :opretset false :opcollid 0 :inputcollid 0 :args ({FUNCEXPR :funcid 1381 :funcresulttype 23 :funcretset false :funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 950 :args ({VAR :varno 1 :varattno 2 :vartype 25 :vartypmod -1 :varcollid 950 :varnullingrels (b) :varlevelsup 0 :varreturningtype 0 :varnosyn 1 :varattnosyn 2 :location -1}) :location -1} {FUNCEXPR :funcid 1381 :funcresulttype 23 :funcretset false :funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 950 :args ({FUNCEXPR :funcid 2285 :funcresulttype 25 :funcretset false :funcvariadic false :funcformat 0 :funccollid 950 :inputcollid 950 :args ({COLLATEEXPR :arg {VAR :varno 1 :varattno 2 :vartype 25 :vartypmod -1 :varcollid 950 :varnullingrels (b) :varlevelsup 0 :varreturningtype 0 :varnosyn 1 :varattnosyn 2 :location -1} :collOid 950 :location -1} {CONST :consttype 25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false :constisnull false :location -1 :constvalue 11 [ 44 0 0 0 91 1 45 -17 -65 -65 93 ]} {CONST :consttype 25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false :constisnull false :location -1 :constvalue 4 [ 16 0 0 0 ]} {CONST :consttype 25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false :constisnull false :location -1 :constvalue 5 [ 20 0 0 0 103 ]}) :location -1}) :location -1}) :location -1} {CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location -1 :constvalue 4 [ 0 1 0 0 0 0 0 0 ]}) :location -1}","condeferrable":false,"condeferred":false,"conenforced":true,"conexclop":null,"confdelsetcols":null,"confdeltype":" ","conffeqop":null,"confkey":null,"confmatchtype":" ","confrelid":"0","confupdtype":" ","conindid":"0","coninhcount":0,"conislocal":true,"conkey":[2],"conname":"CK_Company_Name_SourceLength","connamespace":"2200","connoinherit":false,"conparentid":"0","conperiod":false,"conpfeqop":null,"conppeqop":null,"conrelid":"16390","contype":"c","contypid":"0","convalidated":true,"oid":"16425"}
        """;
    private const string FunctionTemplate = /*lang=json,strict*/ """
        {"oid":"16428","proacl":null,"proallargtypes":null,"proargdefaults":null,"proargmodes":null,"proargnames":null,"proargtypes":[],"probin":null,"proconfig":["search_path=pg_catalog"],"procost":100,"proisstrict":false,"prokind":"f","prolang":"13681","proleakproof":false,"proname":"NormalizeCompanySource","pronamespace":"2200","pronargdefaults":0,"pronargs":0,"proowner":"10","proparallel":"u","proretset":false,"prorettype":"2279","prorows":0,"prosecdef":false,"prosqlbody":null,"prosrc":"@body","prosupport":"-","protrftypes":null,"provariadic":"0","provolatile":"v"}
        """;
    private const string TriggerTemplate = /*lang=json,strict*/ """
        {"oid":"16429","tgargs":"\\x","tgattr":[2,4,3],"tgconstraint":"0","tgconstrindid":"0","tgconstrrelid":"0","tgdeferrable":false,"tgenabled":"O","tgfoid":"16428","tginitdeferred":false,"tgisinternal":false,"tgname":"NormalizeCompanySource","tgnargs":0,"tgnewtable":null,"tgoldtable":null,"tgparentid":"0","tgqual":null,"tgrelid":"16390","tgtype":23}
        """;
}
