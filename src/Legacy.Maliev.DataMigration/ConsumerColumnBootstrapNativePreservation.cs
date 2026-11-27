using System.Text.Json.Nodes;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record ConsumerColumnBootstrapPreservationObservation(CurrentAppOwnedRetained31Observation Native,
    string LogicalDatabase, string ContractSha256, bool After, CurrentAppOwnedRelationFact OriginalRows,
    IReadOnlyDictionary<string, (uint File, long Blocks)> HeapStorage, int ProviderVersion, string CompositeDefense, ulong WalUpper);

/// <summary>Closed native observation only. No permit, executor or persistent-write authority.</summary>
internal static class ConsumerColumnBootstrapNativePreservation
{
    private static readonly string[] Catalogs =
    [
        "pg_class", "pg_type", "pg_namespace", "pg_constraint", "pg_attrdef", "pg_trigger", "pg_proc", "pg_collation", "pg_policy", "pg_rewrite",
        "pg_extension", "pg_event_trigger", "pg_authid", "pg_database", "pg_tablespace", "pg_language", "pg_operator", "pg_cast", "pg_opclass", "pg_opfamily",
        "pg_am", "pg_conversion", "pg_attribute", "pg_index", "pg_depend", "pg_shdepend", "pg_description", "pg_shdescription", "pg_auth_members",
        "pg_default_acl", "pg_init_privs", "pg_inherits", "pg_partitioned_table", "pg_sequence", "pg_statistic", "pg_statistic_ext", "pg_statistic_ext_data",
        "pg_amop", "pg_amproc", "pg_range", "pg_transform", "pg_seclabel", "pg_shseclabel",
    ];
    internal static IReadOnlyList<string> CatalogNames => Array.AsReadOnly(Catalogs.ToArray());

    internal static async Task<ConsumerColumnBootstrapPreservationObservation> CaptureAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        ConsumerColumnBootstrapContract contract, string database, bool after, CancellationToken ct)
    {
        if (transaction.IsolationLevel is not (System.Data.IsolationLevel.RepeatableRead or System.Data.IsolationLevel.Serializable))
        { throw Invalid("transaction_isolation"); }
        ConsumerColumnBootstrapOperand operand = Operand(database);
        int providerVersion; string defense;
        await using (var provider = new NpgsqlCommand("SELECT current_setting('server_encoding')='UTF8' AND (current_schemas(true))[1]='pg_catalog',current_setting('server_version_num')::integer,coalesce(current_setting('composite_type_mismatch',true),'');", connection, transaction))
        await using (NpgsqlDataReader reader = await provider.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(ct).ConfigureAwait(false) || !reader.GetBoolean(0)) { throw Invalid("provider"); }
            providerVersion = reader.GetInt32(1); defense = reader.GetString(2);
            if (providerVersion is < 180000 or > 189999 || (providerVersion >= 180007 && defense != "error")) { throw Invalid("provider"); }
        }
        DatabaseSchemaPlan physical = after ? contract.After(database) : contract.Before(database);
        await using (var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false))
        { if (await inspector.InspectSchemaAsync(physical, ct).ConfigureAwait(false) != physical.TargetSchemaSha256) { throw Invalid("physical_schema"); } }
        var native = await CurrentAppOwnedRetained31Preservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        CurrentAppOwnedRelationFact projection;
        await using (var command = new NpgsqlCommand("SELECT count(*),encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h COLLATE \"C\"),''),'UTF8')),'hex') FROM (SELECT encode(sha256(convert_to((to_jsonb(x)" +
            (after ? "-'" + operand.Column + "'" : string.Empty) + ")::text,'UTF8')),'hex') h FROM public." + PostgreSqlShadowTarget.QuoteIdentifier(operand.Table) + " x) rows;", connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        { if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw Invalid("projection"); } projection = new("public", operand.Table, reader.GetInt64(0), reader.GetString(1)); }
        if (after)
        {
            await using var values = new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM public." + PostgreSqlShadowTarget.QuoteIdentifier(operand.Table) + " WHERE " +
                PostgreSqlShadowTarget.QuoteIdentifier(operand.Column) + (operand.Nullable ? " IS NOT NULL" : " IS DISTINCT FROM false") + ");", connection, transaction);
            if (await values.ExecuteScalarAsync(ct).ConfigureAwait(false) is not true) { throw Invalid("added_values"); }
        }
        var heaps = new Dictionary<string, (uint, long)>(StringComparer.Ordinal);
        await using (var command = new NpgsqlCommand("""
            SELECT c.oid::text,pg_relation_filenode(c.oid),pg_relation_size(c.oid)/current_setting('block_size')::bigint
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','t') AND
             ((n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema') OR c.oid IN
              (SELECT u.reltoastrelid FROM pg_class u JOIN pg_namespace un ON un.oid=u.relnamespace
               WHERE u.relkind='r' AND un.nspname NOT LIKE 'pg_%' AND un.nspname<>'information_schema'));
            """, connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        { while (await reader.ReadAsync(ct).ConfigureAwait(false)) { heaps.Add(reader.GetString(0), (reader.GetFieldValue<uint>(1), reader.GetInt64(2))); } }
        await using var wal = new NpgsqlCommand("SELECT pg_current_wal_insert_lsn()::text;", connection, transaction);
        string[] parts = ((string)(await wal.ExecuteScalarAsync(ct).ConfigureAwait(false))!).Split('/');
        if (parts.Length != 2 || !uint.TryParse(parts[0], System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture, out uint high) ||
            !uint.TryParse(parts[1], System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture, out uint low)) { throw Invalid("wal"); }
        var observation = new ConsumerColumnBootstrapPreservationObservation(native, database, contract.ComputeSha256(), after, projection, heaps, providerVersion, defense, ((ulong)high << 32) | low);
        _ = Bind(observation);
        return observation;
    }

    internal static void RequirePreserved(ConsumerColumnBootstrapPreservationObservation before, ConsumerColumnBootstrapPreservationObservation after,
        ConsumerColumnBootstrapContract contract)
    {
        if (before.After || !after.After || before.LogicalDatabase != after.LogicalDatabase || before.ContractSha256 != contract.ComputeSha256() ||
            before.ContractSha256 != after.ContractSha256 || before.Native.Snapshot.Database != after.Native.Snapshot.Database ||
            before.ProviderVersion != after.ProviderVersion || before.CompositeDefense != after.CompositeDefense || after.WalUpper < before.WalUpper) { throw Invalid("binding"); }
        var operand = Operand(before.LogicalDatabase); var left = Bind(before); var right = Bind(after);
        JsonObject addedAttribute = One(after.Native.Read("pg_attribute"), x => V(x, "attrelid") == right.Table && V(x, "attname") == operand.Column);
        RequireNewAttributeOptions(addedAttribute["attoptions"], after.ProviderVersion, after.CompositeDefense, before.WalUpper, after.WalUpper);
        if (left.Table != right.Table || left.Namespace != right.Namespace || before.OriginalRows != after.OriginalRows ||
            !before.Native.Snapshot.Sequences.SequenceEqual(after.Native.Snapshot.Sequences) ||
            !before.Native.Snapshot.Relations.Where(x => x.Schema != "public" || x.Name != operand.Table).SequenceEqual(after.Native.Snapshot.Relations.Where(x => x.Schema != "public" || x.Name != operand.Table)) ||
            !before.HeapStorage.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(after.HeapStorage.OrderBy(x => x.Key, StringComparer.Ordinal))) { throw Invalid("rows_sequences_heaps"); }
        foreach (string catalog in Catalogs)
        { if (!Normalize(before, left, catalog).SequenceEqual(Normalize(after, right, catalog), StringComparer.Ordinal)) { throw Invalid("catalog_" + catalog); } }
        var oldIndexes = before.Native.Read("pg_class").Where(x => V(x, "relkind") == "i").ToArray();
        var newIndexes = after.Native.Read("pg_class").Where(x => V(x, "relkind") == "i").ToArray();
        if (!oldIndexes.Select(x => V(x, "oid")).Order(StringComparer.Ordinal).SequenceEqual(newIndexes.Select(x => V(x, "oid")).Order(StringComparer.Ordinal))) { throw Invalid("index_inventory"); }
        foreach (JsonObject index in oldIndexes)
        {
            string oid = V(index, "oid"); var oldStorage = before.Native.Storage(oid); var newStorage = after.Native.Storage(oid);
            if (!operand.Nullable && FixedIndex(before.Native, index))
            {
                RequireFixedStorage(oldStorage.FileNode, oldStorage.Blocks, newStorage.FileNode, newStorage.Blocks,
                    uint.Parse(oid, System.Globalization.CultureInfo.InvariantCulture));
            }
            else if (oldStorage != newStorage) { throw Invalid("index_storage"); }
        }
    }

    private sealed record Binding(string Table, string Namespace, string Attribute, string? Default, string? Constraint);
    private static Binding Bind(ConsumerColumnBootstrapPreservationObservation observation)
    {
        var operand = Operand(observation.LogicalDatabase); var native = observation.Native;
        string ns = V(One(native.Read("pg_namespace"), x => V(x, "nspname") == "public"), "oid");
        JsonObject table = One(native.Read("pg_class"), x => V(x, "relnamespace") == ns && V(x, "relname") == operand.Table && V(x, "relkind") == "r");
        string id = V(table, "oid");
        if (V(table, "relnatts") != (observation.After ? operand.AppendOrdinal : operand.AppendOrdinal - 1).ToString(System.Globalization.CultureInfo.InvariantCulture)) { throw Invalid("column_count"); }
        if (!observation.After)
        {
            if (native.Read("pg_attribute").Any(x => V(x, "attrelid") == id && V(x, "attname") == operand.Column)) { throw Invalid("already_added"); }
            if (!operand.Nullable)
            {
                JsonObject[] fixedIndexes = native.Read("pg_class").Where(x => V(x, "relkind") == "i" && FixedIndex(native, x)).ToArray();
                if (fixedIndexes.Length != 2) { throw Invalid("fixed_index_inventory"); }
                foreach (JsonObject index in fixedIndexes)
                { var (FileNode, Blocks) = native.Storage(V(index, "oid")); if (Blocks is not (1 or 2) || FileNode.ToString(System.Globalization.CultureInfo.InvariantCulture) != V(index, "oid")) { throw Invalid("storage_preimage"); } }
            }
            return new(id, ns, string.Empty, null, null);
        }
        JsonObject attribute = One(native.Read("pg_attribute"), x => V(x, "attrelid") == id && V(x, "attname") == operand.Column);
        JsonObject expected = JsonNode.Parse(operand.Nullable ? TimestampAttribute : BooleanAttribute)!.AsObject(); expected["attrelid"] = id;
        RequireNewAttributeOptions(attribute["attoptions"], observation.ProviderVersion, observation.CompositeDefense, 0, observation.WalUpper);
        expected["attoptions"] = attribute["attoptions"]?.DeepClone();
        if (Canonical(attribute) != Canonical(expected)) { throw Invalid("attribute"); }
        string? defId = null, constraintId = null;
        if (!operand.Nullable)
        {
            JsonObject def = One(native.Read("pg_attrdef"), x => V(x, "adrelid") == id && V(x, "adnum") == "19"); defId = V(def, "oid");
            expected = JsonNode.Parse(BooleanDefault)!.AsObject(); expected["oid"] = defId; expected["adrelid"] = id;
            if (Canonical(def) != Canonical(expected)) { throw Invalid("default"); }
            JsonObject constraint = One(native.Read("pg_constraint"), x => V(x, "conrelid") == id && V(x, "conname") == "AspNetUsers_PasswordSetupRequired_not_null"); constraintId = V(constraint, "oid");
            expected = JsonNode.Parse(BooleanConstraint)!.AsObject(); expected["oid"] = constraintId; expected["conrelid"] = id; expected["connamespace"] = ns;
            if (Canonical(constraint) != Canonical(expected)) { throw Invalid("constraint"); }
        }
        return new(id, ns, Canonical(attribute), defId, constraintId);
    }

    private static string[] Normalize(ConsumerColumnBootstrapPreservationObservation observation, Binding binding, string catalog)
    {
        var result = new List<string>(); int added = 0; var dependencies = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonObject row in observation.Native.Read(catalog))
        {
            if (observation.After)
            {
                if ((catalog == "pg_attribute" && Canonical(row) == binding.Attribute) ||
                    (catalog == "pg_attrdef" && binding.Default is not null && V(row, "oid") == binding.Default) ||
                    (catalog == "pg_constraint" && binding.Constraint is not null && V(row, "oid") == binding.Constraint)) { added++; continue; }
                if (catalog == "pg_depend" && ((binding.Default is not null && V(row, "classid") == "2604" && V(row, "objid") == binding.Default) ||
                    (binding.Constraint is not null && V(row, "classid") == "2606" && V(row, "objid") == binding.Constraint)))
                {
                    JsonObject expected = JsonNode.Parse("""{"classid":"0","objid":"0","objsubid":0,"refclassid":"1259","refobjid":"0","refobjsubid":19,"deptype":"a"}""")!.AsObject();
                    expected["classid"] = V(row, "classid"); expected["objid"] = V(row, "objid"); expected["refobjid"] = binding.Table;
                    if (Canonical(row) != Canonical(expected) || !dependencies.Add(V(row, "classid") + "/" + V(row, "objid"))) { throw Invalid("dependency"); }
                    added++; continue;
                }
                if (catalog == "pg_class" && V(row, "oid") == binding.Table) { row["relnatts"] = Operand(observation.LogicalDatabase).AppendOrdinal - 1; }
            }
            result.Add(Canonical(row));
        }
        int expectedAdded = catalog == "pg_attribute" ? 1 : binding.Default is not null ? catalog switch { "pg_attrdef" or "pg_constraint" => 1, "pg_depend" => 2, _ => 0 } : 0;
        return observation.After && added != expectedAdded
            ? throw Invalid("tuple_multiplicity")
            : result.Order(StringComparer.Ordinal).ToArray();
    }

    private static bool FixedIndex(CurrentAppOwnedRetained31Observation native, JsonObject index)
    {
        string name = V(index, "relname"); if (name is not ("pg_attrdef_adrelid_adnum_index" or "pg_attrdef_oid_index")) { return false; }
        string oid = name == "pg_attrdef_oid_index" ? "2657" : "2656";
        JsonObject space = One(native.Read("pg_namespace"), x => V(x, "oid") == V(index, "relnamespace"));
        JsonObject definition = One(native.Read("pg_index"), x => V(x, "indexrelid") == V(index, "oid"));
        return V(index, "oid") != oid || V(index, "relfilenode") != oid || V(space, "nspname") != "pg_catalog" || V(index, "relam") != "403" ||
            V(definition, "indrelid") != "2604" || V(definition, "indisvalid") != "true" || V(definition, "indisready") != "true" || V(definition, "indislive") != "true"
            ? throw Invalid("fixed_index_identity")
            : true;
    }
    internal static void RequireFixedStorage(uint beforeFile, long beforeBlocks, uint afterFile, long afterBlocks, uint expectedFile)
    {
        if (beforeFile != expectedFile || afterFile != beforeFile || beforeBlocks is not (1 or 2) ||
            (beforeBlocks == 1 ? afterBlocks is not (1 or 2) : afterBlocks != 2)) { throw Invalid("fixed_storage"); }
    }
    // The fixed ADD COLUMN statements specify no user options. Only the security backpatch's one reserved creation version is possible.
    internal static void RequireNewAttributeOptions(JsonNode? options, int providerVersion, string compositeDefense, ulong beforeWal, ulong afterWal)
    {
        if (providerVersion is < 180000 or > 189999 || afterWal < beforeWal) { throw Invalid("new_attribute_provider"); }
        if (providerVersion < 180007)
        { if (options is not null) { throw Invalid("legacy_new_attribute_options"); } return; }
        if (compositeDefense != "error" || options is not JsonArray { Count: 1 } array || array[0] is not JsonValue value ||
            !value.TryGetValue(out string? text) || text is null || !text.StartsWith("pg_attver=", StringComparison.Ordinal)) { throw Invalid("new_attribute_options"); }
        string raw = text[10..];
        if (!ulong.TryParse(raw, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out ulong version) ||
            version == 0 || version.ToString(System.Globalization.CultureInfo.InvariantCulture) != raw || version <= beforeWal || version > afterWal)
        { throw Invalid("new_attribute_version"); }
    }
    private static ConsumerColumnBootstrapOperand Operand(string database)
    {
        return ConsumerColumnBootstrapContract.Operands().SingleOrDefault(x => x.Database == database) ?? throw Invalid("database");
    }

    private static JsonObject One(IEnumerable<JsonObject> rows, Func<JsonObject, bool> predicate) { JsonObject[] found = rows.Where(predicate).ToArray(); return found.Length == 1 ? found[0] : throw Invalid("catalog_identity"); }
    private static string V(JsonObject row, string key)
    {
        return row[key]?.ToString() ?? "null";
    }

    private static string Canonical(JsonObject row)
    {
        return new JsonObject([.. row.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new KeyValuePair<string, JsonNode?>(x.Key, x.Value?.DeepClone()))]).ToJsonString();
    }

    private static MigrationExecutionException Invalid(string detail)
    {
        return new("consumer_column_bootstrap_preservation_invalid", "Closed bootstrap observation rejected: " + detail);
    }

    private const string BooleanAttribute = /*lang=json,strict*/ """{"attacl":null,"attalign":"c","attbyval":true,"attcollation":"0","attcompression":"","attfdwoptions":null,"attgenerated":"","atthasdef":true,"atthasmissing":true,"attidentity":"","attinhcount":0,"attisdropped":false,"attislocal":true,"attlen":1,"attmissingval":[false],"attname":"PasswordSetupRequired","attndims":0,"attnotnull":true,"attnum":19,"attoptions":null,"attrelid":"0","attstattarget":null,"attstorage":"p","atttypid":"16","atttypmod":-1}""";
    private const string TimestampAttribute = /*lang=json,strict*/ """{"attacl":null,"attalign":"d","attbyval":true,"attcollation":"0","attcompression":"","attfdwoptions":null,"attgenerated":"","atthasdef":false,"atthasmissing":false,"attidentity":"","attinhcount":0,"attisdropped":false,"attislocal":true,"attlen":8,"attmissingval":null,"attname":"DecisionOrderVersion","attndims":0,"attnotnull":false,"attnum":24,"attoptions":null,"attrelid":"0","attstattarget":null,"attstorage":"p","atttypid":"1114","atttypmod":-1}""";
    private const string BooleanDefault = """{"adbin":"{CONST :consttype 16 :consttypmod -1 :constcollid 0 :constlen 1 :constbyval true :constisnull false :location -1 :constvalue 1 [ 0 0 0 0 0 0 0 0 ]}","adnum":19,"adrelid":"0","oid":"0"}""";
    private const string BooleanConstraint = """{"conbin":null,"condeferrable":false,"condeferred":false,"conenforced":true,"conexclop":null,"confdelsetcols":null,"confdeltype":" ","conffeqop":null,"confkey":null,"confmatchtype":" ","confrelid":"0","confupdtype":" ","conindid":"0","coninhcount":0,"conislocal":true,"conkey":[19],"conname":"AspNetUsers_PasswordSetupRequired_not_null","connamespace":"0","connoinherit":false,"conparentid":"0","conperiod":false,"conpfeqop":null,"conppeqop":null,"conrelid":"0","contype":"n","contypid":"0","convalidated":true,"oid":"0"}""";
}
