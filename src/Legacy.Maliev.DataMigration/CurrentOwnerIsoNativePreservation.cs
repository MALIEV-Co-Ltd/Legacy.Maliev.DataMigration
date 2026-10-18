using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentOwnerIsoStorage(uint FileNode, long Blocks, long Rows);
internal sealed record CurrentOwnerIsoStorageFrame(string? ObjectId, string? Relation, string? Kind, bool Rebuilt, bool Index,
    string CatalogFileNode, uint ActualFileNode, long ActualBlocks, long? ActualRows, long ExpectedTuples,
    long CatalogPages, string CatalogTuples, long CatalogAllVisible, long CatalogAllFrozen);
internal sealed record CurrentOwnerIsoLiteralRows(long Rows, string Sha256, bool ExactWidths);

/// <summary>Component observation only. Raw values stay in memory; this grants no permission.</summary>
internal sealed class CurrentOwnerIsoNativeObservation
{
    internal CurrentAppOwnedDatabaseSnapshot Snapshot { get; }
    internal string OverlaySha256 { get; }
    internal bool Selected { get; }
    internal CurrentOwnerIsoLiteralRows LiteralRows { get; }
    internal uint SnapshotXmin { get; }
    private readonly Dictionary<string, string[]> _catalog;
    private readonly Dictionary<string, CurrentOwnerIsoStorage> _storage;
    internal CurrentOwnerIsoNativeObservation(CurrentAppOwnedDatabaseSnapshot snapshot, string overlaySha256, bool selected,
        CurrentOwnerIsoLiteralRows literalRows, Dictionary<string, string[]> catalog, Dictionary<string, CurrentOwnerIsoStorage> storage, uint snapshotXmin)
    {
        Snapshot = snapshot with
        {
            Catalog = Array.AsReadOnly(snapshot.Catalog.ToArray()),
            Relations = Array.AsReadOnly(snapshot.Relations.ToArray()),
            Sequences = Array.AsReadOnly(snapshot.Sequences.ToArray())
        };
        OverlaySha256 = overlaySha256; Selected = selected; LiteralRows = literalRows;
        SnapshotXmin = snapshotXmin;
        _catalog = catalog.ToDictionary(x => x.Key, x => x.Value.ToArray(), StringComparer.Ordinal);
        _storage = new(storage, StringComparer.Ordinal);
    }
    internal JsonObject[] Read(string name)
    {
        return _catalog[name].Select(x => JsonNode.Parse(x)!.AsObject()).ToArray();
    }

    internal Dictionary<string, string[]> CopyCatalog()
    {
        return _catalog.ToDictionary(x => x.Key, x => x.Value.ToArray(), StringComparer.Ordinal);
    }

    internal Dictionary<string, CurrentOwnerIsoStorage> CopyStorage()
    {
        return new(_storage, StringComparer.Ordinal);
    }

    internal CurrentOwnerIsoStorage Storage(string oid)
    {
        return _storage[oid];
    }
}

/// <summary>Fixed ISO type/physical replacement proposal; unsupported native rewrites fail closed.</summary>
internal static class CurrentOwnerIsoNativePreservation
{
    internal static string OwnerPolicySha256(DeltaTargetAuthority target)
    {
        return CurrentAppOwnedSnapshotSerialization.Sha256(new
        {
            Domain = "Legacy.Maliev.CurrentOwnerIsoRepair.OperandOwners.v1",
            Country = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.CountryIsoLiteral, target),
            MaterialCountry = CurrentRepairOperandOwnerProfile.PolicySha256(CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral, target),
        });
    }

    internal static Task<string> RequireOperandOwnerAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CurrentOwnerIsoRepairScope scope, CurrentOwnerIsoNativeObservation observation, CancellationToken ct)
    {
        if ((scope.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg && scope.OwnerPolicySha256 is null) ||
            (scope.OwnerPolicySha256 is not null && scope.OwnerPolicySha256 != OwnerPolicySha256(scope.Target))) { throw Invalid("operand_owner_policy"); }
        CurrentRepairOperandOwnerPurpose purpose = connection.Database switch
        {
            "Country" => CurrentRepairOperandOwnerPurpose.CountryIsoLiteral,
            "Material" => CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral,
            _ => throw Invalid("operand_owner_database"),
        };
        return CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, transaction, purpose, scope.Target, observation.Snapshot, ct);
    }

    private static readonly string[] PhysicalReplacementFieldNames = ["relfilenode", "relpages", "reltuples"];
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
    private sealed record Binding(string Heap, Dictionary<string, string> Columns, HashSet<string> Storage,
        HashSet<string> Indexes);

    internal static async Task<CurrentOwnerIsoNativeObservation> CaptureAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        ApprovedCurrentOwnerIsoOverlay overlay, bool selected, CancellationToken ct)
    {
        if (connection.Database is not ("Country" or "Material") || transaction.Connection != connection ||
            transaction.IsolationLevel is not (IsolationLevel.Serializable or IsolationLevel.RepeatableRead)) { throw Invalid("capture_scope"); }
        CurrentAppOwnedDatabaseSnapshot snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        TableCopyPlan[] physical = overlay.PhysicalTables(connection.Database, selected);
        // Existing schema inspector supplies a same-transaction whole physical component check.
        // Private relations remain in complete raw/row evidence; no historical fingerprint is rewritten.
        var inspectionPlan = new DatabaseSchemaPlan(connection.Database, "1.0", new string('0', 64), new string('0', 64), physical);
        await using (var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false))
        {
            var (SchemaSha256, Components, Columns) = await inspector.InspectSchemaWithComponentsAsync(inspectionPlan, ct).ConfigureAwait(false);
            foreach (TableCopyPlan table in physical)
            {
                ProductionSchemaTableComponents expected = PostgreSqlSchemaFingerprint.ComputeExpectedComponents(table);
                ProductionSchemaTableComponents actual = Components.Single(x => x.Schema == table.TargetSchema && x.Table == table.TargetTable);
                if (actual != expected) { throw Invalid("physical_table"); }
            }
            if (!Components.Where(x => x.Schema == "public").Select(x => x.Table).ToHashSet(StringComparer.Ordinal)
                .SetEquals(physical.Where(x => x.TargetSchema == "public").Select(x => x.TargetTable))) { throw Invalid("public_inventory"); }
        }
        var catalog = new Dictionary<string, string[]>(StringComparer.Ordinal);
        foreach (string name in Catalogs)
        {
            string filter = name == "pg_shdepend" ? " WHERE x.dbid=0 OR x.dbid=(SELECT oid FROM pg_database WHERE datname=current_database())" : "";
            await using var command = new NpgsqlCommand($"SELECT to_jsonb(x)::text FROM pg_catalog.{name} x{filter};", connection, transaction);
            var tuples = new List<string>();
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { tuples.Add(reader.GetString(0)); }
            catalog.Add(name, tuples.ToArray());
        }
        JsonObject[] classes = catalog["pg_class"].Select(x => JsonNode.Parse(x)!.AsObject()).ToArray();
        string ns = Value(catalog["pg_namespace"].Select(x => JsonNode.Parse(x)!.AsObject()).Single(x => Value(x, "nspname") == "public"), "oid");
        string heap = Value(classes.Single(x => Value(x, "relnamespace") == ns && Value(x, "relname") == "Country"), "oid");
        string toast = Value(classes.Single(x => Value(x, "oid") == heap), "reltoastrelid");
        var storageIds = new HashSet<string>(StringComparer.Ordinal) { heap };
        if (toast != "0") { _ = storageIds.Add(toast); }
        foreach (string index in catalog["pg_index"].Select(x => JsonNode.Parse(x)!.AsObject())
            .Where(x => storageIds.Contains(Value(x, "indrelid"))).Select(x => Value(x, "indexrelid")).ToArray()) { _ = storageIds.Add(index); }
        var storage = new Dictionary<string, CurrentOwnerIsoStorage>(StringComparer.Ordinal);
        foreach (string oid in storageIds)
        {
            JsonObject relation = classes.Single(x => Value(x, "oid") == oid);
            string schema = Value(catalog["pg_namespace"].Select(x => JsonNode.Parse(x)!.AsObject())
                .Single(x => Value(x, "oid") == Value(relation, "relnamespace")), "nspname");
            string name = Value(relation, "relname");
            bool index = Value(relation, "relkind") == "i";
            string rowSql = index ? "0::bigint" : $"(SELECT count(*) FROM {Quote(schema)}.{Quote(name)})";
            await using var command = new NpgsqlCommand($"SELECT pg_relation_filenode(@oid::oid),pg_relation_size(@oid::oid)/current_setting('block_size')::bigint,{rowSql};", connection, transaction);
            _ = command.Parameters.AddWithValue("oid", NpgsqlTypes.NpgsqlDbType.Oid, uint.Parse(oid, CultureInfo.InvariantCulture));
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw Invalid("storage_capture"); }
            storage.Add(oid, new(reader.GetFieldValue<uint>(0), reader.GetInt64(1), reader.GetInt64(2)));
        }
        await using var horizonCommand = new NpgsqlCommand("SELECT (pg_snapshot_xmin(pg_current_snapshot())::text::numeric % 4294967296)::text;", connection, transaction);
        uint snapshotXmin = uint.Parse((string)(await horizonCommand.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? throw Invalid("snapshot_xmin")), CultureInfo.InvariantCulture);
        string send2 = selected ? "convert_to(x.\"ISO2\",'UTF8')" : "bpcharsend(x.\"ISO2\")";
        string send3 = selected ? "convert_to(x.\"ISO3\",'UTF8')" : "bpcharsend(x.\"ISO3\")";
        string expression = "(to_jsonb(x)-'ISO2'-'ISO3') || jsonb_build_object('ISO2',encode(" + send2 + ",'hex'),'ISO3',encode(" + send3 + ",'hex'))";
        await using var rowsCommand = new NpgsqlCommand("SELECT count(*),encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h COLLATE \"C\"),''),'UTF8')),'hex'),coalesce(bool_and(w),true) FROM " +
            "(SELECT encode(sha256(convert_to((" + expression + ")::text,'UTF8')),'hex') h," +
            "(x.\"ISO2\" IS NULL OR char_length(convert_from(" + send2 + ",'UTF8'))=2) AND " +
            "(x.\"ISO3\" IS NULL OR char_length(convert_from(" + send3 + ",'UTF8'))=3) w FROM public.\"Country\" x) rows;", connection, transaction);
        await using NpgsqlDataReader rowsReader = await rowsCommand.ExecuteReaderAsync(ct).ConfigureAwait(false);
        return !await rowsReader.ReadAsync(ct).ConfigureAwait(false)
            ? throw Invalid("literal_capture")
            : new(snapshot, overlay.ComputeSha256(), selected, new(rowsReader.GetInt64(0), rowsReader.GetString(1), rowsReader.GetBoolean(2)), catalog, storage, snapshotXmin);
    }

    internal static void RequireBefore(CurrentOwnerIsoNativeObservation before, ApprovedCurrentOwnerIsoOverlay overlay)
    {
        if (before.Selected || before.OverlaySha256 != overlay.ComputeSha256()) { throw Invalid("preimage"); }
        _ = Bind(before, overlay);
    }

    internal static void RequirePreserved(CurrentOwnerIsoNativeObservation before, CurrentOwnerIsoNativeObservation after, ApprovedCurrentOwnerIsoOverlay overlay)
    {
        RequireBefore(before, overlay);
        if (!after.Selected || after.OverlaySha256 != before.OverlaySha256 || after.Snapshot.Database != before.Snapshot.Database ||
            !before.Snapshot.Sequences.SequenceEqual(after.Snapshot.Sequences) || before.LiteralRows != after.LiteralRows) { throw Invalid("literal_rows_or_sequence"); }
        Binding left = Bind(before, overlay), right = Bind(after, overlay);
        if (left.Heap != right.Heap || !left.Storage.SetEquals(right.Storage) || !left.Columns.OrderBy(x => x.Key).SequenceEqual(right.Columns.OrderBy(x => x.Key)))
        { throw Invalid("object_identity"); }
        if (before.Storage(left.Heap).FileNode == after.Storage(right.Heap).FileNode) { throw Invalid("heap_not_replaced"); }
        foreach (string oid in left.Storage.Where(x => !left.Indexes.Contains(x)))
        {
            RequireHeapStatisticsPreserved(before.Read("pg_class").Single(x => Value(x, "oid") == oid),
                after.Read("pg_class").Single(x => Value(x, "oid") == oid));
            if (oid == left.Heap)
            {
                RequireFrozenXidProgression(before.Read("pg_class").Single(x => Value(x, "oid") == oid),
                    after.Read("pg_class").Single(x => Value(x, "oid") == oid), after.SnapshotXmin);
            }
        }
        CurrentAppOwnedRelationFact[] leftRows = [.. before.Snapshot.Relations.Select(NormalizeRows)];
        CurrentAppOwnedRelationFact[] rightRows = [.. after.Snapshot.Relations.Select(NormalizeRows)];
        if (!leftRows.SequenceEqual(rightRows)) { throw Invalid("retained_rows"); }
        foreach (string name in Catalogs)
        {
            if (!Normalize(before, left, name).SequenceEqual(Normalize(after, right, name), StringComparer.Ordinal)) { throw Invalid("catalog_" + name); }
        }
        CurrentAppOwnedRelationFact NormalizeRows(CurrentAppOwnedRelationFact row)
        {
            return row.Schema == "public" && row.Name == "Country"
            ? row with { RowSha256 = before.LiteralRows.Sha256 } : row;
        }
    }

    private static Binding Bind(CurrentOwnerIsoNativeObservation observation, ApprovedCurrentOwnerIsoOverlay overlay)
    {
        RequireRawBinding(observation);
        if (observation.Snapshot.Database is not ("Country" or "Material") || !observation.LiteralRows.ExactWidths ||
            observation.LiteralRows.Rows != observation.Snapshot.Relations.Single(x => x.Schema == "public" && x.Name == "Country").Rows)
        { throw Invalid("literal_widths"); }
        JsonObject[] classes = observation.Read("pg_class"), attrs = observation.Read("pg_attribute"), deps = observation.Read("pg_depend");
        string ns = Value(observation.Read("pg_namespace").Single(x => Value(x, "nspname") == "public"), "oid");
        JsonObject heap = classes.Single(x => Value(x, "relnamespace") == ns && Value(x, "relname") == "Country");
        string id = Value(heap, "oid");
        if (Value(heap, "relkind") != "r" || Value(heap, "relpersistence") != "p" || Value(heap, "relispartition") != "false" ||
            Value(heap, "relrowsecurity") != "false" || Value(heap, "relforcerowsecurity") != "false" || heap["reloptions"] is not null) { throw Invalid("heap_behavior"); }
        JsonObject[] heapAttributes = [.. attrs.Where(x => Value(x, "attrelid") == id && Number(x, "attnum") > 0)];
        TableCopyPlan physical = overlay.PhysicalTables(observation.Snapshot.Database, observation.Selected)
            .Single(x => x.TargetSchema == "public" && x.TargetTable == "Country");
        if (heapAttributes.Length != 8 || !heapAttributes.Select(x => Value(x, "attname")).ToHashSet(StringComparer.Ordinal)
            .SetEquals(physical.OrderedColumns) || heapAttributes.Any(x => Value(x, "attisdropped") != "false")) { throw Invalid("complete_columns"); }
        JsonObject[] heapConstraints = [.. observation.Read("pg_constraint").Where(x => Value(x, "conrelid") == id)];
        if (heapConstraints.Length != 3 || !heapConstraints.Select(x => Value(x, "conname")).ToHashSet(StringComparer.Ordinal)
            .SetEquals(["PK_Country", "Country_ID_not_null", "Country_Name_not_null"])) { throw Invalid("unknown_constraint"); }
        foreach (JsonObject constraint in heapConstraints)
        {
            string column = Value(constraint, "conname") == "Country_Name_not_null" ? "Name" : "ID";
            string number = Value(heapAttributes.Single(x => Value(x, "attname") == column), "attnum");
            JsonNode? key = constraint["conkey"];
            string actualKey = key is JsonArray array ? string.Join(' ', array.Select(x => x!.ToString())) : Value(constraint, "conkey");
            if (actualKey != number || Value(constraint, "contype") != (Value(constraint, "conname") == "PK_Country" ? "p" : "n") ||
                Value(constraint, "convalidated") != "true" || Value(constraint, "conenforced") != "true" || Value(constraint, "condeferrable") != "false" ||
                Value(constraint, "condeferred") != "false" || Value(constraint, "conparentid") != "0") { throw Invalid("constraint_shape"); }
        }
        var columns = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (CurrentOwnerIsoOperand operand in ApprovedCurrentOwnerIsoOverlay.Operands().Where(x => x.Database == observation.Snapshot.Database))
        {
            JsonObject attr = attrs.Single(x => Value(x, "attrelid") == id && Value(x, "attname") == operand.Column);
            string number = Value(attr, "attnum");
            if (Value(attr, "atttypid") != (observation.Selected ? "1043" : "1042") || Number(attr, "atttypmod") != operand.CharacterWidth + 4 ||
                Value(attr, "attnotnull") != "false" || Value(attr, "attisdropped") != "false" || Value(attr, "atthasdef") != "false" ||
                Value(attr, "attidentity") != "" || Value(attr, "attgenerated") != "") { throw Invalid("typed_operand"); }
            string coll = Value(attr, "attcollation");
            JsonObject collation = observation.Read("pg_collation").Single(x => Value(x, "oid") == coll);
            if (Value(collation, "collnamespace") != ns || Value(collation, "collname") != "legacy_ci_as" ||
                Value(collation, "collprovider") != "i" || Value(collation, "collisdeterministic") != "false" ||
                Value(collation, "colllocale") != "und-u-ks-level2") { throw Invalid("collation"); }
            columns.Add(number, operand.Column);
            if (deps.Any(x => Value(x, "refclassid") == "1259" && Value(x, "refobjid") == id && Value(x, "refobjsubid") == number))
            { throw Invalid("incoming_operand_dependency"); }
            JsonObject[] outgoing = [.. deps.Where(x => Value(x, "classid") == "1259" && Value(x, "objid") == id && Value(x, "objsubid") == number)];
            int typeDependencies = outgoing.Count(x => Value(x, "refclassid") == "1247" && Value(x, "refobjid") == (observation.Selected ? "1043" : "1042") &&
                Value(x, "refobjsubid") == "0" && Value(x, "deptype") == "n");
            // PostgreSQL omits references to pinned built-ins. Preserve that absence;
            // if an exact explicit type dependency exists, only its typed endpoint may change.
            if (typeDependencies > 1 || outgoing.Length != 1 + typeDependencies ||
                outgoing.Count(x => Value(x, "refclassid") == "3456" && Value(x, "refobjid") == coll && Value(x, "refobjsubid") == "0" && Value(x, "deptype") == "n") != 1)
            { throw Invalid("outgoing_operand_dependency"); }
        }
        if (columns.Count != 2 || observation.Read("pg_statistic").Any(x => Value(x, "starelid") == id) ||
            observation.Read("pg_statistic_ext").Any(x => Value(x, "stxrelid") == id) ||
            observation.Read("pg_trigger").Any(x => Value(x, "tgrelid") == id) || observation.Read("pg_policy").Any(x => Value(x, "polrelid") == id))
        { throw Invalid("unsupported_behavior_or_statistics"); }
        JsonObject[] indexes = [.. observation.Read("pg_index").Where(x => Value(x, "indrelid") == id)];
        string idNumber = Value(attrs.Single(x => Value(x, "attrelid") == id && Value(x, "attname") == "ID"), "attnum");
        if (indexes.Length != 1) { throw Invalid("unknown_index"); }
        JsonObject pk = indexes[0]; string pkId = Value(pk, "indexrelid");
        JsonObject pkClass = classes.Single(x => Value(x, "oid") == pkId);
        if (Value(pkClass, "relname") != "PK_Country" || Value(pkClass, "relkind") != "i" || Value(pkClass, "relam") != "403" ||
            Value(pk, "indisunique") != "true" || Value(pk, "indisprimary") != "true" || Value(pk, "indnullsnotdistinct") != "false" ||
            Value(pk, "indisvalid") != "true" || Value(pk, "indisready") != "true" || Value(pk, "indislive") != "true" ||
            Value(pk, "indnatts") != "1" || Value(pk, "indnkeyatts") != "1" || !VectorEquals(pk, "indkey", [uint.Parse(idNumber, CultureInfo.InvariantCulture)]) ||
            !VectorEquals(pk, "indclass", [1978]) || !VectorEquals(pk, "indcollation", [0]) || !VectorEquals(pk, "indoption", [0]) || pk["indexprs"] is not null || pk["indpred"] is not null)
        { throw Invalid("primary_index"); }
        var storage = new HashSet<string>(StringComparer.Ordinal) { id, pkId };
        var storageIndexes = new HashSet<string>(StringComparer.Ordinal) { pkId };
        string toast = Value(heap, "reltoastrelid");
        if (toast != "0")
        {
            JsonObject toastClass = classes.Single(x => Value(x, "oid") == toast);
            string toastNs = Value(observation.Read("pg_namespace").Single(x => Value(x, "nspname") == "pg_toast"), "oid");
            if (Value(toastClass, "relkind") != "t" || Value(toastClass, "relnamespace") != toastNs || Value(toastClass, "relowner") != Value(heap, "relowner") ||
                Value(toastClass, "relname") != "pg_toast_" + id || Value(toastClass, "reltoastrelid") != "0") { throw Invalid("toast_identity"); }
            JsonObject[] toastIndexes = [.. observation.Read("pg_index").Where(x => Value(x, "indrelid") == toast)];
            if (toastIndexes.Length != 1 || Value(toastIndexes[0], "indisunique") != "true" || Value(toastIndexes[0], "indisvalid") != "true" ||
                !VectorEquals(toastIndexes[0], "indkey", [1, 2]) || !VectorEquals(toastIndexes[0], "indclass", [1989, 1978]) ||
                !VectorEquals(toastIndexes[0], "indcollation", [0, 0]) || !VectorEquals(toastIndexes[0], "indoption", [0, 0])) { throw Invalid("toast_index"); }
            string toastIndex = Value(toastIndexes[0], "indexrelid");
            JsonObject toastIndexClass = classes.Single(x => Value(x, "oid") == toastIndex);
            if (Value(toastIndexClass, "relname") != "pg_toast_" + id + "_index" || Value(toastIndexClass, "relkind") != "i" ||
                Value(toastIndexClass, "relam") != "403" || Value(toastIndexClass, "relnamespace") != toastNs ||
                Value(toastIndexClass, "relowner") != Value(heap, "relowner")) { throw Invalid("toast_index_identity"); }
            _ = storage.Add(toast); _ = storage.Add(toastIndex); _ = storageIndexes.Add(toastIndex);
            if (observation.Storage(toast).Rows != 0) { throw Invalid("nonempty_toast"); }
        }
        foreach (string oid in storage)
        {
            long rows = oid == pkId ? observation.LiteralRows.Rows : storageIndexes.Contains(oid) ? 0 : observation.Storage(oid).Rows;
            RequireStorage(classes.Single(x => Value(x, "oid") == oid), observation.Storage(oid), rows, observation.Selected, storageIndexes.Contains(oid));
        }
        return new(id, columns, storage, storageIndexes);
    }

    internal static void RequireStorage(JsonObject row, CurrentOwnerIsoStorage storage, long rows, bool rebuilt, bool index)
    {
        long pages = Number(row, "relpages"), visible = Number(row, "relallvisible"), frozen = Number(row, "relallfrozen");
        double tuples = double.Parse(Value(row, "reltuples"), CultureInfo.InvariantCulture);
        if (storage.FileNode == 0 || Value(row, "relfilenode") != storage.FileNode.ToString(CultureInfo.InvariantCulture) ||
            storage.Blocks < 0 || (index && storage.Blocks < 1) || pages < 0 || pages > storage.Blocks ||
            rows < 0 || !double.IsFinite(tuples) || tuples < -1 || tuples > rows || visible < 0 || frozen < 0 || frozen > visible || visible > storage.Blocks ||
            (rebuilt && ((index && (pages != storage.Blocks || tuples != rows)) || visible != 0 || frozen != 0)))
        {
            // Native catalog/storage metadata only; never row values or SQL credentials.
            throw new MigrationExecutionException("current_owner_iso_native_physical_storage",
                "The fixed ISO native preservation component refused physical_storage: " +
                System.Text.Json.JsonSerializer.Serialize(DescribeStorage(row, storage, rows, rebuilt, index)) +
                ". No execution authority is granted.");
        }
    }

    // PG18 ALTER rewrites the selected heap without refreshing its existing planner statistics.
    // Bounded standalone validation is insufficient; the exact pair must preserve both fields.
    internal static void RequireHeapStatisticsPreserved(JsonObject before, JsonObject after)
    {
        if (Value(before, "relpages") != Value(after, "relpages") || Value(before, "reltuples") != Value(after, "reltuples"))
        { throw Invalid("heap_statistics"); }
    }

    // PostgreSQL18 ATRewriteTable advances the selected heap's freeze boundary to RecentXmin.
    // Check the exact pair against a real same-transaction snapshot horizon, including XID wraparound.
    internal static void RequireFrozenXidProgression(JsonObject before, JsonObject after, uint snapshotXmin)
    {
        if (!uint.TryParse(Value(before, "relfrozenxid"), NumberStyles.None, CultureInfo.InvariantCulture, out uint left) ||
            !uint.TryParse(Value(after, "relfrozenxid"), NumberStyles.None, CultureInfo.InvariantCulture, out uint right) ||
            left < 3 || right < 3 || snapshotXmin < 3 || unchecked((int)(right - left)) < 0 ||
            unchecked((int)(snapshotXmin - right)) < 0)
        { throw Invalid("heap_freeze_boundary"); }
    }

    internal static CurrentOwnerIsoStorageFrame DescribeStorage(JsonObject row, CurrentOwnerIsoStorage storage,
        long rows, bool rebuilt, bool index)
    {
        return new(row["oid"]?.ToString(), row["relname"]?.ToString(), row["relkind"]?.ToString(), rebuilt, index,
            Value(row, "relfilenode"), storage.FileNode, storage.Blocks, index ? null : storage.Rows, rows, Number(row, "relpages"),
            Value(row, "reltuples"), Number(row, "relallvisible"), Number(row, "relallfrozen"));
    }

    private static string[] Normalize(CurrentOwnerIsoNativeObservation observation, Binding binding, string catalog)
    {
        return [.. observation.Read(catalog).Select(row =>
        {
            if (catalog == "pg_attribute" && Value(row, "attrelid") == binding.Heap && binding.Columns.ContainsKey(Value(row, "attnum")))
            { row["atttypid"] = "fixed-bpchar-varchar-transition"; }
            if (catalog == "pg_depend" && Value(row, "classid") == "1259" && Value(row, "objid") == binding.Heap &&
                binding.Columns.ContainsKey(Value(row, "objsubid")) && Value(row, "refclassid") == "1247")
            { row["refobjid"] = "fixed-bpchar-varchar-transition"; }
            if (catalog == "pg_class" && binding.Storage.Contains(Value(row, "oid")))
            {
                row["relfilenode"] = "validated-physical-replacement";
                if (binding.Indexes.Contains(Value(row, "oid")))
                { foreach (string field in PhysicalReplacementFieldNames) { row[field] = "validated-physical-replacement"; } }
                if (!binding.Indexes.Contains(Value(row, "oid")))
                { row["relallvisible"] = "validated-empty-visibility-map"; row["relallfrozen"] = "validated-empty-visibility-map"; }
                if (Value(row, "oid") == binding.Heap)
                { row["relfrozenxid"] = "validated-paired-snapshot-bounded-freeze-boundary"; }
            }
            return row.ToJsonString();
        }).Order(StringComparer.Ordinal)];
    }

    private static void RequireRawBinding(CurrentOwnerIsoNativeObservation observation)
    {
        Dictionary<string, string[]> raw = observation.CopyCatalog();
        if (!raw.Keys.Order(StringComparer.Ordinal).SequenceEqual(Catalogs.Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw Invalid("catalog_inventory"); }
        string ns = Value(observation.Read("pg_namespace").Single(x => Value(x, "nspname") == "pg_catalog"), "oid");
        Dictionary<string, string> classes = observation.Read("pg_class").Where(x => Value(x, "relnamespace") == ns)
            .ToDictionary(x => Value(x, "relname"), x => Value(x, "oid"), StringComparer.Ordinal);
        var expectedFacts = new List<CurrentAppOwnedCatalogFact>();
        foreach (string catalog in Catalogs)
        {
            var occurrences = new Dictionary<string, int>(StringComparer.Ordinal);
            bool hasOid = Array.IndexOf(Catalogs, catalog) < 22;
            foreach (string text in raw[catalog])
            {
                JsonObject row = JsonNode.Parse(text)!.AsObject();
                string digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
                int occurrence = occurrences.GetValueOrDefault(digest) + 1; occurrences[digest] = occurrence;
                string key = hasOid ? Value(row, "oid") : digest + "/" + occurrence.ToString(CultureInfo.InvariantCulture);
                string objectClass = catalog switch
                {
                    "pg_attribute" or "pg_index" => classes["pg_class"],
                    "pg_depend" or "pg_shdepend" => Value(row, "classid"),
                    _ => classes[catalog]
                };
                string objectId = catalog switch
                {
                    "pg_attribute" => Value(row, "attrelid"),
                    "pg_index" => Value(row, "indexrelid"),
                    "pg_depend" or "pg_shdepend" => Value(row, "objid"),
                    "pg_sequence" => Value(row, "seqrelid"),
                    "pg_description" or "pg_seclabel" => Value(row, "objoid"),
                    _ => hasOid ? Value(row, "oid") : ""
                };
                expectedFacts.Add(new(catalog, key, digest, objectClass, objectId));
            }
        }
        if (!expectedFacts.OrderBy(x => x.Catalog + "/" + x.Key, StringComparer.Ordinal)
            .SequenceEqual(observation.Snapshot.Catalog.OrderBy(x => x.Catalog + "/" + x.Key, StringComparer.Ordinal)))
        { throw Invalid("raw_digest_identity_multiplicity"); }
    }
    // Only these fixed index operands use decoded vectors. Raw catalog tuples remain exact.
    internal static bool VectorEquals(JsonObject row, string key, ReadOnlySpan<uint> expected)
    {
        if (row[key] is JsonArray array)
        {
            if (array.Count != expected.Length) { return false; }
            for (int index = 0; index < array.Count; index++)
            {
                if (array[index] is not JsonValue value) { return false; }
                string? token = value.TryGetValue(out string? text) ? text : value.ToJsonString();
                if (!CanonicalVectorElement(token, expected[index])) { return false; }
            }
            return true;
        }
        // Preserve the existing exact PostgreSQL text representation for held primitive captures.
        if (row[key] is not JsonValue scalar || !scalar.TryGetValue(out string? vector) || vector is null) { return false; }
        string[] values = vector.Split(' ');
        if (values.Length != expected.Length) { return false; }
        for (int index = 0; index < values.Length; index++)
        { if (!CanonicalVectorElement(values[index], expected[index])) { return false; } }
        return true;
    }
    private static bool CanonicalVectorElement(string? token, uint expected)
    {
        return token is not null && uint.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out uint number) &&
        number == expected && token == number.ToString(CultureInfo.InvariantCulture);
    }

    private static string Value(JsonObject row, string key)
    {
        return row[key]?.ToString() ?? throw Invalid("native_field");
    }

    private static long Number(JsonObject row, string key)
    {
        return long.Parse(Value(row, key), CultureInfo.InvariantCulture);
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static MigrationExecutionException Invalid(string facet)
    {
        return new("current_owner_iso_native_" + facet,
            "The fixed ISO native preservation component refused: " + facet + ". No execution authority is granted.");
    }
}
