using System.Text.Json.Nodes;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Native component observation only; grants no retained31 execution permission.</summary>
internal sealed class CurrentAppOwnedRetained31Observation
{
    private readonly Dictionary<string, string[]> _tuples;
    private readonly Dictionary<string, (uint FileNode, long Blocks)> _storage;
    internal CurrentAppOwnedDatabaseSnapshot Snapshot { get; }
    internal CurrentAppOwnedRetained31Observation(CurrentAppOwnedDatabaseSnapshot snapshot, Dictionary<string, string[]> tuples,
        Dictionary<string, (uint FileNode, long Blocks)> storage)
    {
        Snapshot = snapshot with
        {
            Catalog = Array.AsReadOnly(snapshot.Catalog.ToArray()),
            Relations = Array.AsReadOnly(snapshot.Relations.ToArray()),
            Sequences = Array.AsReadOnly(snapshot.Sequences.ToArray())
        };
        _tuples = tuples.ToDictionary(x => x.Key, x => x.Value.ToArray(), StringComparer.Ordinal); _storage = new(storage, StringComparer.Ordinal);
    }
    internal JsonObject[] Read(string catalog)
    {
        return _tuples[catalog].Select(text => JsonNode.Parse(text)!.AsObject()).ToArray();
    }

    internal (uint FileNode, long Blocks) Storage(string oid)
    {
        return _storage[oid];
    }
}

/// <summary>
/// Compares complete visible catalog tuples with explicit attribute/index collation
/// changes and exact logical rebinding of the affected indexes and their constraints.
/// Extended statistics touching an operand are rejected before alteration.
/// </summary>
internal static class CurrentAppOwnedRetained31Preservation
{
    private static readonly string[] Catalogs =
    [
        "pg_class", "pg_type", "pg_namespace", "pg_constraint", "pg_attrdef", "pg_trigger", "pg_proc",
        "pg_collation", "pg_policy", "pg_rewrite", "pg_extension", "pg_event_trigger",
        "pg_authid", "pg_database", "pg_tablespace", "pg_language", "pg_operator", "pg_cast",
        "pg_opclass", "pg_opfamily", "pg_am", "pg_conversion", "pg_attribute", "pg_index", "pg_depend",
        "pg_shdepend", "pg_description", "pg_shdescription", "pg_auth_members", "pg_default_acl",
        "pg_init_privs", "pg_inherits", "pg_partitioned_table", "pg_sequence", "pg_statistic",
        "pg_statistic_ext", "pg_statistic_ext_data", "pg_amop", "pg_amproc", "pg_range", "pg_transform",
        "pg_seclabel", "pg_shseclabel",
    ];
    private static readonly string[] RebuiltStorageFields = ["relfilenode", "relpages", "reltuples"];

    internal static async Task<CurrentAppOwnedRetained31Observation> CaptureAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken ct)
    {
        CurrentAppOwnedDatabaseSnapshot snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
        var tuples = new Dictionary<string, string[]>(StringComparer.Ordinal);
        foreach (string catalog in Catalogs)
        {
            string filter = catalog == "pg_shdepend" ? " WHERE x.dbid=0 OR x.dbid=(SELECT oid FROM pg_database WHERE datname=current_database())" : string.Empty;
            await using var command = new NpgsqlCommand($"SELECT to_jsonb(x)::text FROM pg_catalog.{catalog} x{filter};", connection, transaction);
            var values = new List<string>();
            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { values.Add(reader.GetString(0)); }
            tuples.Add(catalog, values.ToArray());
        }
        var storage = new Dictionary<string, (uint FileNode, long Blocks)>(StringComparer.Ordinal);
        await using (var command = new NpgsqlCommand("SELECT oid::text,pg_relation_filenode(oid),pg_relation_size(oid)/current_setting('block_size')::bigint FROM pg_class WHERE relkind='i';", connection, transaction))
        await using (NpgsqlDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        { while (await reader.ReadAsync(ct).ConfigureAwait(false)) { storage.Add(reader.GetString(0), (reader.GetFieldValue<uint>(1), reader.GetInt64(2))); } }
        return new(snapshot, tuples, storage);
    }

    internal static void RequireBefore(CurrentAppOwnedRetained31Observation before, FreshSchemaPlan oldSchema,
        FreshSchemaPlan currentSchema, DateTimeOffset now)
    {
        CurrentAppOwnedRepairManifest.RequireSchemaPair(oldSchema, currentSchema, now);
        string database = before.Snapshot.Database;
        if (!CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations).Contains(database, StringComparer.Ordinal))
        { throw Invalid("database"); }
        Binding binding = Bind(before, oldSchema.Databases.Single(x => x.Database == database),
            [.. CurrentAppOwnedRepairManifest.RetainedOperands().Where(x => x.Database == database)], after: false);
        _ = Normalize(before, binding, "pg_constraint", after: false);
    }

    internal static void RequirePreserved(CurrentAppOwnedRetained31Observation before, CurrentAppOwnedRetained31Observation after,
        FreshSchemaPlan oldSchema, FreshSchemaPlan currentSchema, DateTimeOffset now)
    {
        CurrentAppOwnedRepairManifest.RequireSchemaPair(oldSchema, currentSchema, now);
        string database = before.Snapshot.Database;
        if (database != after.Snapshot.Database || !CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations)
            .Contains(database, StringComparer.Ordinal)) { throw Invalid("database"); }
        if (!before.Snapshot.Relations.SequenceEqual(after.Snapshot.Relations) || !before.Snapshot.Sequences.SequenceEqual(after.Snapshot.Sequences))
        { throw Invalid("rows_or_sequences"); }
        CurrentAppOwnedCollationOperand[] operands = [.. CurrentAppOwnedRepairManifest.RetainedOperands().Where(x => x.Database == database)];
        DatabaseSchemaPlan old = oldSchema.Databases.Single(x => x.Database == database);
        DatabaseSchemaPlan current = currentSchema.Databases.Single(x => x.Database == database);
        Binding left = Bind(before, old, operands, after: false);
        Binding right = Bind(after, current, operands, after: true);
        if (!left.TableColumns.SetEquals(right.TableColumns)) { throw Invalid("operand_binding"); }
        foreach (string catalog in Catalogs)
        {
            string[] expected = Normalize(before, left, catalog, after: false);
            string[] actual = Normalize(after, right, catalog, after: true);
            if (!expected.SequenceEqual(actual, StringComparer.Ordinal))
            {
                // Diagnostic exposes catalog/field names only, never tuple values.
                string? missing = expected.FirstOrDefault(x => !actual.Contains(x, StringComparer.Ordinal));
                JsonObject? leftRow = missing is null ? null : JsonNode.Parse(missing)!.AsObject();
                JsonObject? rightRow = actual.Select(x => JsonNode.Parse(x)!.AsObject())
                    .FirstOrDefault(x => (leftRow?["oid"] is not null && x["oid"]?.ToString() == leftRow["oid"]!.ToString()) ||
                        (catalog == "pg_constraint" && leftRow is not null && x["conname"]?.ToString() == leftRow["conname"]?.ToString() &&
                            x["conrelid"]?.ToString() == leftRow["conrelid"]?.ToString()));
                string fields = rightRow is null || leftRow is null ? "tuple" : string.Join('_', leftRow.Where(x => !JsonNode.DeepEquals(x.Value, rightRow[x.Key])).Select(x => x.Key));
                if (catalog == "pg_constraint" && leftRow is not null && rightRow is not null && fields == "conbin")
                {
                    string leftExpression = Value(leftRow, "conbin");
                    string rightExpression = Value(rightRow, "conbin");
                    int prefix = 0;
                    while (prefix < Math.Min(leftExpression.Length, rightExpression.Length) && leftExpression[prefix] == rightExpression[prefix]) { prefix++; }
                    int colon = leftExpression.LastIndexOf(':', Math.Max(0, prefix - 1));
                    if (colon >= 0) { fields += "_" + leftExpression[(colon + 1)..].Split(' ', 2)[0]; }
                    if (fields == "conbin_relabelformat")
                    {
                        fields += "_" + leftExpression[(colon + 1)..].Split(' ', 3)[1] + "_" + rightExpression[(colon + 1)..].Split(' ', 3)[1];
                    }
                }
                if (catalog == "pg_constraint" && leftRow is not null) { fields += "_kind_" + Value(leftRow, "contype"); }
                if (catalog == "pg_constraint" && leftRow is not null && Value(leftRow, "contype") == "c")
                { fields += Value(leftRow, "oid").StartsWith("constraint/", StringComparison.Ordinal) ? "_bound" : "_unbound"; }
                throw Invalid("catalog_" + catalog + "_" + fields);
            }
        }
    }

    // Resolve names only from the compiled physical contracts. No externally
    // supplied OID/field allowlist can enter the comparison.
    private static Binding Bind(CurrentAppOwnedRetained31Observation observation, DatabaseSchemaPlan schema,
        CurrentAppOwnedCollationOperand[] operands, bool after)
    {
        JsonObject[] classes = observation.Read("pg_class");
        JsonObject[] namespaces = observation.Read("pg_namespace");
        JsonObject[] attributes = observation.Read("pg_attribute");
        JsonObject[] indexes = observation.Read("pg_index");
        JsonObject[] constraints = observation.Read("pg_constraint");
        JsonObject[] collations = observation.Read("pg_collation");
        string catalogNamespace = Value(namespaces.Single(x => Value(x, "nspname") == "pg_catalog"), "oid");
        foreach (string name in Catalogs.Where(x => x is "pg_class" or "pg_constraint"))
        {
            if (Value(classes.Single(x => Value(x, "relnamespace") == catalogNamespace && Value(x, "relname") == name), "oid") != ClassOid(name))
            { throw Invalid("builtin_class_binding"); }
        }
        string c = Value(collations.Single(x => Value(x, "collname") == "C" && Value(x, "collnamespace") ==
            Value(namespaces.Single(n => Value(n, "nspname") == "pg_catalog"), "oid")), "oid");
        string defaultCollation = Value(collations.Single(x => Value(x, "collname") == "default" && Value(x, "collnamespace") ==
            Value(namespaces.Single(n => Value(n, "nspname") == "pg_catalog"), "oid")), "oid");
        var binding = new Binding(new(StringComparer.Ordinal), new(StringComparer.Ordinal), new(StringComparer.Ordinal), new(StringComparer.Ordinal),
            new(StringComparer.Ordinal), c, defaultCollation);
        foreach (IGrouping<(string Schema, string Table), CurrentAppOwnedCollationOperand> group in operands.GroupBy(x => (x.Schema, x.Table)))
        {
            string ns = Value(namespaces.Single(x => Value(x, "nspname") == group.Key.Schema), "oid");
            JsonObject table = classes.Single(x => Value(x, "relnamespace") == ns && Value(x, "relname") == group.Key.Table);
            if (Value(table, "relkind") != "r") { throw Invalid("table_kind"); }
            string tableId = Value(table, "oid");
            var numbers = new HashSet<int>();
            var types = new Dictionary<int, int>();
            foreach (CurrentAppOwnedCollationOperand operand in group)
            {
                JsonObject attribute = attributes.Single(x => Value(x, "attrelid") == tableId && Value(x, "attname") == operand.Column);
                int number = int.Parse(Value(attribute, "attnum"), System.Globalization.CultureInfo.InvariantCulture);
                if (Value(attribute, "attcollation") != (after ? c : defaultCollation) || Value(attribute, "attisdropped") != "false")
                { throw Invalid("attribute_collation"); }
                string typeName = operand.PostgreSqlType == "text" ? "text" : operand.PostgreSqlType.StartsWith("character varying(", StringComparison.Ordinal) ? "varchar" : "bpchar";
                int typmod = operand.PostgreSqlType == "text" ? -1 : int.Parse(operand.PostgreSqlType[(operand.PostgreSqlType.IndexOf('(') + 1)..^1], System.Globalization.CultureInfo.InvariantCulture) + 4;
                JsonObject type = observation.Read("pg_type").Single(x => Value(x, "oid") == Value(attribute, "atttypid"));
                if (Value(type, "typname") != typeName || Value(type, "typnamespace") != Value(namespaces.Single(x => Value(x, "nspname") == "pg_catalog"), "oid") ||
                    Value(attribute, "atttypmod") != typmod.ToString(System.Globalization.CultureInfo.InvariantCulture)) { throw Invalid("attribute_type"); }
                _ = numbers.Add(number); _ = binding.TableColumns.Add(tableId + "/" + number);
                types.Add(number, int.Parse(Value(attribute, "atttypid"), System.Globalization.CultureInfo.InvariantCulture));
            }
            foreach (JsonObject statistics in observation.Read("pg_statistic_ext").Where(x => Value(x, "stxrelid") == tableId))
            {
                // Expression statistics on an affected table are conservatively unsupported,
                // including expression-only statistics whose stxkeys vector is empty.
                if (Vector(statistics, "stxkeys").Any(numbers.Contains) || statistics["stxexprs"] is not null)
                { throw Invalid("extended_statistics"); }
            }
            TableCopyPlan physical = ApprovedConsumerColumnOverlayManifest.ComposePhysical(schema)
                .Single(x => x.TargetSchema == group.Key.Schema && x.TargetTable == group.Key.Table);
            // PostgreSQL 18 recreates operand NOT NULL constraint identities even
            // for this binary-compatible collation change. Bind only the exact
            // single-column constraints required by the immutable table shape;
            // every name, semantic flag and dependency remains compared in full.
            foreach (int number in numbers)
            {
                JsonObject attribute = attributes.Single(x => Value(x, "attrelid") == tableId && Value(x, "attnum") == number.ToString(System.Globalization.CultureInfo.InvariantCulture));
                string column = Value(attribute, "attname");
                bool nullable = physical.NullableColumns.Contains(column, StringComparer.Ordinal);
                if (Value(attribute, "attnotnull") != (nullable ? "false" : "true")) { throw Invalid("attribute_nullability"); }
                JsonObject[] notNull = [.. constraints.Where(x => Value(x, "conrelid") == tableId && Value(x, "contype") == "n" && Vector(x, "conkey").SequenceEqual([number]))];
                if (notNull.Length != (nullable ? 0 : 1)) { throw Invalid("not_null_binding"); }
                if (!nullable) { binding.ConstraintIds.Add(Value(notNull[0], "oid"), group.Key.Schema + "/" + group.Key.Table + "/not-null/" + column); }
            }
            var declared = physical.Indexes.Select(x => (x.Name, x.Columns, x.Unique, Kind: "i"))
                .Concat(physical.UniqueConstraints.Select(x => (x.Name, x.Columns, Unique: true, Kind: "u")))
                .Concat(physical.PrimaryKey is { } pk ? [(pk.Name, pk.Columns, Unique: true, Kind: "p")] : []);
            foreach (var (Name, Columns, Unique, Kind) in declared)
            {
                int[] changed = [.. Columns.Select((column, position) => (column, position))
                    .Where(x => group.Any(operand => operand.Column == x.column)).Select(x => x.position)];
                if (changed.Length == 0) { continue; }
                JsonObject indexClass = classes.Single(x => Value(x, "relnamespace") == ns && Value(x, "relname") == Name);
                string indexId = Value(indexClass, "oid");
                var (FileNode, Blocks) = observation.Storage(indexId);
                long rows = observation.Snapshot.Relations.Single(x => x.Schema == group.Key.Schema && x.Name == group.Key.Table).Rows;
                RequireIndexStorage(indexClass, FileNode, Blocks, rows, after);
                JsonObject index = indexes.Single(x => Value(x, "indexrelid") == indexId);
                int[] keys = Vector(index, "indkey");
                int[] colls = Vector(index, "indcollation");
                if (Value(indexClass, "relkind") != "i" || Value(index, "indrelid") != tableId ||
                    Value(indexClass, "relallvisible") != "0" || Value(indexClass, "relallfrozen") != "0" ||
                    Value(index, "indisvalid") != "true" || Value(index, "indisready") != "true" || Value(index, "indislive") != "true" ||
                    Value(index, "indisunique") != (Unique ? "true" : "false") || keys.Length != Columns.Count || colls.Length != keys.Length)
                { throw Invalid("index_shape"); }
                for (int position = 0; position < keys.Length; position++)
                {
                    JsonObject attribute = attributes.Single(x => Value(x, "attrelid") == tableId && Value(x, "attnum") == keys[position].ToString(System.Globalization.CultureInfo.InvariantCulture));
                    if (Value(attribute, "attname") != Columns[position]) { throw Invalid("index_key"); }
                    if (!changed.Contains(position)) { continue; }
                    if (colls[position].ToString(System.Globalization.CultureInfo.InvariantCulture) != (after ? c : defaultCollation)) { throw Invalid("index_collation"); }
                    JsonObject indexAttribute = attributes.Single(x => Value(x, "attrelid") == indexId && Value(x, "attnum") == (position + 1).ToString(System.Globalization.CultureInfo.InvariantCulture));
                    if (Value(indexAttribute, "attcollation") != (after ? c : defaultCollation)) { throw Invalid("index_attribute_collation"); }
                    _ = binding.IndexColumns.Add(indexId + "/" + (position + 1));
                }
                string logical = group.Key.Schema + "/" + Name;
                binding.IndexIds.Add(indexId, logical);
                binding.IndexPositions.Add(indexId, changed);
                if (Kind is "p" or "u")
                {
                    JsonObject constraint = constraints.Single(x => Value(x, "conrelid") == tableId && Value(x, "conname") == Name);
                    if (Value(constraint, "contype") != Kind || Value(constraint, "conindid") != indexId) { throw Invalid("constraint_binding"); }
                    binding.ConstraintIds.Add(Value(constraint, "oid"), logical);
                }
            }
            foreach (CheckConstraintCopyPlan check in physical.CheckConstraints.Where(x => x.Columns.Any(column => group.Any(operand => operand.Column == column))))
            {
                JsonObject constraint = constraints.Single(x => Value(x, "conrelid") == tableId && Value(x, "conname") == check.Name);
                if (Value(constraint, "contype") != "c") { throw Invalid("check_binding"); }
                string id = Value(constraint, "oid");
                binding.ConstraintIds.Add(id, group.Key.Schema + "/" + check.Name);
                binding.CheckColumns.Add(id, types);
            }
        }
        return binding;
    }

    private static string[] Normalize(CurrentAppOwnedRetained31Observation observation, Binding binding, string catalog, bool after)
    {
        var result = new List<string>();
        foreach (JsonObject row in observation.Read(catalog))
        {
            string relation = catalog switch { "pg_attribute" => Value(row, "attrelid"), "pg_statistic" => Value(row, "starelid"), _ => string.Empty };
            if (catalog == "pg_statistic" && binding.TableColumns.Contains(relation + "/" + Value(row, "staattnum")))
            { if (after) { throw Invalid("statistics_not_invalidated"); } continue; }
            if (catalog == "pg_class" && binding.IndexIds.ContainsKey(Value(row, "oid")))
            { foreach (string field in RebuiltStorageFields) { row[field] = "reviewed-rebuilt-index-storage"; } }
            if (catalog == "pg_attribute" && (binding.TableColumns.Contains(relation + "/" + Value(row, "attnum")) ||
                binding.IndexColumns.Contains(relation + "/" + Value(row, "attnum")))) { row["attcollation"] = "reviewed-C-transition"; }
            if (catalog == "pg_index" && binding.IndexPositions.TryGetValue(Value(row, "indexrelid"), out int[]? positions))
            {
                string[] vector = Vector(row, "indcollation").Select(x => x.ToString(System.Globalization.CultureInfo.InvariantCulture)).ToArray();
                foreach (int position in positions) { vector[position] = "reviewed-C-transition"; }
                row["indcollation"] = string.Join(' ', vector);
            }
            if (catalog == "pg_constraint" && binding.CheckColumns.TryGetValue(Value(row, "oid"), out Dictionary<int, int>? columns))
            { row["conbin"] = NormalizeExpression(Value(row, "conbin"), columns, after ? binding.C : binding.DefaultCollation, after); }
            Replace(row, catalog, binding);
            result.Add(row.ToJsonString());
        }
        // Whole-row sorting retains every duplicate dependency occurrence.
        return [.. result.Order(StringComparer.Ordinal)];
    }

    private static void Replace(JsonObject row, string catalog, Binding binding)
    {
        string classOid = ClassOid("pg_class");
        string constraintOid = ClassOid("pg_constraint");
        if (catalog == "pg_class") { Index("oid"); }
        if (catalog == "pg_attribute") { Index("attrelid"); }
        if (catalog == "pg_index") { Index("indexrelid"); }
        if (catalog == "pg_constraint") { Constraint("oid"); Index("conindid"); }
        if (catalog is "pg_depend" or "pg_shdepend")
        {
            if (Value(row, "classid") == classOid) { Index("objid"); }
            if (Value(row, "classid") == constraintOid) { Constraint("objid"); }
            if (Value(row, "refclassid") == classOid) { Index("refobjid"); }
            if (Value(row, "refclassid") == constraintOid) { Constraint("refobjid"); }
        }
        if (catalog is "pg_description" or "pg_seclabel")
        {
            if (Value(row, "classoid") == classOid) { Index("objoid"); }
            if (Value(row, "classoid") == constraintOid) { Constraint("objoid"); }
        }
        void Index(string field) { if (binding.IndexIds.TryGetValue(Value(row, field), out string? name)) { row[field] = "index/" + name; } }
        void Constraint(string field) { if (binding.ConstraintIds.TryGetValue(Value(row, field), out string? name)) { row[field] = "constraint/" + name; } }
    }

    // Stable built-in PostgreSQL relation OIDs, checked by native fixture/version
    // before this component is usable; they are not supplied catalog allowlists.
    private static string ClassOid(string name)
    {
        return name switch { "pg_class" => "1259", "pg_constraint" => "2606", _ => throw Invalid("class") };
    }

    private static string Value(JsonObject row, string key)
    {
        return row[key]?.ToString() ?? throw Invalid("catalog_field");
    }

    private static int[] Vector(JsonObject row, string key)
    {
        return row[key] is JsonArray array
            ? array.Select(value => int.Parse(value!.ToString(), System.Globalization.CultureInfo.InvariantCulture)).ToArray()
            : Value(row, key).Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(value => int.Parse(value, System.Globalization.CultureInfo.InvariantCulture)).ToArray();
    }

    private static MigrationExecutionException Invalid(string facet)
    {
        return new("retained31_native_preservation_" + facet,
            "The native retained31 transition is outside the fixed preservation contract: " + facet + ".");
    }

    private sealed record Binding(Dictionary<string, string> IndexIds, Dictionary<string, string> ConstraintIds,
        Dictionary<string, int[]> IndexPositions, HashSet<string> TableColumns,
        Dictionary<string, Dictionary<int, int>> CheckColumns, string C, string DefaultCollation)
    { internal HashSet<string> IndexColumns { get; } = new(StringComparer.Ordinal); }

    // Parse node boundaries and named fields, retaining every byte except validated
    // source locations and precisely propagated operand collation fields. Constants,
    // operator/function/type IDs, argument order and all other fields remain exact.
    internal static void RequireIndexStorage(JsonObject row, uint physicalFileNode, long physicalBlocks, long tableRows, bool rebuilt)
    {
        if (!uint.TryParse(Value(row, "relfilenode"), out uint fileNode) || fileNode == 0 || fileNode != physicalFileNode ||
            !long.TryParse(Value(row, "relpages"), out long pages) || pages < 0 || pages > physicalBlocks || physicalBlocks < 1 ||
            !double.TryParse(Value(row, "reltuples"), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out double tuples) || !double.IsFinite(tuples) || tuples < -1 || tuples > tableRows ||
            tableRows < 0 || (rebuilt && (pages != physicalBlocks || tuples != tableRows)))
        { throw Invalid("index_storage"); }
    }

    internal static string NormalizeExpression(string text, IReadOnlyDictionary<int, int> columns, string collation, bool after = false)
    {
        var edits = new List<(int Start, int Length, string Text)>();
        var nodes = new Dictionary<int, (string Kind, int End, int Parent, Dictionary<string, (int Start, int Length, bool ChangedChild)> Fields)>();
        int parent = -1;
        int cursor = 0;
        _ = ParseNode();
        if (cursor != text.Length) { throw Invalid("expression_trailing"); }
        foreach (var (Start, Length, Text) in edits.OrderByDescending(x => x.Start)) { text = text.Remove(Start, Length).Insert(Start, Text); }
        return text;

        bool ParseNode()
        {
            int nodeStart = cursor;
            int savedParent = parent;
            parent = nodeStart;
            if (cursor >= text.Length || text[cursor++] != '{') { throw Invalid("expression_node"); }
            int typeStart = cursor;
            while (cursor < text.Length && !char.IsWhiteSpace(text[cursor]) && text[cursor] != '}') { cursor++; }
            string kind = text[typeStart..cursor];
            var fields = new Dictionary<string, (int Start, int Length, bool ChangedChild)>(StringComparer.Ordinal);
            while (true)
            {
                while (cursor < text.Length && char.IsWhiteSpace(text[cursor])) { cursor++; }
                if (cursor >= text.Length) { throw Invalid("expression_unclosed"); }
                if (text[cursor] == '}') { cursor++; break; }
                if (text[cursor++] != ':') { throw Invalid("expression_field"); }
                int nameStart = cursor;
                while (cursor < text.Length && !char.IsWhiteSpace(text[cursor])) { cursor++; }
                string name = text[nameStart..cursor];
                while (cursor < text.Length && char.IsWhiteSpace(text[cursor])) { cursor++; }
                int valueStart = cursor; bool changed = false; bool quoted = false;
                while (cursor < text.Length)
                {
                    char character = text[cursor];
                    if (quoted)
                    {
                        cursor++;
                        if (character == '\\' && cursor < text.Length) { cursor++; }
                        else if (character == '"') { quoted = false; }
                        continue;
                    }
                    if (character == '"') { quoted = true; cursor++; continue; }
                    if (character == '{') { changed |= ParseNode(); continue; }
                    if (character is ':' or '}') { break; }
                    cursor++;
                }
                int end = cursor;
                while (end > valueStart && char.IsWhiteSpace(text[end - 1])) { end--; }
                if (quoted || end == valueStart || !fields.TryAdd(name, (valueStart, end - valueStart, changed))) { throw Invalid("expression_value"); }
            }
            nodes.Add(nodeStart, (kind, cursor, savedParent, fields));
            parent = savedParent;
            if (fields.TryGetValue("location", out var location))
            {
                if (Number(location) < -1) { throw Invalid("expression_location"); }
                edits.Add((location.Start, location.Length, "@location"));
            }
            if (kind == "VAR")
            {
                int attnum = Number(Field("varattno"));
                if (!columns.TryGetValue(attnum, out int type)) { return false; }
                if (Number(Field("varno")) != 1 || Number(Field("varlevelsup")) != 0 || Number(Field("vartype")) != type)
                { throw Invalid("expression_var_binding"); }
                Mark("varcollid"); return true;
            }
            string argumentField = kind is "RELABELTYPE" or "NULLTEST" ? "arg" : "args";
            bool changedArguments = fields.TryGetValue(argumentField, out var arguments) && arguments.ChangedChild;
            if (!changedArguments) { return false; }
            if (kind == "RELABELTYPE")
            {
                // Native PG18.4 rebuild deparses the operand's implicit varchar
                // to text relabel as an explicit cast. Only this direct bound VAR
                // -> text/-1 node permits the observed display-form 2 -> 1.
                var (Start, Length, ChangedChild) = Field("arg");
                var format = Field("relabelformat");
                if (!text.AsSpan(Start, Length).StartsWith("{VAR ", StringComparison.Ordinal) ||
                    Number(Field("resulttype")) != 25 || Number(Field("resulttypmod")) != -1 ||
                    Number(format) != (after ? 1 : 2)) { throw Invalid("expression_relabel_binding"); }
                edits.Add((format.Start, format.Length, "@operand-text-display"));
            }
            if (kind is "OPEXPR" or "DISTINCTEXPR" or "NULLIFEXPR" or "SCALARARRAYOPEXPR" or "FUNCEXPR") { Mark("inputcollid"); }
            if (kind == "SCALARARRAYOPEXPR")
            {
                var arrays = nodes.Where(x => x.Value.Parent == nodeStart && x.Value.Kind is "ARRAYCOERCEEXPR" or "ARRAYEXPR").ToArray();
                if (arrays.Length != 1) { throw Invalid("expression_array_binding"); }
                NormalizeArray(arrays[0].Key);
            }
            string? resultField = kind switch { "OPEXPR" or "DISTINCTEXPR" or "NULLIFEXPR" => "opcollid", "FUNCEXPR" => "funccollid", "RELABELTYPE" => "resultcollid", _ => null };
            if (resultField is not null && Number(Field(resultField)) != 0) { Mark(resultField); return true; }
            return kind is not ("OPEXPR" or "DISTINCTEXPR" or "NULLIFEXPR" or "SCALARARRAYOPEXPR" or "FUNCEXPR" or "RELABELTYPE" or "NULLTEST" or "BOOLEXPR")
                ? throw Invalid("expression_propagation")
                : false;
            (int Start, int Length, bool ChangedChild) Field(string name)
            {
                return fields.TryGetValue(name, out var value) ? value : throw Invalid("expression_required_field");
            }

            int Number((int Start, int Length, bool ChangedChild) field)
            {
                return int.Parse(text.AsSpan(field.Start, field.Length), System.Globalization.CultureInfo.InvariantCulture);
            }

            void Mark(string name)
            {
                var (Start, Length, ChangedChild) = Field(name);
                if (text.Substring(Start, Length) != collation) { throw Invalid("expression_collation"); }
                edits.Add((Start, Length, "@C"));
            }
        }

        void NormalizeArray(int start)
        {
            var (Kind, End, Parent, Fields) = nodes[start];
            int arrayStart = start;
            if (!after)
            {
                RequireKind(start, "ARRAYCOERCEEXPR", 7);
                RequireNumber(start, "resulttype", 1009); RequireNumber(start, "resulttypmod", -1);
                RequireNumber(start, "resultcollid", 100); RequireNumber(start, "coerceformat", 2); RequireNumber(start, "location", -1);
                arrayStart = Child(start, "arg");
                int element = Child(start, "elemexpr");
                RequireKind(element, "RELABELTYPE", 6);
                RequireTextRelabel(element, 2);
                int test = Child(element, "arg");
                RequireKind(test, "CASETESTEXPR", 3);
                RequireNumber(test, "typeId", 1043); RequireNumber(test, "typeMod", -1); RequireNumber(test, "collation", 0);
            }
            RequireKind(arrayStart, "ARRAYEXPR", 8);
            RequireNumber(arrayStart, "array_typeid", after ? 1009 : 1015);
            RequireNumber(arrayStart, "element_typeid", after ? 25 : 1043);
            RequireNumber(arrayStart, "array_collid", 100); RequireNumber(arrayStart, "list_start", -1);
            RequireNumber(arrayStart, "list_end", -1); RequireNumber(arrayStart, "location", -1);
            RequireValue(arrayStart, "multidims", "false");
            var (Start, Length, ChangedChild) = FieldOf(arrayStart, "elements");
            int[] children = [.. nodes.Where(x => x.Value.Parent == arrayStart && x.Key >= Start && x.Value.End <= Start + Length).Select(x => x.Key).Order()];
            if (children.Length == 0) { throw Invalid("expression_array_empty"); }
            RequireValue(arrayStart, "elements", "(" + string.Join(' ', children.Select(child => text[child..nodes[child].End])) + ")");
            var constants = new List<string>();
            foreach (int child in children)
            {
                int constant = child;
                if (after) { RequireKind(child, "RELABELTYPE", 6); RequireTextRelabel(child, 1); constant = Child(child, "arg"); }
                RequireKind(constant, "CONST", 8);
                RequireNumber(constant, "consttype", 1043); RequireNumber(constant, "consttypmod", -1);
                RequireNumber(constant, "constcollid", 100); RequireNumber(constant, "constlen", -1);
                RequireNumber(constant, "location", -1); RequireValue(constant, "constbyval", "false"); RequireValue(constant, "constisnull", "false");
                // Full CONST bytes, length and datum are retained, in exact order.
                constants.Add(text[constant..nodes[constant].End]);
            }
            _ = edits.RemoveAll(edit => edit.Start >= start && edit.Start < End);
            edits.Add((start, End - start, "@reviewed-varchar-text-array(" + string.Join(' ', constants) + ")"));

            void RequireTextRelabel(int node, int form)
            {
                RequireNumber(node, "resulttype", 25); RequireNumber(node, "resulttypmod", -1);
                RequireNumber(node, "resultcollid", 100); RequireNumber(node, "relabelformat", form); RequireNumber(node, "location", -1);
            }
        }
        int Child(int node, string field)
        {
            var (Start, Length, ChangedChild) = FieldOf(node, field);
            int[] children = [.. nodes.Where(x => x.Value.Parent == node && x.Key >= Start && x.Value.End <= Start + Length).Select(x => x.Key)];
            return children.Length != 1 || children[0] != Start || nodes[children[0]].End != Start + Length
                ? throw Invalid("expression_array_child")
                : children[0];
        }
        (int Start, int Length, bool ChangedChild) FieldOf(int node, string field)
        {
            return nodes[node].Fields.TryGetValue(field, out var value) ? value : throw Invalid("expression_array_field");
        }

        void RequireKind(int node, string kind, int fields)
        { if (nodes[node].Kind != kind || nodes[node].Fields.Count != fields) { throw Invalid("expression_array_shape"); } }
        void RequireNumber(int node, string field, int expected)
        { RequireValue(node, field, expected.ToString(System.Globalization.CultureInfo.InvariantCulture)); }
        void RequireValue(int node, string field, string expected)
        {
            var (Start, Length, ChangedChild) = FieldOf(node, field);
            if (text.Substring(Start, Length) != expected) { throw Invalid("expression_array_value"); }
        }
    }
}
