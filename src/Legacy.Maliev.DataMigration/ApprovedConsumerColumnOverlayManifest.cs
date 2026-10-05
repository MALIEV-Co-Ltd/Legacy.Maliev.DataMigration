namespace Legacy.Maliev.DataMigration;

internal sealed record ConsumerColumnOverlay(TableCopyPlan Root, string Column, string Type, bool Nullable, string? Default);

/// <summary>Exact opt-in profiles; source projections and historical default selection are unchanged.</summary>
internal static class ApprovedConsumerColumnOverlayManifest
{
    internal const string CustomerV2 = "auth-customer-create-authority-v2";
    internal const string QuotationV1 = "quotation-decision-order-version-v1";

    internal static ConsumerColumnOverlay? For(DatabaseSchemaPlan schema)
    {
        var definition = (schema.Database, schema.TargetExtensionProfile) switch
        {
            ("CustomerIdentity", CustomerV2 or ApprovedCurrentConsumerSchemaManifest.CustomerIdentity) => (Table: "AspNetUsers", Key: "Id", KeyType: "character varying(450)", Column: "PasswordSetupRequired", Type: "boolean", Nullable: false, Default: "false"),
            ("Quotation", QuotationV1 or ApprovedCurrentConsumerSchemaManifest.Quotation) => (Table: "Quotation", Key: "ID", KeyType: "integer", Column: "DecisionOrderVersion", Type: "timestamp without time zone", Nullable: true, Default: null),
            _ => default,
        };
        if (definition.Table is null) { return null; }
        var roots = schema.Tables.Where(t => t.TargetSchema == "public" && t.TargetTable == definition.Table).ToArray();
        if (roots.Length != 1 || roots[0].SourceSchema != "dbo" || roots[0].SourceTable != definition.Table ||
            roots[0].PrimaryKey is null || !roots[0].PrimaryKey!.Columns.SequenceEqual([definition.Key], StringComparer.Ordinal) ||
            roots[0].ColumnTypes.GetValueOrDefault(definition.Key) != definition.KeyType || roots[0].NullableColumns.Contains(definition.Key, StringComparer.Ordinal))
        { throw Invalid("target_extension_overlay_source_invalid"); }
        var root = roots[0];
        return root.OrderedColumns.Contains(definition.Column, StringComparer.OrdinalIgnoreCase) ||
            root.SourceColumns.Any(c => c.Column.Equals(definition.Column, StringComparison.OrdinalIgnoreCase)) ||
            root.SourceColumnTypes.Keys.Any(c => c.Equals(definition.Column, StringComparison.OrdinalIgnoreCase)) ||
            root.ColumnTypes.Keys.Any(c => c.Equals(definition.Column, StringComparison.OrdinalIgnoreCase))
            ? throw Invalid("target_extension_source_overlap")
            : new(root, definition.Column, definition.Type, definition.Nullable, definition.Default);
    }

    internal static IReadOnlyList<TableCopyPlan> ComposePhysical(DatabaseSchemaPlan schema, bool mapSourceDispositions = true)
    {
        var extras = ApprovedTargetExtensionManifest.TablesFor(schema);
        var overlay = For(schema);
        var mapped = mapSourceDispositions ? ApprovedSourceDispositionManifest.TargetTablesFor(schema) : schema.Tables;
        return overlay is null
            ? [.. mapped, .. extras]
            : [.. mapped.Select(t => t.TargetSchema == overlay.Root.TargetSchema && t.TargetTable == overlay.Root.TargetTable
            ? t with
            {
                OrderedColumns = [.. t.OrderedColumns, overlay.Column],
                ColumnTypes = t.ColumnTypes.Append(new(overlay.Column, overlay.Type)).ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal),
                NullableColumns = overlay.Nullable ? [.. t.NullableColumns, overlay.Column] : t.NullableColumns,
                DefaultExpressions = overlay.Default is null ? t.DefaultExpressions : t.DefaultExpressions.Append(new(overlay.Column, overlay.Default)).ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal),
            } : t), .. extras];
    }

    internal static bool HasState(DatabaseSchemaPlan schema)
    {
        return ApprovedTargetExtensionManifest.TablesFor(schema).Count != 0 || For(schema) is not null;
    }

    internal static IReadOnlySet<string> InsertKeys(DatabaseSchemaPlan schema, DeltaSynchronizationPlan plan)
    {
        var overlay = For(schema);
        if (overlay is null) { return new HashSet<string>(StringComparer.Ordinal); }
        string table = $"{overlay.Root.TargetSchema}.{overlay.Root.TargetTable}";
        var operations = plan.Databases.Single(d => d.Database == schema.Database).Tables.Single(t => t.Table == table).Operations;
        if (operations.Any(o => o.Kind == DeltaOperationKind.Delete)) { throw Invalid("target_extension_overlay_delete_forbidden"); }
        var keys = operations.Where(o => o.Kind == DeltaOperationKind.Insert).Select(o => o.KeySha256).ToArray();
        return keys.Any(k => !PostgreSqlDeltaCanonicalTarget.Hash(k)) || keys.Distinct(StringComparer.Ordinal).Count() != keys.Length
            ? throw Invalid("target_extension_overlay_state_invalid")
            : (IReadOnlySet<string>)new HashSet<string>(keys, StringComparer.Ordinal);
    }

    internal static MigrationExecutionException Invalid(string code)
    {
        return new(code, "The exact consumer column overlay contract is invalid.");
    }
}
