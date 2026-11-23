namespace Legacy.Maliev.DataMigration;

/// <summary>Planner-only ISO widths for the truthful SQL Country preimage; grants no repair authority.</summary>
internal static class CurrentConsumerSchemaV3SourceOrderIsoManifest
{
    internal const string Country = "country-current-consumer-v3-source-order-iso-744b4747b1b6db1e106d1c19872043bc66bcad7a";
    private static readonly string[] Columns = ["ID", "Name", "Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"];
    private static readonly string[] Types = ["integer", "character varying(50)", "character varying(50)", "character varying(30)",
        "character(2)", "character(3)", "timestamp without time zone", "timestamp without time zone"];
    private static readonly string[] SourceTypes = ["int", "nvarchar(50)", "nvarchar(50)", "nvarchar(30)", "nchar(2)", "nchar(3)", "datetime", "datetime"];
    private static readonly string[] Defaults = ["CreatedDate", "ModifiedDate"];
    private static readonly string[] Collated = ["Name", "Continent", "CountryCode", "ISO2", "ISO3"];

    internal static bool IsProfile(string? profile)
    {
        return profile == Country;
    }

    internal static DatabaseSchemaPlan BasePlan(DatabaseSchemaPlan plan)
    {
        return plan.Database == "Country" && IsProfile(plan.TargetExtensionProfile)
            ? plan with { TargetExtensionProfile = CurrentConsumerSchemaV3Manifest.ProfileForDatabase("Country") }
            : throw Invalid();
    }

    internal static IReadOnlyList<TableCopyPlan> Apply(IReadOnlyList<TableCopyPlan> physical)
    {
        TableCopyPlan[] roots = [.. physical.Where(x => x.TargetSchema == "public" && x.TargetTable == "Country")];
        if (roots.Length != 1) { throw Invalid(); }
        TableCopyPlan root = roots[0];
        return root.SourceSchema != "dbo" || root.SourceTable != "Country" ||
            !root.OrderedColumns.SequenceEqual(Columns, StringComparer.Ordinal) || root.ColumnTypes.Count != 8 ||
            Columns.Zip(Types).Any(x => root.ColumnTypes.GetValueOrDefault(x.First) != x.Second) ||
            root.SourceColumnTypes.Count != 8 || Columns.Zip(SourceTypes).Any(x => root.SourceColumnTypes.GetValueOrDefault(x.First) != x.Second) ||
            !root.SourceColumns.Select(x => x.Column).SequenceEqual(Columns, StringComparer.Ordinal) ||
            root.SourceColumns.Any(x => x.DeclaredType != root.SourceColumnTypes.GetValueOrDefault(x.Column) ||
                x.MetadataSha256 is not { Length: 64 } || !x.MetadataSha256.All(char.IsAsciiHexDigit) || x.MaxObservedDataLength is < 0) ||
            !root.OrderByColumns.SequenceEqual(["ID"], StringComparer.Ordinal) || root.PrimaryKey is not { Name: "PK_Country" } key ||
            !key.Columns.SequenceEqual(["ID"], StringComparer.Ordinal) || root.NullableColumns.Count != 6 ||
            !root.NullableColumns.ToHashSet(StringComparer.Ordinal).SetEquals(["Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"]) ||
            !root.IdentityColumns.SequenceEqual(["ID"], StringComparer.Ordinal) || root.Identities.Count != 1 ||
            root.Identities[0] is not { Column: "ID", SeedValue: 1, IncrementValue: 1 } ||
            root.DefaultExpressions.Count != 2 || Defaults.Any(column => PostgreSqlDefaultExpressionCanonicalizer.Canonicalize(
                root.DefaultExpressions.GetValueOrDefault(column, "")) != "utc-current-timestamp") ||
            root.Collations.Count != 5 || Collated.Any(column => root.Collations.GetValueOrDefault(column) != ApprovedProductionCollationManifest.Collation) ||
            root.UniqueConstraints.Count != 0 || root.Indexes.Count != 0 || root.ForeignKeys.Count != 0 ||
            root.CheckConstraints.Count != 0 || root.GeneratedColumns.Count != 0
            ? throw Invalid()
            : [.. physical.Select(table => ReferenceEquals(root, table) ? table with
        {
            ColumnTypes = table.ColumnTypes.ToDictionary(x => x.Key, x => x.Key switch
            { "ISO2" => "character varying(2)", "ISO3" => "character varying(3)", _ => x.Value }, StringComparer.Ordinal),
        } : table)];
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_consumer_source_order_iso_profile_invalid",
        "The source-order ISO profile requires the exact reviewed SQL Country shape.");
    }
}
