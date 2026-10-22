namespace Legacy.Maliev.DataMigration;

/// <summary>Appended physical profile only; does not authorize repairs or row writes.</summary>
internal static class CurrentConsumerSchemaV3IsoManifest
{
    private static readonly string[] DefaultColumnNames = ["CreatedDate", "ModifiedDate"];
    private static readonly string[] CollatedColumnNames = ["Name", "Continent", "CountryCode", "ISO2", "ISO3"];
    // Full immutable owner commits are part of each signed profile identifier.
    internal const string Country = "country-current-consumer-v3-iso-744b4747b1b6db1e106d1c19872043bc66bcad7a";
    internal const string Material = "material-current-consumer-v3-iso-61a5cf8ccf5c0754c6a5ba3906c59517962e3fc3";

    internal static bool IsProfile(string? profile)
    {
        return profile is Country or Material;
    }

    internal static string? ProfileForDatabase(string database)
    {
        return database switch
        {
            "Country" => Country,
            "Material" => Material,
            _ => CurrentConsumerSchemaV3Manifest.ProfileForDatabase(database),
        };
    }

    internal static DatabaseSchemaPlan BasePlan(DatabaseSchemaPlan plan)
    {
        return !IsProfile(plan.TargetExtensionProfile) || plan.TargetExtensionProfile != ProfileForDatabase(plan.Database)
            ? throw Invalid()
            : (plan with { TargetExtensionProfile = CurrentConsumerSchemaV3Manifest.ProfileForDatabase(plan.Database) });
    }

    internal static IReadOnlyList<TableCopyPlan> Apply(string database, IReadOnlyList<TableCopyPlan> physical)
    {
        if (database is not ("Country" or "Material")) { throw Invalid(); }
        TableCopyPlan[] roots = [.. physical.Where(table => table.TargetSchema == "public" && table.TargetTable == "Country")];
        if (roots.Length != 1) { throw Invalid(); }
        RequireBefore(database, roots[0]);
        return [.. physical.Select(table => ReferenceEquals(table, roots[0]) ? table with
        {
            ColumnTypes = table.ColumnTypes.ToDictionary(pair => pair.Key, pair => pair.Key switch
            {
                "ISO2" => "character varying(2)",
                "ISO3" => "character varying(3)",
                _ => pair.Value,
            }, StringComparer.Ordinal),
        } : table)];
    }
    private static void RequireBefore(string database, TableCopyPlan table)
    {
        string[] columns = database == "Country"
            ? ["Continent", "CountryCode", "CreatedDate", "ID", "ISO2", "ISO3", "ModifiedDate", "Name"]
            : ["ID", "Name", "Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"];
        string[] typedColumns = ["ID", "Name", "Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"];
        string[] types = ["integer", "character varying(50)", "character varying(50)", "character varying(30)",
            "character(2)", "character(3)", "timestamp without time zone", "timestamp without time zone"];
        if (table.SourceSchema != (database == "Country" ? "dbo" : "target-only") || table.SourceTable != "Country" ||
            !table.OrderedColumns.SequenceEqual(columns, StringComparer.Ordinal) || table.ColumnTypes.Count != columns.Length ||
            typedColumns.Zip(types).Any(x => table.ColumnTypes.GetValueOrDefault(x.First) != x.Second) ||
            !table.OrderByColumns.SequenceEqual(["ID"], StringComparer.Ordinal) || table.PrimaryKey is not { } primary || primary.Name != "PK_Country" ||
            !primary.Columns.SequenceEqual(["ID"], StringComparer.Ordinal) ||
            !table.NullableColumns.ToHashSet(StringComparer.Ordinal).SetEquals(["Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"]) ||
            table.NullableColumns.Count != 6 || table.Identities.Count != 1 || table.Identities[0].Column != "ID" ||
            table.DefaultExpressions.Count != 2 || DefaultColumnNames.Any(column =>
                PostgreSqlDefaultExpressionCanonicalizer.Canonicalize(table.DefaultExpressions.GetValueOrDefault(column, "")) != "utc-current-timestamp") ||
            table.Collations.Count != 5 || CollatedColumnNames.Any(column =>
                table.Collations.GetValueOrDefault(column) != ApprovedProductionCollationManifest.Collation) ||
            table.UniqueConstraints.Count != 0 || table.Indexes.Count != 0 || table.ForeignKeys.Count != 0 ||
            table.CheckConstraints.Count != 0 || table.GeneratedColumns.Count != 0)
        { throw Invalid(); }
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_consumer_iso_profile_invalid",
    "The appended V3 ISO profile requires the exact reviewed Country shape.");
    }
}