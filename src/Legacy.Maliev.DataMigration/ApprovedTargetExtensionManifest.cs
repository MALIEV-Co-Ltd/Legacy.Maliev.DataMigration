namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Reviewed PostgreSQL-only service tables. These tables are part of the target schema
/// fingerprint but never part of SQL Server row comparison or delta operations.
/// </summary>
internal static class ApprovedTargetExtensionManifest
{
    internal const string MaterialCatalogV1 = "material-catalog-v1";
    internal const string QuotationRequestIdempotencyV1 = "quotation-request-idempotency-v1";

    internal static string? ProfileForDatabase(string database)
    {
        return database switch
        {
            "Material" => MaterialCatalogV1,
            "QuotationRequest" => QuotationRequestIdempotencyV1,
            _ => null,
        };
    }

    internal static IReadOnlyList<TableCopyPlan> TablesFor(DatabaseSchemaPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        IReadOnlyList<TableCopyPlan> extensions = (plan.Database, plan.TargetExtensionProfile) switch
        {
            (_, null) => [],
            ("Material", MaterialCatalogV1) => [Country(), Currency()],
            ("QuotationRequest", QuotationRequestIdempotencyV1) => [RequestCreateIdempotency()],
            _ => throw new MigrationExecutionException("target_extension_profile_invalid",
                "The target extension profile is not approved for this database."),
        };

        HashSet<string> sourceTables = [.. plan.Tables.Select(table => $"{table.TargetSchema}.{table.TargetTable}")];
        return extensions.Any(table => sourceTables.Contains($"{table.TargetSchema}.{table.TargetTable}"))
            ? throw new MigrationExecutionException("target_extension_source_overlap",
                "A SQL Server source table cannot be classified as a target-only extension.")
            : extensions;
    }

    private static TableCopyPlan Country()
    {
        return new(
        "target-only", "Country", "public", "Country",
        ["ID", "Name", "Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "integer",
                ["Name"] = "character varying(50)",
                ["Continent"] = "character varying(50)",
                ["CountryCode"] = "character varying(30)",
                ["ISO2"] = "character(2)",
                ["ISO3"] = "character(3)",
                ["CreatedDate"] = "timestamp without time zone",
                ["ModifiedDate"] = "timestamp without time zone",
            },
            NullableColumns = ["Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"],
            Identities = [new IdentityCopyPlan("ID", 1, 1, 1, false)],
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Country", ["ID"]),
            DefaultExpressions = UtcTimestampDefaults(),
        };
    }

    private static TableCopyPlan Currency()
    {
        return new(
        "target-only", "Currency", "public", "Currency",
        ["ID", "ShortName", "LongName", "CreatedDate", "ModifiedDate"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "integer",
                ["ShortName"] = "character varying(10)",
                ["LongName"] = "character varying(50)",
                ["CreatedDate"] = "timestamp without time zone",
                ["ModifiedDate"] = "timestamp without time zone",
            },
            NullableColumns = ["CreatedDate", "ModifiedDate"],
            Identities = [new IdentityCopyPlan("ID", 1, 1, 1, false)],
            PrimaryKey = new PrimaryKeyCopyPlan("PK_Currency", ["ID"]),
            DefaultExpressions = UtcTimestampDefaults(),
        };
    }

    private static TableCopyPlan RequestCreateIdempotency()
    {
        return new(
        "target-only", "RequestCreateIdempotency", "public", "RequestCreateIdempotency",
        ["KeyHash", "Fingerprint", "RequestID"], ["KeyHash"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["KeyHash"] = "character(64)",
                ["Fingerprint"] = "character(64)",
                ["RequestID"] = "integer",
            },
            PrimaryKey = new PrimaryKeyCopyPlan("PK_RequestCreateIdempotency", ["KeyHash"]),
        };
    }

    private static Dictionary<string, string> UtcTimestampDefaults()
    {
        return new(StringComparer.Ordinal)
        {
            ["CreatedDate"] = "(CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)",
            ["ModifiedDate"] = "(CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)",
        };
    }
}
