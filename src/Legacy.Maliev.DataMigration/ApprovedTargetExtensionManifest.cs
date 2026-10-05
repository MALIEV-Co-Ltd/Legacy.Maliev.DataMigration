namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Reviewed PostgreSQL-only service tables. These tables are part of the target schema
/// fingerprint but never part of SQL Server row comparison or delta operations.
/// </summary>
internal static class ApprovedTargetExtensionManifest
{
    internal const string MaterialCatalogV1 = "material-catalog-v1";
    internal const string QuotationRequestIdempotencyV1 = "quotation-request-idempotency-v1";
    internal const string AccountingInvoiceAuthorityV1 = "accounting-invoice-authority-v1";
    internal const string AuthCustomerCreateAuthorityV1 = "auth-customer-create-authority-v1";
    internal const string AuthEmployeeRecoveryAuthorityV1 = "auth-employee-recovery-authority-v1";

    internal static string? ProfileForDatabase(string database)
    {
        return database switch
        {
            "Material" => MaterialCatalogV1,
            "QuotationRequest" => QuotationRequestIdempotencyV1,
            "Invoice" => AccountingInvoiceAuthorityV1,
            "CustomerIdentity" => AuthCustomerCreateAuthorityV1,
            "EmployeeIdentity" => AuthEmployeeRecoveryAuthorityV1,
            _ => null,
        };
    }

    internal static IReadOnlyList<TableCopyPlan> TablesFor(DatabaseSchemaPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        IReadOnlyList<TableCopyPlan> extensions = ApprovedCurrentConsumerSchemaManifest.IsProfile(plan.TargetExtensionProfile)
            ? ApprovedCurrentConsumerSchemaManifest.TablesFor(plan)
            : (plan.Database, plan.TargetExtensionProfile) switch
            {
                (_, null) => [],
                ("Material", MaterialCatalogV1) => [Country(), Currency()],
                ("QuotationRequest", QuotationRequestIdempotencyV1) => [RequestCreateIdempotency()],
                ("Invoice", AccountingInvoiceAuthorityV1) => ApprovedConsumerTargetExtensionShapes.Invoice(),
                ("CustomerIdentity", AuthCustomerCreateAuthorityV1) => ApprovedConsumerTargetExtensionShapes.CustomerIdentity(),
                ("CustomerIdentity", ApprovedConsumerColumnOverlayManifest.CustomerV2) => ApprovedConsumerTargetExtensionShapes.CustomerIdentity(),
                ("Quotation", ApprovedConsumerColumnOverlayManifest.QuotationV1) => [],
                ("EmployeeIdentity", AuthEmployeeRecoveryAuthorityV1) => ApprovedConsumerTargetExtensionShapes.EmployeeIdentity(),
                _ => throw new MigrationExecutionException("target_extension_profile_invalid",
                    "The target extension profile is not approved for this database."),
            };

        _ = ApprovedConsumerColumnOverlayManifest.For(plan);

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
            Collations = ApprovedProductionCollationManifest.ForTable(
                "Material", "public", "Country",
                ["ID", "Name", "Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"]),
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
            Collations = ApprovedProductionCollationManifest.ForTable(
                "Material", "public", "Currency",
                ["ID", "ShortName", "LongName", "CreatedDate", "ModifiedDate"]),
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
