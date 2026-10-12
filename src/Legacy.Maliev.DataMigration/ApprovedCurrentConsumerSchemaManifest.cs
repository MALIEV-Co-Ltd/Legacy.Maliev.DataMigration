namespace Legacy.Maliev.DataMigration;

/// <summary>Closed current service schema; source projections and prior profiles remain unchanged.</summary>
internal static class ApprovedCurrentConsumerSchemaManifest
{
    internal const string ServiceContractsSha256 = "88ae7dde6a17d3698c1205ad465b4cb180db08deab9acf7b0127752b85f7b234";
    internal const string RetainedCollationReviewSha256 = "68e738ab1d4f34ffc8ad4bb8f2d9a9d533e4232926cfe5a9cb81badb583f8e55";
    internal const string Customer = "customer-current-consumer-schema-v2";
    internal const string Upload = "upload-current-consumer-schema-v2";
    internal const string Order = "order-current-consumer-schema-v2";
    internal const string Invoice = "invoice-current-consumer-schema-v2";
    internal const string CustomerIdentity = "customer-identity-current-consumer-schema-v2";
    internal const string EmployeeIdentity = "employee-identity-current-consumer-schema-v2";
    internal const string Quotation = "quotation-current-consumer-schema-v2";
    internal const string QuotationRequest = "quotation-request-current-consumer-schema-v2";

    internal static string? ProfileForDatabase(string database)
    {
        return database switch
        {
            "Customer" => Customer,
            "Upload" => Upload,
            "Order" => Order,
            "Invoice" => Invoice,
            "CustomerIdentity" => CustomerIdentity,
            "EmployeeIdentity" => EmployeeIdentity,
            "Quotation" => Quotation,
            "QuotationRequest" => QuotationRequest,
            _ => ApprovedTargetExtensionManifest.ProfileForDatabase(database),
        };
    }

    internal static bool IsProfile(string? profile)
    {
        return profile is Customer or Upload or Order or Invoice or
        CustomerIdentity or EmployeeIdentity or Quotation or QuotationRequest;
    }

    internal static IReadOnlyList<TableCopyPlan> TablesFor(DatabaseSchemaPlan plan)
    {
        if (!IsProfile(plan.TargetExtensionProfile) ||
            plan.TargetExtensionProfile != ProfileForDatabase(plan.Database))
        { throw ApprovedConsumerColumnOverlayManifest.Invalid("target_extension_profile_invalid"); }
        IReadOnlyList<TableCopyPlan> tables = plan.Database switch
        {
            "Customer" or "Upload" or "Order" => ApprovedCurrentConsumerTargetShapes.ForDatabase(plan.Database),
            "Invoice" => ApprovedConsumerTargetExtensionShapes.Invoice(),
            "CustomerIdentity" => ApprovedConsumerTargetExtensionShapes.CustomerIdentity(),
            "EmployeeIdentity" => ApprovedConsumerTargetExtensionShapes.EmployeeIdentity(),
            "QuotationRequest" => ApprovedTargetExtensionManifest.TablesFor(plan with
            { TargetExtensionProfile = ApprovedTargetExtensionManifest.QuotationRequestIdempotencyV1 }),
            "Quotation" => [],
            _ => throw ApprovedConsumerColumnOverlayManifest.Invalid("target_extension_profile_invalid"),
        };
        return [.. tables.Select(WithExplicitTextCollations)];
    }

    internal static TableCopyPlan WithExplicitTextCollations(TableCopyPlan table)
    {
        return table with
        {
            Collations = table.ColumnTypes.Where(column => column.Value == "text" ||
                column.Value.StartsWith("character varying(", StringComparison.Ordinal) ||
                column.Value.StartsWith("character(", StringComparison.Ordinal))
            .ToDictionary(column => column.Key, _ => "C", StringComparer.Ordinal),
        };
    }
}
