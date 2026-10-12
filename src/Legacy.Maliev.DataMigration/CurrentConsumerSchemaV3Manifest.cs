namespace Legacy.Maliev.DataMigration;

/// <summary>Opt-in October 2026 target-only contracts; does not grant repair or row-write authority.</summary>
internal static class CurrentConsumerSchemaV3Manifest
{
    internal const string PurchaseOrder = "purchase-order-current-consumer-schema-v3";
    internal const string Quotation = "quotation-current-consumer-schema-v3";
    internal const string Invoice = "invoice-current-consumer-schema-v3";
    internal static bool IsProfile(string? profile)
    {
        return profile is PurchaseOrder or Quotation or Invoice;
    }

    internal static string? ProfileForDatabase(string database)
    {
        return database switch
        {
            "PurchaseOrder" => PurchaseOrder,
            "Quotation" => Quotation,
            "Invoice" => Invoice,
            _ => ApprovedCurrentConsumerSchemaManifest.ProfileForDatabase(database),
        };
    }

    internal static IReadOnlyList<TableCopyPlan> TablesFor(DatabaseSchemaPlan plan)
    {
        return !IsProfile(plan.TargetExtensionProfile) || plan.TargetExtensionProfile != ProfileForDatabase(plan.Database)
            ? throw ApprovedConsumerColumnOverlayManifest.Invalid("target_extension_profile_invalid")
            : plan.Database switch
            {
                "PurchaseOrder" => [Receipt("OrderItemCreateReceipt", 3), Receipt("PurchaseOrderFileCreateReceipt", 4)],
                "Quotation" => [Completion()],
                "Invoice" => [.. ApprovedCurrentConsumerSchemaManifest.TablesFor(plan with
                { TargetExtensionProfile = ApprovedCurrentConsumerSchemaManifest.Invoice }).Select(AddInvoiceOwnership)],
                _ => throw ApprovedConsumerColumnOverlayManifest.Invalid("target_extension_profile_invalid"),
            };
    }

    private static TableCopyPlan AddInvoiceOwnership(TableCopyPlan table)
    {
        return table.TargetTable != "InvoiceCreationAdmission"
            ? table
            : ApprovedCurrentConsumerSchemaManifest.WithExplicitTextCollations(table with
            {
                OrderedColumns = [.. table.OrderedColumns, "OriginIssuer", "FinancialResultJson", "FinancialOwnershipJson", "EmployeeCompletionJson"],
                ColumnTypes = table.ColumnTypes.Concat(new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["OriginIssuer"] = "character varying(512)",
                    ["FinancialResultJson"] = "text",
                    ["FinancialOwnershipJson"] = "text",
                    ["EmployeeCompletionJson"] = "text"
                })
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal),
                NullableColumns = [.. table.NullableColumns, "OriginIssuer", "FinancialResultJson", "FinancialOwnershipJson", "EmployeeCompletionJson"],
            });
    }

    private static TableCopyPlan Shape(string table, (string Name, string Type)[] columns, string[] key, string[] nullable)
    {
        return new("target-only", table, "public", table, columns.Select(column => column.Name).ToArray(), key)
        {
            ColumnTypes = columns.ToDictionary(column => column.Name, column => column.Type, StringComparer.Ordinal),
            NullableColumns = nullable,
            PrimaryKey = new("PK_" + table, key),
        };
    }

    private static TableCopyPlan Receipt(string name, short operation)
    {
        return Shape(name,
            [("IssuerDigest", "bytea"), ("SubjectDigest", "bytea"), ("Operation", "smallint"),
             ("KeyDigest", "bytea"), ("CanonicalVersion", "smallint"), ("PayloadDigest", "bytea"),
             ("ResponseVersion", "smallint"), ("EntityId", "integer"), ("ResponseBody", "bytea"),
             ("ResponseDigest", "bytea"), ("CreatedAtUtc", "timestamp with time zone")],
            ["IssuerDigest", "SubjectDigest", "Operation", "KeyDigest"], []) with
        {
            CheckConstraints =
            [
                new("CK_" + name + "_Digests", "octet_length(\"IssuerDigest\") = 32 AND octet_length(\"SubjectDigest\") = 32 AND octet_length(\"KeyDigest\") = 32 AND octet_length(\"PayloadDigest\") = 32 AND octet_length(\"ResponseDigest\") = 32")
                { Columns = ["IssuerDigest", "SubjectDigest", "KeyDigest", "PayloadDigest", "ResponseDigest"] },
                new("CK_" + name + "_Operation", "\"Operation\" = " + operation.ToString(System.Globalization.CultureInfo.InvariantCulture)) { Columns = ["Operation"] },
                new("CK_" + name + "_Versions", "\"CanonicalVersion\" = 1 AND \"ResponseVersion\" = 1") { Columns = ["CanonicalVersion", "ResponseVersion"] },
                new("CK_" + name + "_Complete", "\"EntityId\" > 0 AND octet_length(\"ResponseBody\") > 0") { Columns = ["EntityId", "ResponseBody"] },
            ],
        };
    }

    private static TableCopyPlan Completion()
    {
        const string name = "QuotationInvoiceCompletionOperation";
        return ApprovedCurrentConsumerSchemaManifest.WithExplicitTextCollations(Shape(name,
            [("OperationId", "uuid"), ("QuotationId", "integer"), ("InvoiceId", "integer"),
             ("AuthorityJson", "text"), ("OrderIdsJson", "text"), ("CompletedOrderIdsJson", "text"),
             ("State", "character varying(32)"), ("DecisionOrderVersion", "text"), ("ModifiedDate", "text"),
             ("ClaimId", "uuid"), ("ClaimUntil", "timestamp without time zone")], ["OperationId"], ["ClaimId", "ClaimUntil"]) with
        { Indexes = [new("IX_" + name + "_QuotationId", ["QuotationId"], true)] });
    }
}
