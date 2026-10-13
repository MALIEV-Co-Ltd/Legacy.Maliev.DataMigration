namespace Legacy.Maliev.DataMigration;

internal sealed record ReviewedRepairDatabaseFlag(string Name, bool IsTemplate, bool AllowsConnections);

// Exact reviewed discovery inventory. This pure profile grants no execution permission.
internal static class ReviewedProductionRepairInventory
{
    internal const string DiscoveryReportSha256 = "fbfb1ceb37a4da27dd396b0978032320c62ebde313e69938ab91d55c94d8b703";
    private static readonly string[] ProductionNames =
    [
        "Auth",
        "ContactRequest",
        "Country",
        "Currency",
        "Customer",
        "CustomerIdentity",
        "DataProtectionKeys",
        "DataProtectionKeysEmployee",
        "Employee",
        "EmployeeIdentity",
        "Invoice",
        "JobOffers",
        "LocationData",
        "Material",
        "Message",
        "Order",
        "OrderStatus",
        "Payment",
        "PurchaseOrder",
        "Quotation",
        "QuotationRequest",
        "Receipt",
        "Supplier",
        "Upload",
        "legacy_migration_control",
        "legacy_shadow_contact_4939d015_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_country_aff64e4f_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_currenc_466e5b9c_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_custome_8e752dc3_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_custome_b6c45863_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_datapro_31b72101_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_datapro_35b21653_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_employe_2fdc0177_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_employe_97429b04_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_invoice_52d6e3de_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_joboffe_ad34aeba_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_locatio_9b00942f_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_materia_40b30b4e_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_message_ab530a13_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_order_3eeb7e96_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_orderst_28340f2b_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_payment_040ffd59_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_purchas_32b703ee_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_quotati_d5e44483_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_quotati_fcd9bd43_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_receipt_6f328609_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_supplie_955ed10b_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "legacy_shadow_upload_ff4085ad_99dd9a9f4e6149c7ad64d6cd9ccc302e",
        "postgres",
    ];
    private static readonly string[] LocalExtraNames = ["Auth", "postgres", "legacy_local"];
    private static readonly string[] LocalNames = DatabaseInventory.ActiveDatabases.Concat(LocalExtraNames).ToArray();
    private static readonly ReviewedRepairDatabaseFlag[] Templates = [new("template0", true, false), new("template1", true, true)];

    internal static IReadOnlyList<string> ExportProductionNames() => Array.AsReadOnly((string[])ProductionNames.Clone());

    internal static IReadOnlyList<ReviewedRepairDatabaseFlag> ExportProductionCatalog() => Array.AsReadOnly(
        ProductionNames.Select(x => new ReviewedRepairDatabaseFlag(x, false, true)).Concat(Templates)
            .OrderBy(x => x.Name, StringComparer.Ordinal).ToArray());

    internal static bool MatchesKeys(string kind, IEnumerable<string> names)
    {
        string[] actual = names.ToArray();
        string[] expected = kind switch
        {
            DeltaTargetAuthorityKind.ProductionCloudNativePg => ProductionNames,
            DeltaTargetAuthorityKind.LocalAspire => LocalNames,
            _ => []
        };
        return expected.Length > 0 && actual.All(x => !string.IsNullOrWhiteSpace(x)) &&
            actual.Distinct(StringComparer.Ordinal).Count() == actual.Length &&
            actual.Order(StringComparer.Ordinal).SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal);
    }

    internal static void RequireComplete(string kind, IReadOnlyList<ReviewedRepairDatabaseFlag> flags, IEnumerable<string> baselineKeys)
    {
        if (!MatchesKeys(kind, baselineKeys) || flags.Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != flags.Count ||
            flags.Any(x => string.IsNullOrWhiteSpace(x.Name)) ||
            !MatchesKeys(kind, flags.Where(x => !x.IsTemplate).Select(x => x.Name)) ||
            flags.Any(x => !x.IsTemplate && !x.AllowsConnections)) { throw Invalid(); }
        var templates = flags.Where(x => x.IsTemplate).OrderBy(x => x.Name, StringComparer.Ordinal).ToArray();
        if (templates.Length != 2 || templates[0] != new ReviewedRepairDatabaseFlag("template0", true, false) ||
            templates[1] != new ReviewedRepairDatabaseFlag("template1", true, true)) { throw Invalid(); }
        if (kind == DeltaTargetAuthorityKind.ProductionCloudNativePg &&
            !flags.OrderBy(x => x.Name, StringComparer.Ordinal).SequenceEqual(ExportProductionCatalog())) { throw Invalid(); }
    }

    private static MigrationExecutionException Invalid() => new("reviewed_production_inventory_mismatch",
        "Complete reviewed database names and template/connection flags required; no baseline may be omitted.");
}
