using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public static class DatabaseInventory
{
    public static IReadOnlyDictionary<string, DatabaseDispositionEntry> Entries { get; } =
        new ReadOnlyDictionary<string, DatabaseDispositionEntry>(
            new Dictionary<string, DatabaseDispositionEntry>(StringComparer.Ordinal)
            {
                ["Country"] = Migrate("Legacy.Maliev.CatalogService"),
                ["Currency"] = Migrate("Legacy.Maliev.CatalogService"),
                ["CustomerIdentity"] = Migrate("Legacy.Maliev.AuthService"),
                ["Customer"] = Migrate("Legacy.Maliev.CustomerService"),
                ["DataProtectionKeysEmployee"] = Migrate("Legacy.Maliev.AuthService"),
                ["DataProtectionKeys"] = Migrate("Legacy.Maliev.AuthService"),
                ["EmployeeIdentity"] = Migrate("Legacy.Maliev.AuthService"),
                ["Employee"] = Migrate("Legacy.Maliev.EmployeeService"),
                ["Hangfire"] = new("Legacy.Maliev.CompatibilityContracts", DatabaseDisposition.Excluded),
                ["Invoice"] = Migrate("Legacy.Maliev.AccountingService"),
                ["JobOffers"] = Migrate("Legacy.Maliev.CareerService"),
                ["Log"] = new("Legacy.Maliev.CompatibilityContracts", DatabaseDisposition.Excluded),
                ["MachineLearning"] = new("Legacy.Maliev.CompatibilityContracts", DatabaseDisposition.Excluded),
                ["MachineLearningData"] = new("Legacy.Maliev.CompatibilityContracts", DatabaseDisposition.Excluded),
                ["Material"] = Migrate("Legacy.Maliev.CatalogService"),
                ["Message"] = Migrate("Legacy.Maliev.ContactService"),
                ["OrderStatus"] = Migrate("Legacy.Maliev.OrderService"),
                ["Order"] = Migrate("Legacy.Maliev.OrderService"),
                ["Payment"] = Migrate("Legacy.Maliev.AccountingService"),
                ["PurchaseOrder"] = Migrate("Legacy.Maliev.ProcurementService"),
                ["QuotationRequest"] = Migrate("Legacy.Maliev.QuotationService"),
                ["Quotation"] = Migrate("Legacy.Maliev.QuotationService"),
                ["Receipt"] = Migrate("Legacy.Maliev.AccountingService"),
                ["Supplier"] = Migrate("Legacy.Maliev.ProcurementService"),
                ["Upload"] = Migrate("Legacy.Maliev.FileService"),
                ["ContactRequest"] = Migrate("Legacy.Maliev.ContactService"),
                ["LocationData"] = Migrate("Legacy.Maliev.CatalogService"),
            });

    public static IReadOnlyList<string> ActiveDatabases { get; } = [.. Entries
        .Where(entry => entry.Value.Disposition == DatabaseDisposition.Migrate)
        .Select(entry => entry.Key)
        .OrderBy(database => database, StringComparer.Ordinal)];

    public static string InventorySha256 { get; } = ComputeInventorySha256();

    private static DatabaseDispositionEntry Migrate(string owner)
    {
        return new(owner, DatabaseDisposition.Migrate);
    }

    private static string ComputeInventorySha256()
    {
        string canonical = string.Join(
            '\n',
            Entries
                .OrderBy(entry => entry.Key, StringComparer.Ordinal)
                .Select(entry => string.Join(
                    '|',
                    entry.Key,
                    entry.Value.Owner,
                    entry.Value.Disposition)));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }
}
