using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

/// <summary>Exact reviewed target collation inventory for the canonical legacy PostgreSQL schema.</summary>
internal static class ApprovedProductionCollationManifest
{
    internal const string Collation = "legacy_ci_as";
    internal const int ColumnCount = 304;
    internal const string InventorySha256 = "f93642d9fb2a2516b1032e1b4d35ac0c36defdd21709d73d5a8b442beff7fbc5";

    private static readonly IReadOnlyDictionary<string, string[]> Columns =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["Country|public|Country"] = ["Continent", "CountryCode", "ISO2", "ISO3", "Name"],
            ["Currency|public|Currency"] = ["LongName", "ShortName"],
            ["Customer|public|Address"] = ["AddressLine1", "AddressLine2", "Building", "City", "PostalCode", "State"],
            ["Customer|public|Company"] = ["BranchID", "BranchName", "FaxNumber", "Name", "PhoneNumber", "Registrar", "TaxNumber"],
            ["Customer|public|Customer"] = ["Email", "Fax", "FirstName", "FullName", "LastName", "Mobile", "Notes", "Telephone"],
            ["Customer|public|CustomerFiles"] = ["Description"],
            ["Customer|public|NdaFiles"] = ["Description"],
            ["CustomerIdentity|public|AspNetRoleClaims"] = ["ClaimType", "ClaimValue", "RoleId"],
            ["CustomerIdentity|public|AspNetRoles"] = ["ConcurrencyStamp", "Id", "Name", "NormalizedName"],
            ["CustomerIdentity|public|AspNetUserClaims"] = ["ClaimType", "ClaimValue", "UserId"],
            ["CustomerIdentity|public|AspNetUserLogins"] = ["LoginProvider", "ProviderDisplayName", "ProviderKey", "UserId"],
            ["CustomerIdentity|public|AspNetUserRoles"] = ["RoleId", "UserId"],
            ["CustomerIdentity|public|AspNetUsers"] = ["ConcurrencyStamp", "Email", "FaxNumber", "Id", "MobileNumber", "NormalizedEmail", "NormalizedUserName", "PasswordHash", "PhoneNumber", "SecurityStamp", "UserName"],
            ["CustomerIdentity|public|AspNetUserTokens"] = ["LoginProvider", "Name", "UserId", "Value"],
            ["CustomerIdentity|public|__EFMigrationsHistory"] = ["MigrationId", "ProductVersion"],
            ["DataProtectionKeys|public|DataProtectionKeys"] = ["FriendlyName", "Xml"],
            ["DataProtectionKeys|public|__EFMigrationsHistory"] = ["MigrationId", "ProductVersion"],
            ["DataProtectionKeysEmployee|public|DataProtectionKeys"] = ["FriendlyName", "Xml"],
            ["DataProtectionKeysEmployee|public|__EFMigrationsHistory"] = ["MigrationId", "ProductVersion"],
            ["Employee|public|Address"] = ["AddressLine1", "AddressLine2", "Building", "City", "PostalCode", "State"],
            ["Employee|public|ContractType"] = ["Description", "Name"],
            ["Employee|public|Employee"] = ["Email", "EmploymentStatus", "FirstName", "FullName", "LastName", "PhoneNumber"],
            ["Employee|public|EmployeeFiles"] = ["Bucket", "Description", "ObjectName"],
            ["Employee|public|Role"] = ["Description", "Name"],
            ["Employee|public|SignatureImageFile"] = ["Bucket", "ObjectName"],
            ["EmployeeIdentity|public|AspNetRoleClaims"] = ["ClaimType", "ClaimValue", "RoleId"],
            ["EmployeeIdentity|public|AspNetRoles"] = ["ConcurrencyStamp", "Id", "Name", "NormalizedName"],
            ["EmployeeIdentity|public|AspNetUserClaims"] = ["ClaimType", "ClaimValue", "UserId"],
            ["EmployeeIdentity|public|AspNetUserLogins"] = ["LoginProvider", "ProviderDisplayName", "ProviderKey", "UserId"],
            ["EmployeeIdentity|public|AspNetUserRoles"] = ["RoleId", "UserId"],
            ["EmployeeIdentity|public|AspNetUsers"] = ["ConcurrencyStamp", "Email", "Id", "NormalizedEmail", "NormalizedUserName", "PasswordHash", "PhoneNumber", "SecurityStamp", "UserName"],
            ["EmployeeIdentity|public|AspNetUserTokens"] = ["LoginProvider", "Name", "UserId", "Value"],
            ["EmployeeIdentity|public|__EFMigrationsHistory"] = ["MigrationId", "ProductVersion"],
            ["Invoice|public|Invoice"] = ["BillingAddressBuilding", "BillingAddressCity", "BillingAddressCompany", "BillingAddressCountry", "BillingAddressLine1", "BillingAddressLine2", "BillingAddressPostalCode", "BillingAddressRecipient", "BillingAddressState", "Comment", "CommercialRegistration", "Currency", "Fob", "InternalComment", "Number", "PurchaseOrderNumber", "Requisitioner", "SalesPerson", "ShippedVia", "ShippingAddressBuilding", "ShippingAddressCity", "ShippingAddressCompany", "ShippingAddressCountry", "ShippingAddressLine1", "ShippingAddressLine2", "ShippingAddressPostalCode", "ShippingAddressRecipient", "ShippingAddressRecipientTelephone", "ShippingAddressState", "TaxIdentification", "Terms"],
            ["Invoice|public|InvoiceFile"] = ["Bucket", "ObjectName"],
            ["Invoice|public|OrderItem"] = ["Description"],
            ["JobOffers|public|Level"] = ["Description", "Name"],
            ["JobOffers|public|Offer"] = ["Description", "Introduction", "Location", "Prerequisites", "Title", "WhatWeOffer"],
            ["Material|public|Color"] = ["Name"],
            ["Material|public|Country"] = ["Continent", "CountryCode", "ISO2", "ISO3", "Name"],
            ["Material|public|Currency"] = ["LongName", "ShortName"],
            ["Material|public|Material"] = ["AFNOR", "AISI", "AMS", "ASTM", "BTS", "Comment", "DIN", "EN", "JIS", "ManufacturerReference", "MaterialNumber", "Name", "SAE", "SIS", "UNI", "UNS", "URL"],
            ["Material|public|MaterialGroup"] = ["Description", "Name"],
            ["Material|public|SurfaceFinish"] = ["Name"],
            ["Message|public|Message"] = ["Company", "Country", "Email", "FirstName", "LastName", "MessageContent", "Telephone"],
            ["Order|public|Category"] = ["Name"],
            ["Order|public|FileFormat"] = ["Extension", "Name"],
            ["Order|public|Order"] = ["Comment", "Description", "Name", "TrackingNumber"],
            ["Order|public|OrderFile"] = ["Bucket", "ObjectName"],
            ["Order|public|Process"] = ["Name"],
            ["OrderStatus|public|OrderStatus"] = ["Description", "Name"],
            ["Payment|public|Account"] = ["AccountNumber", "Bank", "Branch", "Swift"],
            ["Payment|public|Payment"] = ["Description", "Recipient", "TransactionNumber"],
            ["Payment|public|PaymentDirection"] = ["Description", "Name"],
            ["Payment|public|PaymentFile"] = ["Bucket", "ObjectName"],
            ["Payment|public|PaymentMethod"] = ["Description", "Name"],
            ["Payment|public|PaymentType"] = ["Description", "Name"],
            ["PurchaseOrder|public|Address"] = ["AddressLine1", "AddressLine2", "Building", "City", "PostalCode", "State"],
            ["PurchaseOrder|public|OrderItem"] = ["Description", "PartNumber"],
            ["PurchaseOrder|public|PurchaseOrder"] = ["BillingContactPerson", "BillingFax", "BillingMobile", "BillingTelephone", "FOB", "Notes", "ShippingContactPerson", "ShippingFax", "ShippingMethod", "ShippingMobile", "ShippingTelephone", "SupplierContactPerson", "Terms"],
            ["PurchaseOrder|public|PurchaseOrderFile"] = ["Bucket", "ObjectName"],
            ["Quotation|public|OrderItem"] = ["Description"],
            ["Quotation|public|Quotation"] = ["Comment", "FOB", "ShippedVia", "Terms"],
            ["Quotation|public|QuotationFile"] = ["Bucket", "ObjectName"],
            ["QuotationRequest|public|Request"] = ["CompanyName", "Country", "Email", "FirstName", "InternalComment", "LastName", "Message", "TaxIdentification", "TelephoneNumber"],
            ["QuotationRequest|public|RequestFile"] = ["Bucket", "ObjectName"],
            ["Receipt|public|OrderItem"] = ["Description"],
            ["Receipt|public|Receipt"] = ["BillingAddressBuilding", "BillingAddressCity", "BillingAddressCompany", "BillingAddressCountry", "BillingAddressLine1", "BillingAddressLine2", "BillingAddressPostalCode", "BillingAddressRecipient", "BillingAddressState", "Comment", "CommercialRegistration", "Currency", "InvoiceNumber", "TaxIdentification"],
            ["Receipt|public|ReceiptFile"] = ["Bucket", "ObjectName"],
            ["Supplier|public|Address"] = ["Address1", "Address2", "Building", "City", "PostalCode", "State"],
            ["Supplier|public|Supplier"] = ["Email", "Fax", "Mobile", "Name", "Note", "TaxNumber", "Telephone", "Website"],
            ["Upload|public|Upload"] = ["Bucket", "ContentType", "Name", "OriginalFileName", "StoredFileName"],
        };

    internal static IReadOnlyDictionary<string, string> ForTable(
        string database, string schema, string table, IReadOnlyList<string> orderedColumns)
    {
        return !Columns.TryGetValue($"{database}|{schema}|{table}", out string[]? approved)
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : approved.Any(column => !orderedColumns.Contains(column, StringComparer.Ordinal))
                ? throw new MigrationExecutionException("production_collation_inventory_drift",
                    "The reviewed production collation inventory no longer matches the source table.")
                : approved.ToDictionary(column => column, _ => Collation, StringComparer.Ordinal);
    }

    internal static int ReviewedColumnCount => Columns.Values.Sum(columns => columns.Length);

    internal static string ComputeInventorySha256()
    {
        string inventory = string.Join("\n", Columns.SelectMany(group => group.Value.Select(
            column => $"{group.Key}|{column}")).Order(StringComparer.Ordinal)) + "\n";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(inventory))).ToLowerInvariant();
    }
}
