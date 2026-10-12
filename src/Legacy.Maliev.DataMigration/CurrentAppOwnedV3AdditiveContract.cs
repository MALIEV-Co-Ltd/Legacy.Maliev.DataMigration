using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record V3AddedColumnContract(string Database, string Schema, string Table,
    string Column, string PostgreSqlType, int PhysicalOrdinal, bool Nullable, string Collation);

internal sealed record V3CreateTableContract(string Database, TableCopyPlan Table);

/// <summary>Closed additive preparation only. Does not issue authority or execute a database operation.</summary>
internal sealed class CurrentAppOwnedV3AdditiveContract
{
    private readonly FreshSchemaPlan _before;
    private readonly FreshSchemaPlan _after;
    private readonly string _digest;
    private static readonly string[] AddedNames =
        ["OriginIssuer", "FinancialResultJson", "FinancialOwnershipJson", "EmployeeCompletionJson"];
    private static readonly string[] ChangedDatabases = ["Invoice", "PurchaseOrder", "Quotation"];
    private static readonly string[] ReceiptKey = ["IssuerDigest", "SubjectDigest", "Operation", "KeyDigest"];
    private static readonly string[] CompletionKey = ["OperationId"];
    private static readonly string[] CompletionNullable = ["ClaimId", "ClaimUntil"];
    private static readonly string[] CompletionIndex = ["QuotationId"];

    private CurrentAppOwnedV3AdditiveContract(FreshSchemaPlan before, FreshSchemaPlan after)
    {
        _before = before;
        _after = after;
        byte[] payload = [.. "Legacy.Maliev.CurrentAppOwnedV3.AdditivePreparation.v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(new
            {
                Source = after.SourceCommitSha,
                Before = SchemaPlanCanonicalizer.ComputeSha256(before),
                After = SchemaPlanCanonicalizer.ComputeSha256(after),
                Physical = DatabaseInventory.ActiveDatabases.Select(database => new
                {
                    Database = database,
                    Before = BeforeForDatabase(database).TargetSchemaSha256,
                    After = AfterForDatabase(database).TargetSchemaSha256,
                }).ToArray(),
                Columns = AddedColumns(),
                Tables = CreateTables(),
            })];
        _digest = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
    }

    internal string SourceCommitSha => _after.SourceCommitSha;

    internal string ComputeSha256()
    {
        return _digest;
    }

    internal ReadOnlyCollection<V3AddedColumnContract> AddedColumns()
    {
        TableCopyPlan table = ApprovedConsumerColumnOverlayManifest.ComposePhysical(_after.Databases.Single(x => x.Database == "Invoice"))
            .Single(x => x.TargetTable == "InvoiceCreationAdmission");
        return Array.AsReadOnly(AddedNames.Select((column, index) => new V3AddedColumnContract(
            "Invoice", "public", "InvoiceCreationAdmission", column,
            table.ColumnTypes[column], index + 10, true, table.Collations[column])).ToArray());
    }

    internal ReadOnlyCollection<V3CreateTableContract> CreateTables()
    {
        return Array.AsReadOnly(ChangedDatabases.SelectMany(database =>
            ApprovedConsumerColumnOverlayManifest.ComposePhysical(AfterForDatabase(database))
                .Where(table => IsNewTable(database, table.TargetTable))
                .Select(table => new V3CreateTableContract(database, Clone(table)))).ToArray());
    }

    internal DatabaseSchemaPlan BeforeForDatabase(string database)
    {
        RequireDatabase(database);
        return Clone(_before.Databases.Single(x => x.Database == database));
    }

    internal DatabaseSchemaPlan AfterForDatabase(string database)
    {
        RequireDatabase(database);
        return Clone(_after.Databases.Single(x => x.Database == database));
    }

    internal void RequireTableContract(string database, TableCopyPlan observed, bool after)
    {
        DatabaseSchemaPlan plan = after ? AfterForDatabase(database) : BeforeForDatabase(database);
        TableCopyPlan[] matches = [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(plan)
            .Where(table => table.TargetSchema == observed.TargetSchema && table.TargetTable == observed.TargetTable)];
        if (matches.Length != 1 || !Same(matches[0], observed)) { throw Invalid(); }
    }

    internal static CurrentAppOwnedV3AdditiveContract Create(FreshSchemaPlan before, FreshSchemaPlan after,
        string expectedSourceCommitSha, DateTimeOffset nowUtc)
    {
        if (expectedSourceCommitSha.Length != 40 ||
            !expectedSourceCommitSha.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f')) ||
            before.SourceCommitSha != expectedSourceCommitSha || after.SourceCommitSha != expectedSourceCommitSha)
        { throw Invalid(); }
        before = Clone(before);
        after = Clone(after);
        ProductionSchemaCatalogInspector.ValidatePlan(before, nowUtc);
        ProductionSchemaCatalogInspector.ValidatePlan(after, nowUtc);
        if (!ApprovedConsumerOverlaySelection.IsApproved(before) || !ApprovedConsumerOverlaySelection.IsApproved(after) ||
            before.Databases.Sum(x => x.Tables.Count) != 100 || after.Databases.Sum(x => x.Tables.Count) != 100 ||
            before.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(
                x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV2)) ||
            after.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(
                x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)))
        { throw Invalid(); }
        if (after.Databases.Single(x => x.Database == "Quotation").SourceDispositionProfile !=
            ApprovedSourceDispositionManifest.QuotationOutboxesV1) { throw Invalid(); }
        foreach ((DatabaseSchemaPlan left, DatabaseSchemaPlan right) in before.Databases.Zip(after.Databases))
        {
            if (!Same(left with { TargetExtensionProfile = right.TargetExtensionProfile, TargetSchemaSha256 = right.TargetSchemaSha256 }, right))
            { throw Invalid(); }
            TableCopyPlan[] oldTables = [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(left)];
            TableCopyPlan[] newTables = [.. ApprovedConsumerColumnOverlayManifest.ComposePhysical(right)];
            if (oldTables.Any(table => IsNewTable(left.Database, table.TargetTable)) ||
                !oldTables.Select(x => (x.TargetSchema, x.TargetTable)).SequenceEqual(newTables
                    .Where(x => !IsNewTable(right.Database, x.TargetTable)).Select(x => (x.TargetSchema, x.TargetTable))))
            { throw Invalid(); }
            foreach (TableCopyPlan oldTable in oldTables)
            {
                TableCopyPlan newTable = newTables.Single(x => x.TargetSchema == oldTable.TargetSchema && x.TargetTable == oldTable.TargetTable);
                if (left.Database == "Invoice" && oldTable.TargetTable == "InvoiceCreationAdmission")
                { RequireInvoiceAddition(oldTable, newTable); }
                else if (!Same(oldTable, newTable)) { throw Invalid(); }
            }
            RequireNewTables(right.Database, newTables);
        }
        return new(before, after);
    }

    private static void RequireInvoiceAddition(TableCopyPlan before, TableCopyPlan after)
    {
        if (before.OrderedColumns.Count != 9 || after.OrderedColumns.Count != 13 ||
            !after.OrderedColumns.SequenceEqual(before.OrderedColumns.Concat(AddedNames)) ||
            !after.NullableColumns.SequenceEqual(before.NullableColumns.Concat(AddedNames)) ||
            AddedNames.Any(column => before.ColumnTypes.ContainsKey(column) ||
                after.ColumnTypes.GetValueOrDefault(column) != (column == "OriginIssuer" ? "character varying(512)" : "text") ||
                after.Collations.GetValueOrDefault(column) != "C" || after.DefaultExpressions.ContainsKey(column)))
        { throw Invalid(); }
        TableCopyPlan retained = after with
        {
            OrderedColumns = before.OrderedColumns,
            NullableColumns = before.NullableColumns,
            ColumnTypes = after.ColumnTypes.Where(x => !AddedNames.Contains(x.Key, StringComparer.Ordinal))
                .ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal),
            Collations = after.Collations.Where(x => !AddedNames.Contains(x.Key, StringComparer.Ordinal))
                .ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal),
        };
        if (!Same(before, retained)) { throw Invalid(); }
    }

    private static void RequireNewTables(string database, TableCopyPlan[] tables)
    {
        TableCopyPlan[] additions = [.. tables.Where(x => IsNewTable(database, x.TargetTable))];
        string[] expected = database switch
        {
            "PurchaseOrder" => ["OrderItemCreateReceipt", "PurchaseOrderFileCreateReceipt"],
            "Quotation" => ["QuotationInvoiceCompletionOperation"],
            _ => [],
        };
        if (!additions.Select(x => x.TargetTable).SequenceEqual(expected) ||
            additions.Any(x => x.TargetSchema != "public" || x.OrderedColumns.Count != 11 ||
                x.Identities.Count != 0 || x.IdentityColumns.Count != 0 || x.DefaultExpressions.Count != 0 ||
                x.GeneratedColumns.Count != 0 || x.ForeignKeys.Count != 0))
        { throw Invalid(); }
        foreach (TableCopyPlan table in additions)
        {
            if (database == "PurchaseOrder" && (table.NullableColumns.Count != 0 || table.CheckConstraints.Count != 4 ||
                table.PrimaryKey is not { } receiptKey || !receiptKey.Columns.SequenceEqual(ReceiptKey)))
            { throw Invalid(); }
            if (database == "Quotation" && (table.PrimaryKey is not { } completionKey || !completionKey.Columns.SequenceEqual(CompletionKey) ||
                !table.NullableColumns.SequenceEqual(CompletionNullable) || table.Indexes.Count != 1 ||
                !table.Indexes[0].Unique || !table.Indexes[0].Columns.SequenceEqual(CompletionIndex)))
            { throw Invalid(); }
        }
    }

    private static bool IsNewTable(string database, string table)
    {
        return (database == "PurchaseOrder" && table is "OrderItemCreateReceipt" or "PurchaseOrderFileCreateReceipt") ||
            (database == "Quotation" && table == "QuotationInvoiceCompletionOperation");
    }

    private static void RequireDatabase(string database)
    {
        if (!DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal)) { throw Invalid(); }
    }

    private static bool Same<T>(T left, T right)
    {
        return JsonSerializer.Serialize(left) == JsonSerializer.Serialize(right);
    }

    private static T Clone<T>(T value)
    {
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value)) ?? throw Invalid();
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_app_owned_v3_additive_contract_invalid", "The fixed V2 to V3 additive preparation contract is invalid.");
    }
}
