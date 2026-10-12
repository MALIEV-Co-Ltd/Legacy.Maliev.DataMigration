namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAppOwnedV3AdditiveContractTests
{
    private static readonly DateTimeOffset Now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly string Source = new('a', 40);
    private static readonly string[] Added = ["OriginIssuer", "FinancialResultJson", "FinancialOwnershipJson", "EmployeeCompletionJson"];

    [Fact]
    public void Derives_only_four_nullable_columns_three_new_tables_and_complete_physical_inventory()
    {
        var (before, after) = Pair();
        CurrentAppOwnedV3AdditiveContract contract = CurrentAppOwnedV3AdditiveContract.Create(before, after, Source, Now);
        Assert.Equal(23, after.Databases.Count);
        Assert.Equal(100, after.Databases.Sum(x => x.Tables.Count));
        Assert.Equal(Added, contract.AddedColumns().Select(x => x.Column));
        Assert.Equal([10, 11, 12, 13], contract.AddedColumns().Select(x => x.PhysicalOrdinal));
        Assert.All(contract.AddedColumns(), column =>
        {
            Assert.True(column.Nullable);
            Assert.Equal("C", column.Collation);
            Assert.Equal("InvoiceCreationAdmission", column.Table);
        });
        Assert.Equal(3, contract.CreateTables().Count);
        Assert.Equal(64, contract.ComputeSha256().Length);
        Assert.Equal(contract.ComputeSha256(), CurrentAppOwnedV3AdditiveContract.Create(before, after, Source, Now).ComputeSha256());
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            Assert.Equal(before.Databases.Single(x => x.Database == database).TargetSchemaSha256,
                contract.BeforeForDatabase(database).TargetSchemaSha256);
            Assert.Equal(after.Databases.Single(x => x.Database == database).TargetSchemaSha256,
                contract.AfterForDatabase(database).TargetSchemaSha256);
        }
        TableCopyPlan oldNotification = ApprovedConsumerColumnOverlayManifest.ComposePhysical(contract.BeforeForDatabase("Invoice"))
            .Single(x => x.TargetTable == "InvoiceNotificationCorrelation");
        contract.RequireTableContract("Invoice", oldNotification, after: true);
    }

    [Theory]
    [InlineData("source")]
    [InlineData("stale")]
    [InlineData("future")]
    [InlineData("missing-database")]
    [InlineData("wrong-before-profile")]
    [InlineData("mixed-after")]
    [InlineData("source-projection")]
    [InlineData("missing-disposition")]
    public void Rejects_unpinned_stale_incomplete_mixed_or_changed_source_contracts(string fault)
    {
        var (before, after) = Pair();
        string expected = fault == "source" ? new('b', 40) : Source;
        if (fault == "stale") { before = before with { CapturedAtUtc = Now.AddHours(-3) }; }
        if (fault == "future") { after = after with { CapturedAtUtc = Now.AddSeconds(1) }; }
        if (fault == "missing-database") { after = after with { Databases = [.. after.Databases.Skip(1)] }; }
        if (fault == "wrong-before-profile") { before = after; }
        if (fault == "missing-disposition")
        {
            before = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
            after = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        }
        if (fault is "mixed-after" or "source-projection")
        {
            after = after with
            {
                Databases = [.. after.Databases.Select(database => database.Database != "Invoice" ? database :
                fault == "mixed-after" ? Reprofile(database, ConsumerOverlaySelection.CurrentConsumerSchemaV2) :
                database with { SourceSchemaSha256 = new('e', 64) })]
            };
        }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedV3AdditiveContract.Create(before, after, expected, Now));
    }

    [Fact]
    public void Observed_table_contract_rejects_wrong_phase_defaults_reordered_columns_and_extra_indices()
    {
        var (before, after) = Pair();
        CurrentAppOwnedV3AdditiveContract contract = CurrentAppOwnedV3AdditiveContract.Create(before, after, Source, Now);
        TableCopyPlan invoice = ApprovedConsumerColumnOverlayManifest.ComposePhysical(contract.AfterForDatabase("Invoice"))
            .Single(x => x.TargetTable == "InvoiceCreationAdmission");
        contract.RequireTableContract("Invoice", invoice, after: true);
        _ = Assert.Throws<MigrationExecutionException>(() => contract.RequireTableContract("Invoice", invoice, after: false));
        _ = Assert.Throws<MigrationExecutionException>(() => contract.RequireTableContract("Invoice", invoice with
        { DefaultExpressions = new Dictionary<string, string>(StringComparer.Ordinal) { ["FinancialResultJson"] = "'{}'::text" } }, after: true));
        _ = Assert.Throws<MigrationExecutionException>(() => contract.RequireTableContract("Invoice", invoice with
        { OrderedColumns = [.. invoice.OrderedColumns.Take(9), .. Added.Reverse()] }, after: true));
        V3CreateTableContract receipt = contract.CreateTables().First(x => x.Database == "PurchaseOrder");
        _ = Assert.Throws<MigrationExecutionException>(() => contract.RequireTableContract(receipt.Database, receipt.Table with
        { Indexes = [new("Unreviewed", ["EntityId"], true)] }, after: true));
        _ = Assert.Throws<MigrationExecutionException>(() => contract.RequireTableContract(receipt.Database, receipt.Table, after: false));
        _ = Assert.Throws<MigrationExecutionException>(() => contract.BeforeForDatabase("Auth"));
    }

    [Fact]
    public void Input_and_exported_mutations_cannot_change_retained_contract_or_digest()
    {
        var (before, after) = Pair();
        CurrentAppOwnedV3AdditiveContract contract = CurrentAppOwnedV3AdditiveContract.Create(before, after, Source, Now);
        string digest = contract.ComputeSha256();
        ((IDictionary<string, string>)before.Databases[0].Tables[0].ColumnTypes)["Value"] = "integer";
        ((IDictionary<string, string>)contract.CreateTables()[0].Table.ColumnTypes)["Operation"] = "integer";
        DatabaseSchemaPlan exported = contract.AfterForDatabase("Invoice");
        ((IDictionary<string, string>)exported.Tables[0].ColumnTypes)["Value"] = "integer";
        Assert.Equal("text", contract.AfterForDatabase("Invoice").Tables[0].ColumnTypes["Value"]);
        Assert.Equal("smallint", contract.CreateTables().First(x => x.Database == "PurchaseOrder").Table.ColumnTypes["Operation"]);
        Assert.Equal(digest, contract.ComputeSha256());
    }

    private static (FreshSchemaPlan Before, FreshSchemaPlan After) Pair()
    {
        FreshSchemaPlan before = WithOutboxes(CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2));
        FreshSchemaPlan after = before with { Databases = [.. before.Databases.Select(x => Reprofile(x, ConsumerOverlaySelection.CurrentConsumerSchemaV3))] };
        return (before, after);
    }

    private static DatabaseSchemaPlan Reprofile(DatabaseSchemaPlan plan, ConsumerOverlaySelection selection)
    {
        plan = plan with { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(plan.Database, selection) };
        return plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
    }

    private static FreshSchemaPlan WithOutboxes(FreshSchemaPlan schema)
    {
        return schema with { Databases = [.. schema.Databases.Select(database => database.Database == "Quotation" ? Map(database) : database)] };
        static DatabaseSchemaPlan Map(DatabaseSchemaPlan database)
        {
            TableCopyPlan[] tables = [database.Tables[0],
                ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                    "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
                ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                    "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
                .. database.Tables.Skip(3)];
            database = database with
            {
                Tables = tables,
                SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
                SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables),
            };
            return database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        }
    }
}
