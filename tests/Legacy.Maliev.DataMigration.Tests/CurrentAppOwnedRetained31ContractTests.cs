namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAppOwnedRetained31ContractTests
{
    private static readonly DateTimeOffset Now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly string Source = new('a', 40);
    private static readonly string[] EightDatabases = ["Customer", "Order", "Upload"];

    [Fact]
    public void Derived_phase_keeps_exact_source_inventory_eight_tables_and_fixed31_contract()
    {
        var (old, current) = Pair();
        CurrentAppOwnedRetained31Contract contract = CurrentAppOwnedRetained31Contract.Create(old, current, Source, Now);
        Assert.Equal(23, current.Databases.Count);
        Assert.Equal(100, current.Databases.Sum(x => x.Tables.Count));
        Assert.Equal(31, contract.Operands().Length);
        Assert.Equal(6, contract.Indexes().Count);
        Assert.Equal(64, contract.ComputeSha256().Length);
        Assert.Equal(contract.ComputeSha256(), CurrentAppOwnedRetained31Contract.Create(old, current, Source, Now).ComputeSha256());
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            DatabaseSchemaPlan before = contract.BeforeForDatabase(database);
            DatabaseSchemaPlan after = contract.AfterForDatabase(database);
            bool retained = CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations)
                .Contains(database, StringComparer.Ordinal);
            Assert.Equal((retained ? old : current).Databases.Single(x => x.Database == database).TargetSchemaSha256, before.TargetSchemaSha256);
            Assert.Equal(current.Databases.Single(x => x.Database == database).TargetSchemaSha256, after.TargetSchemaSha256);
            Assert.Equal(before.SourceSchemaSha256, after.SourceSchemaSha256);
            Assert.Equal(before.Tables.Count, after.Tables.Count);
        }
        Assert.Equal(8, EightDatabases.Sum(database =>
            CurrentAppOwnedRepairManifest.NewTables(database).Count(name =>
                ApprovedConsumerColumnOverlayManifest.ComposePhysical(contract.BeforeForDatabase(database)).Any(x => x.TargetTable == name))));
        Retained31IndexContract invoice = contract.Indexes().Single(x => x.Name == "UQ_InvoiceNotificationCorrelation_InvoicePurpose");
        Assert.Equal([1], invoice.ChangedPositions);
        Assert.Equal("unique-constraint", invoice.Kind);
        Assert.Equal([0, 1], contract.Indexes().Single(x => x.Name == "IX_EmployeeRecoveryEffects_TokenSha256_Purpose").ChangedPositions);
        Assert.Equal("primary-key", contract.Indexes().Single(x => x.Name == "PK_RequestCreateIdempotency").Kind);
    }

    [Theory]
    [InlineData("source")]
    [InlineData("stale")]
    [InlineData("future")]
    [InlineData("mixed")]
    [InlineData("unknown-profile")]
    [InlineData("missing-database")]
    [InlineData("source-projection")]
    [InlineData("missing-outbox-disposition")]
    public void Rejects_unpinned_stale_incomplete_or_arbitrary_profile_inputs(string fault)
    {
        var (old, current) = Pair();
        string expected = fault == "source" ? new('b', 40) : Source;
        if (fault == "stale") { old = old with { CapturedAtUtc = Now.AddHours(-3) }; }
        if (fault == "future") { current = current with { CapturedAtUtc = Now.AddSeconds(1) }; }
        if (fault == "missing-database") { current = current with { Databases = [.. current.Databases.Skip(1)] }; }
        if (fault == "missing-outbox-disposition")
        {
            old = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerColumnsV1);
            current = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
        }
        if (fault is "mixed" or "unknown-profile" or "source-projection" or "missing-outbox-disposition")
        {
            current = current with
            {
                Databases = [.. current.Databases.Select(database => database.Database != "Quotation" ? database : Change(database))],
            };
        }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRetained31Contract.Create(old, current, expected, Now));

        DatabaseSchemaPlan Change(DatabaseSchemaPlan database)
        {
            database = fault switch
            {
                "mixed" => database with { TargetExtensionProfile = ApprovedConsumerColumnOverlayManifest.QuotationV1 },
                "unknown-profile" => database with { TargetExtensionProfile = "quotation-current-consumer-schema-v3" },
                "source-projection" => database with { SourceSchemaSha256 = new('e', 64) },
                _ => database with
                {
                    Tables = [.. database.Tables.Where(x => !x.SourceTable.EndsWith("Outbox", StringComparison.Ordinal))],
                    SourceDispositionProfile = null,
                    SourceTableDispositions = []
                },
            };
            return fault == "unknown-profile" ? database : database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        }
    }

    [Fact]
    public void Observed_table_contract_rejects_extra_indices_columns_types_and_wrong_phase()
    {
        var (old, current) = Pair();
        CurrentAppOwnedRetained31Contract contract = CurrentAppOwnedRetained31Contract.Create(old, current, Source, Now);
        TableCopyPlan table = ApprovedConsumerColumnOverlayManifest.ComposePhysical(contract.AfterForDatabase("Invoice"))
            .Single(x => x.TargetTable == "InvoiceCreationAdmission");
        contract.RequireTableContract("Invoice", table, after: true);
        _ = Assert.Throws<MigrationExecutionException>(() => contract.RequireTableContract("Invoice", table, after: false));
        _ = Assert.Throws<MigrationExecutionException>(() => contract.RequireTableContract("Invoice",
            table with { Indexes = [new("Unreviewed", ["EmployeeSubject"], true)] }, after: true));
        _ = Assert.Throws<MigrationExecutionException>(() => contract.RequireTableContract("Invoice",
            table with { OrderedColumns = [.. table.OrderedColumns, "FinancialOwnershipJson"] }, after: true));
        var types = table.ColumnTypes.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        types["EmployeeSubject"] = "text";
        _ = Assert.Throws<MigrationExecutionException>(() => contract.RequireTableContract("Invoice", table with { ColumnTypes = types }, after: true));
        _ = Assert.Throws<MigrationExecutionException>(() => contract.BeforeForDatabase("Unknown"));
    }

    [Fact]
    public void Returned_operands_and_database_plans_cannot_mutate_retained_internal_contract()
    {
        var (old, current) = Pair();
        CurrentAppOwnedRetained31Contract contract = CurrentAppOwnedRetained31Contract.Create(old, current, Source, Now);
        string digest = contract.ComputeSha256();
        CurrentAppOwnedCollationOperand[] operands = contract.Operands();
        operands[0] = operands[0] with { Column = "Unreviewed" };
        DatabaseSchemaPlan exported = contract.BeforeForDatabase("Invoice");
        ((IDictionary<string, string>)exported.Tables[0].ColumnTypes)["Value"] = "integer";
        Assert.Equal("text", contract.BeforeForDatabase("Invoice").Tables[0].ColumnTypes["Value"]);
        Assert.DoesNotContain(contract.Operands(), x => x.Column == "Unreviewed");
        Assert.Equal(digest, contract.ComputeSha256());
    }

    private static (FreshSchemaPlan Old, FreshSchemaPlan Current) Pair()
    {
        FreshSchemaPlan old = WithOutboxes(CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerColumnsV1));
        FreshSchemaPlan current = WithOutboxes(CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2));
        return (old, current);
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
                SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables)
            };
            return database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        }
    }
}
