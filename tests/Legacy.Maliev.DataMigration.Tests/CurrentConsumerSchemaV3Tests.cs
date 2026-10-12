using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentConsumerSchemaV3Tests
{
    [Fact]
    public void Coherent_opt_in_profile_keeps_all_source_projections_and_historical_profiles()
    {
        FreshSchemaPlan before = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2);
        FreshSchemaPlan after = before with
        {
            Databases = [.. before.Databases.Select(plan => Reprofile(plan, ConsumerOverlaySelection.CurrentConsumerSchemaV3))],
        };
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(after));
        Assert.True(ApprovedConsumerOverlaySelection.IsCurrent(after));
        Assert.Equal(100, after.Databases.Sum(database => database.Tables.Count));
        string[] changed = ["Invoice", "PurchaseOrder", "Quotation"];
        foreach ((DatabaseSchemaPlan oldPlan, DatabaseSchemaPlan newPlan) in before.Databases.Zip(after.Databases))
        {
            Assert.Equal(oldPlan.SourceSchemaSha256, newPlan.SourceSchemaSha256);
            Assert.Equal(oldPlan.SourceDispositionProfile, newPlan.SourceDispositionProfile);
            Assert.Same(oldPlan.Tables, newPlan.Tables);
            Assert.Equal(changed.Contains(newPlan.Database), oldPlan.TargetSchemaSha256 != newPlan.TargetSchemaSha256);
        }
        foreach (string database in changed)
        {
            DatabaseSchemaPlan oldPlan = before.Databases.Single(plan => plan.Database == database);
            FreshSchemaPlan mixed = after with
            { Databases = [.. after.Databases.Select(plan => plan.Database == database ? oldPlan : plan)] };
            Assert.False(ApprovedConsumerOverlaySelection.IsApproved(mixed));
        }
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(before));
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.HistoricalDefaults)));
    }

    [Fact]
    public void Target_only_contracts_retain_receipt_binding_and_nullable_ownership_without_backfill()
    {
        FreshSchemaPlan schema = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        TableCopyPlan[] receipts = [.. ApprovedTargetExtensionManifest.TablesFor(schema.Databases.Single(plan => plan.Database == "PurchaseOrder"))];
        Assert.Equal(2, receipts.Length);
        foreach (TableCopyPlan receipt in receipts)
        {
            Assert.Equal(11, receipt.OrderedColumns.Count);
            Assert.Equal(["IssuerDigest", "SubjectDigest", "Operation", "KeyDigest"], receipt.PrimaryKey!.Columns);
            Assert.Equal(4, receipt.CheckConstraints.Count);
            Assert.Empty(receipt.NullableColumns);
            Assert.Empty(receipt.Identities);
            Assert.Empty(receipt.DefaultExpressions);
            Assert.Empty(receipt.ForeignKeys);
            Assert.All(receipt.CheckConstraints.Single(check => check.Name.EndsWith("_Digests", StringComparison.Ordinal)).Columns,
                column => Assert.Equal("bytea", receipt.ColumnTypes[column]));
            Assert.Contains(receipt.TargetTable == "OrderItemCreateReceipt" ? "= 3" : "= 4",
                receipt.CheckConstraints.Single(check => check.Name.EndsWith("_Operation", StringComparison.Ordinal)).Expression);
        }
        TableCopyPlan invoice = ApprovedTargetExtensionManifest.TablesFor(schema.Databases.Single(plan => plan.Database == "Invoice"))
            .Single(table => table.TargetTable == "InvoiceCreationAdmission");
        foreach (string column in new[] { "FinancialOwnershipJson", "EmployeeCompletionJson" })
        {
            Assert.Equal("text", invoice.ColumnTypes[column]);
            Assert.Contains(column, invoice.NullableColumns);
            Assert.Equal("C", invoice.Collations[column]);
            Assert.False(invoice.DefaultExpressions.ContainsKey(column));
        }
        DatabaseSchemaPlan quotation = schema.Databases.Single(plan => plan.Database == "Quotation");
        TableCopyPlan completion = Assert.Single(ApprovedTargetExtensionManifest.TablesFor(quotation));
        Assert.Equal(11, completion.OrderedColumns.Count);
        Assert.Equal(["ClaimId", "ClaimUntil"], completion.NullableColumns);
        Assert.Equal("character varying(32)", completion.ColumnTypes["State"]);
        Assert.Equal("text", completion.ColumnTypes["DecisionOrderVersion"]);
        Assert.Equal("timestamp without time zone", completion.ColumnTypes["ClaimUntil"]);
        Assert.True(Assert.Single(completion.Indexes).Unique);
        Assert.Equal("DecisionOrderVersion", ApprovedConsumerColumnOverlayManifest.For(quotation)!.Column);
        Assert.Empty(completion.DefaultExpressions);
        Assert.All(completion.Collations.Values, collation => Assert.Equal("C", collation));
    }

    [Theory]
    [InlineData("OrderItemCreateReceipt")]
    [InlineData("PurchaseOrderFileCreateReceipt")]
    public void Receipt_check_compatibility_accepts_only_exact_native_forms(string table)
    {
        var source = new PostgreSqlSchemaFingerprint.ConstraintShape("public", table, "CK_" + table + "_Versions", 'c',
            ["CanonicalVersion", "ResponseVersion"], "\"CanonicalVersion\" = 1 AND \"ResponseVersion\" = 1");
        var native = source with { Expression = "((\"CanonicalVersion\" = 1) AND (\"ResponseVersion\" = 1))" };
        string expected = ConsumerCheckPredicateCompatibility.Canonicalize(source);
        Assert.Equal(expected, ConsumerCheckPredicateCompatibility.Canonicalize(native));
        Assert.NotEqual(expected, ConsumerCheckPredicateCompatibility.Canonicalize(native with
        { Expression = "((\"CanonicalVersion\" = 1) AND (\"ResponseVersion\" = 2))" }));
        Assert.NotEqual(expected, ConsumerCheckPredicateCompatibility.Canonicalize(native with { Columns = ["ResponseVersion", "CanonicalVersion"] }));
        Assert.NotEqual(expected, ConsumerCheckPredicateCompatibility.Canonicalize(native with { Name = "Unreviewed" }));
    }

    [Theory]
    [InlineData("Invoice")]
    [InlineData("PurchaseOrder")]
    [InlineData("Quotation")]
    public void Reconciliation_requires_complete_new_extension_evidence(string database)
    {
        DatabaseSchemaPlan schema = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3)
            .Databases.Single(plan => plan.Database == database);
        var state = new ApprovedTargetExtensionState(
            [.. ApprovedTargetExtensionManifest.TablesFor(schema).Select(table => new TableReconciliationEvidence(
                $"{table.TargetSchema}.{table.TargetTable}", 0, new string('a', 64), new string('b', 64),
                table.OrderedColumns.ToDictionary(column => column, _ => 0L, StringComparer.Ordinal),
                new Dictionary<string, long>(StringComparer.Ordinal)))], new Dictionary<string, long>(StringComparer.Ordinal));
        if (ApprovedConsumerColumnOverlayManifest.For(schema) is { } overlay)
        {
            var evidence = new TableReconciliationEvidence($"{overlay.Root.TargetSchema}.{overlay.Root.TargetTable}", 0,
                new string('c', 64), new string('d', 64),
                new Dictionary<string, long>(StringComparer.Ordinal) { [overlay.Root.PrimaryKey!.Columns[0]] = 0, [overlay.Column] = 0 },
                new Dictionary<string, long>(StringComparer.Ordinal));
            state = state with { Overlay = new(evidence, evidence, 0) };
        }
        Assert.Equal(64, ApprovedTargetExtensionStateInspector.ComputeSha256(schema, state).Length);
        TableReconciliationEvidence first = state.Tables[0];
        var incomplete = first.NullCounts.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        _ = incomplete.Remove(incomplete.Keys.Last());
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedTargetExtensionStateInspector.ComputeSha256(schema,
            state with { Tables = [first with { NullCounts = incomplete }, .. state.Tables.Skip(1)] }));
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedTargetExtensionStateInspector.ComputeSha256(schema,
            state with { Tables = [.. state.Tables.Skip(1)] }));
    }

    [Theory]
    [InlineData("Invoice")]
    [InlineData("PurchaseOrder")]
    [InlineData("Quotation")]
    public async Task Native_opt_in_physical_schema_matches_the_complete_profile(string database)
    {
        await using var postgres = new PostgreSqlBuilder(
            "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382")
            .WithDatabase(database).WithUsername("postgres").WithPassword(Guid.NewGuid().ToString("N"))
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384 * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500_000_000;
            }).Build();
        await postgres.StartAsync();
        await using var connection = new NpgsqlConnection(postgres.GetConnectionString());
        await connection.OpenAsync();
        DatabaseSchemaPlan schema = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3)
            .Databases.Single(plan => plan.Database == database);
        await using var transaction = await connection.BeginTransactionAsync();
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        await inspector.ApplySchemaAsync(schema, CancellationToken.None);
        await inspector.FinalizeSchemaAsync(schema, CancellationToken.None);
        Assert.Equal(schema.TargetSchemaSha256, await inspector.InspectSchemaAsync(schema, CancellationToken.None));
        await transaction.RollbackAsync();
    }

    private static DatabaseSchemaPlan Reprofile(DatabaseSchemaPlan plan, ConsumerOverlaySelection selection)
    {
        plan = plan with { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(plan.Database, selection) };
        return plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
    }
}
