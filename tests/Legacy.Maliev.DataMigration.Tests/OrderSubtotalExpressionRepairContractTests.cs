using System.Text.Json;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class OrderSubtotalExpressionRepairContractTests
{
    // Existing reviewed catalog counterpart in PostgreSqlGeneratedExpressionCanonicalizer.Known, not a new equivalence.
    private const string ReviewedCatalogExpression = "(((\"UnitPrice\" * (\"Quantity\")::numeric) - (((\"UnitPrice\" * (\"Quantity\")::numeric) * \"DiscountPercent\") / (100)::numeric)))::numeric(18,2)";

    [Fact]
    public void Approved_catalog_spelling_retains_exact_raw_preimage_and_digest_without_changing_logical_source()
    {
        FreshSchemaPlan logical = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical());
        string before = JsonSerializer.Serialize(logical);
        var observed = OrderSubtotalExpressionRepairContract.Create(logical, logical.SourceCommitSha, ReviewedCatalogExpression, ConsumerColumnBootstrapTestData.Now);
        var sourceSpelling = Create(logical);
        Assert.Equal(ReviewedCatalogExpression, observed.ObservedHistoricalExpression);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ReviewedCatalogExpression))), observed.ObservedHistoricalExpressionSha256);
        Assert.Equal(ReviewedCatalogExpression, observed.BeforePhysical().Tables.Single(x => x.TargetTable == "Order").GeneratedColumns.Single(x => x.Column == "Subtotal").Expression);
        Assert.Equal(sourceSpelling.BeforePhysical().TargetSchemaSha256, observed.BeforePhysical().TargetSchemaSha256);
        Assert.NotEqual(sourceSpelling.ComputeSha256(), observed.ComputeSha256());
        Assert.Equal(before, JsonSerializer.Serialize(logical));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(OrderSubtotalExpressionRepairContract.CorrectedExpression)]
    [InlineData("0::numeric(18,2)")]
    public void Unapproved_observed_expression_is_rejected(string observed)
    {
        FreshSchemaPlan logical = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical());
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalExpressionRepairContract.Create(logical, logical.SourceCommitSha, observed, ConsumerColumnBootstrapTestData.Now));
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalExpressionRepairContract.Create(logical, logical.SourceCommitSha,
            ReviewedCatalogExpression.Replace("UnitPrice", "Total", StringComparison.Ordinal), ConsumerColumnBootstrapTestData.Now));
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalExpressionRepairContract.Create(logical, logical.SourceCommitSha,
            new string(' ', 8193), ConsumerColumnBootstrapTestData.Now));
    }

    [Fact]
    public void Corrected_source_is_immutable_and_historical_expression_exists_only_in_detached_physical_view()
    {
        FreshSchemaPlan logical = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical());
        string bytes = JsonSerializer.Serialize(logical), sha = SchemaPlanCanonicalizer.ComputeSha256(logical);
        var contract = Create(logical);
        Assert.Equal(bytes, JsonSerializer.Serialize(logical));
        Assert.Equal(sha, contract.LogicalSourcePlanSha256);
        Assert.Equal(logical.SourceCommitSha, contract.SourceCommitSha);
        Assert.Equal(logical.CapturedAtUtc, contract.SourceCapturedAtUtc);
        DatabaseSchemaPlan before = contract.BeforePhysical(), after = contract.AfterPhysical();
        Assert.DoesNotContain(before.Tables, x => x.TargetTable == "OrderDeletionIntent");
        Assert.DoesNotContain(after.Tables, x => x.TargetTable == "OrderDeletionIntent");
        Assert.Contains(ApprovedConsumerColumnOverlayManifest.ComposePhysical(logical.Databases.Single(x => x.Database == "Order")), x => x.TargetTable == "OrderDeletionIntent");
        TableCopyPlan oldRoot = before.Tables.Single(x => x.TargetTable == "Order");
        TableCopyPlan newRoot = after.Tables.Single(x => x.TargetTable == "Order");
        Assert.Equal(OrderSubtotalExpressionRepairContract.HistoricalExpression, oldRoot.GeneratedColumns.Single(x => x.Column == "Subtotal").Expression);
        Assert.Equal(OrderSubtotalExpressionRepairContract.CorrectedExpression, newRoot.GeneratedColumns.Single(x => x.Column == "Subtotal").Expression);
        Assert.Equal(JsonSerializer.Serialize(oldRoot with { GeneratedColumns = newRoot.GeneratedColumns }), JsonSerializer.Serialize(newRoot));
        Assert.Equal(before.SourceSchemaSha256, after.SourceSchemaSha256);
        Assert.NotEqual(before.TargetSchemaSha256, after.TargetSchemaSha256);
        Assert.Equal(contract.ComputeSha256(), Create(logical).ComputeSha256());
        ((Dictionary<string, string>)before.Tables.Single(x => x.TargetTable == "Order").ColumnTypes)["Subtotal"] = "text";
        Assert.Equal("numeric(18,2)", contract.BeforePhysical().Tables.Single(x => x.TargetTable == "Order").ColumnTypes["Subtotal"]);
    }

    [Theory]
    [InlineData("old-source")]
    [InlineData("preimage")]
    [InlineData("stale")]
    [InlineData("source-commit")]
    [InlineData("incomplete")]
    public void Unknown_preimage_or_source_cannot_prepare_rewrite(string fault)
    {
        FreshSchemaPlan historical = ConsumerColumnBootstrapTestData.Logical();
        FreshSchemaPlan logical = ConsumerColumnBootstrapTestData.WithCorrectedOrder(historical);
        logical = fault switch
        {
            "old-source" => historical,
            "stale" => logical with { CapturedAtUtc = ConsumerColumnBootstrapTestData.Now.AddHours(-3) },
            "source-commit" => logical with { SourceCommitSha = new string('0', 40) },
            "incomplete" => logical with { Databases = [.. logical.Databases.Skip(1)] },
            _ => logical,
        };
        _ = Assert.Throws<MigrationExecutionException>(() => OrderSubtotalExpressionRepairContract.Create(logical, historical.SourceCommitSha,
            fault == "preimage" ? OrderSubtotalExpressionRepairContract.CorrectedExpression : OrderSubtotalExpressionRepairContract.HistoricalExpression,
            ConsumerColumnBootstrapTestData.Now));
    }

    private static OrderSubtotalExpressionRepairContract Create(FreshSchemaPlan logical)
    {
        return OrderSubtotalExpressionRepairContract.Create(logical, logical.SourceCommitSha,
            OrderSubtotalExpressionRepairContract.HistoricalExpression, ConsumerColumnBootstrapTestData.Now);
    }
}
