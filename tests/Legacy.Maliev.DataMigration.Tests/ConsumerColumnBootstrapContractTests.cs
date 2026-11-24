using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsumerColumnBootstrapContractTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Fixed_bootstrap_preserves_complete_logical_source_including_either_Order_translation(bool correctedOrder)
    {
        FreshSchemaPlan logical = ConsumerColumnBootstrapTestData.Logical();
        if (correctedOrder)
        {
            string oldExpression = logical.Databases.Single(x => x.Database == "Order").Tables.Single(x => x.SourceTable == "Order")
                .GeneratedColumns.Single(x => x.Column == "Subtotal").Expression;
            logical = ConsumerColumnBootstrapTestData.WithCorrectedOrder(logical);
            Assert.NotEqual(oldExpression, logical.Databases.Single(x => x.Database == "Order").Tables.Single(x => x.SourceTable == "Order")
                .GeneratedColumns.Single(x => x.Column == "Subtotal").Expression);
        }
        string original = JsonSerializer.Serialize(logical);
        string hash = SchemaPlanCanonicalizer.ComputeSha256(logical);
        ConsumerColumnBootstrapContract contract = Create(logical);
        Assert.Equal(original, JsonSerializer.Serialize(logical));
        Assert.Equal(hash, contract.LogicalSourcePlanSha256);
        Assert.Equal(logical.CapturedAtUtc, contract.SourceCapturedAtUtc);
        Assert.Equal(logical.SourceCommitSha, contract.SourceCommitSha);
        Assert.Equal(100, logical.Databases.Sum(x => x.Tables.Count));
        Assert.Equal(2, ConsumerColumnBootstrapContract.Operands().Count);
        foreach (ConsumerColumnBootstrapOperand operand in ConsumerColumnBootstrapContract.Operands())
        {
            DatabaseSchemaPlan before = contract.Before(operand.Database), after = contract.After(operand.Database);
            TableCopyPlan oldTable = before.Tables.Single(x => x.TargetSchema == operand.Schema && x.TargetTable == operand.Table);
            TableCopyPlan newTable = after.Tables.Single(x => x.TargetSchema == operand.Schema && x.TargetTable == operand.Table);
            Assert.Equal(operand.AppendOrdinal - 1, oldTable.OrderedColumns.Count);
            Assert.Equal(operand.AppendOrdinal, newTable.OrderedColumns.Count);
            Assert.Equal(operand.Column, newTable.OrderedColumns[^1]);
            Assert.Equal(operand.PostgreSqlType, newTable.ColumnTypes[operand.Column]);
            Assert.Equal(operand.Nullable, newTable.NullableColumns.Contains(operand.Column, StringComparer.Ordinal));
            Assert.Equal(operand.DefaultExpression, newTable.DefaultExpressions.GetValueOrDefault(operand.Column));
            Assert.False(newTable.Collations.ContainsKey(operand.Column));
            Assert.Equal(JsonSerializer.Serialize(oldTable.SourceColumns), JsonSerializer.Serialize(newTable.SourceColumns));
            Assert.Equal(JsonSerializer.Serialize(oldTable.SourceColumnTypes), JsonSerializer.Serialize(newTable.SourceColumnTypes));
            Assert.Equal(before.SourceSchemaSha256, after.SourceSchemaSha256);
            Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(before), before.TargetSchemaSha256);
            Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(after), after.TargetSchemaSha256);
            Assert.NotEqual(before.TargetSchemaSha256, after.TargetSchemaSha256);
        }
        Assert.Equal(contract.ComputeSha256(), Create(logical).ComputeSha256());
    }

    [Fact]
    public void Physical_getters_are_detached_and_do_not_modify_the_immutable_contract_or_source()
    {
        FreshSchemaPlan logical = ConsumerColumnBootstrapTestData.Logical();
        string before = JsonSerializer.Serialize(logical);
        ConsumerColumnBootstrapContract contract = Create(logical);
        DatabaseSchemaPlan returned = contract.After("CustomerIdentity");
        ((Dictionary<string, string>)returned.Tables.Single(x => x.TargetTable == "AspNetUsers").ColumnTypes)["PasswordSetupRequired"] = "text";
        Assert.Equal("boolean", contract.After("CustomerIdentity").Tables.Single(x => x.TargetTable == "AspNetUsers").ColumnTypes["PasswordSetupRequired"]);
        Assert.Equal(before, JsonSerializer.Serialize(logical));
        _ = Assert.Throws<MigrationExecutionException>(() => contract.Before("Auth"));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapContract.CandidateSql("Order"));
    }

    [Theory]
    [InlineData("source-commit")]
    [InlineData("stale")]
    [InlineData("missing-database")]
    [InlineData("source-hash")]
    [InlineData("target-version")]
    public void Unreviewed_source_inventory_or_freshness_cannot_create_preparation(string fault)
    {
        FreshSchemaPlan logical = ConsumerColumnBootstrapTestData.Logical();
        DatabaseSchemaPlan first = logical.Databases[0];
        logical = fault switch
        {
            "source-commit" => logical with { SourceCommitSha = new string('0', 40) },
            "stale" => logical with { CapturedAtUtc = ConsumerColumnBootstrapTestData.Now.AddHours(-3) },
            "missing-database" => logical with { Databases = [.. logical.Databases.Skip(1)] },
            "source-hash" => logical with { Databases = [first with { SourceSchemaSha256 = "invalid" }, .. logical.Databases.Skip(1)] },
            "target-version" => logical with { Databases = [first with { TargetSchemaVersion = "2.0" }, .. logical.Databases.Skip(1)] },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapContract.Create(logical,
            ConsumerColumnBootstrapTestData.Logical().SourceCommitSha, ConsumerColumnBootstrapTestData.Now));
    }

    private static ConsumerColumnBootstrapContract Create(FreshSchemaPlan logical)
    {
        return ConsumerColumnBootstrapContract.Create(logical, logical.SourceCommitSha, ConsumerColumnBootstrapTestData.Now);
    }
}
