using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ProductionGeneratedExpressionEquivalenceTests
{
    public static TheoryData<string, string> ReviewedExpressions => new()
    {
        {
            "(((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2))::numeric(18,2)",
            "((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(18,2)"
        },
        {
            "(((\"Total\" - \"WithholdingTax\"))::numeric(19,2))::numeric(18,2)",
            "((\"Total\" - \"WithholdingTax\"))::numeric(18,2)"
        },
        {
            "(((((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2) - ((((((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2) * \"DiscountPercent\"))::numeric(35,4) / (100)::numeric))::numeric(38,7)))::numeric(38,6))::numeric(18,2)",
            "(((\"UnitPrice\" * (\"Quantity\")::numeric) - (((\"UnitPrice\" * (\"Quantity\")::numeric) * \"DiscountPercent\") / (100)::numeric)))::numeric(18,2)"
        },
    };

    [Theory]
    [MemberData(nameof(ReviewedExpressions))]
    public void ExactReviewedPair_MatchesWholeSchemaAndColumnDiagnostics(string expected, string observed)
    {
        var table = new TableCopyPlan("dbo", "Sample", "public", "Sample", ["Value"], ["Value"])
        {
            ColumnTypes = new Dictionary<string, string> { ["Value"] = "numeric(18,2)" },
            GeneratedColumns = [new GeneratedColumnCopyPlan("Value", expected)],
        };
        PostgreSqlSchemaFingerprint.ColumnShape planned =
            PostgreSqlSchemaFingerprint.ExpectedColumn(table, "Value", 1);
        PostgreSqlSchemaFingerprint.ColumnShape actual = planned with { GeneratedExpression = observed };
        var name = new PostgreSqlSchemaFingerprint.TableShape("public", "Sample");
        string plannedHash = PostgreSqlSchemaFingerprint.Compute([name], [planned], [], [], []);
        string actualHash = PostgreSqlSchemaFingerprint.Compute([name], [actual], [], [], []);
        Assert.Equal(plannedHash, actualHash);

        var observation = new ProductionSchemaObservation("Test",
            [new ObservedTargetTable("public", "Sample", ["Value"])], actualHash);
        ProductionSchemaColumnDiagnostic diagnostic = Assert.Single(
            ProductionSchemaColumnDiagnostics.Compare([table], observation, [actual], []));
        Assert.Equal("match", diagnostic.Status);
        Assert.Equal("match", diagnostic.GeneratedState);

        string changed = observed.Replace("\"UnitPrice\"", "\"ChangedPrice\"", StringComparison.Ordinal)
            .Replace("\"Total\"", "\"ChangedTotal\"", StringComparison.Ordinal);
        PostgreSqlSchemaFingerprint.ColumnShape invalid = actual with { GeneratedExpression = changed };
        Assert.NotEqual(plannedHash, PostgreSqlSchemaFingerprint.Compute([name], [invalid], [], [], []));
        ProductionSchemaColumnDiagnostic changedDiagnostic = Assert.Single(
            ProductionSchemaColumnDiagnostics.Compare([table], observation, [invalid], []));
        Assert.Equal("present-different", changedDiagnostic.GeneratedState);
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ProductionGeneratedExpressionPostgresTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [MemberData(nameof(ProductionGeneratedExpressionEquivalenceTests.ReviewedExpressions),
        MemberType = typeof(ProductionGeneratedExpressionEquivalenceTests))]
    public async Task ReviewedPair_HasSameValuesAndOverflowOnDisposablePostgreSql18(
        string expected, string observed)
    {
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        (decimal UnitPrice, int Quantity, decimal Discount, decimal Total, decimal Tax)[] cases =
        [
            (0.15m, 1, 10.00m, 100.00m, 7.00m),
            (-0.15m, 1, 10.00m, -100.00m, 7.00m),
            (9999999999999999.99m, 1, 100.00m, 9999999999999999.99m, 0.00m),
            (9999999999999999.99m, 1, 0.00m, -9999999999999999.99m, 0.00m),
            (0.01m, int.MaxValue, 99.99m, 0.01m, 0.01m),
            (0.01m, int.MinValue, 0.01m, 0.01m, 0.01m),
        ];
        foreach (var sample in cases)
        {
            Assert.Equal(await EvaluateAsync(connection, expected, sample),
                await EvaluateAsync(connection, observed, sample));
        }

        var overflow = (9999999999999999.99m, 2, 0.00m,
            9999999999999999.99m, -9999999999999999.99m);
        PostgresException expectedOverflow = await Assert.ThrowsAsync<PostgresException>(() =>
            EvaluateAsync(connection, expected, overflow));
        PostgresException actualOverflow = await Assert.ThrowsAsync<PostgresException>(() =>
            EvaluateAsync(connection, observed, overflow));
        Assert.Equal("22003", expectedOverflow.SqlState);
        Assert.Equal(expectedOverflow.SqlState, actualOverflow.SqlState);
    }

    private static async Task<string> EvaluateAsync(NpgsqlConnection connection, string expression,
        (decimal UnitPrice, int Quantity, decimal Discount, decimal Total, decimal Tax) sample)
    {
        string sql = $$"""
            WITH input("UnitPrice", "Quantity", "DiscountPercent", "Total", "WithholdingTax") AS
            (SELECT @unitPrice::numeric(18,2), @quantity::integer, @discount::numeric(5,2),
                    @total::numeric(18,2), @tax::numeric(18,2))
            SELECT ({{expression}})::text FROM input
            """;
        await using var command = new NpgsqlCommand(sql, connection);
        _ = command.Parameters.AddWithValue("unitPrice", sample.UnitPrice);
        _ = command.Parameters.AddWithValue("quantity", sample.Quantity);
        _ = command.Parameters.AddWithValue("discount", sample.Discount);
        _ = command.Parameters.AddWithValue("total", sample.Total);
        _ = command.Parameters.AddWithValue("tax", sample.Tax);
        return (string)(await command.ExecuteScalarAsync())!;
    }
}
