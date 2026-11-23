using System.Globalization;
using Npgsql;
using NpgsqlTypes;

namespace Legacy.Maliev.DataMigration.Tests;

// Real translator output on the existing disposable PG fixture; no SQL Server connection or persistent target.
[Collection(SqlServerPostgreSqlAdapterTestGroup.Name)]
public sealed class SqlServerDecimalDivisionPostgresTests(PostgreSqlAdapterFixture fixture)
{
    private const string SourceExpression = "(CONVERT([decimal](18,2),[UnitPrice]*[Quantity]-(([UnitPrice]*[Quantity])*[DiscountPercent])/(100)))";
    // Exact pre-patch translator literal pinned by SqlServerMigrationSourceContractTests at fc1.
    private const string PrePatchTranslatedExpression = "(((((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2) - ((((((\"UnitPrice\" * (\"Quantity\")::numeric))::numeric(29,2) * \"DiscountPercent\"))::numeric(35,4) / (100)::numeric))::numeric(38,7)))::numeric(38,6))::numeric(18,2)";
    private const string LegacyExpression = "(((\"UnitPrice\" * (\"Quantity\")::numeric) - (((\"UnitPrice\" * (\"Quantity\")::numeric) * \"DiscountPercent\") / (100)::numeric)))::numeric(18,2)";

    [Fact]
    public async Task RealTranslator_generated_column_survives_shadow_seed_catalog_fingerprint_and_named_inserts()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase? oldShadow = null, correctedShadow = null;
        string run = Guid.NewGuid().ToString("D");
        DatabaseSchemaPlan before = GeneratedPlan(PrePatchTranslatedExpression);
        DatabaseSchemaPlan after = GeneratedPlan(Translate("numeric(18,2)", "numeric(5,2)"));
        Assert.NotEqual(before.TargetSchemaSha256, after.TargetSchemaSha256);
        try
        {
            oldShadow = await target.CreateUniqueEmptyShadowAsync("Order", $"legacy_shadow_decimal_old_{Guid.NewGuid():N}", run, deadline.Token);
            string oldFingerprint = await SeedAndInspectShadowAsync(oldShadow, before, deadline.Token);
            correctedShadow = await target.CreateUniqueEmptyShadowAsync("Order", $"legacy_shadow_decimal_new_{Guid.NewGuid():N}", run, deadline.Token);
            string newFingerprint = await SeedAndInspectShadowAsync(correctedShadow, after, deadline.Token);
            Assert.NotEqual(oldFingerprint, newFingerprint);

            string settings = new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = correctedShadow.Name }.ConnectionString;
            await using var connection = new NpgsqlConnection(settings);
            await connection.OpenAsync(deadline.Token);
            await using var transaction = await connection.BeginTransactionAsync(deadline.Token);
            await using (var insert = new NpgsqlCommand("""
                INSERT INTO public."Order" ("ID","UnitPrice","Quantity","DiscountPercent") VALUES
                  (1,@price,2,99.99), (2,-@price,2,99.99), (3,NULL,2,99.99), (4,@price,2,NULL);
                """, connection, transaction) { CommandTimeout = 30 })
            {
                _ = insert.Parameters.AddWithValue("price", NpgsqlDbType.Numeric, 9999999999990024.76m);
                Assert.Equal(4, await insert.ExecuteNonQueryAsync(deadline.Token));
            }
            await using (var readback = new NpgsqlCommand("""SELECT "ID","Subtotal"::text FROM public."Order" ORDER BY "ID";""",
                connection, transaction)
            { CommandTimeout = 30 })
            await using (NpgsqlDataReader reader = await readback.ExecuteReaderAsync(deadline.Token))
            {
                foreach ((int id, string? expected) in new (int, string?)[]
                    { (1, "1999999999998.00"), (2, "-1999999999998.00"), (3, null), (4, null) })
                {
                    Assert.True(await reader.ReadAsync(deadline.Token));
                    Assert.Equal(id, reader.GetInt32(0));
                    if (expected is null) { Assert.True(reader.IsDBNull(1)); }
                    else { Assert.Equal(expected, reader.GetString(1)); }
                }
                Assert.False(await reader.ReadAsync(deadline.Token));
            }
            await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
            string retainedFingerprint = await inspection.InspectSchemaAsync(after, deadline.Token);
            Assert.Equal(after.TargetSchemaSha256, retainedFingerprint);
            Assert.NotEqual(oldFingerprint, retainedFingerprint);
            await transaction.RollbackAsync(deadline.Token);
        }
        finally
        {
            try
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                if (correctedShadow is not null) { await target.DeleteRunOwnedShadowAsync(correctedShadow, cleanup.Token); }
            }
            finally
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                if (oldShadow is not null) { await target.DeleteRunOwnedShadowAsync(oldShadow, cleanup.Token); }
            }
        }
    }

    [Theory]
    [InlineData("9999999999990024.76", 2, "99.99", "1999999999998.00", "1999999999998.01")]
    [InlineData("-9999999999990024.76", 2, "99.99", "-1999999999998.00", "-1999999999998.01")]
    public async Task RealTranslator_preserves_source_rounding_when_large_gross_nearly_cancels(
        string price, int quantity, string discount, string expectedSource, string expectedLegacy)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync(deadline.Token);
        string corrected = Translate("numeric(18,2)", "numeric(5,2)");
        string? actual = await EvaluateAsync(connection, corrected, price, quantity, discount,
            "numeric(18,2)", "numeric(5,2)", deadline.Token);
        string? legacy = await EvaluateAsync(connection, LegacyExpression, price, quantity, discount,
            "numeric(18,2)", "numeric(5,2)", deadline.Token);
        string? prePatch = await EvaluateAsync(connection, PrePatchTranslatedExpression, price, quantity, discount,
            "numeric(18,2)", "numeric(5,2)", deadline.Token);
        Assert.Equal(expectedSource, actual);
        Assert.Equal(expectedLegacy, legacy);
        Assert.Equal(expectedLegacy, prePatch);
        Assert.NotEqual(prePatch, actual);
        Assert.NotEqual(legacy, actual);
        Assert.NotEqual(PostgreSqlGeneratedExpressionCanonicalizer.Canonicalize(LegacyExpression),
            PostgreSqlGeneratedExpressionCanonicalizer.Canonicalize(corrected));
    }

    [Theory]
    [InlineData("0.15", 1, "10.00", "numeric(18,2)", "numeric(5,2)", "0.14")]
    [InlineData("-0.15", 1, "10.00", "numeric(18,2)", "numeric(5,2)", "-0.14")]
    [InlineData("0.15", -1, "10.00", "numeric(18,2)", "numeric(5,2)", "-0.14")]
    [InlineData("0.15", 1, "-10.00", "numeric(18,2)", "numeric(5,2)", "0.17")]
    [InlineData("0.00", 2, "99.99", "numeric(18,2)", "numeric(5,2)", "0.00")]
    [InlineData("9999999999999999.99", 0, "99.99", "numeric(18,2)", "numeric(5,2)", "0.00")]
    [InlineData("9999999999999999.99", -2147483648, "100.00", "numeric(18,2)", "numeric(5,2)", "0.00")]
    [InlineData(null, 2, "99.99", "numeric(18,2)", "numeric(5,2)", null)]
    [InlineData("1.00", null, "99.99", "numeric(18,2)", "numeric(5,2)", null)]
    [InlineData("1.00", 2, null, "numeric(18,2)", "numeric(5,2)", null)]
    [InlineData("3", 2, "50", "numeric(2,0)", "numeric(2,0)", "3.00")]
    [InlineData("0.0050", 1, "50.00", "numeric(5,4)", "numeric(5,2)", "0.00")]
    [InlineData("1.2345", 3, "12.345", "numeric(8,4)", "numeric(5,3)", "3.25")]
    [InlineData("1.23456789", 3, "12.34", "numeric(18,8)", "numeric(5,2)", "3.25")]
    public async Task RealTranslator_retains_ties_nulls_zero_and_supported_input_scales(string? price, int? quantity,
        string? discount, string priceType, string discountType, string? expected)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync(deadline.Token);
        Assert.Equal(expected, await EvaluateAsync(connection, Translate(priceType, discountType), price, quantity,
            discount, priceType, discountType, deadline.Token));
    }

    [Theory]
    [InlineData("9999999999999999.99", 2)]
    [InlineData("-9999999999999999.99", 2)]
    public async Task RealTranslator_keeps_final_source_precision_overflow(string price, int quantity)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var connection = new NpgsqlConnection(fixture.ConnectionString);
        await connection.OpenAsync(deadline.Token);
        PostgresException failure = await Assert.ThrowsAsync<PostgresException>(() => EvaluateAsync(connection,
            Translate("numeric(18,2)", "numeric(5,2)"), price, quantity, "0.00", "numeric(18,2)", "numeric(5,2)", deadline.Token));
        Assert.Equal(PostgresErrorCodes.NumericValueOutOfRange, failure.SqlState);
    }

    private async Task<string> SeedAndInspectShadowAsync(ShadowDatabase shadow, DatabaseSchemaPlan plan, CancellationToken ct)
    {
        string settings = new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadow.Name }.ConnectionString;
        await using var connection = new NpgsqlConnection(settings);
        await connection.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var seed = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
        await seed.ApplySchemaAsync(plan, ct);
        await seed.FinalizeSchemaAsync(plan, ct);
        string fingerprint = await seed.InspectSchemaAsync(plan, ct);
        Assert.Equal(plan.TargetSchemaSha256, fingerprint);
        await transaction.CommitAsync(ct);
        return fingerprint;
    }

    private static DatabaseSchemaPlan GeneratedPlan(string expression)
    {
        var table = new TableCopyPlan("dbo", "Order", "public", "Order",
            ["ID", "UnitPrice", "Quantity", "DiscountPercent", "Subtotal"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ID"] = "integer",
                ["UnitPrice"] = "numeric(18,2)",
                ["Quantity"] = "integer",
                ["DiscountPercent"] = "numeric(5,2)",
                ["Subtotal"] = "numeric(18,2)"
            },
            NullableColumns = ["UnitPrice", "DiscountPercent", "Subtotal"],
            PrimaryKey = new("PK_Order", ["ID"]),
            GeneratedColumns = [new("Subtotal", expression)],
        };
        var plan = new DatabaseSchemaPlan("Order", "1.0", new('a', 64), new('b', 64), [table]);
        return plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
    }

    private static string Translate(string priceType, string discountType)
    {
        var target = new Dictionary<string, string>(StringComparer.Ordinal)
        { ["UnitPrice"] = priceType, ["Quantity"] = "integer", ["DiscountPercent"] = discountType };
        var source = target.ToDictionary(x => x.Key, x => x.Key == "Quantity" ? "int" :
            x.Value.Replace("numeric", "decimal", StringComparison.Ordinal), StringComparer.Ordinal);
        return SqlServerMigrationSource.TranslateGeneratedExpressionForPostgreSql(SourceExpression, source, target);
    }

    private static async Task<string?> EvaluateAsync(NpgsqlConnection connection, string expression, string? price,
        int? quantity, string? discount, string priceType, string discountType, CancellationToken ct)
    {
        // Both SQL snippets/types originate from the fixed grammar and inline test cases above.
        string sql = $$"""
            WITH input("UnitPrice", "Quantity", "DiscountPercent") AS
            (SELECT @price::{{priceType}}, @quantity::integer, @discount::{{discountType}})
            SELECT ({{expression}})::text FROM input;
            """;
        await using var command = new NpgsqlCommand(sql, connection) { CommandTimeout = 30 };
        _ = command.Parameters.AddWithValue("price", NpgsqlDbType.Numeric,
            price is null ? DBNull.Value : decimal.Parse(price, CultureInfo.InvariantCulture));
        _ = command.Parameters.AddWithValue("quantity", NpgsqlDbType.Integer,
            quantity is null ? DBNull.Value : quantity.Value);
        _ = command.Parameters.AddWithValue("discount", NpgsqlDbType.Numeric,
            discount is null ? DBNull.Value : decimal.Parse(discount, CultureInfo.InvariantCulture));
        object? result = await command.ExecuteScalarAsync(ct);
        return result is null or DBNull ? null : (string)result;
    }
}
