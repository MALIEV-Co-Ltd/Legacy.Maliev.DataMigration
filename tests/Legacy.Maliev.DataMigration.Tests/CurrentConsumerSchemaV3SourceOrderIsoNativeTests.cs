using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class CurrentConsumerSchemaV3SourceOrderIsoNativeTests(PostgreSqlAdapterFixture fixture)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Both_physical_orders_inspect_and_copy_by_logical_column_names(bool alphabetical)
    {
        DatabaseSchemaPlan selected = CurrentConsumerSchemaV3SourceOrderIsoTests.Select(CurrentConsumerSchemaV3SourceOrderIsoTests.Country());
        string sourceJson = JsonSerializer.Serialize(selected.Tables);
        byte[] sourceSha = SHA256.HashData(Encoding.UTF8.GetBytes(sourceJson));
        TableCopyPlan logical = Assert.Single(selected.Tables);
        TableCopyPlan physicalShape = Assert.Single(ApprovedConsumerColumnOverlayManifest.ComposePhysical(selected));
        Assert.Equal("character(2)", logical.ColumnTypes["ISO2"]);
        Assert.Equal("character(3)", logical.ColumnTypes["ISO3"]);
        Assert.Equal("character varying(2)", physicalShape.ColumnTypes["ISO2"]);
        Assert.Equal("character varying(3)", physicalShape.ColumnTypes["ISO3"]);
        TableCopyPlan physical = alphabetical ? physicalShape with { OrderedColumns = [.. physicalShape.OrderedColumns.Order(StringComparer.Ordinal)] } : physicalShape;
        DatabaseSchemaPlan materialized = selected with { Tables = [physical], TargetExtensionProfile = null };
        Assert.Equal(selected.TargetSchemaSha256, PostgreSqlSchemaFingerprint.ComputeExpected(materialized));
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        Guid run = Guid.NewGuid();
        var shadow = new ShadowDatabase($"legacy_shadow_country_source_{run:N}", run.ToString("D"), "Country")
        { OwnerAttempt = 1, FencingToken = Guid.NewGuid() };
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        CancellationToken ct = deadline.Token;
        _ = await target.CreateUniqueEmptyShadowAsync(shadow, ct);
        try
        {
            await using IPostgreSqlWholeDatabaseTransaction tx = await target.BeginWholeDatabaseTransactionAsync(shadow, ct);
            await tx.ApplySchemaAsync(materialized, ct);
            MigrationRow[] rows =
            [
                Row(1, "ประเทศไทย", "TH", "THA"),
                Row(2, "ประเทศทดสอบ", null, null),
                Row(3, "รหัสทดสอบ", "A ", "B  "),
            ];
            Assert.Equal(3, await tx.CopyBatchAsync(logical, rows, ct));
            await tx.FinalizeSchemaAsync(materialized, ct);
            Assert.Equal(selected.TargetSchemaSha256, await tx.InspectSchemaAsync(selected, ct));
            using var collector = new TableEvidenceCollector(logical);
            foreach (MigrationRow row in rows) { collector.Append(row); }
            ReconciliationDiagnostics.CompareTable("Country", collector.Finish(), await tx.InspectTableAsync(logical, ct));
            await tx.CommitAsync(ct);
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString)
            { Database = shadow.Name, Pooling = false }.ConnectionString);
            await connection.OpenAsync(ct);
            await using var readback = new NpgsqlCommand("""
                SELECT "ISO2","ISO3",convert_to("ISO2",'UTF8'),convert_to("ISO3",'UTF8')
                FROM public."Country" WHERE "ID"=3;
                """, connection);
            await using (NpgsqlDataReader reader = await readback.ExecuteReaderAsync(ct))
            {
                Assert.True(await reader.ReadAsync(ct));
                Assert.Equal("A ", reader.GetString(0));
                Assert.Equal("B  ", reader.GetString(1));
                Assert.Equal(Encoding.UTF8.GetBytes("A "), reader.GetFieldValue<byte[]>(2));
                Assert.Equal(Encoding.UTF8.GetBytes("B  "), reader.GetFieldValue<byte[]>(3));
                Assert.False(await reader.ReadAsync(ct));
            }
            Assert.Equal(sourceJson, JsonSerializer.Serialize(selected.Tables));
            Assert.Equal(sourceSha, SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(selected.Tables))));
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await target.DeleteRunOwnedShadowAsync(shadow, cleanup.Token);
        }
    }

    private static MigrationRow Row(int id, string name, string? iso2, string? iso3)
    {
        return new(new Dictionary<string, object?>
        {
            ["ID"] = id,
            ["Name"] = name,
            ["Continent"] = "เอเชีย",
            ["CountryCode"] = null,
            ["ISO2"] = iso2,
            ["ISO3"] = iso3,
            ["CreatedDate"] = null,
            ["ModifiedDate"] = null,
        });
    }
}
