namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ApprovedProductionCollationManifestTests
{
    [Fact]
    public void ReviewedInventory_ListsOnlyExactObservedColumns()
    {
        Assert.Equal(304, ApprovedProductionCollationManifest.ColumnCount);
        Assert.Equal(304, ApprovedProductionCollationManifest.ReviewedColumnCount);
        Assert.Equal("f93642d9fb2a2516b1032e1b4d35ac0c36defdd21709d73d5a8b442beff7fbc5",
            ApprovedProductionCollationManifest.InventorySha256);
        Assert.Equal(ApprovedProductionCollationManifest.InventorySha256,
            ApprovedProductionCollationManifest.ComputeInventorySha256());
        IReadOnlyDictionary<string, string> country = ApprovedProductionCollationManifest.ForTable(
            "Country", "public", "Country", ["ID", "Continent", "CountryCode", "ISO2", "ISO3", "Name"]);
        Assert.Equal(5, country.Count);
        Assert.All(country.Values, value => Assert.Equal("legacy_ci_as", value));
        Assert.Empty(ApprovedProductionCollationManifest.ForTable("ContactRequest", "public", "Message", ["ID"]));
        Assert.Equal("production_collation_inventory_drift", Assert.Throws<MigrationExecutionException>(() =>
            ApprovedProductionCollationManifest.ForTable("Country", "public", "Country", ["ID"])).Code);
    }
}

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class ApprovedProductionCollationBootstrapTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task DisposableBootstrap_CreatesReviewedCollationAndMatchesStrictFingerprint()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync(
            "Country", $"legacy_shadow_collation_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"),
            CancellationToken.None);
        try
        {
            var table = new TableCopyPlan("dbo", "Country", "public", "Country",
                ["ID", "Continent", "CountryCode", "ISO2", "ISO3", "Name"], ["ID"])
            {
                ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ID"] = "integer",
                    ["Continent"] = "character varying(50)",
                    ["CountryCode"] = "character varying(30)",
                    ["ISO2"] = "character(2)",
                    ["ISO3"] = "character(3)",
                    ["Name"] = "character varying(50)",
                },
                NullableColumns = ["Continent", "CountryCode", "ISO2", "ISO3"],
                PrimaryKey = new PrimaryKeyCopyPlan("PK_Country", ["ID"]),
                Collations = ApprovedProductionCollationManifest.ForTable("Country", "public", "Country",
                    ["ID", "Continent", "CountryCode", "ISO2", "ISO3", "Name"]),
            };
            var draft = new DatabaseSchemaPlan("Country", "1.0", new string('a', 64), "", [table]);
            DatabaseSchemaPlan plan = draft with
            {
                TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(draft),
            };
            await using IPostgreSqlWholeDatabaseTransaction transaction =
                await target.BeginWholeDatabaseTransactionAsync(shadow, CancellationToken.None);
            await transaction.ApplySchemaAsync(plan, CancellationToken.None);
            await transaction.FinalizeSchemaAsync(plan, CancellationToken.None);
            Assert.Equal(plan.TargetSchemaSha256,
                await transaction.InspectSchemaAsync(plan, CancellationToken.None));
            await transaction.RollbackAsync(CancellationToken.None);
        }
        finally
        {
            await target.DeleteRunOwnedShadowAsync(shadow, CancellationToken.None);
        }
    }
}
