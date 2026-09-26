namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact23TargetDatabaseInventoryTests
{
    [Fact]
    public void Validate_ExactInventoryWithRuntimeAndMigrationDatabases_Passes()
    {
        string[] inventory =
        [
            .. DatabaseInventory.ActiveDatabases,
            "Auth",
            "legacy_migration_control",
            "legacy_shadow_country_12345678_12345678901234567890123456789012",
        ];

        Exact23TargetDatabaseInventory.Validate(inventory);
    }

    [Fact]
    public void Validate_ExactInventoryWithAspireLocalDatabase_Passes()
    {
        string[] inventory = [.. DatabaseInventory.ActiveDatabases, "Auth", "legacy_local"];

        Exact23TargetDatabaseInventory.Validate(inventory);
    }

    [Fact]
    public void Validate_MissingCanonicalDatabase_FailsClosed()
    {
        string[] inventory = [.. DatabaseInventory.ActiveDatabases.Where(database => database != "ContactRequest")];

        DeltaExecutionException failure = Assert.Throws<DeltaExecutionException>(
            () => Exact23TargetDatabaseInventory.Validate(inventory));

        Assert.Equal("delta_target_database_inventory_invalid", failure.Code);
    }

    [Theory]
    [InlineData("Hangfire")]
    [InlineData("Log")]
    [InlineData("UnexpectedApplicationDatabase")]
    [InlineData("Legacy_Local")]
    public void Validate_RetiredOrUnknownDatabase_FailsClosed(string unexpected)
    {
        string[] inventory = [.. DatabaseInventory.ActiveDatabases, unexpected];

        DeltaExecutionException failure = Assert.Throws<DeltaExecutionException>(
            () => Exact23TargetDatabaseInventory.Validate(inventory));

        Assert.Equal("delta_target_database_inventory_invalid", failure.Code);
    }

    [Fact]
    public void Validate_DuplicateDatabaseName_FailsClosed()
    {
        string[] inventory = [.. DatabaseInventory.ActiveDatabases, "Country"];

        DeltaExecutionException failure = Assert.Throws<DeltaExecutionException>(
            () => Exact23TargetDatabaseInventory.Validate(inventory));

        Assert.Equal("delta_target_database_inventory_invalid", failure.Code);
    }

    [Fact]
    public void QuotationDisposable_AdmitsOnlyItsSingleDatabaseAndDistinctLocalAuthority()
    {
        var disposable = new DeltaTargetAuthority("local-aspire",
            "aspire://legacy-postgres-main-local/disposable-abcdef123456", new string('a', 64));

        Exact23TargetDatabaseInventory.ValidateQuotationDisposable(["Quotation"], disposable);
        _ = Assert.Throws<DeltaExecutionException>(() => Exact23TargetDatabaseInventory.Validate(["Quotation"]));
    }

    [Fact]
    public void QuotationDisposable_RejectsMissingExtraDuplicateRetiredOrWrongCase()
    {
        var disposable = new DeltaTargetAuthority("local-aspire",
            "aspire://legacy-postgres-main-local/disposable-abcdef123456", new string('a', 64));

        foreach (string[] databases in new string[][]
        {
            [], ["Quotation", "Customer"], ["Quotation", "Quotation"], ["Hangfire"], ["quotation"]
        })
        {
            DeltaExecutionException failure = Assert.Throws<DeltaExecutionException>(() =>
                Exact23TargetDatabaseInventory.ValidateQuotationDisposable(databases, disposable));
            Assert.Equal("delta_target_database_inventory_invalid", failure.Code);
        }
    }

    [Theory]
    [InlineData("local-aspire", "aspire://legacy-postgres-main-local/persistent-abcdef123456")]
    [InlineData("cloudnativepg", "aspire://legacy-postgres-main-local/disposable-abcdef123456")]
    public void QuotationDisposable_RejectsNonDisposableOrProductionAuthority(string kind, string authorityId)
    {
        var authority = new DeltaTargetAuthority(kind, authorityId, new string('a', 64));

        DeltaExecutionException failure = Assert.Throws<DeltaExecutionException>(() =>
            Exact23TargetDatabaseInventory.ValidateQuotationDisposable(["Quotation"], authority));
        Assert.Equal("delta_target_database_inventory_invalid", failure.Code);
    }
}
