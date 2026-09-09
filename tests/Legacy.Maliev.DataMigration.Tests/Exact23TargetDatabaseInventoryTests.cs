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
}
