using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CustomerCompanyStorageRepairContractTests
{
    internal static readonly DateTimeOffset Now = new(2026, 11, 24, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Fixed_preparation_binds_owner_source_and_both_physical_plans_without_mutating_inputs()
    {
        DatabaseSchemaPlan before = Before();
        CustomerCompanyStorageRepairOwner owner = Owner();
        string original = JsonSerializer.Serialize(before);
        var contract = Create(before, owner);
        DatabaseSchemaPlan after = contract.After();
        Assert.Equal(original, JsonSerializer.Serialize(contract.Before()));
        Assert.Equal(original, JsonSerializer.Serialize(before));
        Assert.Equal(JsonSerializer.Serialize(before.Tables), JsonSerializer.Serialize(after.Tables));
        Assert.Equal(before.SourceSchemaSha256, after.SourceSchemaSha256);
        Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(before), before.TargetSchemaSha256);
        Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(after), after.TargetSchemaSha256);
        Assert.NotEqual(before.TargetSchemaSha256, after.TargetSchemaSha256);
        Assert.Equal(CustomerCompanyStorageManifest.Profile, after.TargetExtensionProfile);
        Assert.Equal(64, contract.ComputeSha256().Length);
        Assert.Equal(contract.ComputeSha256(), Create(Before(), Owner()).ComputeSha256());
        Assert.Equal(JsonSerializer.Serialize(ApprovedTargetExtensionManifest.TablesFor(before)),
            JsonSerializer.Serialize(ApprovedTargetExtensionManifest.TablesFor(after)));
        // Returned copies cannot change the retained preparation.
        ((Dictionary<string, string>)contract.Before().Tables[0].ColumnTypes)["Name"] = "text";
        Assert.Equal(original, JsonSerializer.Serialize(contract.Before()));
    }

    [Theory]
    [InlineData("head")]
    [InlineData("dirty")]
    [InlineData("stale")]
    [InlineData("future")]
    [InlineData("missing-file")]
    [InlineData("changed-file")]
    [InlineData("extra-file")]
    [InlineData("source")]
    [InlineData("profile")]
    [InlineData("fingerprint")]
    [InlineData("default")]
    public void Unbound_or_unreviewed_preparation_is_rejected(string fault)
    {
        DatabaseSchemaPlan before = Before();
        CustomerCompanyStorageRepairOwner owner = Owner();
        var files = owner.Files.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        if (fault == "missing-file") { _ = files.Remove(files.Keys.First()); }
        if (fault == "changed-file") { files[files.Keys.First()] = new('f', 64); }
        if (fault == "extra-file") { files["unreviewed"] = new('f', 64); }
        owner = owner with { Files = files };
        if (fault == "head") { owner = owner with { Head = new('f', 40) }; }
        if (fault == "dirty") { owner = owner with { Clean = false }; }
        if (fault == "stale") { owner = owner with { ObservedAtUtc = Now.AddHours(-3) }; }
        if (fault == "future") { owner = owner with { ObservedAtUtc = Now.AddSeconds(1) }; }
        if (fault == "profile") { before = before with { TargetExtensionProfile = CustomerCompanyStorageManifest.Profile }; }
        if (fault == "fingerprint") { before = before with { TargetSchemaSha256 = new('f', 64) }; }
        if (fault == "default")
        {
            before = before with
            {
                Tables = [before.Tables[0] with
                { DefaultExpressions = new Dictionary<string, string> { ["Name"] = "'invented'" } }]
            };
            before = before with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(before) };
        }
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCustomerCompanyStorageRepair.Create(before,
            new('a', 40), fault == "source" ? new('b', 40) : new('a', 40), owner, Now));
    }

    internal static ApprovedCustomerCompanyStorageRepair Create(DatabaseSchemaPlan before, CustomerCompanyStorageRepairOwner owner)
    {
        return ApprovedCustomerCompanyStorageRepair.Create(before, new('a', 40), new('a', 40), owner, Now);
    }

    internal static DatabaseSchemaPlan Before()
    {
        DatabaseSchemaPlan before = CustomerCompanyStorageProfileTests.Before();
        TableCopyPlan company = before.Tables[0] with
        {
            Identities = [new("ID", 100, 1, 102, true)],
            Collations = new Dictionary<string, string> { ["Name"] = "C", ["TaxNumber"] = "C", ["Registrar"] = "C" },
        };
        before = before with { Tables = [company] };
        return before with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(before) };
    }

    internal static CustomerCompanyStorageRepairOwner Owner()
    {
        return new(
        ApprovedCustomerCompanyStorageRepair.OwnerHead, true, Now, new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Legacy.Maliev.CustomerService.Data/CustomerDbContext.cs"] = "4f33a8c15cc5b1241ee42327a4945260c775e3c3d34939ab85f29afa8963c82f",
            ["Legacy.Maliev.CustomerService.Data/Migrations/CustomerDbContextModelSnapshot.cs"] = "208f45fa79c738fed5e9b5151b92e7185342141ad96415d5e3b4213232f21750",
            ["Legacy.Maliev.CustomerService.Data/Migrations/20261024150000_EnforceCompanySourceStorage.cs"] = "6f5f3dd97d809ebddca5c4fdc98041fbb4388a70a529d0d165c3d5bb17ab2db5",
            ["Legacy.Maliev.CustomerService.Data/CompanySourceConstraints.cs"] = "7834a0a588e10c079e6f85e27dd8d47c8b905ddc77f328748955ae155898942f",
        });
    }
}
