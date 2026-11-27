using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SourceOrderOwnerIsoContractTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Truthful_source_and_every_historical_source_field_are_immutable(bool companyAlreadyApplied)
    {
        var source = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical());
        string before = JsonSerializer.Serialize(source), hash = SchemaPlanCanonicalizer.ComputeSha256(source);
        var contract = SourceOrderOwnerIsoContract.Create(source, source.SourceCommitSha, companyAlreadyApplied,
            ApprovedCurrentOwnerIsoOverlayTests.Owners(), ConsumerColumnBootstrapTestData.Now);
        Assert.Equal(hash, contract.SourcePlanSha256);
        Assert.Equal(23, source.Databases.Count); Assert.Equal(100, source.Databases.Sum(x => x.Tables.Count));
        foreach (string database in SourceOrderOwnerIsoProtocol.Databases)
        {
            var original = contract.PhysicalTables(database, false); var selected = contract.PhysicalTables(database, true);
            foreach ((var left, var right) in original.Zip(selected))
            {
                if (left.TargetSchema == "public" && left.TargetTable == "Country")
                {
                    Assert.Equal("ID", left.OrderedColumns[0]); Assert.Equal("character(2)", left.ColumnTypes["ISO2"]);
                    Assert.Equal("character varying(2)", right.ColumnTypes["ISO2"]); Assert.Equal("character varying(3)", right.ColumnTypes["ISO3"]);
                    Assert.Equal(JsonSerializer.Serialize(left), JsonSerializer.Serialize(right with { ColumnTypes = left.ColumnTypes }));
                }
                else { Assert.Equal(JsonSerializer.Serialize(left), JsonSerializer.Serialize(right)); }
            }
        }
        Assert.Equal(before, JsonSerializer.Serialize(source));
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentOwnerIsoOverlayTests.Create(source));
    }
    [Fact]
    public void Company_phase_is_detached_physical_only_and_binds_distinct_contract()
    {
        var source = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical());
        var owners = ApprovedCurrentOwnerIsoOverlayTests.Owners();
        var before = SourceOrderOwnerIsoContract.Create(source, source.SourceCommitSha, false, owners, ConsumerColumnBootstrapTestData.Now);
        var after = SourceOrderOwnerIsoContract.Create(source, source.SourceCommitSha, true, owners, ConsumerColumnBootstrapTestData.Now);
        Assert.Equal(before.SourcePlanSha256, after.SourcePlanSha256); Assert.NotEqual(before.ComputeSha256(), after.ComputeSha256());
        foreach (var database in source.Databases.Where(x => x.Database != "Customer"))
        { Assert.Equal(JsonSerializer.Serialize(before.PhysicalTables(database.Database, false)), JsonSerializer.Serialize(after.PhysicalTables(database.Database, false))); }
    }
    [Theory]
    [InlineData("owner")]
    [InlineData("ordinal")]
    [InlineData("source-type")]
    [InlineData("seed")]
    [InlineData("increment")]
    [InlineData("selection")]
    public void Rejects_unknown_owner_source_or_identity_definition(string fault)
    {
        var source = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical());
        var owners = ApprovedCurrentOwnerIsoOverlayTests.Owners();
        if (fault == "owner") { owners[0] = owners[0] with { Head = new('0', 40) }; }
        var country = source.Databases.Single(x => x.Database == "Country"); var table = country.Tables.Single(x => x.SourceTable == "Country");
        if (fault == "ordinal") { table = table with { OrderedColumns = table.OrderedColumns.Reverse().ToArray() }; }
        if (fault == "source-type") { table = table with { SourceColumnTypes = table.SourceColumnTypes.ToDictionary(x => x.Key, x => x.Key == "ISO2" ? "char(2)" : x.Value) }; }
        if (fault == "seed") { table = table with { Identities = [table.Identities[0] with { SeedValue = 2 }] }; }
        if (fault == "increment") { table = table with { Identities = [table.Identities[0] with { IncrementValue = 2 }] }; }
        country = country with { Tables = [.. country.Tables.Select(x => x.SourceTable == "Country" ? table : x)] };
        if (fault == "selection")
        {
            Assert.NotEqual(CurrentConsumerSchemaV3SourceOrderIsoManifest.Country, country.TargetExtensionProfile);
            country = country with { TargetExtensionProfile = CurrentConsumerSchemaV3SourceOrderIsoManifest.Country };
        }
        country = country with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(country) };
        source = source with { Databases = [.. source.Databases.Select(x => x.Database == "Country" ? country : x)] };
        _ = Assert.Throws<MigrationExecutionException>(() => SourceOrderOwnerIsoContract.Create(source, source.SourceCommitSha, false, owners, ConsumerColumnBootstrapTestData.Now));
    }
    [Theory]
    [InlineData("observe")]
    [InlineData("verify")]
    [InlineData("apply")]
    [InlineData("native-faults")]
    public async Task Testhost_cannot_issue_accepted_console_authority(string action)
    {
        using var output = new StringWriter(); using var error = new StringWriter();
        Assert.Equal(1, await MigrationConsole.RunSourceOrderOwnerIsoAsync(action, "unused-owner-only-file", output, error, CancellationToken.None));
        Assert.Equal(string.Empty, output.ToString()); Assert.Contains("source_order_owner_iso_refused", error.ToString(), StringComparison.Ordinal);
    }
}
