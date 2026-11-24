using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentConsumerSchemaV3SourceOrderIsoTests
{
    [Fact]
    public void Truthful_source_bytes_are_unchanged_and_old_guard_stays_closed()
    {
        DatabaseSchemaPlan before = Country();
        string bytes = JsonSerializer.Serialize(before);
        DatabaseSchemaPlan selected = Select(before);
        TableCopyPlan physical = Assert.Single(ApprovedConsumerColumnOverlayManifest.ComposePhysical(selected));
        Assert.Equal("character varying(2)", physical.ColumnTypes["ISO2"]);
        Assert.Equal("character varying(3)", physical.ColumnTypes["ISO3"]);
        Assert.Equal("nchar(2)", physical.SourceColumnTypes["ISO2"]);
        Assert.Equal("datetime", physical.SourceColumnTypes["CreatedDate"]);
        Assert.Equal(JsonSerializer.Serialize(before.Tables[0]), JsonSerializer.Serialize(physical with { ColumnTypes = before.Tables[0].ColumnTypes }));
        Assert.Equal(bytes, JsonSerializer.Serialize(before));
        Assert.Equal(JsonSerializer.Serialize(before.Tables), JsonSerializer.Serialize(selected.Tables));
        Assert.Equal(before.SourceSchemaSha256, selected.SourceSchemaSha256);
        Assert.Empty(ApprovedTargetExtensionManifest.TablesFor(selected));
        Assert.NotEqual(before.TargetSchemaSha256, selected.TargetSchemaSha256);
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(before with
        { TargetExtensionProfile = CurrentConsumerSchemaV3IsoManifest.Country }));
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(selected with { Database = "Material" }));
    }

    [Fact]
    public void Captured_identity_state_is_retained_without_freezing_its_current_value()
    {
        DatabaseSchemaPlan before = Country();
        TableCopyPlan root = before.Tables[0] with { Identities = [new("ID", 1, 1, 91, true)] };
        TableCopyPlan after = Assert.Single(ApprovedConsumerColumnOverlayManifest.ComposePhysical(Select(before with { Tables = [root] })));
        Assert.Equal(root.Identities, after.Identities);
    }

    [Fact]
    public void Exact_combined_set_is_approved_and_mixed_sets_stay_closed()
    {
        FreshSchemaPlan baseline = ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        FreshSchemaPlan selected = baseline with
        {
            Databases = [.. baseline.Databases.Select(database =>
            {
                DatabaseSchemaPlan root = database.Database switch
                { "Country" => Country(), "Customer" => CustomerCompanyStorageProfileTests.Before(), _ => database };
                root = root with { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(
                    database.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3CompanyStorageSourceOrder) };
                return root with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(root) };
            })],
        };
        Assert.True(ApprovedConsumerOverlaySelection.IsCurrent(selected));
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(selected));
        Assert.Equal(CustomerCompanyStorageManifest.Profile, selected.Databases.Single(x => x.Database == "Customer").TargetExtensionProfile);
        Assert.Equal(CurrentConsumerSchemaV3IsoManifest.Material, selected.Databases.Single(x => x.Database == "Material").TargetExtensionProfile);
        foreach (string database in new[] { "Country", "Customer", "Material" })
        {
            DatabaseSchemaPlan old = baseline.Databases.Single(x => x.Database == database);
            Assert.False(ApprovedConsumerOverlaySelection.IsApproved(selected with
            { Databases = [.. selected.Databases.Select(x => x.Database == database ? old : x)] }));
        }
        DatabaseSchemaPlan invoice = baseline.Databases.Single(x => x.Database == "Invoice");
        Assert.Equal(invoice.TargetExtensionProfile, selected.Databases.Single(x => x.Database == "Invoice").TargetExtensionProfile);
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(selected with
        { Databases = [.. selected.Databases.Select(x => x.Database == "Invoice" ? invoice : x)] }));
        DatabaseSchemaPlan historical = selected.Databases.Single(x => x.Database == "Country") with
        { TargetExtensionProfile = CurrentConsumerSchemaV3IsoManifest.Country };
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(selected with
        { Databases = [.. selected.Databases.Select(x => x.Database == "Country" ? historical : x)] }));
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(historical));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedRepairManifest.RequireSchemaPair(baseline, selected, baseline.CapturedAtUtc));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAppOwnedV3AdditiveContract.Create(baseline, selected, baseline.SourceCommitSha, baseline.CapturedAtUtc));
    }

    [Theory]
    [InlineData("order")]
    [InlineData("source-order")]
    [InlineData("source-type")]
    [InlineData("declared-type")]
    [InlineData("hash")]
    [InlineData("length")]
    [InlineData("identity-columns")]
    [InlineData("identity-count")]
    [InlineData("seed")]
    [InlineData("increment")]
    [InlineData("default")]
    [InlineData("collation")]
    [InlineData("nullable")]
    [InlineData("key")]
    [InlineData("index")]
    [InlineData("generated")]
    [InlineData("type")]
    [InlineData("source-name")]
    public void Unreviewed_preimage_fails_before_replacement_hash(string fault)
    {
        DatabaseSchemaPlan before = Country();
        TableCopyPlan root = before.Tables[0];
        root = fault switch
        {
            "order" => root with { OrderedColumns = [.. root.OrderedColumns.Reverse()] },
            "source-order" => root with { SourceColumns = [.. root.SourceColumns.Reverse()] },
            "source-type" => root with { SourceColumnTypes = new Dictionary<string, string>(root.SourceColumnTypes) { ["ISO2"] = "char(2)" } },
            "declared-type" => root with { SourceColumns = [root.SourceColumns[0] with { DeclaredType = "bigint" }, .. root.SourceColumns.Skip(1)] },
            "hash" => root with { SourceColumns = [root.SourceColumns[0] with { MetadataSha256 = new string('z', 64) }, .. root.SourceColumns.Skip(1)] },
            "length" => root with { SourceColumns = [root.SourceColumns[0] with { MaxObservedDataLength = -1 }, .. root.SourceColumns.Skip(1)] },
            "identity-columns" => root with { IdentityColumns = [] },
            "identity-count" => root with { Identities = [.. root.Identities, root.Identities[0]] },
            "seed" => root with { Identities = [root.Identities[0] with { SeedValue = 2 }] },
            "increment" => root with { Identities = [root.Identities[0] with { IncrementValue = 2 }] },
            "default" => root with { DefaultExpressions = new Dictionary<string, string>(root.DefaultExpressions) { ["ISO2"] = "'TH'" } },
            "collation" => root with { Collations = new Dictionary<string, string>(root.Collations) { ["ISO2"] = "C" } },
            "nullable" => root with { NullableColumns = [.. root.NullableColumns, "Name"] },
            "key" => root with { PrimaryKey = new("other", ["ID"]) },
            "index" => root with { Indexes = [new("unexpected", ["Name"], false)] },
            "generated" => root with { GeneratedColumns = [new("Name", "'other'")] },
            "type" => root with { ColumnTypes = new Dictionary<string, string>(root.ColumnTypes) { ["ISO2"] = "character varying(2)" } },
            "source-name" => root with { SourceTable = "Other" },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => Select(before with { Tables = [root] }));
    }

    [Fact]
    public void Identity_current_state_is_retained()
    {
        DatabaseSchemaPlan before = Country();
        TableCopyPlan root = before.Tables[0] with { Identities = [new("ID", 1, 1, 91, true)] };
        TableCopyPlan after = Assert.Single(ApprovedConsumerColumnOverlayManifest.ComposePhysical(Select(before with { Tables = [root] })));
        Assert.Equal(root.Identities, after.Identities);
    }

    // Synthetic metadata-only fixture matching reviewed SQL types/order, not source acceptance evidence.
    internal static DatabaseSchemaPlan Country()
    {
        DatabaseSchemaPlan material = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3)
            .Databases.Single(x => x.Database == "Material");
        TableCopyPlan root = ApprovedTargetExtensionManifest.TablesFor(material).Single(x => x.TargetTable == "Country");
        string[] types = ["int", "nvarchar(50)", "nvarchar(50)", "nvarchar(30)", "nchar(2)", "nchar(3)", "datetime", "datetime"];
        var sourceTypes = root.OrderedColumns.Zip(types).ToDictionary(x => x.First, x => x.Second, StringComparer.Ordinal);
        root = root with
        {
            SourceSchema = "dbo",
            SourceColumnTypes = sourceTypes,
            IdentityColumns = ["ID"],
            SourceColumns = [.. root.OrderedColumns.Select(x => new SourceColumnInventory(x, sourceTypes[x], new string('a', 64), null))],
        };
        var plan = new DatabaseSchemaPlan("Country", "1.0", new('a', 64), new('b', 64), [root]);
        return plan with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(plan) };
    }

    internal static DatabaseSchemaPlan Select(DatabaseSchemaPlan before)
    {
        DatabaseSchemaPlan selected = before with { TargetExtensionProfile = CurrentConsumerSchemaV3SourceOrderIsoManifest.Country };
        return selected with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(selected) };
    }
}
