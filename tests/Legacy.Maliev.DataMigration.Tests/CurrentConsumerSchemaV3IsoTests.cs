using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentConsumerSchemaV3IsoTests
{
    [Fact]
    public void Appended_profile_changes_only_four_physical_types_and_two_signed_target_hashes()
    {
        FreshSchemaPlan before = ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        string original = JsonSerializer.Serialize(before);
        FreshSchemaPlan after = Select(before);
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(after));
        Assert.True(ApprovedConsumerOverlaySelection.IsCurrent(after));
        Assert.NotEqual(SchemaPlanCanonicalizer.ComputeSha256(before), SchemaPlanCanonicalizer.ComputeSha256(after));
        var approved = ApprovedCurrentOwnerIsoOverlay.Create(before, before.SourceCommitSha,
            CurrentOwnerIsoSelection.LiteralWidthV1, ApprovedCurrentOwnerIsoOverlayTests.Owners(), ApprovedCurrentOwnerIsoOverlayTests.Now);
        foreach ((DatabaseSchemaPlan oldPlan, DatabaseSchemaPlan newPlan) in before.Databases.Zip(after.Databases))
        {
            Assert.Same(oldPlan.Tables, newPlan.Tables);
            Assert.Equal(oldPlan.SourceSchemaSha256, newPlan.SourceSchemaSha256);
            Assert.Equal(oldPlan.SourceDispositionProfile, newPlan.SourceDispositionProfile);
            Assert.Equal(JsonSerializer.Serialize(approved.PhysicalTables(newPlan.Database, true)),
                JsonSerializer.Serialize(ApprovedConsumerColumnOverlayManifest.ComposePhysical(newPlan)));
            Assert.Equal(newPlan.Database is "Country" or "Material", oldPlan.TargetSchemaSha256 != newPlan.TargetSchemaSha256);
            Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(newPlan), newPlan.TargetSchemaSha256);
            Assert.Equal(oldPlan.SourceSchemaSha256, new QuotationDeltaExecutionMapping(newPlan).TargetSchema.SourceSchemaSha256);
        }
        Assert.Equal(original, JsonSerializer.Serialize(before));
    }

    [Theory]
    [InlineData(ConsumerOverlaySelection.HistoricalDefaults)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerColumnsV1)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV2)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV3)]
    public void Historical_profiles_keep_char_widths_and_exact_canonical_bytes(ConsumerOverlaySelection selection)
    {
        FreshSchemaPlan historical = ApprovedCurrentOwnerIsoOverlayTests.Schema(selection);
        string canonical = SchemaPlanCanonicalizer.ComputeSha256(historical);
        string original = JsonSerializer.Serialize(historical);
        _ = Select(ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3));
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(historical));
        foreach (string database in new[] { "Country", "Material" })
        {
            TableCopyPlan country = ApprovedConsumerColumnOverlayManifest.ComposePhysical(historical.Databases.Single(x => x.Database == database))
                .Single(x => x.TargetSchema == "public" && x.TargetTable == "Country");
            Assert.Equal("character(2)", country.ColumnTypes["ISO2"]);
            Assert.Equal("character(3)", country.ColumnTypes["ISO3"]);
        }
        Assert.Equal(original, JsonSerializer.Serialize(historical));
        Assert.Equal(canonical, SchemaPlanCanonicalizer.ComputeSha256(historical));
    }

    [Theory]
    [InlineData("Country")]
    [InlineData("Material")]
    [InlineData("Invoice")]
    public void Partial_or_mixed_profiles_are_not_approved(string database)
    {
        FreshSchemaPlan before = ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        FreshSchemaPlan after = Select(before);
        DatabaseSchemaPlan replaced = before.Databases.Single(x => x.Database == database);
        if (database == "Invoice") { replaced = replaced with { TargetExtensionProfile = ApprovedCurrentConsumerSchemaManifest.Invoice }; }
        Assert.False(ApprovedConsumerOverlaySelection.IsApproved(after with
        { Databases = [.. after.Databases.Select(x => x.Database == database ? replaced : x)] }));
    }

    [Theory]
    [InlineData("partial")]
    [InlineData("collation")]
    [InlineData("default")]
    [InlineData("index")]
    [InlineData("key")]
    [InlineData("profile")]
    [InlineData("ordinal")]
    public void Unknown_shapes_fail_before_generating_a_replacement_fingerprint(string fault)
    {
        FreshSchemaPlan schema = ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        DatabaseSchemaPlan country = schema.Databases.Single(x => x.Database == "Country");
        TableCopyPlan root = country.Tables[0];
        root = fault switch
        {
            "partial" => root with { ColumnTypes = new Dictionary<string, string>(root.ColumnTypes) { ["ISO2"] = "character varying(2)" } },
            "collation" => root with { Collations = new Dictionary<string, string>(root.Collations) { ["ISO2"] = "C" } },
            "default" => root with { DefaultExpressions = new Dictionary<string, string>(root.DefaultExpressions) { ["ISO2"] = "'TH'" } },
            "index" => root with { Indexes = [new("unknown", ["ISO2"], false)] },
            "key" => root with { PrimaryKey = new("other", ["ID"]) },
            "ordinal" => root with { OrderedColumns = ["ID", "Name", "Continent", "CountryCode", "ISO2", "ISO3", "CreatedDate", "ModifiedDate"] },
            _ => root,
        };
        country = country with
        {
            Tables = [root, .. country.Tables.Skip(1)],
            TargetExtensionProfile =
            fault == "profile" ? CurrentConsumerSchemaV3IsoManifest.Material : CurrentConsumerSchemaV3IsoManifest.Country
        };
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(country));
    }

    [Fact]
    public void Material_extension_state_and_full_physical_inspection_share_the_literal_shape()
    {
        DatabaseSchemaPlan material = Select(ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3))
            .Databases.Single(x => x.Database == "Material");
        TableCopyPlan extension = ApprovedTargetExtensionManifest.TablesFor(material).Single(x => x.TargetTable == "Country");
        TableCopyPlan physical = ApprovedConsumerColumnOverlayManifest.ComposePhysical(material).Single(x => x.TargetTable == "Country");
        Assert.Equal(JsonSerializer.Serialize(physical), JsonSerializer.Serialize(extension));
        Assert.Equal(ApprovedProductionCollationManifest.Collation, physical.Collations["ISO2"]);
        Assert.Equal("character varying(2)", physical.ColumnTypes["ISO2"]);
        Assert.Equal("character varying(3)", physical.ColumnTypes["ISO3"]);
    }

    [Theory]
    [InlineData("Country", 4)]
    [InlineData("Material", 1)]
    public void Appended_profile_preserves_exact_database_specific_physical_order(string database, int idOrdinal)
    {
        FreshSchemaPlan before = ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        DatabaseSchemaPlan oldPlan = before.Databases.Single(x => x.Database == database);
        DatabaseSchemaPlan newPlan = Select(before).Databases.Single(x => x.Database == database);
        TableCopyPlan oldRoot = ApprovedConsumerColumnOverlayManifest.ComposePhysical(oldPlan).Single(x => x.TargetTable == "Country");
        TableCopyPlan newRoot = ApprovedConsumerColumnOverlayManifest.ComposePhysical(newPlan).Single(x => x.TargetTable == "Country");
        Assert.Equal(idOrdinal, newRoot.OrderedColumns.ToList().IndexOf("ID") + 1);
        Assert.Equal(oldRoot.OrderedColumns, newRoot.OrderedColumns);
        Assert.Equal(JsonSerializer.Serialize(oldRoot.SourceColumns), JsonSerializer.Serialize(newRoot.SourceColumns));
        Assert.Equal(JsonSerializer.Serialize(oldRoot.SourceColumnTypes), JsonSerializer.Serialize(newRoot.SourceColumnTypes));
        Assert.Equal(oldPlan.SourceSchemaSha256, newPlan.SourceSchemaSha256);
    }
    private static FreshSchemaPlan Select(FreshSchemaPlan source)
    {
        return source with
        {
            Databases = [.. source.Databases.Select(database =>
        {
            DatabaseSchemaPlan selected = database with { TargetExtensionProfile =
                ApprovedConsumerOverlaySelection.ProfileForDatabase(database.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3Iso) };
            return selected with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(selected) };
        })],
        };
    }
}
