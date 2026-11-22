using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CustomerCompanyStorageProfileTests
{
    [Fact]
    public void Complete_appended_selection_preserves_other_profiles_and_rejects_cross_database_activation()
    {
        FreshSchemaPlan source = ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        source = source with
        {
            Databases =
        [
            .. source.Databases.Select(database =>
        {
            DatabaseSchemaPlan selected = database.Database == "Customer" ? Before() : database;
            selected = selected with { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(
                database.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3CompanyStorage) };
            return selected with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(selected) };
            })
        ]
        };
        Assert.True(ApprovedConsumerOverlaySelection.IsApproved(source));
        Assert.True(ApprovedConsumerOverlaySelection.IsCurrent(source));
        DatabaseSchemaPlan wrong = source.Databases.Single(x => x.Database == "Upload") with
        { TargetExtensionProfile = CustomerCompanyStorageManifest.Profile };
        _ = Assert.Throws<MigrationExecutionException>(() => PostgreSqlSchemaFingerprint.ComputeExpected(wrong));
        Assert.False(ApprovedConsumerOverlaySelection.IsApproved(source with
        { Databases = [.. source.Databases.Select(x => x.Database == "Upload" ? wrong : x)] }));
    }

    [Fact]
    public void Opt_in_changes_only_company_physical_storage_and_preserves_source_and_owned_tables()
    {
        DatabaseSchemaPlan before = Before();
        string source = JsonSerializer.Serialize(before.Tables);
        DatabaseSchemaPlan after = Select(before);
        TableCopyPlan company = ApprovedConsumerColumnOverlayManifest.ComposePhysical(after).Single(x => x.TargetTable == "Company");
        Assert.All(CustomerCompanyStorageManifest.Columns, column => Assert.Equal("text", company.ColumnTypes[column]));
        Assert.Equal(3, company.CheckConstraints.Count);
        Assert.Equal(source, JsonSerializer.Serialize(after.Tables));
        Assert.Equal(before.SourceSchemaSha256, after.SourceSchemaSha256);
        Assert.Equal(JsonSerializer.Serialize(ApprovedTargetExtensionManifest.TablesFor(before)),
            JsonSerializer.Serialize(ApprovedTargetExtensionManifest.TablesFor(after)));
        Assert.NotEqual(PostgreSqlSchemaFingerprint.ComputeExpected(before), after.TargetSchemaSha256);
        Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(before), PostgreSqlSchemaFingerprint.ComputeExpected(Before()));
    }

    [Theory]
    [InlineData("type")]
    [InlineData("default")]
    [InlineData("nullable")]
    [InlineData("missing")]
    public void Unreviewed_company_preimage_is_rejected(string fault)
    {
        DatabaseSchemaPlan before = Before();
        TableCopyPlan company = before.Tables[0];
        company = fault switch
        {
            "type" => company with { ColumnTypes = new Dictionary<string, string>(company.ColumnTypes) { ["Name"] = "text" } },
            "default" => company with { DefaultExpressions = new Dictionary<string, string> { ["Name"] = "'unknown'" } },
            "nullable" => company with { NullableColumns = ["Name", "Registrar", "TaxNumber"] },
            _ => company with { TargetTable = "Other" },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => Select(before with { Tables = [company] }));
    }

    [Theory]
    [InlineData(ConsumerOverlaySelection.HistoricalDefaults)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerColumnsV1)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV2)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV3)]
    [InlineData(ConsumerOverlaySelection.CurrentConsumerSchemaV3Iso)]
    public void Selecting_new_profile_does_not_mutate_existing_plan_objects(ConsumerOverlaySelection selection)
    {
        FreshSchemaPlan historical = ApprovedCurrentOwnerIsoOverlayTests.Schema(
            selection == ConsumerOverlaySelection.CurrentConsumerSchemaV3Iso ? ConsumerOverlaySelection.CurrentConsumerSchemaV3 : selection);
        if (selection == ConsumerOverlaySelection.CurrentConsumerSchemaV3Iso)
        {
            historical = historical with
            {
                Databases =
            [
                .. historical.Databases.Select(database =>
            {
                DatabaseSchemaPlan selected = database with { TargetExtensionProfile =
                    ApprovedConsumerOverlaySelection.ProfileForDatabase(database.Database, selection) };
                return selected with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(selected) };
                })
            ]
            };
        }
        string canonical = SchemaPlanCanonicalizer.ComputeSha256(historical);
        string[] hashes = [.. historical.Databases.Select(PostgreSqlSchemaFingerprint.ComputeExpected)];
        _ = Select(Before());
        Assert.Equal(canonical, SchemaPlanCanonicalizer.ComputeSha256(historical));
        Assert.Equal(hashes, historical.Databases.Select(PostgreSqlSchemaFingerprint.ComputeExpected));
    }

    internal static DatabaseSchemaPlan Before()
    {
        TableCopyPlan company = new("dbo", "Company", "public", "Company", ["ID", "Name", "Registrar", "TaxNumber"], ["ID"])
        {
            ColumnTypes = new Dictionary<string, string>
            {
                ["ID"] = "integer",
                ["Name"] = "character varying(256)",
                ["Registrar"] = "character varying(256)",
                ["TaxNumber"] = "character varying(256)"
            },
            PrimaryKey = new("PK_Company", ["ID"]),
            NullableColumns = ["Registrar", "TaxNumber"],
        };
        return new("Customer", "1.0", new('a', 64), new('b', 64), [company])
        { TargetExtensionProfile = ApprovedCurrentConsumerSchemaManifest.Customer };
    }

    internal static DatabaseSchemaPlan Select(DatabaseSchemaPlan before)
    {
        DatabaseSchemaPlan after = before with { TargetExtensionProfile = CustomerCompanyStorageManifest.Profile };
        return after with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(after) };
    }
}
