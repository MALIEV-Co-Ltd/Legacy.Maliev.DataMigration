using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ContactRequestCollationProfileTests
{
    private static readonly string[] ExpectedTextColumns =
        ["Company", "Country", "Email", "FirstName", "LastName", "MessageContent", "Telephone"];
    [Fact]
    public void Contact_C_default_preserves_legacy_plan_bytes_and_original_references()
    {
        DatabaseSchemaPlan original = ContactRequestCollationTestSchema.CreateDraft();
        Assert.Same(original, ApprovedContactRequestCollationManifest.Apply(original, ContactRequestCollationProfile.LegacyInherited));
        Assert.Empty(original.Tables[0].Collations);
        Assert.Equal(JsonSerializer.Serialize(original), JsonSerializer.Serialize(
            ApprovedContactRequestCollationManifest.Apply(original, ContactRequestCollationProfile.LegacyInherited)));
        Assert.Equal("\"LegacyInherited\"", JsonSerializer.Serialize(ContactRequestCollationProfile.LegacyInherited));
        Assert.Equal(ContactRequestCollationProfile.ExplicitC,
            JsonSerializer.Deserialize<ContactRequestCollationProfile>("\"ExplicitC\""));
        _ = Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ContactRequestCollationProfile>("\"unknown\""));
        Assert.Equal("contact_request_collation_profile_invalid", Assert.Throws<MigrationExecutionException>(() =>
            ApprovedContactRequestCollationManifest.Apply(original, (ContactRequestCollationProfile)99)).Code);
    }

    [Fact]
    public void Contact_C_adds_only_exact_seven_collations_and_preserves_source_projection_and_hash()
    {
        DatabaseSchemaPlan original = ContactRequestCollationTestSchema.CreateDraft();
        TableCopyPlan before = original.Tables[0];
        DatabaseSchemaPlan selected = ApprovedContactRequestCollationManifest.Apply(original, ContactRequestCollationProfile.ExplicitC);
        TableCopyPlan after = selected.Tables[0];
        Assert.Equal(7, after.Collations.Count);
        Assert.Equal(ExpectedTextColumns,
            after.Collations.Keys.Order(StringComparer.Ordinal));
        Assert.All(after.Collations.Values, collation => Assert.Equal("C", collation));
        Assert.Equal(JsonSerializer.Serialize(before), JsonSerializer.Serialize(after with { Collations = before.Collations }));
        Assert.Same(before.SourceColumns, after.SourceColumns);
        Assert.Same(before.SourceColumnTypes, after.SourceColumnTypes);
        Assert.Same(before.OrderedColumns, after.OrderedColumns);
        Assert.Same(before.OrderByColumns, after.OrderByColumns);
        Assert.Equal(original.SourceSchemaSha256, selected.SourceSchemaSha256);
        Assert.Equal(original.TargetSchemaSha256, selected.TargetSchemaSha256); // producer computes the selected hash afterward
        Assert.NotEqual(PostgreSqlSchemaFingerprint.ComputeExpected(original), PostgreSqlSchemaFingerprint.ComputeExpected(selected));
        var row = new MigrationRow(new Dictionary<string, object?>
        {
            ["ID"] = 1,
            ["FirstName"] = "é",
            ["LastName"] = "สวัสดี",
            ["Email"] = "synthetic@test.invalid",
            ["Company"] = null,
            ["Telephone"] = null,
            ["MessageContent"] = "é 😀",
            ["Country"] = "TH",
            ["CreatedDate"] = new DateTime(2026, 10, 3, 0, 0, 0, DateTimeKind.Unspecified),
            ["ModifiedDate"] = null,
        });
        Assert.Equal(CanonicalRowFingerprint.Compute(before, [row]), CanonicalRowFingerprint.Compute(after, [row]));
        Assert.Equal(ApprovedProductionCollationManifest.InventorySha256, ApprovedProductionCollationManifest.ComputeInventorySha256());
    }

    [Fact]
    public void Contact_C_all_other_twenty_two_database_plans_remain_byte_identical()
    {
        foreach (string database in DatabaseInventory.ActiveDatabases.Where(database => database != "ContactRequest"))
        {
            DatabaseSchemaPlan other = ContactRequestCollationTestSchema.CreateDraft() with { Database = database };
            Assert.Same(other, ApprovedContactRequestCollationManifest.Apply(other, ContactRequestCollationProfile.ExplicitC));
            Assert.Equal(PostgreSqlSchemaFingerprint.ComputeExpected(other), PostgreSqlSchemaFingerprint.ComputeExpected(
                ApprovedContactRequestCollationManifest.Apply(other, ContactRequestCollationProfile.ExplicitC)));
        }
    }

    [Fact]
    public void Contact_C_preserves_fresh_source_hash_and_identity_progress_without_pinning_historical_data_state()
    {
        DatabaseSchemaPlan fresh = ContactRequestCollationTestSchema.CreateDraft() with { SourceSchemaSha256 = new string('f', 64) };
        fresh = fresh with { Tables = [fresh.Tables[0] with { Identities = [new("ID", 1, 1, 27, true)] }] };
        DatabaseSchemaPlan selected = ApprovedContactRequestCollationManifest.Apply(fresh, ContactRequestCollationProfile.ExplicitC);
        Assert.Equal(fresh.SourceSchemaSha256, selected.SourceSchemaSha256);
        Assert.Equal(fresh.Tables[0].Identities, selected.Tables[0].Identities);
    }

    [Theory]
    [InlineData("column-order")]
    [InlineData("target-type")]
    [InlineData("source-type")]
    [InlineData("source-metadata")]
    [InlineData("nullable")]
    [InlineData("pk")]
    [InlineData("identity")]
    [InlineData("default")]
    [InlineData("index")]
    [InlineData("unique")]
    [InlineData("fk")]
    [InlineData("check")]
    [InlineData("generated")]
    [InlineData("collation")]
    [InlineData("extension")]
    [InlineData("incoming-fk")]
    [InlineData("target-alias")]
    [InlineData("target-schema")]
    [InlineData("missing-message")]
    [InlineData("duplicate-message")]
    [InlineData("disposition")]
    [InlineData("target-version")]
    public void Contact_C_unknown_source_shape_or_dependency_rejects(string drift)
    {
        DatabaseSchemaPlan original = ContactRequestCollationTestSchema.CreateDraft();
        TableCopyPlan table = original.Tables[0];
        TableCopyPlan changed = drift switch
        {
            "column-order" => table with { OrderedColumns = table.OrderedColumns.Reverse().ToArray() },
            "target-type" => table with { ColumnTypes = new Dictionary<string, string>(table.ColumnTypes) { ["FirstName"] = "text" } },
            "source-type" => table with { SourceColumnTypes = new Dictionary<string, string>(table.SourceColumnTypes) { ["FirstName"] = "varchar(50)" } },
            "source-metadata" => table with { SourceColumns = [] },
            "nullable" => table with { NullableColumns = ["FirstName", .. table.NullableColumns] },
            "pk" => table with { PrimaryKey = new("Unexpected", ["ID"]) },
            "identity" => table with { Identities = [new("ID", 2, 1, 2, false)] },
            "default" => table with { DefaultExpressions = new Dictionary<string, string>() },
            "index" => table with { Indexes = [new("IX_FirstName", ["FirstName"], false)] },
            "unique" => table with { UniqueConstraints = [new("UQ_Email", ["Email"])] },
            "fk" => table with { ForeignKeys = [new("FK_Test", ["ID"], "public", "Other", ["ID"])] },
            "check" => table with { CheckConstraints = [new("CK_Test", "length(\"Email\") > 0") { Columns = ["Email"] }] },
            "generated" => table with { GeneratedColumns = [new("FirstName", "lower(\"LastName\")")] },
            "collation" => table with { Collations = new Dictionary<string, string> { ["Email"] = "C" } },
            "target-schema" => table with { TargetSchema = "unreviewed" },
            _ => table,
        };
        DatabaseSchemaPlan invalid = original with
        {
            TargetExtensionProfile = drift == "extension" ? "unreviewed" : null,
            TargetSchemaVersion = drift == "target-version" ? "unreviewed" : original.TargetSchemaVersion,
            SourceDispositionProfile = drift == "disposition" ? "unreviewed" : null,
            Tables = [changed],
        };
        if (drift == "missing-message")
        {
            invalid = invalid with { Tables = [] };
        }
        if (drift == "duplicate-message")
        {
            invalid = invalid with { Tables = [changed, changed] };
        }
        if (drift == "incoming-fk")
        {
            invalid = invalid with
            {
                Tables = [changed, table with
            {
                SourceTable = "Incoming", TargetTable = "Incoming",
                ForeignKeys = [new("FK_Incoming", ["ID"], "public", "Message", ["ID"])],
            }]
            };
        }
        if (drift == "target-alias")
        {
            invalid = invalid with { Tables = [changed, table with { SourceTable = "Alias" }] };
        }
        Assert.Equal("contact_request_collation_profile_invalid", Assert.Throws<MigrationExecutionException>(() =>
            ApprovedContactRequestCollationManifest.Apply(invalid, ContactRequestCollationProfile.ExplicitC)).Code);
    }

}

/// <summary>Synthetic unit/native-test source metadata for the reviewed Message shape; not an observed source authority.</summary>
public static class ContactRequestCollationTestSchema
{
    public static DatabaseSchemaPlan CreateDraft()
    {
        string[] columns = ["ID", "FirstName", "LastName", "Email", "Company", "Telephone", "MessageContent", "Country", "CreatedDate", "ModifiedDate"];
        var targetTypes = columns.ToDictionary(column => column, column => column switch
        {
            "ID" => "integer",
            "MessageContent" => "text",
            "CreatedDate" or "ModifiedDate" => "timestamp without time zone",
            _ => "character varying(50)",
        }, StringComparer.Ordinal);
        var sourceTypes = columns.ToDictionary(column => column, column => column switch
        {
            "ID" => "int",
            "MessageContent" => "nvarchar(max)",
            "CreatedDate" or "ModifiedDate" => "datetime",
            _ => "nvarchar(50)",
        }, StringComparer.Ordinal);
        var table = new TableCopyPlan("dbo", "Message", "public", "Message", columns, ["ID"])
        {
            ColumnTypes = targetTypes,
            SourceColumnTypes = sourceTypes,
            SourceColumns = [.. columns.Select(column => new SourceColumnInventory(column, sourceTypes[column], new string('a', 64), null))],
            PrimaryKey = new("PK_Message", ["ID"]),
            IdentityColumns = ["ID"],
            Identities = [new("ID", 1, 1, 1, false)],
            NullableColumns = ["Company", "Telephone", "CreatedDate", "ModifiedDate"],
            DefaultExpressions = new Dictionary<string, string>
            {
                ["CreatedDate"] = "(timezone('UTC'::text, CURRENT_TIMESTAMP))",
                ["ModifiedDate"] = "(timezone('UTC'::text, CURRENT_TIMESTAMP))",
            },
        };
        return new("ContactRequest", "1.0", "62fc0861aeacbd9272d16729fa5fcde80675042e8e80056e100f03a784742e54",
            new string('0', 64), [table]);
    }
}
