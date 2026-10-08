using System.Text.Json;
using Legacy.Maliev.DataMigration.Tests;

namespace Legacy.Maliev.DataMigration;

public sealed class ContactRequestCollationProducerTests
{
    [Fact]
    public void Contact_C_source_option_is_explicit_and_invalid_enum_rejects_before_connection()
    {
        var options = JsonSerializer.Deserialize<SqlServerMigrationSourceOptions>("{\"ConnectionString\":\"unused\"}");
        Assert.NotNull(options);
        Assert.Equal(ContactRequestCollationProfile.LegacyInherited, options.ContactRequestCollationProfile);
        Assert.Equal("contact_request_collation_profile_invalid", Assert.Throws<MigrationExecutionException>(() =>
            new SqlServerMigrationSource(new("unused") { ContactRequestCollationProfile = (ContactRequestCollationProfile)99 })).Code);
        SqlServerMigrationSourceOptions selected = Assert.IsType<SqlServerMigrationSourceOptions>(
            JsonSerializer.Deserialize<SqlServerMigrationSourceOptions>(
                "{\"ConnectionString\":\"unused\",\"ContactRequestCollationProfile\":\"ExplicitC\"}"));
        Assert.Equal(ContactRequestCollationProfile.ExplicitC, selected.ContactRequestCollationProfile);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Contact_C_source_SQL_projection_and_streaming_lengths_are_identical(bool supportsUtf8)
    {
        DatabaseSchemaPlan before = ContactRequestCollationTestSchema.CreateDraft();
        DatabaseSchemaPlan after = ApprovedContactRequestCollationManifest.Apply(before, ContactRequestCollationProfile.ExplicitC);
        string oldSql = SqlServerMigrationSource.BuildImmediateStreamingReadTableCommand(before.Tables[0], supportsUtf8);
        string newSql = SqlServerMigrationSource.BuildImmediateStreamingReadTableCommand(after.Tables[0], supportsUtf8);
        Assert.Equal(oldSql, newSql);
        Assert.Contains("DATALENGTH(", newSql, StringComparison.Ordinal);
        Assert.Contains("FROM [dbo].[Message] ORDER BY [ID]", newSql, StringComparison.Ordinal);
        Assert.DoesNotContain("COLLATE C", newSql, StringComparison.Ordinal);
        Assert.Equal(before.SourceSchemaSha256, after.SourceSchemaSha256);
    }
}
