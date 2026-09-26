namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ApprovedSourceDispositionManifestTests
{
    [Fact]
    public void ReviewedQuotationOutboxes_AreBoundToSignedSchemaPlan()
    {
        TableCopyPlan[] tables = [
            Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox, "PK_GoogleAnalyticsOutbox",
                "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox, "PK_QuotationOutcomeOutbox",
                "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        string profile = Assert.IsType<string>(ApprovedSourceDispositionManifest.ProfileForDatabase("Quotation", tables));
        Assert.Equal(ApprovedSourceDispositionManifest.QuotationOutboxesV1, profile);

        var unbound = new DatabaseSchemaPlan("Quotation", "1.0", new string('a', 64), new string('b', 64), tables);
        MigrationExecutionException missing = Assert.Throws<MigrationExecutionException>(
            () => ApprovedSourceDispositionManifest.Validate(unbound));
        Assert.Equal("source_disposition_profile_invalid", missing.Code);

        DatabaseSchemaPlan bound = unbound with { SourceDispositionProfile = profile };
        ApprovedSourceDispositionManifest.Validate(bound);
        var unsigned = new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow, new string('c', 40), [unbound]);
        Assert.NotEqual(SchemaPlanCanonicalizer.ComputeSha256(unsigned),
            SchemaPlanCanonicalizer.ComputeSha256(unsigned with { Databases = [bound] }));

        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedSourceDispositionManifest.Validate(
            bound with { Database = "Customer" }));
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedSourceDispositionManifest.Validate(
            bound with { SourceDispositionProfile = "unreviewed" }));
    }

    [Fact]
    public void MissingOrDriftedOutbox_FailsClosed()
    {
        TableCopyPlan analytics = Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
            "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true);
        TableCopyPlan outcome = Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
            "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false);
        _ = Assert.Throws<MigrationExecutionException>(() =>
            ApprovedSourceDispositionManifest.ProfileForDatabase("Quotation", [analytics]));
        _ = Assert.Throws<MigrationExecutionException>(() =>
            ApprovedSourceDispositionManifest.ProfileForDatabase("Quotation", [analytics, outcome with
            {
                SourceColumnTypes = outcome.SourceColumnTypes.ToDictionary(
                    pair => pair.Key, pair => pair.Key == "AcceptedUtc" ? "datetime" : pair.Value,
                    StringComparer.Ordinal),
            }]));
        _ = Assert.Throws<MigrationExecutionException>(() =>
            ApprovedSourceDispositionManifest.ProfileForDatabase("Quotation", [analytics, outcome with
            {
                UniqueConstraints = [],
            }]));
        _ = Assert.Throws<MigrationExecutionException>(() =>
            ApprovedSourceDispositionManifest.ProfileForDatabase("Quotation", [analytics, analytics, outcome]));
    }

    private static TableCopyPlan Outbox(
        SourceTableContract contract, string primaryKeyName, string eventKeyName, bool uniqueIndex)
    {
        string name = contract.Name["dbo.".Length..];
        var table = new TableCopyPlan("dbo", name, "public", name,
            [.. contract.Columns.Select(column => column.Name)], ["ID"])
        {
            SourceColumnTypes = contract.Columns.ToDictionary(column => column.Name,
                column => column.StoreType, StringComparer.Ordinal),
            NullableColumns = [.. contract.Columns.Where(column => column.Nullable).Select(column => column.Name)],
            IdentityColumns = [.. contract.Columns.Where(column => column.Identity is not null).Select(column => column.Name)],
            PrimaryKey = new PrimaryKeyCopyPlan(primaryKeyName, ["ID"]),
            Indexes = uniqueIndex ? [new IndexCopyPlan(eventKeyName, ["EventKey"], true)] : [],
            UniqueConstraints = uniqueIndex ? [] : [new UniqueConstraintCopyPlan(eventKeyName, ["EventKey"])],
        };
        return table;
    }
}
