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

        IReadOnlyList<SourceTableDisposition> dispositions =
            ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables);
        Assert.Collection(dispositions,
            archive =>
            {
                Assert.Equal("dbo.GoogleAnalyticsOutbox", $"{archive.SourceSchema}.{archive.SourceTable}");
                Assert.Equal("legacy_compatibility.GoogleAnalyticsOutbox", $"{archive.TargetSchema}.{archive.TargetTable}");
                Assert.Equal("read-only-archive", archive.Disposition);
            },
            adoption =>
            {
                Assert.Equal("dbo.QuotationOutcomeOutbox", $"{adoption.SourceSchema}.{adoption.SourceTable}");
                Assert.Equal("public.QuotationAcceptedOutcome", $"{adoption.TargetSchema}.{adoption.TargetTable}");
                Assert.Equal("canonical-adoption", adoption.Disposition);
            });
        Assert.All(dispositions, disposition =>
        {
            Assert.Equal(CurrentQuotationSourceContract.SourceContractSha256, disposition.SourceContractSha256);
            Assert.Equal("1.0", disposition.TargetSchemaVersion);
        });

        DatabaseSchemaPlan bound = unbound with
        {
            SourceDispositionProfile = profile,
            SourceTableDispositions = dispositions,
        };
        ApprovedSourceDispositionManifest.Validate(bound);
        var unsigned = new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow, new string('c', 40), [unbound]);
        Assert.NotEqual(SchemaPlanCanonicalizer.ComputeSha256(unsigned),
            SchemaPlanCanonicalizer.ComputeSha256(unsigned with { Databases = [bound] }));

        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedSourceDispositionManifest.Validate(
            bound with { Database = "Customer" }));
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedSourceDispositionManifest.Validate(
            bound with { SourceDispositionProfile = "unreviewed" }));
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedSourceDispositionManifest.Validate(
            bound with { SourceTableDispositions = [dispositions[1], dispositions[0]] }));
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedSourceDispositionManifest.Validate(
            bound with { SourceTableDispositions = [dispositions[0] with { TargetSchema = "public" }, dispositions[1]] }));
        _ = Assert.Throws<MigrationExecutionException>(() => ApprovedSourceDispositionManifest.Validate(
            bound with { SourceTableDispositions = [dispositions[0], dispositions[1] with { SourceContractSha256 = new string('0', 64) }] }));
        DatabaseSchemaPlan altered = bound with
        {
            SourceTableDispositions = [dispositions[0] with { TargetTable = "GoogleAnalyticsOutboxCopy" }, dispositions[1]],
        };
        Assert.NotEqual(SchemaPlanCanonicalizer.ComputeSha256(unsigned with { Databases = [bound] }),
            SchemaPlanCanonicalizer.ComputeSha256(unsigned with { Databases = [altered] }));
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

    [Fact]
    public void ReviewedQuotationTargetShape_UsesArchiveAndCanonicalOutcome_NotSourceNamedPublicTables()
    {
        TableCopyPlan[] tables =
        [
            Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox, "PK_GoogleAnalyticsOutbox",
                "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox, "PK_QuotationOutcomeOutbox",
                "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        var plan = new DatabaseSchemaPlan("Quotation", "1.0", new string('a', 64), new string('b', 64), tables)
        {
            SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
            SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables),
        };

        IReadOnlyList<TableCopyPlan> target = ApprovedSourceDispositionManifest.TargetTablesFor(plan);
        Assert.Equal(["legacy_compatibility.GoogleAnalyticsOutbox", "public.QuotationAcceptedOutcome"],
            target.Select(table => $"{table.TargetSchema}.{table.TargetTable}"));
        TableCopyPlan archive = target[0];
        Assert.Equal(tables[0].OrderedColumns, archive.OrderedColumns);
        Assert.Equal(tables[0].ColumnTypes, archive.ColumnTypes);
        Assert.Equal(tables[0].Identities, archive.Identities);
        TableCopyPlan accepted = target[1];
        Assert.Equal("timestamp without time zone", accepted.ColumnTypes["AcceptedUtc"]);
        Assert.Equal("smallint", accepted.ColumnTypes["AcceptedUtcSubMicrosecondTicks"]);
        Assert.Equal("0", accepted.DefaultExpressions["AcceptedUtcSubMicrosecondTicks"]);
        Assert.Equal(5, accepted.Indexes.Count);
        Assert.Contains(accepted.Indexes, index => index.Name == "IX_QuotationAcceptedOutcome_EventKey" && index.Unique);
        Assert.Matches("^[0-9a-f]{64}$", PostgreSqlSchemaFingerprint.ComputeExpected(plan));
        _ = Assert.Throws<MigrationExecutionException>(() =>
            ApprovedSourceDispositionManifest.TargetTablesFor(plan with { SourceTableDispositions = [] }));
    }

    internal static TableCopyPlan Outbox(
        SourceTableContract contract, string primaryKeyName, string eventKeyName, bool uniqueIndex)
    {
        string name = contract.Name["dbo.".Length..];
        var table = new TableCopyPlan("dbo", name, "public", name,
            [.. contract.Columns.Select(column => column.Name)], ["ID"])
        {
            SourceColumnTypes = contract.Columns.ToDictionary(column => column.Name,
                column => column.StoreType, StringComparer.Ordinal),
            ColumnTypes = contract.Columns.ToDictionary(column => column.Name,
                column => SqlServerTypeMapping.Map(column.StoreType), StringComparer.Ordinal),
            NullableColumns = [.. contract.Columns.Where(column => column.Nullable).Select(column => column.Name)],
            IdentityColumns = [.. contract.Columns.Where(column => column.Identity is not null).Select(column => column.Name)],
            Identities = [new IdentityCopyPlan("ID", 1, 1, 1, false)],
            PrimaryKey = new PrimaryKeyCopyPlan(primaryKeyName, ["ID"]),
            Indexes = uniqueIndex ? [new IndexCopyPlan(eventKeyName, ["EventKey"], true)] : [],
            UniqueConstraints = uniqueIndex ? [] : [new UniqueConstraintCopyPlan(eventKeyName, ["EventKey"])],
        };
        return table;
    }
}
