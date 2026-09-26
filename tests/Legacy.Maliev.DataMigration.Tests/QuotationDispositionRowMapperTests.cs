namespace Legacy.Maliev.DataMigration.Tests;

public sealed class QuotationDispositionRowMapperTests
{
    [Fact]
    public void AnalyticsArchive_PreservesAllDatetime2TicksAndNullableFields()
    {
        QuotationDispositionRowMapper mapper = new(Plan());
        DateTime time = new(2026, 9, 26, 12, 34, 56, DateTimeKind.Unspecified);
        time = time.AddTicks(1234567);
        var source = new MigrationRow(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = 17L,
            ["QuotationID"] = 41,
            ["EventKey"] = "synthetic-event-17",
            ["EventName"] = "quote_accepted",
            ["ClientId"] = "synthetic-client",
            ["SessionId"] = "synthetic-session",
            ["UserId"] = null,
            ["Currency"] = "THB",
            ["Value"] = 123.45m,
            ["OccurredUtc"] = time,
            ["AttemptCount"] = 1,
            ["NextAttemptUtc"] = time.AddTicks(2),
            ["LeaseToken"] = null,
            ["LeaseUntilUtc"] = null,
            ["SentUtc"] = time.AddTicks(1),
            ["FailedUtc"] = null,
            ["LastError"] = null,
            ["SourceRequestID"] = 3,
            ["SourceJourneyID"] = Guid.Parse("ee4c0b2b-9825-4d87-a880-8348d939167f"),
        });

        MigrationRow archived = mapper.MapAnalytics(source);
        Assert.Equal(24, archived.Values.Count);
        Assert.Equal("legacy_compatibility.GoogleAnalyticsOutbox",
            $"{mapper.AnalyticsArchive.TargetSchema}.{mapper.AnalyticsArchive.TargetTable}");
        foreach (string column in ApprovedSourceDispositionManifest.AnalyticsTimestampColumns)
        {
            object? original = source.Values[column];
            object? truncated = archived.Values[column];
            object? remainder = archived.Values[$"{column}SubMicrosecondTicks"];
            if (original is null)
            {
                Assert.Null(truncated);
                Assert.Null(remainder);
            }
            else
            {
                Assert.Equal((DateTime)original, ((DateTime)truncated!).AddTicks((short)remainder!));
                Assert.InRange((short)remainder!, (short)0, (short)9);
            }
        }
        Assert.Equal(source.Values["Value"], archived.Values["Value"]);
        string originalFingerprint = CanonicalRowFingerprint.Compute(mapper.AnalyticsArchive, [archived]);
        var changed = new Dictionary<string, object?>(archived.Values, StringComparer.Ordinal)
        {
            ["OccurredUtcSubMicrosecondTicks"] = (short)0,
        };
        Assert.NotEqual(originalFingerprint,
            CanonicalRowFingerprint.Compute(mapper.AnalyticsArchive, [new MigrationRow(changed)]));

        var wrongKind = new Dictionary<string, object?>(source.Values, StringComparer.Ordinal)
        {
            ["OccurredUtc"] = DateTime.SpecifyKind(time, DateTimeKind.Utc),
        };
        Assert.Equal("quotation_disposition_row_invalid", Assert.Throws<MigrationExecutionException>(
            () => mapper.MapAnalytics(new MigrationRow(wrongKind))).Code);
    }

    [Fact]
    public void AcceptedOutcome_PreservesIdentityNullableReferencesAndSubMicrosecondTicks()
    {
        QuotationDispositionRowMapper mapper = new(Plan());
        DateTime accepted = new DateTime(2026, 9, 26, 12, 34, 56, DateTimeKind.Unspecified).AddTicks(1234567);
        var source = new MigrationRow(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["ID"] = 30L,
            ["EventKey"] = "synthetic-accepted-30",
            ["QuotationID"] = 41,
            ["SourceRequestID"] = null,
            ["SourceJourneyID"] = null,
            ["AcceptedUtc"] = accepted,
            ["AcceptanceOrigin"] = "customer",
        });

        MigrationRow mapped = mapper.MapOutcome(source);
        Assert.Equal(8, mapped.Values.Count);
        Assert.Equal(30L, mapped.Values["ID"]);
        Assert.Null(mapped.Values["SourceRequestID"]);
        Assert.Null(mapped.Values["SourceJourneyID"]);
        Assert.Equal(accepted, ((DateTime)mapped.Values["AcceptedUtc"]!).AddTicks(
            (short)mapped.Values["AcceptedUtcSubMicrosecondTicks"]!));
        Assert.Equal((short)7, mapped.Values["AcceptedUtcSubMicrosecondTicks"]);

        var wrongShape = new Dictionary<string, object?>(source.Values, StringComparer.Ordinal);
        _ = wrongShape.Remove("EventKey");
        Assert.Equal("quotation_disposition_row_invalid", Assert.Throws<MigrationExecutionException>(
            () => mapper.MapOutcome(new MigrationRow(wrongShape))).Code);
        var wrongKind = new Dictionary<string, object?>(source.Values, StringComparer.Ordinal)
        {
            ["AcceptedUtc"] = DateTime.SpecifyKind(accepted, DateTimeKind.Utc),
        };
        Assert.Equal("quotation_outcome_source_invalid", Assert.Throws<MigrationExecutionException>(
            () => mapper.MapOutcome(new MigrationRow(wrongKind))).Code);
    }

    private static DatabaseSchemaPlan Plan()
    {
        TableCopyPlan[] tables =
        [
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        return new("Quotation", "1.0", new string('a', 64), new string('b', 64), tables)
        {
            SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
            SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables),
        };
    }
}
