using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentQuotationSourceContractTests
{
    private const string TargetSchemaSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Fact]
    public void SourceBinding_FreezesExactCurrentRevisionScriptsAndOutboxInventories()
    {
        Assert.Equal("7b4b2af697207d36a6e7b7784dddefa150193e97", CurrentQuotationSourceContract.SourceCommitSha);
        Assert.Equal(
        [
            new SourceScriptContract("Maliev.SqlServer/Deployments/2026-08-12-ga4-quotation-lifecycle.sql", "5f4e276c1a281625153aefbfef129fb20232ff053e3a3142483e79acc6db98c6"),
            new SourceScriptContract("Maliev.SqlServer/Deployments/2026-08-23-quotation-qualified-outcome.sql", "f112303fb61c53e80b470ac6f2a3e892bff6061da13efda46cf52a63423fb912"),
            new SourceScriptContract("Maliev.SqlServer/Deployments/2026-08-30-ga4-quotation-source-reconciliation.sql", "e713841ba8f056e37a7e233a58323859bf4ba9fc57eadd3a149a0a71759928fc"),
        ], CurrentQuotationSourceContract.SourceScripts);

        Assert.Equal(19, CurrentQuotationSourceContract.GoogleAnalyticsOutbox.Columns.Count);
        Assert.Equal(
            ["ID", "QuotationID", "EventKey", "EventName", "ClientId", "SessionId", "UserId", "Currency", "Value", "OccurredUtc", "AttemptCount", "NextAttemptUtc", "LeaseToken", "LeaseUntilUtc", "SentUtc", "FailedUtc", "LastError", "SourceRequestID", "SourceJourneyID"],
            CurrentQuotationSourceContract.GoogleAnalyticsOutbox.Columns.Select(column => column.Name).ToArray());
        Assert.Equal(
            ["ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc", "AcceptanceOrigin"],
            CurrentQuotationSourceContract.QuotationOutcomeOutbox.Columns.Select(column => column.Name).ToArray());

        SourceColumnContract analyticsId = CurrentQuotationSourceContract.GoogleAnalyticsOutbox.Columns[0];
        Assert.Equal(new SourceIdentityContract(1, 1), analyticsId.Identity);
        Assert.False(analyticsId.Nullable);
        Assert.Equal("bigint", analyticsId.StoreType);
        Assert.Equal("datetime2(7)", CurrentQuotationSourceContract.GoogleAnalyticsOutbox.Column("OccurredUtc").StoreType);
        Assert.True(CurrentQuotationSourceContract.GoogleAnalyticsOutbox.Column("SentUtc").Nullable);
        Assert.Equal("uniqueidentifier", CurrentQuotationSourceContract.GoogleAnalyticsOutbox.Column("SourceJourneyID").StoreType);

        Assert.Equal(new SourceIdentityContract(1, 1), CurrentQuotationSourceContract.QuotationOutcomeOutbox.Column("ID").Identity);
        Assert.False(CurrentQuotationSourceContract.QuotationOutcomeOutbox.Column("AcceptedUtc").Nullable);
        Assert.True(CurrentQuotationSourceContract.QuotationOutcomeOutbox.Column("SourceRequestID").Nullable);
        Assert.Contains("UX_GoogleAnalyticsOutbox_EventKey", CurrentQuotationSourceContract.GoogleAnalyticsOutbox.UniqueKeys);
        Assert.Contains("UQ_QuotationOutcomeOutbox_EventKey", CurrentQuotationSourceContract.QuotationOutcomeOutbox.UniqueKeys);
    }

    [Fact]
    public void Transform_MapsOnlyActualRowsPreservesNullsIdsTimestampsAndNextIdentity()
    {
        var source = new QuotationOutcomeSourceRow(
            41,
            "quotation-accepted:7001",
            7001,
            null,
            Guid.Parse("11111111-2222-3333-4444-555555555555"),
            new DateTime(2026, 8, 30, 8, 9, 10, 123, DateTimeKind.Unspecified).AddTicks(4567),
            "customer");

        QuotationOutcomeImportPlan plan = QuotationOutcomeTransformPlanner.Create([source], [], sourceNextIdentity: 57);

        QuotationAcceptedOutcomeImportRow row = Assert.Single(plan.Inserts);
        Assert.Equal(source.ID, row.ID);
        Assert.Equal(source.EventKey, row.EventKey);
        Assert.Equal(source.QuotationID, row.QuotationID);
        Assert.Null(row.SourceRequestID);
        Assert.Equal(source.SourceJourneyID, row.SourceJourneyID);
        Assert.Equal(source.AcceptedUtc, row.AcceptedUtc);
        Assert.Equal(DateTimeKind.Unspecified, row.AcceptedUtc.Kind);
        Assert.Equal(source.AcceptanceOrigin, row.AcceptanceOrigin);
        Assert.Equal(57, plan.NextIdentity);
        Assert.Empty(plan.AlreadyApplied);

        Assert.Empty(QuotationOutcomeTransformPlanner.Create([], [], sourceNextIdentity: 1).Inserts);
    }

    [Fact]
    public void Transform_ReplaySkipsByteEquivalentOutcomeAndRejectsConflictingEventKey()
    {
        var source = new QuotationOutcomeSourceRow(
            42, "quotation-accepted:7002", 7002, 91, null,
            new DateTime(2026, 8, 30, 9, 10, 11, DateTimeKind.Unspecified), "employee");
        QuotationAcceptedOutcomeImportRow existing = QuotationOutcomeTransformPlanner.Map(source);

        QuotationOutcomeImportPlan replay = QuotationOutcomeTransformPlanner.Create([source], [existing], sourceNextIdentity: 43);

        Assert.Empty(replay.Inserts);
        Assert.Equal([existing], replay.AlreadyApplied);

        QuotationAcceptedOutcomeImportRow conflict = existing with { AcceptanceOrigin = "customer" };
        QuotationOutcomeTransformException failure = Assert.Throws<QuotationOutcomeTransformException>(() =>
            QuotationOutcomeTransformPlanner.Create([source], [conflict], sourceNextIdentity: 43));
        Assert.Equal("quotation_outcome_replay_conflict", failure.Code);
    }

    [Fact]
    public void Transform_RejectsExistingIdentityAssignedToAnotherEvent()
    {
        var source = new QuotationOutcomeSourceRow(
            42, "quotation-accepted:7002", 7002, null, null,
            new DateTime(2026, 8, 30, 9, 10, 11, DateTimeKind.Unspecified), "employee");
        QuotationAcceptedOutcomeImportRow conflictingIdentity =
            QuotationOutcomeTransformPlanner.Map(source) with { EventKey = "quotation-accepted:other" };

        QuotationOutcomeTransformException failure = Assert.Throws<QuotationOutcomeTransformException>(() =>
            QuotationOutcomeTransformPlanner.Create([source], [conflictingIdentity], sourceNextIdentity: 43));

        Assert.Equal("quotation_outcome_replay_conflict", failure.Code);
    }

    [Fact]
    public void SignedContract_BindsLosslessMappingArchiveIsolationAndEfFirstDmlOnlyAdoption()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        QuotationOutcomeAdoptionContract unsigned = CurrentQuotationSourceContract.CreateAdoptionContract(
            TargetSchemaSha256, "quotation-adoption-review-key");
        QuotationOutcomeAdoptionContract signed = QuotationOutcomeAdoptionAttestation.Sign(unsigned, key);
        var trust = new ReceiptAttestationTrustStore(
        [
            new TrustedAttestationKey("quotation-adoption-review-key", key.ExportSubjectPublicKeyInfo()),
        ]);

        Assert.True(QuotationOutcomeAdoptionAttestation.Verify(signed, trust));
        Assert.Equal("dbo.QuotationOutcomeOutbox", signed.OutcomeSourceTable);
        Assert.Equal("QuotationAcceptedOutcome", signed.CanonicalTargetTable);
        Assert.Equal(
            ["ID", "EventKey", "QuotationID", "SourceRequestID", "SourceJourneyID", "AcceptedUtc", "AcceptanceOrigin"],
            signed.FieldMappings.Select(mapping => mapping.Source).ToArray());
        Assert.All(signed.FieldMappings, mapping => Assert.Equal(mapping.Source, mapping.Target));
        Assert.True(signed.PreserveSourceIdentity);
        Assert.True(signed.PreserveNextIdentity);
        Assert.False(signed.SynthesizeMissingAcceptedQuotations);
        Assert.Equal("legacy_compatibility.GoogleAnalyticsOutbox", signed.AnalyticsArchive.Table);
        Assert.True(signed.AnalyticsArchive.ReadOnly);
        Assert.False(signed.AnalyticsArchive.RuntimeWorkerEnabled);
        Assert.False(signed.AnalyticsArchive.DirectGoogleAnalyticsCredentialsAllowed);
        Assert.Equal("ef-schema-first-dml-only", signed.Adoption.Mode);
        Assert.False(signed.Adoption.ImporterMayExecuteDdl);

        Assert.False(QuotationOutcomeAdoptionAttestation.Verify(
            signed with { CanonicalTargetSchemaSha256 = new string('c', 64) }, trust));
    }

    [Fact]
    public void AdoptionGate_FailsClosedOnSchemaArchivePrivilegeOrExistingRowDrift()
    {
        QuotationOutcomeAdoptionContract contract = CurrentQuotationSourceContract.CreateAdoptionContract(
            TargetSchemaSha256, "quotation-adoption-review-key");
        var valid = new QuotationAdoptionObservation(
            contract.SourceCommitSha,
            contract.SourceContractSha256,
            TargetSchemaSha256,
            CanonicalSchemaCreatedByEf: true,
            ImporterExecutedDdl: false,
            AnalyticsArchivePrivileges: ["SELECT"],
            RuntimeWorkerConfigured: false,
            DirectGoogleAnalyticsCredentialsConfigured: false);

        QuotationOutcomeAdoptionValidator.Validate(contract, valid);

        foreach (QuotationAdoptionObservation drift in new[]
        {
            valid with { SourceContractSha256 = new string('0', 64) },
            valid with { CanonicalTargetSchemaSha256 = new string('0', 64) },
            valid with { CanonicalSchemaCreatedByEf = false },
            valid with { ImporterExecutedDdl = true },
            valid with { AnalyticsArchivePrivileges = ["SELECT", "UPDATE"] },
            valid with { RuntimeWorkerConfigured = true },
            valid with { DirectGoogleAnalyticsCredentialsConfigured = true },
        })
        {
            QuotationOutcomeAdoptionException failure = Assert.Throws<QuotationOutcomeAdoptionException>(() =>
                QuotationOutcomeAdoptionValidator.Validate(contract, drift));
            Assert.Equal("quotation_adoption_drift", failure.Code);
        }
    }
}
