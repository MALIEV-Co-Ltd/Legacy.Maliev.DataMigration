namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Checks two target-specific signed plans before publishing a paired capture.
/// This is plan-only and never admits a persistent-local apply.
/// </summary>
public static class PairedCapturedDeltaPlanPublicationGate
{
    /// <summary>Rejects stale, untrusted, deleting, or independently recaptured plan pairs.</summary>
    public static void Verify(PairedCapturedDeltaPlans plans, FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(plans);
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(trust);
        DeltaSynchronizationPlan disposable = plans.Disposable;
        DeltaSynchronizationPlan persistent = plans.Persistent;
        string schemaHash = SchemaPlanCanonicalizer.ComputeSha256(schema);
        if (nowUtc.Offset != TimeSpan.Zero ||
            disposable.CreatedAtUtc > nowUtc || persistent.CreatedAtUtc > nowUtc ||
            nowUtc - disposable.CreatedAtUtc > TimeSpan.FromHours(12) ||
            nowUtc - persistent.CreatedAtUtc > TimeSpan.FromHours(12) ||
            !DeltaSynchronizationPlanVerifier.Verify(disposable, trust, nowUtc) ||
            !DeltaSynchronizationPlanVerifier.Verify(persistent, trust, nowUtc) ||
            disposable.SchemaVersion is not ("1.3" or "1.4") ||
            persistent.SchemaVersion != disposable.SchemaVersion ||
            !MatchesTransition(schema, disposable, persistent) ||
            disposable.SourceCaptureManifest is null || persistent.SourceCaptureManifest is null ||
            disposable.Databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            persistent.Databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            !schema.Databases.Select(database => database.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !disposable.Databases.Select(database => database.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !persistent.Databases.Select(database => database.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            disposable.SourceMode != DeltaSourceMode.LiveReadOnly ||
            persistent.SourceMode != DeltaSourceMode.LiveReadOnly ||
            disposable.SourceCommitSha != schema.SourceCommitSha ||
            persistent.SourceCommitSha != schema.SourceCommitSha ||
            disposable.SchemaPlanSha256 != schemaHash || persistent.SchemaPlanSha256 != schemaHash ||
            disposable.SourceCutoffUtc != persistent.SourceCutoffUtc ||
            disposable.SourceCaptureCompletedAtUtc != persistent.SourceCaptureCompletedAtUtc ||
            disposable.SourceObservationSha256 != persistent.SourceObservationSha256 ||
            disposable.RunnerDigestSha256 != persistent.RunnerDigestSha256 ||
            disposable.BackupManifestSha256 != persistent.BackupManifestSha256 ||
            disposable.TargetAuthority?.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            persistent.TargetAuthority?.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(disposable.TargetAuthority) ||
            !persistent.TargetAuthority.AuthorityId.StartsWith(
                "aspire://legacy-postgres-main-local/persistent-", StringComparison.Ordinal) ||
            disposable.TargetAuthority.SystemIdentifierSha256 ==
                persistent.TargetAuthority.SystemIdentifierSha256 ||
            disposable.AttestationKeyId == persistent.AttestationKeyId ||
            schema.Databases.Any(database => !MatchesInventory(database, disposable, persistent)) ||
            disposable.Databases.SelectMany(database => database.Tables).Any(table => table.DeleteCount != 0) ||
            persistent.Databases.SelectMany(database => database.Tables).Any(table => table.DeleteCount != 0) ||
            !DisposableDeltaProofVerifier.MatchingOperations(disposable, persistent) ||
            !DisposableDeltaProofVerifier.MatchingCapturedSourceEvidence(disposable, persistent))
        {
            throw new DeltaPlanException("delta_paired_plan_publication_invalid",
                "A fresh signed zero-delete exact-23 pair from one captured source is required.");
        }
    }

    private static bool MatchesInventory(DatabaseSchemaPlan schema,
        DeltaSynchronizationPlan disposable, DeltaSynchronizationPlan persistent)
    {
        string[] expected = [.. new QuotationDeltaExecutionMapping(schema).TargetSchema.Tables
            .Select(table => $"{table.TargetSchema}.{table.TargetTable}").Order(StringComparer.Ordinal)];
        return disposable.Databases.Single(database => database.Database == schema.Database).Tables
                .Select(table => table.Table).Order(StringComparer.Ordinal)
                .SequenceEqual(expected, StringComparer.Ordinal) &&
            persistent.Databases.Single(database => database.Database == schema.Database).Tables
                .Select(table => table.Table).Order(StringComparer.Ordinal)
                .SequenceEqual(expected, StringComparer.Ordinal);
    }

    private static bool MatchesTransition(FreshSchemaPlan schema,
        DeltaSynchronizationPlan disposable, DeltaSynchronizationPlan persistent)
    {
        if (disposable.SchemaVersion == "1.3")
        {
            return disposable.QuotationTransitionSchemaSha256 is null &&
                persistent.QuotationTransitionSchemaSha256 is null &&
                disposable.PairedTransitionPlanOnly is null &&
                persistent.PairedTransitionPlanOnly is null;
        }

        DatabaseSchemaPlan? quotation = schema.Databases.SingleOrDefault(database =>
            database.Database == "Quotation");
        if (quotation is null || disposable.PairedTransitionPlanOnly is not null ||
            persistent.PairedTransitionPlanOnly != true)
        {
            return false;
        }
        try
        {
            string expected = PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(quotation, true);
            return DeltaSynchronizationPlanProducer.FixedHashEquals(
                    disposable.QuotationTransitionSchemaSha256 ?? string.Empty, expected) &&
                DeltaSynchronizationPlanProducer.FixedHashEquals(
                    persistent.QuotationTransitionSchemaSha256 ?? string.Empty, expected);
        }
        catch (MigrationExecutionException)
        {
            return false;
        }
    }
}
