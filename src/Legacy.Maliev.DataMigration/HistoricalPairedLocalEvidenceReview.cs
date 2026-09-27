namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Signature and checkpoint review of a past persistent LOCAL completion. This is
/// historical evidence only: it does not observe Docker, PostgreSQL, or current rows
/// and must never be used as an execution permit.
/// </summary>
public sealed record HistoricalPairedLocalEvidenceReview(
    string PlanSha256,
    string ReconciliationSha256,
    DateTimeOffset SourceCutoffUtc,
    DateTimeOffset ReconciledAtUtc,
    int DatabasesVerified)
{
    public static bool AuthorizesExecution => false;
}

public static class HistoricalPairedLocalEvidenceReviewer
{
    public static HistoricalPairedLocalEvidenceReview Verify(
        DeltaSynchronizationPlan? plan,
        Exact23DeltaReconciliationResult? receipt,
        IReceiptAttestationTrustStore trust,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(trust);
        // Evaluate intrinsic capture freshness as it was signed, not as an
        // execution freshness check against today's clock.
        if (plan is null || receipt is null || plan.Databases is null ||
            plan.SourceCaptureManifest?.Databases is null || receipt.Databases is null ||
            receipt.Checkpoints is null || nowUtc.Offset != TimeSpan.Zero ||
            plan.SchemaVersion != "1.4" || plan.PairedTransitionPlanOnly != true ||
            !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(plan.TargetAuthority) ||
            !ValidDockerBinding(plan) ||
            plan.CreatedAtUtc > nowUtc || receipt.ReconciledAtUtc > nowUtc ||
            receipt.ReconciledAtUtc < plan.CreatedAtUtc ||
            !DistinctSigners(plan, receipt, trust) ||
            !DeltaSynchronizationPlanVerifier.Verify(plan, trust, plan.CreatedAtUtc) ||
            !Exact23DeltaReconciliationCoordinator.Verify(receipt, trust) ||
            receipt.PlanId != plan.PlanId || receipt.SourceCutoffUtc != plan.SourceCutoffUtc)
        {
            throw Invalid();
        }

        string planHash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        if (!DeltaSynchronizationPlanProducer.FixedHashEquals(receipt.PlanSha256, planHash) ||
            !receipt.Databases.Select(database => database.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !receipt.Checkpoints.Select(checkpoint => checkpoint.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw Invalid();
        }

        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            DeltaDatabasePlan databasePlan = plan.Databases.Single(item => item.Database == database);
            DatabaseReconciliationEvidence evidence = receipt.Databases.Single(item => item.Database == database);
            DeltaDatabaseCheckpointEvidence checkpoint = receipt.Checkpoints.Single(item => item.Database == database);
            DeltaDatabaseCaptureBinding capture = plan.SourceCaptureManifest!.Databases.Single(item =>
                item.Database == database);
            string expectedPhysicalSchema = database == "Quotation"
                ? plan.QuotationTransitionSchemaSha256!
                : capture.SourceReconciliation.TargetSchemaSha256;
            if (!DeltaSynchronizationPlanProducer.FixedHashEquals(checkpoint.TargetObservationSha256,
                    plan.TargetObservationSha256) ||
                !DeltaSynchronizationPlanProducer.FixedHashEquals(checkpoint.OperationsSha256,
                    DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(databasePlan)) ||
                !DeltaSynchronizationPlanProducer.FixedHashEquals(evidence.SourceSchemaSha256,
                    capture.SourceReconciliation.SourceSchemaSha256) ||
                !DeltaSynchronizationPlanProducer.FixedHashEquals(evidence.TargetSchemaSha256,
                    expectedPhysicalSchema) ||
                !evidence.Tables.Select(table => table.Table).Order(StringComparer.Ordinal)
                    .SequenceEqual(databasePlan.Tables.Select(table => table.Table).Order(StringComparer.Ordinal),
                        StringComparer.Ordinal))
            {
                throw Invalid();
            }
        }

        return new(planHash, Exact23DeltaReconciliationCoordinator.ComputeSha256(receipt),
            plan.SourceCutoffUtc, receipt.ReconciledAtUtc, DatabaseInventory.ActiveDatabases.Count);
    }

    private static bool DistinctSigners(DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult receipt, IReceiptAttestationTrustStore trust)
    {
        return trust.TryGetPublicKeyFingerprintSha256(plan.AttestationKeyId, out string planKey) &&
            trust.TryGetPublicKeyFingerprintSha256(receipt.AttestationKeyId, out string evidenceKey) &&
            !DeltaSynchronizationPlanProducer.FixedHashEquals(planKey, evidenceKey) &&
            !DeltaSynchronizationPlanProducer.FixedHashEquals(evidenceKey,
                plan.ExecutionAuthorizationKeyFingerprintSha256) &&
            !DeltaSynchronizationPlanProducer.FixedHashEquals(evidenceKey,
                plan.BackupKeyFingerprintSha256);
    }

    private static bool ValidDockerBinding(DeltaSynchronizationPlan plan)
    {
        string[] parts = plan.TargetGeneration?.Split(':') ?? [];
        return parts.Length == 5 && parts[0] == "docker" && parts[1].Length == 64 &&
            parts[1].All(char.IsAsciiHexDigit) &&
            parts.Skip(2).All(part => long.TryParse(part,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out long value) && value > 0) &&
            plan.TargetAuthority?.AuthorityId ==
                "aspire://legacy-postgres-main-local/persistent-" + parts[1][..12];
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_historical_local_evidence_invalid",
            "The prior signed LOCAL plan and exact-23 reconciliation do not form a trusted historical completion.");
    }
}
