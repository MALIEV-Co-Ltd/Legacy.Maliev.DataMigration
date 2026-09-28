namespace Legacy.Maliev.DataMigration;

/// <summary>Read-only terminal comparison. The signed receipt is the completion evidence.</summary>
internal sealed record LocalRolloverTerminalReview(Guid ClaimId, string PlanSha256,
    string ReconciliationSha256, int AdoptedDatabases)
{
    internal static bool AuthorizesExecution => false;
}

internal static class LocalRolloverTerminalReviewer
{
    internal static LocalRolloverTerminalReview Verify(
        AuthenticatedHistoricalLocalRolloverSnapshot observed,
        DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult disposableProof,
        Exact23DeltaReconciliationResult terminalReceipt,
        IReceiptAttestationTrustStore trust)
    {
        string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        return !Exact23DeltaReconciliationCoordinator.Verify(terminalReceipt, trust) ||
            !Exact23DeltaReconciliationCoordinator.Verify(disposableProof, trust) ||
            plan.PlanId != terminalReceipt.PlanId ||
            plan.SourceCutoffUtc != terminalReceipt.SourceCutoffUtc ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(planSha256,
                terminalReceipt.PlanSha256) ||
            !PostgreSqlDeltaCanonicalTarget.Fixed(planSha256,
                observed.Claim.FuturePlanSha256) ||
            plan.TargetGeneration != observed.Claim.TargetGeneration ||
            terminalReceipt.ReconciledAtUtc > observed.ObservedAtUtc ||
            !observed.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            observed.Databases.Any(item =>
                item.Phase != HistoricalLocalRolloverDatabasePhase.Adopted ||
                !PostgreSqlDeltaCanonicalTarget.Hash(item.AdoptionJournalSha256 ?? string.Empty)) ||
            !disposableProof.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !terminalReceipt.Databases.Zip(disposableProof.Databases).All(pair =>
                PostgreSqlDeltaCanonicalTarget.Fixed(
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(pair.First),
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(pair.Second))) ||
            !terminalReceipt.Checkpoints.All(checkpoint =>
                PostgreSqlDeltaCanonicalTarget.Fixed(checkpoint.OperationsSha256,
                    DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(
                        plan.Databases.Single(item => item.Database == checkpoint.Database))))
            ? throw new DeltaExecutionException("delta_rollover_terminal_invalid",
                "A fresh exact-23 signed receipt and all-adopted target state are required.")
            : new(observed.Claim.ClaimId, planSha256,
            Exact23DeltaReconciliationCoordinator.ComputeSha256(terminalReceipt),
            DatabaseInventory.ActiveDatabases.Count);
    }
}
