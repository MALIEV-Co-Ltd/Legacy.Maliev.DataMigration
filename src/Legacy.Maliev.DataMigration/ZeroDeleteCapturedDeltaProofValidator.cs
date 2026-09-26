namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Validates a captured exact-23 disposable proof for a zero-delete persistent-local plan.
/// This is a proof prerequisite, not authorization to run the Quotation physical transition
/// against persistent local PostgreSQL; schema-1.4 execution remains disposable-only.
/// </summary>
public static class ZeroDeleteCapturedDeltaProofValidator
{
    /// <summary>Rejects unsigned, mismatched, stale, or deleting captured plan pairs.</summary>
    public static void Verify(DeltaSynchronizationPlan proofPlan,
        Exact23DeltaReconciliationResult proofResult, DeltaSynchronizationPlan localPlan,
        FreshSchemaPlan schema, IReceiptAttestationTrustStore trust, DateTimeOffset nowUtc)
    {
        DisposableDeltaProofVerifier.Verify(proofPlan, proofResult, localPlan, schema, trust, nowUtc);
        if (proofPlan.SchemaVersion is not ("1.3" or "1.4") ||
            localPlan.SchemaVersion != proofPlan.SchemaVersion ||
            proofPlan.SourceCaptureManifest is null || localPlan.SourceCaptureManifest is null ||
            proofPlan.Databases.SelectMany(database => database.Tables).Any(table => table.DeleteCount != 0) ||
            localPlan.Databases.SelectMany(database => database.Tables).Any(table => table.DeleteCount != 0))
        {
            throw new DeltaExecutionException("delta_zero_delete_captured_proof_invalid",
                "A signed, matched, zero-delete captured exact-23 proof is required before local row execution.");
        }
    }
}
