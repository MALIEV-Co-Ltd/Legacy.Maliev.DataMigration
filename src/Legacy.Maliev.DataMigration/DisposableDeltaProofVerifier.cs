namespace Legacy.Maliev.DataMigration;

/// <summary>Validates a signed exact-23 disposable run before a persistent-local delta can be admitted.</summary>
public static class DisposableDeltaProofVerifier
{
    public static void Verify(
        DeltaSynchronizationPlan proofPlan,
        Exact23DeltaReconciliationResult proofResult,
        DeltaSynchronizationPlan localPlan,
        FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(proofPlan);
        ArgumentNullException.ThrowIfNull(proofResult);
        ArgumentNullException.ThrowIfNull(localPlan);
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(trust);

        if (nowUtc.Offset != TimeSpan.Zero ||
            !DeltaSynchronizationPlanVerifier.Verify(proofPlan, trust, nowUtc) ||
            !DeltaSynchronizationPlanVerifier.Verify(localPlan, trust, nowUtc) ||
            !Exact23DeltaReconciliationCoordinator.Verify(proofResult, trust) ||
            proofResult.PlanId != proofPlan.PlanId ||
            proofResult.SourceCutoffUtc != proofPlan.SourceCutoffUtc ||
            !string.Equals(proofResult.PlanSha256,
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(proofPlan), StringComparison.Ordinal) ||
            proofResult.Checkpoints.Any(checkpoint => !string.Equals(checkpoint.TargetObservationSha256,
                proofPlan.TargetObservationSha256, StringComparison.Ordinal)) ||
            !string.Equals(proofPlan.SourceMode, DeltaSourceMode.LiveReadOnly, StringComparison.Ordinal) ||
            !string.Equals(localPlan.SourceMode, DeltaSourceMode.LiveReadOnly, StringComparison.Ordinal) ||
            !string.Equals(proofPlan.SourceCommitSha, localPlan.SourceCommitSha, StringComparison.Ordinal) ||
            !string.Equals(proofPlan.SourceCommitSha, schema.SourceCommitSha, StringComparison.Ordinal) ||
            !string.Equals(proofPlan.SchemaPlanSha256, localPlan.SchemaPlanSha256, StringComparison.Ordinal) ||
            !string.Equals(proofPlan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(schema),
                StringComparison.Ordinal) ||
            !string.Equals(proofPlan.RunnerDigestSha256, localPlan.RunnerDigestSha256, StringComparison.Ordinal) ||
            !string.Equals(proofPlan.BackupManifestSha256, localPlan.BackupManifestSha256, StringComparison.Ordinal) ||
            !string.Equals(proofPlan.SourceObservationSha256, localPlan.SourceObservationSha256,
                StringComparison.Ordinal) ||
            proofPlan.TargetAuthority?.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            localPlan.TargetAuthority?.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !proofPlan.TargetAuthority.AuthorityId.StartsWith(
                "aspire://legacy-postgres-main-local/disposable-", StringComparison.Ordinal) ||
            !localPlan.TargetAuthority.AuthorityId.StartsWith(
                "aspire://legacy-postgres-main-local/persistent-", StringComparison.Ordinal) ||
            string.Equals(proofPlan.TargetAuthority.SystemIdentifierSha256,
                localPlan.TargetAuthority.SystemIdentifierSha256, StringComparison.Ordinal) ||
            string.Equals(proofPlan.TargetAuthority.AuthorityId,
                localPlan.TargetAuthority.AuthorityId, StringComparison.Ordinal) ||
            proofResult.ReconciledAtUtc > nowUtc ||
            proofResult.ReconciledAtUtc > localPlan.CreatedAtUtc ||
            nowUtc - proofResult.ReconciledAtUtc > TimeSpan.FromHours(12) ||
            proofPlan.Databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            proofResult.Databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            !schema.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            schema.Databases.Any(database => !MatchesTables(database, proofPlan, localPlan, proofResult)) ||
            !MatchingOperations(proofPlan, localPlan) ||
            !MatchingCapturedSourceEvidence(proofPlan, localPlan))
        {
            throw new DeltaExecutionException("delta_disposable_proof_invalid",
                "A fresh signed exact-23 disposable reconciliation for the same runner and source is required.");
        }
    }

    private static bool MatchesTables(DatabaseSchemaPlan schema, DeltaSynchronizationPlan proofPlan,
        DeltaSynchronizationPlan localPlan, Exact23DeltaReconciliationResult proofResult)
    {
        string[] expected = [.. new QuotationDeltaExecutionMapping(schema).TargetSchema.Tables
            .Select(item => $"{item.TargetSchema}.{item.TargetTable}").Order(StringComparer.Ordinal)];
        return proofPlan.Databases.Single(item => item.Database == schema.Database).Tables
                .Select(item => item.Table).Order(StringComparer.Ordinal).SequenceEqual(expected, StringComparer.Ordinal) &&
            localPlan.Databases.Single(item => item.Database == schema.Database).Tables
                .Select(item => item.Table).Order(StringComparer.Ordinal).SequenceEqual(expected, StringComparer.Ordinal) &&
            proofResult.Databases.Single(item => item.Database == schema.Database).Tables
                .Select(item => item.Table).Order(StringComparer.Ordinal).SequenceEqual(expected, StringComparer.Ordinal);
    }

    private static bool MatchingOperations(DeltaSynchronizationPlan proof, DeltaSynchronizationPlan local)
    {
        return proof.Databases.Zip(local.Databases).All(pair =>
            string.Equals(pair.First.Database, pair.Second.Database, StringComparison.Ordinal) &&
            pair.First.Tables.Count == pair.Second.Tables.Count &&
            pair.First.Tables.Zip(pair.Second.Tables).All(tables =>
                string.Equals(tables.First.Table, tables.Second.Table, StringComparison.Ordinal) &&
                tables.First.InsertCount == tables.Second.InsertCount &&
                tables.First.UpdateCount == tables.Second.UpdateCount &&
                tables.First.DeleteCount == tables.Second.DeleteCount &&
                tables.First.UnchangedCount == tables.Second.UnchangedCount &&
                string.Equals(tables.First.OperationsSha256, tables.Second.OperationsSha256,
                    StringComparison.Ordinal)));
    }

    private static bool MatchingCapturedSourceEvidence(
        DeltaSynchronizationPlan proof, DeltaSynchronizationPlan local)
    {
        return proof.SchemaVersion == local.SchemaVersion &&
            (proof.SchemaVersion != "1.3" ||
                (proof.SourceCaptureManifest is { } proofCapture &&
                 local.SourceCaptureManifest is { } localCapture &&
                 proofCapture.Databases.Zip(localCapture.Databases)
                     .All(pair => string.Equals(pair.First.Database, pair.Second.Database, StringComparison.Ordinal) &&
                         string.Equals(
                             DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(pair.First.SourceReconciliation),
                             DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(pair.Second.SourceReconciliation),
                             StringComparison.Ordinal))));
    }
}
