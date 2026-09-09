namespace Legacy.Maliev.DataMigration.Console;

internal sealed class GuardedLocalDeltaFinalizationRuntime(
    IGuardedDeltaConsoleRuntime guardedRuntime,
    DeltaApplyRuntimeRequest applyRequest,
    DeltaReconcileRuntimeRequest reconcileRequest,
    Exact23RepresentativeServiceQueryValidator queryValidator,
    IReceiptAttestationTrustStore terminalReceiptTrust,
    string snapshotOutputDirectory,
    string snapshotId,
    ReadOnlyMemory<byte> snapshotEncryptionKey,
    IPostgreSqlDumpSource dumpSource,
    IMigrationEvidenceSigner evidenceSigner,
    TimeProvider timeProvider) : IExact23LocalDeltaFinalizationRuntime
{
    public Task<Exact23DeltaExecutionResult> ApplyAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        return guardedRuntime.ApplyAsync(applyRequest with { Plan = plan, Schema = schema }, cancellationToken);
    }

    public Task<Exact23DeltaReconciliationResult> ReconcileAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        return guardedRuntime.ReconcileAsync(reconcileRequest with { Plan = plan, Schema = schema }, cancellationToken);
    }

    public Task<Exact23RepresentativeServiceQueryEvidence> ValidateRepresentativeQueriesAsync(
        DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult terminalReceipt,
        CancellationToken cancellationToken)
    {
        return queryValidator.ValidateAsync(plan, applyRequest.Schema, terminalReceipt, cancellationToken);
    }

    public Task<LocalSnapshotManifest> ExportEncryptedSnapshotAsync(
        DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult terminalReceipt,
        Exact23RepresentativeServiceQueryEvidence queryEvidence,
        CancellationToken cancellationToken)
    {
        return LocalSnapshotExporter.ExportCanonicalDeltaAsync(terminalReceipt, terminalReceiptTrust,
            snapshotOutputDirectory, snapshotId, snapshotEncryptionKey, dumpSource, cancellationToken);
    }

    public Task<AppHostMigrationEvidenceV2Document> ProduceAppHostEvidenceAsync(
        DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult terminalReceipt,
        Exact23RepresentativeServiceQueryEvidence queryEvidence,
        LocalSnapshotManifest snapshot,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Exact23LocalDeltaAppHostEvidenceV2Producer.Produce(plan, applyRequest.Schema,
            terminalReceipt, queryEvidence, snapshot, terminalReceiptTrust, evidenceSigner, timeProvider));
    }
}
