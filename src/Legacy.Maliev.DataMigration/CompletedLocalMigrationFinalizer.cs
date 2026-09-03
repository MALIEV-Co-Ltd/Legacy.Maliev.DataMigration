using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Authenticated local-only completion with no execution signer, remote adapter or native-tool dependency.</summary>
public static class CompletedLocalMigrationFinalizer
{
    /// <summary>Verifies exact admission, terminal receipt, checkpoint and local inventories under the original Windows binding, then publishes or replays unchanged.</summary>
    public static async Task<IncrementalMigrationResult> FinalizeAsync(RecoveryJournalSnapshot snapshot, RecoveryAuthorityVerificationOptions verification,
        string root, string output, string snapshotId, ReadOnlyMemory<byte> rootKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshot); ArgumentNullException.ThrowIfNull(verification);
        MigrationExecutionReceipt receipt = AdmittedSequentialMigrationCoordinator.ValidateCompletion(snapshot.Admission, verification, snapshot);
        DatabaseMigrationCheckpoint[] checkpoints = AdmittedSequentialMigrationCoordinator.ReadCheckpoints(snapshot.Baseline);
        FreshSchemaPlan plan = JsonSerializer.Deserialize<FreshSchemaPlan>(snapshot.Admission.Payload.OriginalSchemaPlanJson)!;
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(root, snapshot.Admission.Payload.LocalBinding);
        using var store = IncrementalLocalSnapshotStore.OpenCompleted(root, snapshotId, rootKey,
            new(new(snapshot.Admission.Payload.Identity, plan, verification.TrustStore)), GuardAsync);
        IReadOnlyList<DatabaseMigrationCheckpoint> local = await store.ReadVerifiedCheckpointsAsync(cancellationToken).ConfigureAwait(false);
        if (!AdmittedSequentialMigrationCoordinator.SameCheckpoints(checkpoints, local))
        { throw new MigrationExecutionException("completed_local_inventory_incomplete", "Completed finalization requires the exact authenticated local checkpoint inventory."); }
        await GuardAsync(cancellationToken).ConfigureAwait(false);
        LocalSnapshotManifest manifest = await store.FinalizeAsync(output, checkpoints, cancellationToken).ConfigureAwait(false);
        return new(receipt, manifest, new(null, checkpoints.Length, 0, checkpoints.Length));

        Task GuardAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); authority.ValidateHeld();
            _ = AdmittedSequentialMigrationCoordinator.ValidateCompletion(snapshot.Admission, verification, snapshot);
            return Task.CompletedTask;
        }
    }
}
