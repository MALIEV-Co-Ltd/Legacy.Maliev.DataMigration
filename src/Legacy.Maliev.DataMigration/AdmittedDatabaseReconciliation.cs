using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public sealed partial class AdmittedSequentialMigrationCoordinator
{
    private async Task<DatabaseReconciliationEvidence?> ReconcileAsync(ShadowDatabase shadow, DatabaseSchemaPlan plan,
        DatabaseMigrationCheckpoint? checkpoint, CancellationToken token)
    {
        IPostgreSqlShadowRecoverySession session = await _runtime.Recovery.BeginReadOnlyRecoveryAsync(shadow, token).ConfigureAwait(false);
        Exception? primary = null;
        try
        {
            PostgreSqlShadowRecoveryInspection target = await session.InspectAsync(plan, token).ConfigureAwait(false);
            Require(target.OriginalShadow == shadow, "shadow_ownership_invalid");
            if (target.IsVerifiedEmpty)
            {
                Require(checkpoint is null && target.TargetSchemaSha256 is null && target.Tables.Count == 0 && target.SequenceNextValues.Count == 0, "checkpoint_target_empty");
                return null;
            }
            ReconciliationDiagnostics.CompareSchema(plan.Database, plan.TargetSchemaSha256, target.TargetSchemaSha256!);
            Require(target.Tables.Select(item => item.Table).Order(StringComparer.Ordinal).SequenceEqual(
                plan.Tables.Select(table => $"{table.TargetSchema}.{table.TargetTable}").Order(StringComparer.Ordinal), StringComparer.Ordinal), "target_table_inventory_mismatch");
            foreach (TableCopyPlan table in plan.Tables)
            {
                using var collector = new TableEvidenceCollector(table);
                await foreach (MigrationRow row in _runtime.Source.ReadTableAsync(plan.Database, table, token).WithCancellation(token).ConfigureAwait(false))
                {
                    foreach (StreamingLob lob in row.Values.Values.OfType<StreamingLob>()) { await lob.ConsumeAsync(Stream.Null, token).ConfigureAwait(false); }
                    collector.Append(row);
                }
                TableReconciliationEvidence source = collector.Finish() with
                {
                    ForeignKeyOrphanCounts = await _runtime.Source.InspectForeignKeyOrphansAsync(plan.Database, table, token).ConfigureAwait(false),
                    ForeignKeyRelationshipCounts = await _runtime.Source.InspectForeignKeyRelationshipsAsync(plan.Database, table, token).ConfigureAwait(false),
                };
                Require(!table.SourceKnownEmpty || source.RowCount == 0, "source_empty_table_drift");
                ReconciliationDiagnostics.CompareTable(plan.Database, source, target.Tables.Single(item => item.Table == source.Table));
            }
            IReadOnlyDictionary<string, long> sequences = await _runtime.Source.InspectSequenceNextValuesAsync(plan.Database, plan, token).ConfigureAwait(false);
            ReconciliationDiagnostics.CompareSequences(plan, sequences, target.SequenceNextValues);
            var reconciled = new DatabaseReconciliationEvidence(plan.Database, plan.SourceSchemaSha256, target.TargetSchemaSha256!, target.Tables)
            { SequenceNextValues = target.SequenceNextValues };
            if (checkpoint is not null)
            {
                _checkpoints.Validate(checkpoint, shadow);
                Require(EqualEvidence(checkpoint.Reconciliation, reconciled), "checkpoint_reconciliation_mismatch");
            }
            return reconciled;
        }
        catch (Exception failure) { primary = failure; throw; }
        finally
        {
            try { await session.DisposeAsync().ConfigureAwait(false); }
            catch (Exception secondary) when (primary is not null) { primary.Data["recovery_dispose_failure"] = secondary.GetType().Name; }
        }
    }

    private async Task<RestoredSourceObservation> ObserveSourceAsync(CancellationToken token)
    {
        RestoredSourceObservation observed = await _runtime.ObserveSource(token).ConfigureAwait(false);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Require(observed.ObservedAtUtc.Offset == TimeSpan.Zero && observed.ObservedAtUtc >= _admission.Payload.AdmittedAtUtc &&
            observed.ObservedAtUtc <= now && now - observed.ObservedAtUtc <= _admission.Payload.MaximumObservationAge &&
            observed.ComputeStableStateSha256() == _admission.Payload.SourceObservation.ComputeStableStateSha256(), "source_continuity_drift");
        return observed;
    }

    private void ValidateRuntime(FreshRunnerObservation runner, FreshTargetObservation target)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        ExecutionAuthorizationReceipt original = OriginalMigrationDocumentReader.Read<ExecutionAuthorizationReceipt>(_admission.Payload.OriginalAuthorizationJson);
        Require(runner.ObservedAtUtc >= _admission.Payload.AdmittedAtUtc && runner.ObservedAtUtc <= now && runner.ObservedAtUtc.Offset == TimeSpan.Zero &&
            now - runner.ObservedAtUtc <= _admission.Payload.MaximumObservationAge && runner.RunnerDigestSha256 == _admission.Payload.Identity.RunnerDigestSha256,
            "runtime_runner_drift");
        Require(target.ObservedAtUtc >= _admission.Payload.AdmittedAtUtc && target.ObservedAtUtc <= now && target.ObservedAtUtc.Offset == TimeSpan.Zero &&
            now - target.ObservedAtUtc <= _admission.Payload.MaximumObservationAge && target.Target == original.TargetObservation, "runtime_target_drift");
    }

    private void ValidateRegisteredState(IReadOnlyList<ShadowDatabase> shadows, IReadOnlyList<DatabaseMigrationCheckpoint> checkpoints,
        RecoveryJournalBaseline? original)
    {
        Require(shadows.Select(item => item.Database).Distinct(StringComparer.Ordinal).Count() == shadows.Count &&
            checkpoints.Select(item => item.Database.Database).Distinct(StringComparer.Ordinal).Count() == checkpoints.Count, "journal_inventory_invalid");
        if (original is null) { Require(shadows.Count == 0 && checkpoints.Count == 0, "initial_journal_state_conflict"); }
        else
        {
            Require(shadows.OrderBy(item => item.Database, StringComparer.Ordinal).SequenceEqual(original.Shadows.Select(item => item.Shadow).OrderBy(item => item.Database, StringComparer.Ordinal)) &&
                SameCheckpoints(checkpoints, ReadCheckpoints(original)), "journal_recovery_divergence");
        }
        foreach (DatabaseMigrationCheckpoint checkpoint in checkpoints)
        { _checkpoints.Validate(checkpoint, shadows.Single(item => item.Database == checkpoint.Database.Database)); }
    }

    private static void ValidateLocalSubset(IReadOnlyList<DatabaseMigrationCheckpoint> local, RecoveryJournalBaseline baseline)
    {
        foreach (DatabaseMigrationCheckpoint checkpoint in local)
        {
            string json = CheckpointJson(checkpoint);
            Require(baseline.Checkpoints.Count(item => item.Database == checkpoint.Database.Database && item.SignedCheckpointJson == json) == 1,
                "local_journal_divergence");
        }
    }

    private async Task<DateTimeOffset> ReadSigningTimeAsync(MigrationRunLease lease, IReadOnlyList<DatabaseMigrationCheckpoint> expected,
        ShadowDatabase? shadow, CancellationToken token)
    {
        // Observe the journal clock after the work being attested, never derive it from a prior lease.
        // This read grants no write authority; locked journal writes must still validate the live lease.
        RecoveryJournalSnapshot snapshot = await _runtime.Journal.ReadRecoverySnapshotAsync(_admission.Payload.Identity, token).ConfigureAwait(false);
        RecoveryJournalBaseline baseline = snapshot.Baseline;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Require(snapshot.Admission.ExactJson == _admission.ExactJson && baseline.Identity == _admission.Payload.Identity &&
            lease.Identity == baseline.Identity && baseline.Status == "in_progress" && baseline.LeaseOwner == lease.Owner &&
            baseline.LeaseAttempt == lease.Attempt && baseline.FencingToken == lease.FencingToken &&
            snapshot.LeaseExpiresAtUtc > snapshot.ObservedAtUtc, "signing_snapshot_invalid");
        Require(snapshot.ObservedAtUtc.Offset == TimeSpan.Zero && snapshot.ObservedAtUtc >= _admission.Payload.AdmittedAtUtc &&
            snapshot.ObservedAtUtc <= now && now - snapshot.ObservedAtUtc <= _admission.Payload.MaximumObservationAge, "signing_snapshot_stale");
        _ = _authorityVerifier.GetPermittedOperations(_admission, baseline, snapshot.ObservedAtUtc);
        Require(SameCheckpoints(ReadCheckpoints(baseline), expected) &&
            (shadow is null || baseline.Shadows.Count(item => item.Shadow == shadow) == 1), "signing_snapshot_divergence");
        return snapshot.ObservedAtUtc;
    }

    private DatabaseMigrationCheckpoint SignCheckpoint(ShadowDatabase shadow, DatabaseReconciliationEvidence evidence, DateTimeOffset committedAt)
    {
        var database = new MigratedShadowDatabase(shadow.Database, shadow.Name, evidence.Tables.Sum(item => item.RowCount), GuardedShadowMigrationRunner.HashEvidence(evidence.Tables))
        { OwnerAttempt = shadow.OwnerAttempt, FencingToken = shadow.FencingToken };
        var unsigned = new DatabaseMigrationCheckpoint(_admission.Payload.Identity, shadow, database, evidence, committedAt, _signer.KeyId, null);
        var signed = unsigned with { AttestationSignature = Convert.ToBase64String(_signer.Sign(MigrationEvidenceAttestation.CreatePayload(unsigned))) };
        _checkpoints.Validate(signed, shadow);
        return signed;
    }

    private MigrationExecutionReceipt SignCompletion(IReadOnlyList<DatabaseMigrationCheckpoint> checkpoints, DateTimeOffset completedAt)
    {
        Require(checkpoints.Select(item => item.Database.Database).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal)),
            "terminal_checkpoint_inventory_incomplete");
        MigrationRunIdentity identity = _admission.Payload.Identity;
        DatabaseMigrationCheckpoint[] sorted = [.. checkpoints.OrderBy(item => item.Database.Database, StringComparer.Ordinal)];
        var unsigned = new MigrationExecutionReceipt(identity.RunId, identity.SourceCommitSha, identity.SchemaPlanSha256, identity.BackupManifestSha256,
            identity.RunnerDigestSha256, identity.TargetGeneration, completedAt, sorted.Select(item => item.Database).ToArray(),
            sorted.Select(item => item.Reconciliation).ToArray(), _signer.KeyId, null);
        byte[] payload = MigrationEvidenceAttestation.CreatePayload(unsigned), signature = _signer.Sign(payload);
        Require(_verification.TrustStore.Verify(_signer.KeyId, payload, signature), "execution_signer_invalid");
        return unsigned with { AttestationSignature = Convert.ToBase64String(signature) };
    }

    private MigrationExecutionReceipt ValidateCompletion(RecoveryJournalSnapshot snapshot)
    {
        return ValidateCompletion(_admission, _verification, snapshot);
    }

    internal static MigrationExecutionReceipt ValidateCompletion(InitialMigrationAdmission admission,
        RecoveryAuthorityVerificationOptions verification, RecoveryJournalSnapshot snapshot)
    {
        var authorityVerifier = new RecoveryAuthorityVerifier(verification);
        authorityVerifier.ValidateAdmission(admission, DateTimeOffset.UtcNow);
        Require(snapshot.Baseline.Status == "completed" && snapshot.ObservedAtUtc.Offset == TimeSpan.Zero && snapshot.ObservedAtUtc <= DateTimeOffset.UtcNow,
            "completed_snapshot_invalid");
        // Same reviewed checkpoint-only authentication projection as the journal; no lease or recovery operation is acquired.
        _ = authorityVerifier.GetPermittedOperations(admission, snapshot.Baseline with { Status = "in_progress" }, snapshot.ObservedAtUtc);
        try
        {
            MigrationExecutionReceipt receipt = JsonSerializer.Deserialize<MigrationExecutionReceipt>(snapshot.Baseline.TerminalReceiptSignedJson!)!;
            Require(receipt is not null && MigrationRunIdentity.FromReceipt(receipt) == admission.Payload.Identity &&
                receipt.AttestationKeyId == verification.Roles.ExecutionKeyId && verification.TrustStore.Verify(receipt.AttestationKeyId,
                    MigrationEvidenceAttestation.CreatePayload(receipt), Convert.FromBase64String(receipt.AttestationSignature!)), "completed_receipt_invalid");
            DatabaseMigrationCheckpoint[] full = ReadCheckpoints(snapshot.Baseline);
            Require(full.Length == DatabaseInventory.ActiveDatabases.Count && receipt!.Databases.Count == full.Length && receipt.Reconciliation.Count == full.Length &&
                receipt.Databases.Select(item => item.Database).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal)) &&
                receipt.Reconciliation.Select(item => item.Database).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal)) &&
                receipt.CompletedAtUtc.Offset == TimeSpan.Zero && receipt.CompletedAtUtc <= snapshot.ObservedAtUtc, "completed_receipt_invalid");
            foreach (DatabaseMigrationCheckpoint checkpoint in full)
            {
                Require(receipt!.CompletedAtUtc >= checkpoint.CommittedAtUtc && receipt.Databases.Single(item => item.Database == checkpoint.Database.Database) == checkpoint.Database &&
                    EqualEvidence(receipt.Reconciliation.Single(item => item.Database == checkpoint.Database.Database), checkpoint.Reconciliation), "completed_receipt_invalid");
            }
            return receipt!;
        }
        catch (Exception failure) when (failure is JsonException or FormatException or ArgumentException or InvalidOperationException or NullReferenceException)
        { throw new MigrationExecutionException("completed_receipt_invalid", "The exact signed terminal receipt is malformed or incomplete.", failure); }
    }

    internal static DatabaseMigrationCheckpoint[] ReadCheckpoints(RecoveryJournalBaseline baseline)
    {
        return [.. baseline.Checkpoints.Select(item => JsonSerializer.Deserialize<DatabaseMigrationCheckpoint>(item.SignedCheckpointJson)!)];
    }

    internal static bool SameCheckpoints(IEnumerable<DatabaseMigrationCheckpoint> first, IEnumerable<DatabaseMigrationCheckpoint> second)
    {
        return first.Select(CheckpointJson).Order(StringComparer.Ordinal).SequenceEqual(second.Select(CheckpointJson).Order(StringComparer.Ordinal), StringComparer.Ordinal);
    }

    private static string CheckpointJson(DatabaseMigrationCheckpoint checkpoint)
    {
        return Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint));
    }

    private static bool EqualEvidence(DatabaseReconciliationEvidence first, DatabaseReconciliationEvidence second)
    {
        return JsonElement.DeepEquals(JsonSerializer.SerializeToElement(first), JsonSerializer.SerializeToElement(second));
    }
}
