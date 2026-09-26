using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

/// <summary>Plans from immutable encrypted per-database snapshots rather than mutable SQL rows.</summary>
public sealed class Exact23CapturedDeltaPlanCoordinator(
    IReadOnlyMigrationSource liveSource,
    IDeltaOrderedRowSource canonicalTarget,
    IDeltaReconciliationInspector sourceInspector,
    DeltaCapturedTableArchive archive,
    P256MigrationEvidenceSigner signer,
    TimeProvider timeProvider)
{
    public async Task<DeltaSynchronizationPlan> ProduceAsync(
        Exact23DeltaPlanRequest request,
        ReadOnlyMemory<byte> captureKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.SourceMode != DeltaSourceMode.LiveReadOnly || captureKey.Length != 32)
        {
            throw new DeltaPlanException("delta_capture_request_invalid",
                "Encrypted source capture requires a live read-only comparison and a fresh 256-bit key.");
        }
        DateTimeOffset preflightUtc = timeProvider.GetUtcNow();
        string keyFingerprint = Convert.ToHexString(SHA256.HashData(captureKey.Span)).ToLowerInvariant();
        if (request.SourceCutoffUtc.Offset != TimeSpan.Zero || request.SourceCutoffUtc > preflightUtc ||
            preflightUtc - request.SourceCutoffUtc > TimeSpan.FromHours(1) ||
            request.SourceObservationSha256 is null || request.SourceObservationSha256.Length != 64 ||
            !request.SourceObservationSha256.All(char.IsAsciiHexDigit) ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(request.TargetAuthority,
                request.TargetNamespace, request.TargetCluster) ||
            new[] { signer.PublicKeyFingerprintSha256, request.BackupKeyFingerprintSha256,
                request.ExecutionAuthorizationKeyFingerprintSha256 }.Any(value =>
                DeltaSynchronizationPlanProducer.FixedHashEquals(value, keyFingerprint)))
        {
            throw new DeltaPlanException("delta_capture_preflight_invalid",
                "The live source, target authority, cutoff, or capture key roles are invalid.");
        }
        Exact23DeltaPlanCoordinator.ValidateInventory(request.SchemaPlan);
        string schemaPlanSha256 = SchemaPlanCanonicalizer.ComputeSha256(request.SchemaPlan);
        var databasePlans = new List<DeltaDatabasePlan>(DatabaseInventory.ActiveDatabases.Count);
        var bindings = new List<DeltaDatabaseCaptureBinding>(DatabaseInventory.ActiveDatabases.Count);
        foreach (DatabaseSchemaPlan schema in request.SchemaPlan.Databases)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var mapping = new QuotationDeltaExecutionMapping(schema);
            DateTimeOffset startedAtUtc = timeProvider.GetUtcNow();
            var fullCaptures = new Dictionary<string, DeltaCapturedTableArtifact>(StringComparer.Ordinal);
            DatabaseReconciliationEvidence sourceEvidence;
            bool snapshotOpen = false;
            try
            {
                await liveSource.BeginDatabaseSnapshotAsync(schema.Database, cancellationToken).ConfigureAwait(false);
                snapshotOpen = true;
                foreach (TableCopyPlan table in OrderedTables(schema))
                {
                    DeltaCapturedTableArtifact full = await archive.CaptureAsync(schema.Database, table,
                        schemaPlanSha256,
                        liveSource.ReadTableImmediatelyAsync(schema.Database, table, cancellationToken),
                        captureKey, cancellationToken).ConfigureAwait(false);
                    fullCaptures.Add(Qualified(table), full);
                }
                sourceEvidence = await sourceInspector.InspectAsync(schema, cancellationToken).ConfigureAwait(false);
                if (!string.Equals(sourceEvidence.Database, schema.Database, StringComparison.Ordinal) ||
                    !DeltaSynchronizationPlanProducer.FixedHashEquals(
                        sourceEvidence.SourceSchemaSha256, schema.SourceSchemaSha256) ||
                    !DeltaSynchronizationPlanProducer.FixedHashEquals(
                        sourceEvidence.TargetSchemaSha256, schema.TargetSchemaSha256) ||
                    sourceEvidence.Tables.Count != fullCaptures.Count ||
                    sourceEvidence.Tables.Any(evidence =>
                    {
                        TableCopyPlan? target = mapping.TargetSchema.Tables.SingleOrDefault(table =>
                            Qualified(table) == evidence.Table);
                        return target is null ||
                            !fullCaptures.TryGetValue(Qualified(mapping.SourceTableFor(target)),
                                out DeltaCapturedTableArtifact? capture) ||
                            capture.RowCount != evidence.RowCount;
                    }))
                {
                    throw new DeltaPlanException("delta_capture_source_evidence_mismatch",
                        "The source snapshot reconciliation does not match its encrypted table captures.");
                }
                await liveSource.CompleteDatabaseSnapshotAsync(schema.Database, cancellationToken).ConfigureAwait(false);
                snapshotOpen = false;
            }
            catch
            {
                if (snapshotOpen)
                {
                    try
                    {
                        await liveSource.RollbackDatabaseSnapshotAsync(schema.Database, CancellationToken.None)
                            .ConfigureAwait(false);
                    }
                    catch (Exception rollbackFailure) when (rollbackFailure is InvalidOperationException or IOException)
                    {
                        // Preserve the capture or reconciliation failure.
                    }
                }
                throw;
            }

            DateTimeOffset completedAtUtc = timeProvider.GetUtcNow();
            var tablePlans = new List<DeltaTablePlan>(mapping.TargetSchema.Tables.Count);
            var tableBindings = new List<DeltaTableCaptureBinding>(mapping.TargetSchema.Tables.Count);
            foreach (TableCopyPlan table in OrderedTables(mapping.TargetSchema))
            {
                TableCopyPlan sourceTable = mapping.SourceTableFor(table);
                DeltaCapturedTableArtifact sourceFull = fullCaptures[Qualified(sourceTable)];
                DeltaCapturedTableArtifact full = sourceTable == table ? sourceFull :
                    await archive.CaptureAsync(schema.Database, table, schemaPlanSha256,
                        MapRows(archive.ReplayAsync(sourceFull, schema.Database, sourceTable,
                            schemaPlanSha256, captureKey, cancellationToken), mapping, table, cancellationToken),
                        captureKey, cancellationToken).ConfigureAwait(false);
                if (sourceFull != full)
                {
                    archive.DiscardRunOwned(sourceFull);
                }
                CanonicalTableDelta delta = await CanonicalAsyncDeltaPlanner.PlanAsync(table,
                    archive.ReplayAsync(full, schema.Database, table, schemaPlanSha256,
                        captureKey, cancellationToken),
                    canonicalTarget.ReadOrderedAsync(schema.Database, table, cancellationToken),
                    cancellationToken).ConfigureAwait(false);
                var planned = new DeltaTablePlan(delta.Table, delta.InsertCount, delta.UpdateCount,
                    delta.DeleteCount, delta.UnchangedCount,
                    DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(delta.Operations), delta.Operations);
                DeltaCapturedTableArtifact selected = await archive.CapturePlannedRowsAsync(full,
                    schema.Database, table, schemaPlanSha256, planned, captureKey, cancellationToken)
                    .ConfigureAwait(false);
                archive.DiscardRunOwned(full);
                tablePlans.Add(planned);
                tableBindings.Add(new(planned.Table, selected.CaptureId, selected.EncryptedSha256,
                    selected.PlaintextSha256, selected.RowCount, planned.OperationsSha256));
            }
            databasePlans.Add(new(schema.Database, tablePlans));
            bindings.Add(new(schema.Database, startedAtUtc, completedAtUtc, sourceEvidence, tableBindings));
        }

        DateTimeOffset nowUtc = timeProvider.GetUtcNow();
        return DeltaSynchronizationPlanProducer.Produce(new(
            request.SchemaPlan.SourceCommitSha,
            request.SourceCutoffUtc,
            request.BackupManifestSha256,
            schemaPlanSha256,
            request.RunnerDigestSha256,
            request.TargetNamespace,
            request.TargetCluster,
            request.TargetGeneration,
            request.TargetObservationSha256,
            request.BackupKeyFingerprintSha256,
            request.ExecutionAuthorizationKeyFingerprintSha256,
            databasePlans)
        {
            TargetAuthority = request.TargetAuthority,
            SourceMode = request.SourceMode,
            SourceObservationSha256 = request.SourceObservationSha256,
            SourceCaptureCompletedAtUtc = nowUtc,
            SourceCaptureManifest = new(keyFingerprint, bindings),
        }, signer, nowUtc);
    }

    private static IEnumerable<TableCopyPlan> OrderedTables(DatabaseSchemaPlan schema)
    {
        return schema.Tables.OrderBy(Qualified, StringComparer.Ordinal);
    }

    private static async IAsyncEnumerable<MigrationRow> MapRows(
        IAsyncEnumerable<MigrationRow> rows,
        QuotationDeltaExecutionMapping mapping,
        TableCopyPlan target,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (MigrationRow row in rows.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            yield return mapping.MapRow(target, row);
        }
    }

    private static string Qualified(TableCopyPlan table)
    {
        return $"{table.TargetSchema}.{table.TargetTable}";
    }
}
