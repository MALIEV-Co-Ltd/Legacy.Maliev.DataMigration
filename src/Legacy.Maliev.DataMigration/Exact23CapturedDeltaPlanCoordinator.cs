using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

/// <summary>Two target-bound plans derived from one immutable source capture.</summary>
public sealed record PairedCapturedDeltaPlans(DeltaSynchronizationPlan Disposable, DeltaSynchronizationPlan Persistent);

/// <summary>Plans from immutable encrypted per-database snapshots rather than mutable SQL rows.</summary>
public sealed class Exact23CapturedDeltaPlanCoordinator(
    IReadOnlyMigrationSource liveSource,
    IDeltaDatabaseSnapshotRowSource canonicalTarget,
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
        PairedCapturedDeltaPlans plans = await ProduceCoreAsync(request, null, null, null,
            captureKey, cancellationToken).ConfigureAwait(false);
        return plans.Disposable;
    }

    /// <summary>Plans disposable and persistent-local targets from the same per-database captures; does not authorize apply.</summary>
    public Task<PairedCapturedDeltaPlans> ProducePairedAsync(
        Exact23DeltaPlanRequest disposableRequest,
        Exact23DeltaPlanRequest persistentRequest,
        IDeltaDatabaseSnapshotRowSource persistentTarget,
        P256MigrationEvidenceSigner persistentSigner,
        ReadOnlyMemory<byte> captureKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(persistentRequest);
        ArgumentNullException.ThrowIfNull(persistentTarget);
        ArgumentNullException.ThrowIfNull(persistentSigner);
        return ProduceCoreAsync(disposableRequest, persistentRequest, persistentTarget, persistentSigner,
            captureKey, cancellationToken);
    }

    private async Task<PairedCapturedDeltaPlans> ProduceCoreAsync(
        Exact23DeltaPlanRequest request,
        Exact23DeltaPlanRequest? persistentRequest,
        IDeltaDatabaseSnapshotRowSource? persistentTarget,
        P256MigrationEvidenceSigner? persistentSigner,
        ReadOnlyMemory<byte> captureKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.SourceMode != DeltaSourceMode.LiveReadOnly || captureKey.Length != 32)
        {
            throw new DeltaPlanException("delta_capture_request_invalid",
                "Encrypted source capture requires a live read-only comparison and a fresh 256-bit key.");
        }
        if (request.UseQuotationPhysicalTransition &&
            (persistentRequest is not null ||
             !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(request.TargetAuthority)))
        {
            throw new DeltaPlanException("delta_quotation_transition_plan_invalid",
                "The Quotation physical transition is limited to an unpaired disposable-local capture.");
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
        if (persistentRequest is not null &&
            (persistentTarget is null || persistentSigner is null ||
             ReferenceEquals(persistentTarget, canonicalTarget) ||
             persistentRequest.SourceMode != DeltaSourceMode.LiveReadOnly ||
             persistentRequest.SourceCutoffUtc != request.SourceCutoffUtc ||
             persistentRequest.SourceObservationSha256 != request.SourceObservationSha256 ||
             SchemaPlanCanonicalizer.ComputeSha256(persistentRequest.SchemaPlan) !=
                SchemaPlanCanonicalizer.ComputeSha256(request.SchemaPlan) ||
             persistentRequest.BackupManifestSha256 != request.BackupManifestSha256 ||
             persistentRequest.RunnerDigestSha256 != request.RunnerDigestSha256 ||
             request.TargetAuthority?.Kind != DeltaTargetAuthorityKind.LocalAspire ||
             persistentRequest.TargetAuthority?.Kind != DeltaTargetAuthorityKind.LocalAspire ||
             !request.TargetAuthority.AuthorityId.StartsWith(
                 "aspire://legacy-postgres-main-local/disposable-", StringComparison.Ordinal) ||
             !persistentRequest.TargetAuthority.AuthorityId.StartsWith(
                 "aspire://legacy-postgres-main-local/persistent-", StringComparison.Ordinal) ||
             request.TargetAuthority.SystemIdentifierSha256 == persistentRequest.TargetAuthority.SystemIdentifierSha256 ||
             request.TargetObservationSha256 == persistentRequest.TargetObservationSha256 ||
             !DeltaSynchronizationPlanProducer.ValidAuthority(persistentRequest.TargetAuthority,
                 persistentRequest.TargetNamespace, persistentRequest.TargetCluster) ||
             persistentSigner.PublicKeyFingerprintSha256 == signer.PublicKeyFingerprintSha256 ||
             new[] { persistentSigner.PublicKeyFingerprintSha256,
                 persistentRequest.BackupKeyFingerprintSha256,
                 persistentRequest.ExecutionAuthorizationKeyFingerprintSha256 }.Any(value =>
                 DeltaSynchronizationPlanProducer.FixedHashEquals(value, keyFingerprint))))
        {
            throw new DeltaPlanException("delta_capture_paired_preflight_invalid",
                "Paired plans require distinct disposable and persistent-local targets and trusted key roles.");
        }
        Exact23DeltaPlanCoordinator.ValidateInventory(request.SchemaPlan);
        string schemaPlanSha256 = SchemaPlanCanonicalizer.ComputeSha256(request.SchemaPlan);
        var databasePlans = new List<DeltaDatabasePlan>(DatabaseInventory.ActiveDatabases.Count);
        var persistentDatabasePlans = new List<DeltaDatabasePlan>(DatabaseInventory.ActiveDatabases.Count);
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
            var targetFullCaptures = new Dictionary<string, DeltaCapturedTableArtifact>(StringComparer.Ordinal);
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
                if (table.SourceSchema == "disposition")
                {
                    using var collector = new TableEvidenceCollector(table);
                    await foreach (MigrationRow row in archive.ReplayAsync(full, schema.Database, table,
                        schemaPlanSha256, captureKey, cancellationToken).ConfigureAwait(false))
                    {
                        collector.Append(row);
                    }
                    TableReconciliationEvidence captured = collector.Finish();
                    TableReconciliationEvidence observed = sourceEvidence.Tables.Single(evidence =>
                        string.Equals(evidence.Table, Qualified(table), StringComparison.Ordinal));
                    if (captured.RowCount != observed.RowCount ||
                        !DeltaSynchronizationPlanProducer.FixedHashEquals(captured.ContentSha256, observed.ContentSha256) ||
                        !DeltaSynchronizationPlanProducer.FixedHashEquals(captured.AggregateSha256, observed.AggregateSha256) ||
                        captured.NullCounts.Count != observed.NullCounts.Count ||
                        captured.NullCounts.Any(pair => !observed.NullCounts.TryGetValue(pair.Key, out long count) ||
                            count != pair.Value))
                    {
                        throw new DeltaPlanException("delta_capture_source_evidence_mismatch",
                            "The reviewed Quotation target rows differ from independent source reconciliation.");
                    }
                }
                targetFullCaptures.Add(Qualified(table), full);
            }
            IReadOnlyList<DeltaTablePlan> tablePlans = await PlanTargetAsync(canonicalTarget, mapping.TargetSchema,
                targetFullCaptures, schemaPlanSha256, captureKey, cancellationToken).ConfigureAwait(false);
            if (persistentTarget is not null)
            {
                IReadOnlyList<DeltaTablePlan> pairedPlans = await PlanTargetAsync(persistentTarget,
                    mapping.TargetSchema, targetFullCaptures, schemaPlanSha256, captureKey, cancellationToken)
                    .ConfigureAwait(false);
                if (tablePlans.Count != pairedPlans.Count || tablePlans.Zip(pairedPlans).Any(pair =>
                    pair.First.Table != pair.Second.Table ||
                    pair.First.InsertCount != pair.Second.InsertCount ||
                    pair.First.UpdateCount != pair.Second.UpdateCount ||
                    pair.First.DeleteCount != pair.Second.DeleteCount ||
                    pair.First.UnchangedCount != pair.Second.UnchangedCount ||
                    pair.First.OperationsSha256 != pair.Second.OperationsSha256 ||
                    !pair.First.Operations.SequenceEqual(pair.Second.Operations)))
                {
                    throw new DeltaPlanException("delta_capture_paired_operations_mismatch",
                        "The disposable and persistent targets do not have the same signed operation set.");
                }
                persistentDatabasePlans.Add(new(schema.Database, pairedPlans));
            }
            var tableBindings = new List<DeltaTableCaptureBinding>(mapping.TargetSchema.Tables.Count);
            foreach (TableCopyPlan table in OrderedTables(mapping.TargetSchema))
            {
                DeltaCapturedTableArtifact full = targetFullCaptures[Qualified(table)];
                DeltaTablePlan planned = tablePlans.Single(item => item.Table == Qualified(table));
                DeltaCapturedTableArtifact selected = await archive.CapturePlannedRowsAsync(full,
                    schema.Database, table, schemaPlanSha256, planned, captureKey, cancellationToken)
                    .ConfigureAwait(false);
                archive.DiscardRunOwned(full);
                tableBindings.Add(new(planned.Table, selected.CaptureId, selected.EncryptedSha256,
                    selected.PlaintextSha256, selected.RowCount, planned.OperationsSha256));
            }
            databasePlans.Add(new(schema.Database, tablePlans));
            bindings.Add(new(schema.Database, startedAtUtc, completedAtUtc, sourceEvidence, tableBindings));
        }

        DateTimeOffset nowUtc = timeProvider.GetUtcNow();
        DeltaSourceCaptureManifest manifest = new(keyFingerprint, bindings);
        DeltaSynchronizationPlan disposable = SignPlan(request, signer, schemaPlanSha256,
            databasePlans, manifest, nowUtc);
        DeltaSynchronizationPlan persistent = persistentRequest is null ? disposable :
            SignPlan(persistentRequest, persistentSigner!, schemaPlanSha256,
                persistentDatabasePlans, manifest, nowUtc);
        return new(disposable, persistent);
    }

    private static DeltaSynchronizationPlan SignPlan(
        Exact23DeltaPlanRequest request,
        P256MigrationEvidenceSigner planSigner,
        string schemaPlanSha256,
        IReadOnlyList<DeltaDatabasePlan> databasePlans,
        DeltaSourceCaptureManifest manifest,
        DateTimeOffset nowUtc)
    {
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
            SourceCaptureManifest = manifest,
            QuotationTransitionSchemaSha256 = request.UseQuotationPhysicalTransition
                ? PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(
                    request.SchemaPlan.Databases.Single(database => database.Database == "Quotation"), true)
                : null,
        }, planSigner, nowUtc);
    }

    private async Task<IReadOnlyList<DeltaTablePlan>> PlanTargetAsync(
        IDeltaDatabaseSnapshotRowSource target,
        DatabaseSchemaPlan schema,
        Dictionary<string, DeltaCapturedTableArtifact> fullCaptures,
        string schemaPlanSha256,
        ReadOnlyMemory<byte> captureKey,
        CancellationToken cancellationToken)
    {
        var tablePlans = new List<DeltaTablePlan>(schema.Tables.Count);
        bool snapshotOpen = false;
        try
        {
            await target.BeginDatabaseSnapshotAsync(schema.Database, cancellationToken).ConfigureAwait(false);
            snapshotOpen = true;
            foreach (TableCopyPlan table in OrderedTables(schema))
            {
                CanonicalTableDelta delta = await CanonicalAsyncDeltaPlanner.PlanAsync(table,
                    archive.ReplayAsync(fullCaptures[Qualified(table)], schema.Database, table,
                        schemaPlanSha256, captureKey, cancellationToken),
                    target.ReadOrderedAsync(schema.Database, table, cancellationToken),
                    cancellationToken).ConfigureAwait(false);
                tablePlans.Add(new(delta.Table, delta.InsertCount, delta.UpdateCount,
                    delta.DeleteCount, delta.UnchangedCount,
                    DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(delta.Operations), delta.Operations));
            }
            await target.CompleteDatabaseSnapshotAsync(schema.Database, cancellationToken).ConfigureAwait(false);
            snapshotOpen = false;
            return tablePlans;
        }
        catch
        {
            if (snapshotOpen)
            {
                try
                {
                    await target.RollbackDatabaseSnapshotAsync(schema.Database, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (Exception rollbackFailure) when (rollbackFailure is
                    DeltaPlanningException or InvalidOperationException or IOException or Npgsql.NpgsqlException)
                {
                    // Preserve the planning failure.
                }
            }
            throw;
        }
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
