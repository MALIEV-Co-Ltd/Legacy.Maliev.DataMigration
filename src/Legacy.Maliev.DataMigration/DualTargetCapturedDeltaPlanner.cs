using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

// This planner captures SQL Server once. Every later row read is explicitly archive replay.
internal sealed class DualTargetCapturedDeltaPlanner(IReadOnlyMigrationSource source,
    IDeltaReconciliationInspector sourceEvidence, DeltaCapturedTableArchive archive, TimeProvider clock)
{
    internal async Task<DualTargetCapturedDeltaBundle> ProduceAsync(
        IReadOnlyList<DualTargetCapturedDeltaDestination> destinations, ReadOnlyMemory<byte> key,
        P256MigrationEvidenceSigner captureSigner, CancellationToken ct)
    {
        if (destinations.Count != 4 || destinations.Select(x => x.Purpose).Distinct().Count() != 4 || key.Length != 32)
        { throw DualTargetCapturedDeltaContract.Invalid(); }
        Exact23DeltaPlanRequest first = destinations[0].Request;
        FreshSchemaPlan schema = first.SchemaPlan;
        Exact23DeltaPlanCoordinator.ValidateInventory(schema);
        string schemaHash = SchemaPlanCanonicalizer.ComputeSha256(schema);
        string keyHash = Convert.ToHexString(SHA256.HashData(key.Span)).ToLowerInvariant();
        if (first.SourceMode != DeltaSourceMode.LiveReadOnly || first.SourceObservationSha256 is null ||
            first.SourceCutoffUtc.Offset != TimeSpan.Zero || first.SourceCutoffUtc > clock.GetUtcNow() ||
            clock.GetUtcNow() - first.SourceCutoffUtc > TimeSpan.FromHours(1)) { throw DualTargetCapturedDeltaContract.Invalid(); }
        foreach (DualTargetCapturedDeltaDestination destination in destinations)
        {
            Exact23DeltaPlanRequest request = destination.Request;
            DualTargetCapturedDeltaContract.RequirePurpose(destination.Purpose, request.TargetAuthority, request.TargetNamespace, request.TargetCluster);
            if (SchemaPlanCanonicalizer.ComputeSha256(request.SchemaPlan) != schemaHash || request.SourceCutoffUtc != first.SourceCutoffUtc ||
                request.SourceMode != first.SourceMode || request.SourceObservationSha256 != first.SourceObservationSha256 ||
                request.RunnerDigestSha256 != first.RunnerDigestSha256 || request.BackupManifestSha256 != first.BackupManifestSha256 ||
                request.RecordSourceReadWindows || request.UseQuotationPhysicalTransition ||
                new[] { destination.Signer.PublicKeyFingerprintSha256, request.BackupKeyFingerprintSha256,
                    request.ExecutionAuthorizationKeyFingerprintSha256, captureSigner.PublicKeyFingerprintSha256 }.Contains(keyHash, StringComparer.Ordinal))
            { throw DualTargetCapturedDeltaContract.Invalid(); }
        }
        if (destinations.Select(x => x.Rows).Distinct(ReferenceEqualityComparer.Instance).Count() != 4 ||
            destinations.Select(x => x.Signer.PublicKeyFingerprintSha256).Distinct(StringComparer.Ordinal).Count() != 4)
        { throw DualTargetCapturedDeltaContract.Invalid(); }
        var owned = new List<DeltaCapturedTableArtifact>();
        var databases = new List<DualTargetCapturedDatabase>();
        var plans = destinations.ToDictionary(x => x.Purpose, _ => new List<DeltaDatabasePlan>());
        var selections = destinations.ToDictionary(x => x.Purpose, _ => new List<DeltaDatabaseCaptureBinding>());
        try
        {
            foreach (DatabaseSchemaPlan database in schema.Databases)
            {
                var mapping = new QuotationDeltaExecutionMapping(database);
                var raw = new Dictionary<string, DeltaCapturedTableArtifact>(StringComparer.Ordinal);
                DateTimeOffset started = clock.GetUtcNow();
                DatabaseReconciliationEvidence evidence;
                bool open = false;
                try
                {
                    await source.BeginDatabaseSnapshotAsync(database.Database, ct).ConfigureAwait(false); open = true;
                    foreach (TableCopyPlan table in Ordered(database))
                    {
                        DeltaCapturedTableArtifact artifact = await archive.CaptureAsync(database.Database, table, schemaHash,
                            source.ReadTableImmediatelyAsync(database.Database, table, ct), key, ct).ConfigureAwait(false);
                        owned.Add(artifact); raw.Add(Qualified(table), artifact);
                    }
                    evidence = await sourceEvidence.InspectAsync(database, ct).ConfigureAwait(false);
                    if (evidence.Database != database.Database || evidence.SourceSchemaSha256 != database.SourceSchemaSha256 ||
                        evidence.TargetSchemaSha256 != database.TargetSchemaSha256) { throw DualTargetCapturedDeltaContract.Invalid(); }
                    await source.CompleteDatabaseSnapshotAsync(database.Database, ct).ConfigureAwait(false); open = false;
                }
                catch (Exception primary)
                {
                    if (open)
                    {
                        try { await source.RollbackDatabaseSnapshotAsync(database.Database, CancellationToken.None).ConfigureAwait(false); }
                        catch (Exception cleanup) { primary.Data["DualCaptureSourceRollback"] = cleanup; }
                    }
                    throw;
                }
                DateTimeOffset completed = clock.GetUtcNow();
                var full = new Dictionary<string, DeltaCapturedTableArtifact>(StringComparer.Ordinal);
                foreach (TableCopyPlan table in Ordered(mapping.TargetSchema))
                {
                    TableCopyPlan sourceTable = mapping.SourceTableFor(table);
                    DeltaCapturedTableArtifact artifact = raw[Qualified(sourceTable)];
                    if (sourceTable != table)
                    {
                        artifact = await archive.CaptureAsync(database.Database, table, schemaHash,
                            Map(archive.ReplayAsync(artifact, database.Database, sourceTable, schemaHash, key, ct), mapping, table, ct), key, ct).ConfigureAwait(false);
                        owned.Add(artifact);
                    }
                    using var collector = new TableEvidenceCollector(table);
                    await foreach (MigrationRow row in archive.ReplayAsync(artifact, database.Database, table, schemaHash, key, ct).ConfigureAwait(false))
                    {
                        foreach (StreamingLob lob in row.Values.Values.OfType<StreamingLob>())
                        { await lob.ConsumeAsync(Stream.Null, ct).ConfigureAwait(false); }
                        collector.Append(row);
                    }
                    ReconciliationDiagnostics.CompareTable(database.Database,
                        evidence.Tables.Single(x => x.Table == Qualified(table)), collector.Finish());
                    full.Add(Qualified(table), artifact);
                }
                if (full.Count != evidence.Tables.Count) { throw DualTargetCapturedDeltaContract.Invalid(); }
                databases.Add(new(database.Database, started, completed, evidence, [.. raw.Values], [.. full.Values]));
                foreach (DualTargetCapturedDeltaDestination destination in destinations)
                {
                    IReadOnlyList<DeltaTablePlan> tablePlans = await PlanAsync(destination.Rows, mapping.TargetSchema, full, schemaHash, key, ct).ConfigureAwait(false);
                    DualTargetCapturedDeltaContract.RequireZeroDeleteAndEffects(database, tablePlans);
                    var bindings = new List<DeltaTableCaptureBinding>();
                    foreach (TableCopyPlan table in Ordered(mapping.TargetSchema))
                    {
                        DeltaTablePlan planned = tablePlans.Single(x => x.Table == Qualified(table));
                        DeltaCapturedTableArtifact selected = await archive.CapturePlannedRowsAsync(full[Qualified(table)], database.Database,
                            table, schemaHash, planned, key, ct).ConfigureAwait(false);
                        owned.Add(selected);
                        bindings.Add(new(planned.Table, selected.CaptureId, selected.EncryptedSha256, selected.PlaintextSha256,
                            selected.RowCount, planned.OperationsSha256));
                    }
                    plans[destination.Purpose].Add(new(database.Database, tablePlans));
                    selections[destination.Purpose].Add(new(database.Database, started, completed, evidence, bindings));
                }
            }
            DateTimeOffset now = clock.GetUtcNow();
            var members = new List<DualTargetCapturedDeltaPlan>();
            foreach (DualTargetCapturedDeltaDestination destination in destinations)
            {
                Exact23DeltaPlanRequest request = destination.Request;
                DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(new(request.SchemaPlan.SourceCommitSha,
                    request.SourceCutoffUtc, request.BackupManifestSha256, schemaHash, request.RunnerDigestSha256,
                    request.TargetNamespace, request.TargetCluster, request.TargetGeneration, request.TargetObservationSha256,
                    request.BackupKeyFingerprintSha256, request.ExecutionAuthorizationKeyFingerprintSha256, plans[destination.Purpose])
                {
                    TargetAuthority = request.TargetAuthority,
                    SourceMode = DeltaSourceMode.LiveReadOnly,
                    SourceObservationSha256 = first.SourceObservationSha256,
                    SourceCaptureCompletedAtUtc = now,
                    SourceCaptureManifest = new(keyHash, selections[destination.Purpose])
                }, destination.Signer, now);
                var evidenceTrust = new ReceiptAttestationTrustStore([destination.EvidenceKey]);
                if (!evidenceTrust.TryGetPublicKeyFingerprintSha256(destination.EvidenceKey.KeyId, out string evidenceFingerprint))
                { throw DualTargetCapturedDeltaContract.Invalid(); }
                members.Add(new(destination.Purpose, plan, destination.EvidenceKey.KeyId, evidenceFingerprint, destination.Observation));
            }
            var bundle = new DualTargetCapturedDeltaBundle(DualTargetCapturedDeltaContract.Kind, Guid.NewGuid(), schemaHash,
                schema.SourceCommitSha, first.SourceObservationSha256, keyHash, now, databases, members, captureSigner.KeyId, null);
            bundle = bundle with { AttestationSignature = Convert.ToBase64String(captureSigner.Sign(DualTargetCapturedDeltaContract.Payload(bundle))) };
            var trust = new ReceiptAttestationTrustStore([new(captureSigner.KeyId, captureSigner.ExportSubjectPublicKeyInfo()),
                .. destinations.Select(x => new TrustedAttestationKey(x.Signer.KeyId, x.Signer.ExportSubjectPublicKeyInfo())),
                .. destinations.Select(x => x.EvidenceKey)]);
            DualTargetCapturedDeltaContract.Verify(bundle, schema, trust, now);
            return bundle;
        }
        catch (Exception primary)
        {
            var failures = new List<Exception>();
            foreach (DeltaCapturedTableArtifact artifact in owned)
            {
                try { archive.DiscardRunOwned(artifact); }
                catch (Exception cleanup) { failures.Add(cleanup); }
            }
            if (failures.Count != 0) { primary.Data["DualCaptureArchiveCleanup"] = new AggregateException(failures); }
            throw;
        }
    }

    private async Task<IReadOnlyList<DeltaTablePlan>> PlanAsync(IDeltaDatabaseSnapshotRowSource target, DatabaseSchemaPlan database,
        Dictionary<string, DeltaCapturedTableArtifact> full, string schemaHash, ReadOnlyMemory<byte> key, CancellationToken ct)
    {
        bool open = false;
        try
        {
            await target.BeginDatabaseSnapshotAsync(database.Database, ct).ConfigureAwait(false); open = true;
            var result = new List<DeltaTablePlan>();
            foreach (TableCopyPlan table in Ordered(database))
            {
                CanonicalTableDelta delta = await CanonicalAsyncDeltaPlanner.PlanAsync(table,
                    archive.ReplayAsync(full[Qualified(table)], database.Database, table, schemaHash, key, ct),
                    target.ReadOrderedAsync(database.Database, table, ct), ct).ConfigureAwait(false);
                result.Add(new(delta.Table, delta.InsertCount, delta.UpdateCount, delta.DeleteCount, delta.UnchangedCount,
                    DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(delta.Operations), delta.Operations));
            }
            await target.CompleteDatabaseSnapshotAsync(database.Database, ct).ConfigureAwait(false); open = false;
            return result;
        }
        catch (Exception primary)
        {
            if (open)
            {
                try { await target.RollbackDatabaseSnapshotAsync(database.Database, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception cleanup) { primary.Data["DualCaptureTargetRollback"] = cleanup; }
            }
            throw;
        }
    }
    private static IEnumerable<TableCopyPlan> Ordered(DatabaseSchemaPlan schema)
    {
        return schema.Tables.OrderBy(Qualified, StringComparer.Ordinal);
    }

    internal static async Task VerifyFullArchivesAsync(DualTargetCapturedDeltaBundle bundle, FreshSchemaPlan schema,
        DeltaCapturedTableArchive archive, ReadOnlyMemory<byte> key, CancellationToken ct)
    {
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            DualTargetCapturedDatabase captured = bundle.Databases.Single(x => x.Database == database.Database);
            await VerifyTablesAsync(database.Tables, captured.SourceTables).ConfigureAwait(false);
            await VerifyTablesAsync(new QuotationDeltaExecutionMapping(database).TargetSchema.Tables, captured.FullTables).ConfigureAwait(false);

            async Task VerifyTablesAsync(IReadOnlyList<TableCopyPlan> tables, IReadOnlyList<DeltaCapturedTableArtifact> artifacts)
            {
                foreach (TableCopyPlan table in tables)
                {
                    DeltaCapturedTableArtifact artifact = artifacts.Single(x => x.Table == Qualified(table));
                    long count = 0;
                    await foreach (MigrationRow row in archive.ReplayAsync(artifact, database.Database, table, bundle.SchemaPlanSha256, key, ct).ConfigureAwait(false))
                    {
                        foreach (StreamingLob lob in row.Values.Values.OfType<StreamingLob>())
                        { await lob.ConsumeAsync(Stream.Null, ct).ConfigureAwait(false); }
                        count = checked(count + 1);
                    }
                    if (count != artifact.RowCount) { throw DualTargetCapturedDeltaContract.Invalid(); }
                }
            }
        }
    }
    private static string Qualified(TableCopyPlan table)
    {
        return table.TargetSchema + "." + table.TargetTable;
    }

    private static async IAsyncEnumerable<MigrationRow> Map(IAsyncEnumerable<MigrationRow> rows, QuotationDeltaExecutionMapping mapping,
        TableCopyPlan table, [EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (MigrationRow row in rows.WithCancellation(ct).ConfigureAwait(false)) { yield return mapping.MapRow(table, row); }
    }
}
