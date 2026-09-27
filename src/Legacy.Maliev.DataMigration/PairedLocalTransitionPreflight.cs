namespace Legacy.Maliev.DataMigration;

/// <summary>PII-free result of a read-only local transition check; never an execution authorization.</summary>
public sealed record PairedLocalTransitionPreflightResult(
    string SchemaVersion,
    Guid AuthorizationId,
    string PersistentPlanSha256,
    string DisposableReconciliationSha256,
    string TargetObservationSha256,
    string QuotationTransitionSchemaSha256,
    int DatabasesChecked,
    long CapturedOperationsChecked,
    DateTimeOffset CheckedAtUtc)
{
    public int UnprovisionedDatabases { get; init; }
    public int PendingDatabases { get; init; }
    public int ReplayedDatabases { get; init; }
}

/// <summary>
/// Read-only pre-metadata gate. Every target row preimage is checked again by the
/// eventual serializable apply transaction; this check alone cannot grant DML.
/// </summary>
public static class PairedLocalTransitionPreflight
{
    public static async Task<PairedLocalTransitionPreflightResult> VerifyAsync(
        PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof,
        PairedLocalTransitionAuthorization authorization,
        FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust,
        DeltaTargetAuthority expectedAuthority,
        string targetObservationSha256,
        Func<CancellationToken, Task> verifyTargetIdentity,
        Func<DatabaseSchemaPlan, bool, CancellationToken, Task> verifyPhysicalSchema,
        Func<DeltaSynchronizationPlan, DatabaseSchemaPlan, CancellationToken,
            Task<PairedLocalTransitionMetadataObservation>> inspectMetadata,
        string captureDirectory,
        ReadOnlyMemory<byte> captureKey,
        IDeltaOrderedRowSource targetRows,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plans);
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(verifyTargetIdentity);
        ArgumentNullException.ThrowIfNull(verifyPhysicalSchema);
        ArgumentNullException.ThrowIfNull(inspectMetadata);
        ArgumentException.ThrowIfNullOrWhiteSpace(captureDirectory);
        ArgumentNullException.ThrowIfNull(targetRows);
        ArgumentNullException.ThrowIfNull(clock);
        string transition = plans.Persistent.QuotationTransitionSchemaSha256 ?? string.Empty;
        void VerifyAdmission()
        {
            PairedLocalTransitionAuthorizationPolicy.Verify(authorization,
                plans, proof, schema, trust, expectedAuthority, targetObservationSha256,
                transition, clock.GetUtcNow());
        }

        VerifyAdmission();
        await verifyTargetIdentity(cancellationToken).ConfigureAwait(false);
        var metadata = new Dictionary<string, PairedLocalTransitionMetadataObservation>(StringComparer.Ordinal);
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            bool quotationTransition = database.Database == "Quotation";
            await verifyPhysicalSchema(database, quotationTransition, cancellationToken).ConfigureAwait(false);
            metadata.Add(database.Database, await inspectMetadata(plans.Persistent, database,
                cancellationToken).ConfigureAwait(false));
        }
        using DeltaCapturedTableRowSource capturedRows = DeltaCapturedTableRowSource.FromSignedPlan(
            new DeltaCapturedTableArchive(captureDirectory), plans.Persistent, trust,
            clock.GetUtcNow(), captureKey.Span);
        long checkedRows = 0;
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            DeltaDatabasePlan signedDatabase = plans.Persistent.Databases.Single(item =>
                item.Database == database.Database);
            DatabaseSchemaPlan targetSchema = new QuotationDeltaExecutionMapping(database).TargetSchema;
            checkedRows = checked(checkedRows + await VerifyCapturedRowsAsync(signedDatabase,
                targetSchema, capturedRows, targetRows, cancellationToken).ConfigureAwait(false));
        }
        await verifyTargetIdentity(cancellationToken).ConfigureAwait(false);
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            await verifyPhysicalSchema(database, database.Database == "Quotation", cancellationToken)
                .ConfigureAwait(false);
            RequireMetadataUnchanged(metadata[database.Database],
                await inspectMetadata(plans.Persistent, database, cancellationToken).ConfigureAwait(false));
        }
        VerifyAdmission();
        return new("1.0", authorization.AuthorizationId,
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plans.Persistent),
            Exact23DeltaReconciliationCoordinator.ComputeSha256(proof),
            plans.Persistent.TargetObservationSha256, transition, schema.Databases.Count,
            checkedRows, clock.GetUtcNow())
        {
            UnprovisionedDatabases = metadata.Values.Count(item =>
                item.State == PairedLocalTransitionMetadataState.Unprovisioned),
            PendingDatabases = metadata.Values.Count(item =>
                item.State == PairedLocalTransitionMetadataState.Pending),
            ReplayedDatabases = metadata.Values.Count(item =>
                item.State == PairedLocalTransitionMetadataState.Replayed),
        };
    }

    internal static void RequireMetadataUnchanged(PairedLocalTransitionMetadataObservation before,
        PairedLocalTransitionMetadataObservation after)
    {
        if (before != after)
        {
            throw new DeltaExecutionException("delta_paired_local_metadata_changed",
                "The local metadata state changed during read-only transition preflight.");
        }
    }

    internal static async Task<long> VerifyCapturedRowsAsync(
        DeltaDatabasePlan signedDatabase,
        DatabaseSchemaPlan targetSchema,
        DeltaCapturedTableRowSource capturedRows,
        IDeltaOrderedRowSource targetRows,
        CancellationToken cancellationToken)
    {
        var sessions = new CapturedDeltaExecutionRowSessionProvider(capturedRows, targetRows);
        long checkedRows = 0;
        foreach (TableCopyPlan table in targetSchema.Tables)
        {
            DeltaTablePlan plan = signedDatabase.Tables.Single(item => item.Table ==
                $"{table.TargetSchema}.{table.TargetTable}");
            if (plan.DeleteCount != 0)
            {
                throw new DeltaExecutionException("delta_paired_local_transition_delete_invalid",
                    "Local transition preflight requires zero planned deletes.");
            }
            await using IDeltaExecutionRowSession session = await sessions.OpenAsync(
                signedDatabase.Database, table, cancellationToken).ConfigureAwait(false);
            await foreach (ResolvedDeltaRow row in session.ResolveAsync(plan, cancellationToken)
                .WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                DeltaExecutionCoordinator.VerifyRow(table, row.Source, row.Operation.KeySha256,
                    row.Operation.SourceRowSha256, "source");
                DeltaExecutionCoordinator.VerifyRow(table, row.Target, row.Operation.KeySha256,
                    row.Operation.TargetRowSha256, "target");
                checkedRows = checked(checkedRows + 1);
            }
        }
        return checkedRows;
    }
}
