namespace Legacy.Maliev.DataMigration;

public sealed record RepresentativeServiceQueryResult(
    string Database,
    string Service,
    string QueryId,
    bool Succeeded);

public sealed record Exact23RepresentativeServiceQueryEvidence(
    string SchemaVersion,
    Guid PlanId,
    string PlanSha256,
    DateTimeOffset SourceCutoffUtc,
    DateTimeOffset ObservedAtUtc,
    IReadOnlyList<RepresentativeServiceQueryResult> Queries);

public sealed record Exact23LocalDeltaFinalizationResult(
    Exact23DeltaExecutionResult Execution,
    Exact23DeltaReconciliationResult TerminalReceipt,
    Exact23RepresentativeServiceQueryEvidence QueryEvidence,
    LocalSnapshotManifest Snapshot,
    AppHostMigrationEvidenceV2Document AppHostEvidence);

public interface IExact23LocalDeltaFinalizationRuntime
{
    Task<Exact23DeltaExecutionResult> ApplyAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schema,
        CancellationToken cancellationToken);

    Task<Exact23DeltaReconciliationResult> ReconcileAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schema,
        CancellationToken cancellationToken);

    Task<Exact23RepresentativeServiceQueryEvidence> ValidateRepresentativeQueriesAsync(
        DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult terminalReceipt,
        CancellationToken cancellationToken);

    Task<LocalSnapshotManifest> ExportEncryptedSnapshotAsync(
        DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult terminalReceipt,
        Exact23RepresentativeServiceQueryEvidence queryEvidence,
        CancellationToken cancellationToken);

    Task<AppHostMigrationEvidenceV2Document> ProduceAppHostEvidenceAsync(
        DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult terminalReceipt,
        Exact23RepresentativeServiceQueryEvidence queryEvidence,
        LocalSnapshotManifest snapshot,
        CancellationToken cancellationToken);
}

public sealed class Exact23LocalDeltaFinalizationCoordinator(
    IExact23LocalDeltaFinalizationRuntime runtime,
    IReceiptAttestationTrustStore terminalReceiptTrust)
{
    public async Task<Exact23LocalDeltaFinalizationResult> FinalizeAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schema,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schema);
        ValidateLocalPlan(plan, schema);
        Exact23DeltaExecutionResult execution = await runtime.ApplyAsync(plan, schema, cancellationToken)
            .ConfigureAwait(false);
        ValidateExecution(plan, execution);

        Exact23DeltaReconciliationResult terminal = await runtime.ReconcileAsync(plan, schema, cancellationToken)
            .ConfigureAwait(false);
        if (!Exact23DeltaReconciliationCoordinator.Verify(terminal, terminalReceiptTrust) ||
            terminal.PlanId != plan.PlanId || !Fixed(terminal.PlanSha256, execution.PlanSha256) ||
            !SameTimestamp(terminal.SourceCutoffUtc, plan.SourceCutoffUtc))
        {
            throw Invalid("local_delta_terminal_receipt_invalid",
                "Local delta delivery requires the journal-bound signed exact-23 terminal receipt.");
        }

        Exact23RepresentativeServiceQueryEvidence queries = await runtime
            .ValidateRepresentativeQueriesAsync(plan, terminal, cancellationToken).ConfigureAwait(false);
        ValidateQueries(plan, terminal, queries);
        LocalSnapshotManifest snapshot = await runtime
            .ExportEncryptedSnapshotAsync(plan, terminal, queries, cancellationToken).ConfigureAwait(false);
        ValidateSnapshot(snapshot);
        AppHostMigrationEvidenceV2Document evidence = await runtime
            .ProduceAppHostEvidenceAsync(plan, terminal, queries, snapshot, cancellationToken).ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(evidence.EvidenceJson) || string.IsNullOrWhiteSpace(evidence.ApprovedBaselineJson)
            ? throw Invalid("local_delta_apphost_evidence_invalid",
                "Local delta finalization requires complete AppHost schema-v2 evidence.")
            : new(execution, terminal, queries, snapshot, evidence);
    }

    private static void ValidateLocalPlan(DeltaSynchronizationPlan plan, FreshSchemaPlan schema)
    {
        if (plan.TargetAuthority?.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(plan.TargetAuthority, plan.TargetNamespace, plan.TargetCluster) ||
            !plan.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !schema.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !string.Equals(plan.SourceCommitSha, schema.SourceCommitSha, StringComparison.Ordinal) ||
            !Fixed(plan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(schema)))
        {
            throw Invalid("local_delta_plan_invalid", "Local delta finalization requires the exact local Aspire plan and schema.");
        }
    }

    private static void ValidateExecution(DeltaSynchronizationPlan plan, Exact23DeltaExecutionResult execution)
    {
        string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        if (execution.PlanId != plan.PlanId || !Fixed(execution.PlanSha256, planSha256) ||
            !SameTimestamp(execution.SourceCutoffUtc, plan.SourceCutoffUtc) ||
            !execution.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            execution.Databases.Any(item => item.Disposition is not (DeltaExecutionDisposition.Committed or DeltaExecutionDisposition.AlreadyCommitted) ||
                !Fixed(item.PlanSha256, planSha256) || string.IsNullOrWhiteSpace(item.ReconciliationSha256)))
        {
            throw Invalid("local_delta_execution_invalid", "Local delta execution is incomplete or does not match the reviewed plan.");
        }
    }

    private static void ValidateQueries(
        DeltaSynchronizationPlan plan,
        Exact23DeltaReconciliationResult terminal,
        Exact23RepresentativeServiceQueryEvidence evidence)
    {
        if (evidence.SchemaVersion != "1.0" || evidence.PlanId != plan.PlanId ||
            !Fixed(evidence.PlanSha256, terminal.PlanSha256) ||
            !SameTimestamp(evidence.SourceCutoffUtc, plan.SourceCutoffUtc) ||
            evidence.ObservedAtUtc.Offset != TimeSpan.Zero || evidence.ObservedAtUtc < terminal.ReconciledAtUtc ||
            !evidence.Queries.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            evidence.Queries.Any(item => !item.Succeeded || string.IsNullOrWhiteSpace(item.Service) || string.IsNullOrWhiteSpace(item.QueryId)) ||
            evidence.Queries.Select(item => $"{item.Service}\0{item.QueryId}").Distinct(StringComparer.Ordinal).Count() != evidence.Queries.Count)
        {
            throw Invalid("local_delta_service_query_evidence_invalid",
                "Representative service queries must pass for every active database after terminal reconciliation.");
        }
    }

    private static void ValidateSnapshot(LocalSnapshotManifest snapshot)
    {
        if (snapshot.SchemaVersion != 2 || snapshot.Format != "MLVSNP02" ||
            snapshot.Encryption != "AES-256-GCM-chunked-v2" || string.IsNullOrWhiteSpace(snapshot.SnapshotId) ||
            !Hash(snapshot.ManifestDigestSha256) || !Hash(snapshot.ManifestMacSha256) ||
            !snapshot.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            snapshot.Databases.Any(item => item.ShadowDatabase != item.Database || item.PlaintextByteLength <= 0 ||
                item.EncryptedByteLength <= 0 || !Hash(item.PlaintextSha256) || !Hash(item.EncryptedSha256)))
        {
            throw Invalid("local_delta_snapshot_invalid", "The encrypted persistent exact-23 local snapshot is incomplete.");
        }
    }

    private static bool Hash(string value)
    {
        return value.Length == 64 && value.All(char.IsAsciiHexDigit);
    }

    private static bool Fixed(string left, string right)
    {
        return Hash(left) && Hash(right) && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
            System.Text.Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static bool SameTimestamp(DateTimeOffset left, DateTimeOffset right)
    {
        const long ticksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1000;
        long leftTicks = left.ToUniversalTime().Ticks;
        long rightTicks = right.ToUniversalTime().Ticks;
        return left.Offset == TimeSpan.Zero && right.Offset == TimeSpan.Zero &&
            leftTicks - (leftTicks % ticksPerMicrosecond) == rightTicks - (rightTicks % ticksPerMicrosecond);
    }

    private static DeltaExecutionException Invalid(string code, string message)
    {
        return new(code, message);
    }
}
