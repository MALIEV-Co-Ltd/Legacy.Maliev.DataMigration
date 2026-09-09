using System.Collections.ObjectModel;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public interface IDeltaReconciliationInspector
{
    Task<DatabaseReconciliationEvidence> InspectAsync(
        DatabaseSchemaPlan schema,
        CancellationToken cancellationToken);
}

public sealed record Exact23DeltaReconciliationResult(
    string SchemaVersion,
    Guid PlanId,
    string PlanSha256,
    DateTimeOffset SourceCutoffUtc,
    DateTimeOffset ReconciledAtUtc,
    IReadOnlyList<DatabaseReconciliationEvidence> Databases,
    string AttestationKeyId,
    string? AttestationSignature)
{
    public IReadOnlyList<DeltaDatabaseCheckpointEvidence> Checkpoints { get; init; } = [];
}

public sealed class Exact23DeltaReconciliationCoordinator(
    IDeltaReconciliationInspector source,
    IDeltaReconciliationInspector target,
    IExact23DeltaCheckpointReader checkpoints,
    TimeProvider timeProvider,
    P256MigrationEvidenceSigner signer)
{
    public async Task<Exact23DeltaReconciliationResult> ReconcileAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schemaPlan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schemaPlan);
        if (!plan.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !schemaPlan.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw new DeltaExecutionException("delta_reconciliation_inventory_invalid",
                "Post-delta reconciliation requires the exact ordered active database inventory.");
        }

        var reconciled = new List<DatabaseReconciliationEvidence>(DatabaseInventory.ActiveDatabases.Count);
        foreach (DatabaseSchemaPlan schema in schemaPlan.Databases)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DatabaseReconciliationEvidence expected = await source.InspectAsync(schema, cancellationToken).ConfigureAwait(false);
            DatabaseReconciliationEvidence observed = await target.InspectAsync(schema, cancellationToken).ConfigureAwait(false);
            ValidateShape(schema, expected, observed);
            ReconciliationDiagnostics.CompareSchema(schema.Database, schema.TargetSchemaSha256, observed.TargetSchemaSha256);
            foreach (TableReconciliationEvidence expectedTable in expected.Tables)
            {
                ReconciliationDiagnostics.CompareTable(schema.Database, expectedTable,
                    observed.Tables.Single(item => string.Equals(item.Table, expectedTable.Table, StringComparison.Ordinal)));
            }
            ReconciliationDiagnostics.CompareSequences(schema, expected.SequenceNextValues, observed.SequenceNextValues);
            reconciled.Add(observed);
        }

        DateTimeOffset reconciledAtUtc = timeProvider.GetUtcNow();
        IReadOnlyList<DeltaDatabaseCheckpointEvidence> checkpointEvidence = await checkpoints
            .ReadAsync(plan, schemaPlan, cancellationToken).ConfigureAwait(false);
        ValidateCheckpoints(plan, reconciled, checkpointEvidence, reconciledAtUtc);
        var unsigned = new Exact23DeltaReconciliationResult("1.1", plan.PlanId,
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), plan.SourceCutoffUtc,
            reconciledAtUtc, new ReadOnlyCollection<DatabaseReconciliationEvidence>(reconciled), signer.KeyId, null)
        {
            Checkpoints = checkpointEvidence,
        };
        return unsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(CreatePayload(unsigned))),
        };
    }

    private static void ValidateCheckpoints(
        DeltaSynchronizationPlan plan,
        IReadOnlyList<DatabaseReconciliationEvidence> reconciled,
        IReadOnlyList<DeltaDatabaseCheckpointEvidence> checkpoints,
        DateTimeOffset reconciledAtUtc)
    {
        string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        bool valid = checkpoints.Select(item => item.Database)
            .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) &&
            checkpoints.Count == DatabaseInventory.ActiveDatabases.Count;
        if (!valid)
        {
            throw new DeltaExecutionException("delta_reconciliation_checkpoint_invalid",
                "Signed exact-23 success requires one matching atomic checkpoint in every active database.");
        }
        foreach (DeltaDatabaseCheckpointEvidence checkpoint in checkpoints)
        {
            DeltaDatabasePlan databasePlan = plan.Databases.Single(item => item.Database == checkpoint.Database);
            DatabaseReconciliationEvidence evidence = reconciled.Single(item => item.Database == checkpoint.Database);
            valid = valid && checkpoint.PlanId == plan.PlanId &&
                Fixed(checkpoint.PlanSha256, planSha256) && SameTimestamp(checkpoint.SourceCutoffUtc, plan.SourceCutoffUtc) &&
                Fixed(checkpoint.TargetObservationSha256, plan.TargetObservationSha256) &&
                Fixed(checkpoint.OperationsSha256,
                    DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(databasePlan)) &&
                Fixed(checkpoint.ReconciliationSha256,
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(evidence)) &&
                checkpoint.CommittedAtUtc.Offset == TimeSpan.Zero && checkpoint.CommittedAtUtc <= reconciledAtUtc;
        }
        if (!valid)
        {
            throw new DeltaExecutionException("delta_reconciliation_checkpoint_invalid",
                "Signed exact-23 success requires one matching atomic checkpoint in every active database.");
        }
    }

    private static void ValidateShape(
        DatabaseSchemaPlan schema,
        DatabaseReconciliationEvidence expected,
        DatabaseReconciliationEvidence observed)
    {
        string[] tables = [.. schema.Tables.Select(item => $"{item.TargetSchema}.{item.TargetTable}").Order(StringComparer.Ordinal)];
        if (!string.Equals(expected.Database, schema.Database, StringComparison.Ordinal) ||
            !string.Equals(observed.Database, schema.Database, StringComparison.Ordinal) ||
            !string.Equals(expected.SourceSchemaSha256, schema.SourceSchemaSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(observed.SourceSchemaSha256, schema.SourceSchemaSha256, StringComparison.OrdinalIgnoreCase) ||
            !expected.Tables.Select(item => item.Table).Order(StringComparer.Ordinal).SequenceEqual(tables, StringComparer.Ordinal) ||
            !observed.Tables.Select(item => item.Table).Order(StringComparer.Ordinal).SequenceEqual(tables, StringComparer.Ordinal))
        {
            throw new DeltaExecutionException("delta_reconciliation_shape_invalid",
                "Reconciliation evidence does not cover the exact signed database table inventory.");
        }
    }

    public static bool Verify(
        Exact23DeltaReconciliationResult result,
        IReceiptAttestationTrustStore trust)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(trust);
        try
        {
            bool valid = result.SchemaVersion == "1.1" && result.PlanId != Guid.Empty &&
                result.SourceCutoffUtc.Offset == TimeSpan.Zero && result.ReconciledAtUtc.Offset == TimeSpan.Zero &&
                result.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) &&
                result.Checkpoints.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) &&
                result.Checkpoints.Count == DatabaseInventory.ActiveDatabases.Count &&
                result.Checkpoints.All(checkpoint => checkpoint.PlanId == result.PlanId &&
                    Fixed(checkpoint.PlanSha256, result.PlanSha256) &&
                    SameTimestamp(checkpoint.SourceCutoffUtc, result.SourceCutoffUtc) &&
                    checkpoint.CommittedAtUtc.Offset == TimeSpan.Zero && checkpoint.CommittedAtUtc <= result.ReconciledAtUtc &&
                    Fixed(checkpoint.ReconciliationSha256, DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(
                        result.Databases.Single(item => item.Database == checkpoint.Database)))) &&
                !string.IsNullOrWhiteSpace(result.AttestationKeyId) && !string.IsNullOrWhiteSpace(result.AttestationSignature) &&
                trust.Verify(result.AttestationKeyId, CreatePayload(result), Convert.FromBase64String(result.AttestationSignature));
            return valid;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool Fixed(string left, string right)
    {
        return left.Length == 64 && right.Length == 64 && left.All(char.IsAsciiHexDigit) && right.All(char.IsAsciiHexDigit) &&
            System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
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

    private static byte[] CreatePayload(Exact23DeltaReconciliationResult result)
    {
        byte[] domain = "legacy-maliev-exact23-delta-reconciliation-v1.1\0"u8.ToArray();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(result with { AttestationSignature = null });
        return [.. domain, .. json];
    }
}
