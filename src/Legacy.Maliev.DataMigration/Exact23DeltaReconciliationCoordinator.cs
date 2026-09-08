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
    string? AttestationSignature);

public sealed class Exact23DeltaReconciliationCoordinator(
    IDeltaReconciliationInspector source,
    IDeltaReconciliationInspector target,
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

        var unsigned = new Exact23DeltaReconciliationResult("1.0", plan.PlanId,
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), plan.SourceCutoffUtc,
            timeProvider.GetUtcNow(), new ReadOnlyCollection<DatabaseReconciliationEvidence>(reconciled), signer.KeyId, null);
        return unsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(CreatePayload(unsigned))),
        };
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
            return result.SchemaVersion == "1.0" && result.PlanId != Guid.Empty &&
                result.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) &&
                !string.IsNullOrWhiteSpace(result.AttestationKeyId) && !string.IsNullOrWhiteSpace(result.AttestationSignature) &&
                trust.Verify(result.AttestationKeyId, CreatePayload(result), Convert.FromBase64String(result.AttestationSignature));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] CreatePayload(Exact23DeltaReconciliationResult result)
    {
        byte[] domain = "legacy-maliev-exact23-delta-reconciliation-v1\0"u8.ToArray();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(result with { AttestationSignature = null });
        return [.. domain, .. json];
    }
}
