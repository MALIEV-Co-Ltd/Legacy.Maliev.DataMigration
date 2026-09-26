using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

/// <summary>Signed, PII-free metadata for encrypted rows captured under SQL Server snapshots.</summary>
public sealed record DeltaTableCaptureBinding(
    string Table,
    Guid CaptureId,
    string EncryptedSha256,
    string PlaintextSha256,
    long CapturedRowCount,
    string OperationsSha256);

public sealed record DeltaDatabaseCaptureBinding(
    string Database,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    DatabaseReconciliationEvidence SourceReconciliation,
    IReadOnlyList<DeltaTableCaptureBinding> Tables);

public sealed record DeltaSourceCaptureManifest(
    string EncryptionKeyFingerprintSha256,
    IReadOnlyList<DeltaDatabaseCaptureBinding> Databases);

internal static partial class DeltaSourceCaptureManifestValidator
{
    internal static void Validate(
        DeltaSourceCaptureManifest? manifest,
        IReadOnlyList<DeltaDatabasePlan> plans,
        DateTimeOffset globalStartUtc,
        DateTimeOffset globalEndUtc,
        DateTimeOffset nowUtc,
        string planKeyFingerprint,
        string backupKeyFingerprint,
        string authorizationKeyFingerprint)
    {
        if (manifest is null || manifest.Databases is null ||
            !Hash().IsMatch(manifest.EncryptionKeyFingerprintSha256 ?? string.Empty) ||
            new[] { planKeyFingerprint, backupKeyFingerprint, authorizationKeyFingerprint }.Any(value =>
                DeltaSynchronizationPlanProducer.FixedHashEquals(value, manifest.EncryptionKeyFingerprintSha256 ?? string.Empty)) ||
            !manifest.Databases.Select(database => database.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            nowUtc - globalStartUtc > TimeSpan.FromHours(12))
        {
            throw Invalid();
        }

        var captureIds = new HashSet<Guid>();
        var encryptedDigests = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (DeltaDatabaseCaptureBinding database in manifest.Databases)
        {
            DeltaDatabasePlan planned = plans.Single(item => item.Database == database.Database);
            if (database.StartedAtUtc.Offset != TimeSpan.Zero || database.CompletedAtUtc.Offset != TimeSpan.Zero ||
                database.StartedAtUtc < globalStartUtc || database.CompletedAtUtc < database.StartedAtUtc ||
                database.CompletedAtUtc > globalEndUtc || database.SourceReconciliation is null ||
                !string.Equals(database.SourceReconciliation.Database, database.Database, StringComparison.Ordinal) ||
                !Hash().IsMatch(database.SourceReconciliation.SourceSchemaSha256 ?? string.Empty) ||
                !Hash().IsMatch(database.SourceReconciliation.TargetSchemaSha256 ?? string.Empty) ||
                database.Tables is null || database.SourceReconciliation.Tables is null ||
                database.Tables.Select(table => table.Table).Distinct(StringComparer.Ordinal).Count() != database.Tables.Count ||
                database.SourceReconciliation.Tables.Select(table => table.Table).Distinct(StringComparer.Ordinal).Count() != database.SourceReconciliation.Tables.Count ||
                !database.Tables.Select(table => table.Table).Order(StringComparer.Ordinal)
                    .SequenceEqual(planned.Tables.Select(table => table.Table).Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
                !database.SourceReconciliation.Tables.Select(table => table.Table).Order(StringComparer.Ordinal)
                    .SequenceEqual(planned.Tables.Select(table => table.Table).Order(StringComparer.Ordinal), StringComparer.Ordinal))
            {
                throw Invalid();
            }

            foreach (DeltaTablePlan table in planned.Tables)
            {
                DeltaTableCaptureBinding capture = database.Tables.Single(item => item.Table == table.Table);
                TableReconciliationEvidence evidence = database.SourceReconciliation.Tables.Single(item => item.Table == table.Table);
                if (capture.CaptureId == Guid.Empty || !captureIds.Add(capture.CaptureId) ||
                    !Hash().IsMatch(capture.EncryptedSha256 ?? string.Empty) ||
                    !encryptedDigests.Add(capture.EncryptedSha256 ?? string.Empty) ||
                    !Hash().IsMatch(capture.PlaintextSha256 ?? string.Empty) ||
                    capture.CapturedRowCount != checked(table.InsertCount + table.UpdateCount) ||
                    !DeltaSynchronizationPlanProducer.FixedHashEquals(capture.OperationsSha256, table.OperationsSha256) ||
                    evidence.RowCount != checked(table.InsertCount + table.UpdateCount + table.UnchangedCount) ||
                    !Hash().IsMatch(evidence.ContentSha256 ?? string.Empty) ||
                    !Hash().IsMatch(evidence.AggregateSha256 ?? string.Empty) ||
                    evidence.NullCounts is null || evidence.NullCounts.Values.Any(value => value < 0) ||
                    evidence.ForeignKeyOrphanCounts is null || evidence.ForeignKeyOrphanCounts.Values.Any(value => value < 0) ||
                    evidence.ForeignKeyRelationshipCounts is null || evidence.ForeignKeyRelationshipCounts.Values.Any(value => value < 0))
                {
                    throw Invalid();
                }
            }
            if (database.SourceReconciliation.SequenceNextValues is null ||
                database.SourceReconciliation.SequenceNextValues.Values.Any(value => value < 0))
            {
                throw Invalid();
            }
        }
    }

    private static DeltaPlanException Invalid()
    {
        return new("delta_plan_capture_invalid", "The encrypted source capture binding is incomplete or inconsistent.");
    }

    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Hash();
}
