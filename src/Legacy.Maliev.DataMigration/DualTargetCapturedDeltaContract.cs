using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal enum DualTargetCapturedDeltaPurpose { Production, PersistentLocal, ProductionProof, LocalProof }

internal sealed record DualTargetCapturedDeltaDestination(DualTargetCapturedDeltaPurpose Purpose,
    Exact23DeltaPlanRequest Request, IDeltaDatabaseSnapshotRowSource Rows, P256MigrationEvidenceSigner Signer,
    TrustedAttestationKey EvidenceKey, DualTargetCapturedTargetObservation Observation);
internal sealed record DualTargetCapturedDeltaPlan(DualTargetCapturedDeltaPurpose Purpose, DeltaSynchronizationPlan Plan,
    string EvidenceKeyId, string EvidenceKeyFingerprintSha256, DualTargetCapturedTargetObservation Observation);
internal sealed record DualTargetCapturedDatabase(string Database, DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc, DatabaseReconciliationEvidence Reconciliation,
    IReadOnlyList<DeltaCapturedTableArtifact> SourceTables, IReadOnlyList<DeltaCapturedTableArtifact> FullTables);
internal sealed record DualTargetCapturedDeltaBundle(string Kind, Guid CaptureRunId, string SchemaPlanSha256,
    string SourceCommitSha, string SourceObservationSha256, string EncryptionKeyFingerprintSha256,
    DateTimeOffset CapturedAtUtc, IReadOnlyList<DualTargetCapturedDatabase> Databases,
    IReadOnlyList<DualTargetCapturedDeltaPlan> Plans, string AttestationKeyId, string? AttestationSignature);

// A new signed purpose envelope binds common FULL captures above the existing, target-specific
// schema-1.3 selected-row manifests. It never turns a local-only 1.4 permit into production authority.
internal static class DualTargetCapturedDeltaContract
{
    internal const string Kind = "legacy-maliev-dual-target-captured-zero-delete-v1";
    internal static byte[] Payload(DualTargetCapturedDeltaBundle value)
    {
        return [.. Encoding.UTF8.GetBytes(Kind + "\0"), .. JsonSerializer.SerializeToUtf8Bytes(value with { AttestationSignature = null })];
    }

    internal static string Hash(DualTargetCapturedDeltaBundle value)
    {
        return Convert.ToHexString(SHA256.HashData(Payload(value))).ToLowerInvariant();
    }

    internal static void RequirePurpose(DualTargetCapturedDeltaPurpose purpose, DeltaTargetAuthority? authority,
        string targetNamespace, string cluster)
    {
        if (!DeltaSynchronizationPlanProducer.ValidAuthority(authority, targetNamespace, cluster) || (purpose switch
        {
            DualTargetCapturedDeltaPurpose.Production => authority!.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg ||
                targetNamespace != "maliev-legacy" || cluster != "legacy-postgres-main",
            DualTargetCapturedDeltaPurpose.PersistentLocal => !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(authority),
            DualTargetCapturedDeltaPurpose.ProductionProof or DualTargetCapturedDeltaPurpose.LocalProof =>
                !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(authority),
            _ => true
        })) { throw Invalid(); }
    }

    internal static void RequireZeroDeleteAndEffects(DatabaseSchemaPlan schema, IReadOnlyList<DeltaTablePlan> plans)
    {
        IReadOnlyList<TableCopyPlan> targetTables = schema.Tables.Any(x => x.SourceSchema == "dbo" &&
            x.SourceTable == "GoogleAnalyticsOutbox") ? new QuotationDeltaExecutionMapping(schema).TargetSchema.Tables : schema.Tables;
        foreach (DeltaTablePlan plan in plans)
        {
            TableCopyPlan table = targetTables.Single(x =>
                x.TargetSchema + "." + x.TargetTable == plan.Table);
            if (plan.DeleteCount != 0 || plan.Operations.Any(x => x.Kind == DeltaOperationKind.Delete || !Enum.IsDefined(x.Kind)) ||
                ((table.SourceSchema == "disposition" || table.TargetSchema == "legacy_compatibility") &&
                 (plan.InsertCount != 0 || plan.UpdateCount != 0 || plan.Operations.Count != 0)))
            { throw Invalid(); }
        }
    }

    internal static void Verify(DualTargetCapturedDeltaBundle bundle, FreshSchemaPlan schema,
        IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        if (bundle.Kind != Kind || bundle.CaptureRunId == Guid.Empty || bundle.SchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(schema) ||
            bundle.SourceCommitSha != schema.SourceCommitSha || now.Offset != TimeSpan.Zero || bundle.CapturedAtUtc.Offset != TimeSpan.Zero ||
            !HashShape(bundle.SourceObservationSha256) || !HashShape(bundle.EncryptionKeyFingerprintSha256) ||
            bundle.CapturedAtUtc > now || now - bundle.CapturedAtUtc > TimeSpan.FromHours(12) ||
            bundle.Plans.Count != 4 || bundle.Plans.Select(x => x.Purpose).Distinct().Count() != 4 ||
            !bundle.Databases.Select(x => x.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            string.IsNullOrEmpty(bundle.AttestationSignature)) { throw Invalid(); }
        try
        {
            if (!trust.Verify(bundle.AttestationKeyId, Payload(bundle), Convert.FromBase64String(bundle.AttestationSignature))) { throw Invalid(); }
        }
        catch (FormatException) { throw Invalid(); }
        foreach (DualTargetCapturedDeltaPlan member in bundle.Plans)
        {
            DeltaSynchronizationPlan plan = member.Plan;
            DeltaSynchronizationPlan first = bundle.Plans[0].Plan;
            RequirePurpose(member.Purpose, plan.TargetAuthority, plan.TargetNamespace, plan.TargetCluster);
            string inventoryKind = member.Purpose is DualTargetCapturedDeltaPurpose.Production or DualTargetCapturedDeltaPurpose.ProductionProof ?
                DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire;
            if (!trust.TryGetPublicKeyFingerprintSha256(member.EvidenceKeyId, out string evidenceFingerprint) ||
                !DeltaSynchronizationPlanProducer.FixedHashEquals(evidenceFingerprint, member.EvidenceKeyFingerprintSha256) ||
                member.EvidenceKeyId == plan.AttestationKeyId || member.EvidenceKeyFingerprintSha256 == plan.ExecutionAuthorizationKeyFingerprintSha256 ||
                member.EvidenceKeyFingerprintSha256 == plan.BackupKeyFingerprintSha256 ||
                member.Observation.Authority != plan.TargetAuthority || member.Observation.Generation != plan.TargetGeneration ||
                member.Observation.Sha256 != plan.TargetObservationSha256 ||
                !ReviewedProductionRepairInventory.MatchesKeys(inventoryKind, member.Observation.NativeBeforeSha256.Keys) ||
                member.Observation.NativeBeforeSha256.Values.Any(x => !HashShape(x)) ||
                plan.SchemaVersion != "1.3" || plan.PairedTransitionPlanOnly is not null || plan.QuotationTransitionSchemaSha256 is not null ||
                !DeltaSynchronizationPlanVerifier.Verify(plan, trust, now) || plan.SchemaPlanSha256 != bundle.SchemaPlanSha256 ||
                plan.SourceCommitSha != bundle.SourceCommitSha || plan.SourceObservationSha256 != bundle.SourceObservationSha256 ||
                plan.RunnerDigestSha256 != first.RunnerDigestSha256 || plan.BackupManifestSha256 != first.BackupManifestSha256 ||
                plan.SourceCutoffUtc != first.SourceCutoffUtc || plan.SourceCaptureCompletedAtUtc != bundle.CapturedAtUtc ||
                plan.SourceCaptureManifest?.EncryptionKeyFingerprintSha256 != bundle.EncryptionKeyFingerprintSha256) { throw Invalid(); }
            foreach (DatabaseSchemaPlan database in schema.Databases)
            {
                DualTargetCapturedDatabase full = bundle.Databases.Single(x => x.Database == database.Database);
                DeltaDatabaseCaptureBinding selection = plan.SourceCaptureManifest.Databases.Single(x => x.Database == database.Database);
                if (full.StartedAtUtc.Offset != TimeSpan.Zero || full.CompletedAtUtc.Offset != TimeSpan.Zero ||
                    full.StartedAtUtc < plan.SourceCutoffUtc || full.CompletedAtUtc < full.StartedAtUtc || full.CompletedAtUtc > bundle.CapturedAtUtc ||
                    full.SourceTables.Count != database.Tables.Count ||
                    full.SourceTables.Any(x => x.Database != database.Database || x.SchemaPlanSha256 != bundle.SchemaPlanSha256) ||
                    full.SourceTables.Concat(full.FullTables).Any(x => x.CaptureId == Guid.Empty || x.RowCount < 0 ||
                        !HashShape(x.EncryptedSha256) || !HashShape(x.PlaintextSha256)) ||
                    !full.SourceTables.Select(x => x.Table).Order(StringComparer.Ordinal).SequenceEqual(
                        database.Tables.Select(x => x.TargetSchema + "." + x.TargetTable).Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
                    selection.StartedAtUtc != full.StartedAtUtc || selection.CompletedAtUtc != full.CompletedAtUtc ||
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(selection.SourceReconciliation) !=
                    DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(full.Reconciliation) ||
                    full.FullTables.Count != selection.Tables.Count || full.FullTables.Any(x => x.Database != database.Database ||
                        x.SchemaPlanSha256 != bundle.SchemaPlanSha256 || x.RowCount != full.Reconciliation.Tables.Single(t => t.Table == x.Table).RowCount))
                { throw Invalid(); }
                RequireZeroDeleteAndEffects(database, plan.Databases.Single(x => x.Database == database.Database).Tables);
            }
        }
        if (bundle.Plans.Select(x => x.Plan.TargetAuthority!.SystemIdentifierSha256).Distinct(StringComparer.Ordinal).Count() != 4 ||
            bundle.Plans.Select(x => x.Plan.AttestationKeyId).Distinct(StringComparer.Ordinal).Count() != 4) { throw Invalid(); }
        RequireProofOperations(bundle, DualTargetCapturedDeltaPurpose.Production, DualTargetCapturedDeltaPurpose.ProductionProof);
        RequireProofOperations(bundle, DualTargetCapturedDeltaPurpose.PersistentLocal, DualTargetCapturedDeltaPurpose.LocalProof);
    }

    private static void RequireProofOperations(DualTargetCapturedDeltaBundle bundle,
        DualTargetCapturedDeltaPurpose target, DualTargetCapturedDeltaPurpose proof)
    {
        if (!DisposableDeltaProofVerifier.MatchingOperations(bundle.Plans.Single(x => x.Purpose == target).Plan,
            bundle.Plans.Single(x => x.Purpose == proof).Plan)) { throw Invalid(); }
    }

    internal static DeltaExecutionException Invalid()
    {
        return new("dual_target_captured_delta_invalid",
        "The closed common-capture zero-delete target/proof binding is invalid.");
    }

    private static bool HashShape(string value)
    {
        return value.Length == 64 && value.All(char.IsAsciiHexDigit);
    }
}
