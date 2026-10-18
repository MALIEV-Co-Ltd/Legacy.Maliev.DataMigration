using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class IsoIntendedRuntimeReader
{
    internal static byte[] Payload(IsoIntendedRuntimeObservation value)
    {
        return [.. "Legacy.Maliev.OwnerIso.IntendedRuntime.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(value with { Signature = null })];
    }

    internal static void RequireFacts(IsoIntendedRuntimeFacts facts, FreshSchemaPlan source, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        LocalExecutionBinding binding, DateTimeOffset now)
    {
        ProductionSchemaCatalogInspector.ValidatePlan(source, now);
        var contract = ApprovedCurrentOwnerIsoOverlay.Create(source, source.SourceCommitSha, CurrentOwnerIsoSelection.LiteralWidthV1, owners, now);
        if (facts.OperationId == Guid.Empty || facts.Target.Kind != DeltaTargetAuthorityKind.LocalAspire || !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(facts.Target) ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(facts.Target, facts.TargetNamespace, facts.TargetCluster) || facts.SourceCommitSha != source.SourceCommitSha || facts.SourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) ||
            facts.OwnerSourcesSha256 != CurrentAppOwnedSnapshotSerialization.Sha256(owners) || facts.ContractSha256 != contract.ComputeSha256() || facts.OperationSha256 != PostgreSqlCurrentOwnerIsoRepair.OperationSha256 || facts.RunBindingSha256 != binding.ComputeSha256() ||
            facts.BeforeDatabaseSha256.Count != 26 || !facts.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).Order(StringComparer.Ordinal)) ||
            source.Databases.Count != 23 || source.Databases.Sum(x => x.Tables.Count) != 100 || source.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)) ||
            facts.BeforeDatabaseSha256.Values.Any(x => !CurrentAppOwnedRepairPermit.HashShape(x)) || !CurrentAppOwnedRepairPermit.HashShape(facts.SourceCatalogSha256) || !CurrentAppOwnedRepairPermit.HashShape(facts.TargetObservationSha256) || !CurrentAppOwnedRepairPermit.HashShape(facts.GlobalPreservationSha256) ||
            facts.MaintenanceValidatorSha256 != CurrentOwnerIsoRepairPermit.MaintenanceValidator || facts.Maintenance.IssuedAtUtc > now || facts.Maintenance.ExpiresAtUtc <= now || facts.Maintenance.ExpiresAtUtc - facts.Maintenance.IssuedAtUtc > TimeSpan.FromHours(4)) { throw Invalid(); }
    }
    internal static void RequireRuntime(IsoIntendedRuntimeObservation value, CurrentOwnerIsoRepairScope runtime)
    {
        var f = value.Facts;
        if (runtime.ProofAdmission != CurrentOwnerIsoProofAdmission.PersistentWithClosedConsoleProof || runtime.BootstrapSubject is not null || runtime.Target.Kind != DeltaTargetAuthorityKind.LocalAspire || !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(runtime.Target) ||
            value.ServerVersionNumber != 180004 || f.OperationId != runtime.OperationId || f.Target != runtime.Target || f.TargetNamespace != runtime.TargetNamespace || f.TargetCluster != runtime.TargetCluster || f.TargetGeneration != runtime.TargetGeneration || f.TargetObservationSha256 != runtime.TargetObservationSha256 || f.RunBindingSha256 != runtime.RunBindingSha256 ||
            f.SourceCommitSha != runtime.SourceCommitSha || f.SourceSchemaPlanSha256 != runtime.BeforeSchemaPlanSha256 || f.SourceCatalogSha256 != runtime.SourceCatalogSha256 || f.OwnerSourcesSha256 != runtime.OwnerSourcesSha256 || f.ContractSha256 != runtime.ContractSha256 || f.OperationSha256 != runtime.OperationSha256 || f.GlobalPreservationSha256 != runtime.GlobalPreservationSha256 ||
            f.Maintenance != runtime.Maintenance || f.MaintenanceValidatorSha256 != runtime.MaintenanceValidatorSha256 || CurrentAppOwnedSnapshotSerialization.Sha256(f.BeforeDatabaseSha256) != CurrentAppOwnedSnapshotSerialization.Sha256(runtime.BeforeDatabaseSha256)) { throw Invalid(); }
    }
    internal static async Task<IsoIntendedRuntimeObservation> RequireHeldAsync(CurrentAppOwnedRepairCustody runtimeFiles, LocalExecutionBinding binding,
        IsoIntendedRuntimeEvidence evidence, FreshSchemaPlan source, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
        CurrentOwnerIsoRepairSigningPins runtimePins, DateTimeOffset now, CancellationToken ct)
    {
        runtimeFiles.Require();
        if (MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(runtimeFiles.Read(evidence.BindingPath, sharedReader: true, maximumBytes: 65536)) != binding) { throw Invalid(); }
        var pins = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairSigningPins>(runtimeFiles.Read(evidence.SigningPinsPath, sharedReader: true, maximumBytes: 65536));
        if (pins != runtimePins) { throw Invalid(); }
        var trust = Trust(runtimeFiles, evidence.TrustedKeys, pins);
        var value = MigrationConsole.DecodeOwnerIso<IsoIntendedRuntimeObservation>(Read(runtimeFiles, evidence.Observation, 8_000_000));
        RequireFacts(value.Facts, source, owners, binding, now); var facts = value.Facts;
        if (value.Kind != "current-owner-iso-intended-runtime-v1" || value.ServerVersionNumber != 180004 || value.ObservedAtUtc.Offset != TimeSpan.Zero || value.ExpiresAtUtc.Offset != TimeSpan.Zero || value.ObservedAtUtc > now || value.ExpiresAtUtc <= now || value.ExpiresAtUtc > facts.Maintenance.ExpiresAtUtc || value.ExpiresAtUtc - value.ObservedAtUtc > TimeSpan.FromHours(2) ||
            value.KeyId != pins.ReviewKeyId || string.IsNullOrWhiteSpace(value.Signature) || !CurrentAppOwnedRepairPermit.HashShape(value.DefinitionPrecursorSha256)) { throw Invalid(); }
        try { if (!trust.Verify(value.KeyId, Payload(value), Convert.FromBase64String(value.Signature))) { throw Invalid(); } } catch (FormatException) { throw Invalid(); }
        var subject = value.DefinitionSubject;
        if (subject.SourceCommitSha != facts.SourceCommitSha || subject.SourceCatalogSha256 != facts.SourceCatalogSha256 || subject.SourceSchemaPlanSha256 != facts.SourceSchemaPlanSha256 || subject.OwnerSourcesSha256 != facts.OwnerSourcesSha256 || subject.ContractSha256 != facts.ContractSha256 ||
            subject.IntendedTargetObservationSha256 != facts.TargetObservationSha256 || subject.IntendedRunBindingSha256 != facts.RunBindingSha256 || subject.ConsoleAssemblySha256 != Image(typeof(MigrationConsole).Assembly.Location) || subject.CoreAssemblySha256 != Image(typeof(CurrentOwnerIsoRepairPermit).Assembly.Location) || !CurrentAppOwnedRepairPermit.HashShape(subject.TestAssemblySha256)) { throw Invalid(); }
        if (SchemaPlanCanonicalizer.ComputeSha256(MigrationConsole.DecodeOwnerIso<FreshSchemaPlan>(Read(runtimeFiles, value.Source, 32 * 1024 * 1024))) != facts.SourceSchemaPlanSha256 || value.Source.Sha256 != subject.RawSourceFileSha256 || CurrentAppOwnedSnapshotSerialization.Sha256(MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoSourceObservation[]>(Read(runtimeFiles, value.Owners, 8_000_000))) != facts.OwnerSourcesSha256 || value.SourceCatalog.Sha256 != facts.SourceCatalogSha256) { throw Invalid(); }
        _ = CurrentOwnerIsoRepairSourceObservation.ReadCatalog(Read(runtimeFiles, value.SourceCatalog, 8_000_000), source, facts.SourceCatalogSha256, facts.SourceCommitSha, now);
        var target = MigrationConsole.DecodeOwnerIso<CurrentAppOwnedRepairTargetPins>(Read(runtimeFiles, value.TargetPins, 1_000_000));
        if (CurrentAppOwnedSnapshotSerialization.Sha256(target) != facts.TargetObservationSha256 || target.CloudOptions is not null || target.CloudObservation is not null) { throw Invalid(); }
        // A signed manifest cannot replace held exact native and full-fleet artifacts.
        var contract = ApprovedCurrentOwnerIsoOverlay.Create(source, facts.SourceCommitSha, CurrentOwnerIsoSelection.LiteralWidthV1, owners, now);
        foreach (var item in new[] { ("Country", value.CountryBefore), ("Material", value.MaterialBefore) })
        { var native = MigrationConsole.DecodeOwnerIso<IsoCapturedNative>(Read(runtimeFiles, item.Item2, 32 * 1024 * 1024)).Observe(); CurrentOwnerIsoNativePreservation.RequireBefore(native, contract); if (native.Snapshot.Database != item.Item1 || native.Snapshot.Sha256 != facts.BeforeDatabaseSha256[item.Item1]) { throw Invalid(); } }
        FileStream held = runtimeFiles.BorrowReadStream(value.FreshFleet.Path); held.Position = 0;
        if (Convert.ToHexStringLower(await SHA256.HashDataAsync(held, ct).ConfigureAwait(false)) != value.FreshFleet.Sha256) { throw Invalid(); }
        var fleet = await runtimeFiles.ReadBaselineAsync(value.FreshFleet.Path, ct, sharedReader: true).ConfigureAwait(false);
        if (fleet.Length != 26 || fleet.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != 26 || fleet.Any(x => !facts.BeforeDatabaseSha256.TryGetValue(x.Database, out string? hash) || hash != x.Sha256) || CurrentAppOwnedSnapshotSerialization.Sha256(fleet) != facts.GlobalPreservationSha256) { throw Invalid(); }
        runtimeFiles.Require(); return value;
    }
    internal static ReceiptAttestationTrustStore Trust(CurrentAppOwnedRepairCustody files, IReadOnlyList<DeltaTrustedKeyReference> keys, CurrentOwnerIsoRepairSigningPins pins)
    {
        if (keys.Count != 3 || keys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != 3) { throw Invalid(); }
        var store = new ReceiptAttestationTrustStore(keys.Select(x => new TrustedAttestationKey(x.KeyId, Convert.FromBase64String(Encoding.UTF8.GetString(files.Read(x.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536)).Trim()))));
        var pairs = new[] { (pins.ReviewKeyId, pins.ReviewFingerprint), (pins.AuthorizationKeyId, pins.AuthorizationFingerprint), (pins.ReceiptKeyId, pins.ReceiptFingerprint) };
        return pairs.Select(x => x.Item1).Distinct().Count() != 3 || pairs.Select(x => x.Item2).Distinct().Count() != 3 || pairs.Any(x => !store.TryGetPublicKeyFingerprintSha256(x.Item1, out string actual) || actual != x.Item2)
            ? throw Invalid()
            : store;
    }
    internal static byte[] Read(CurrentAppOwnedRepairCustody files, IsoDefinitionArtifact artifact, int maximum)
    { byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum); return CurrentAppOwnedRepairPermit.Hash(bytes) != artifact.Sha256 ? throw Invalid() : bytes;
    }
    internal static string Image(string path) { using var held = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(held)); }
    internal static MigrationExecutionException Invalid()
    {
        return new("iso_intended_runtime_invalid", "Fresh independently held intended local18.4 full26 observations and actual completed closed proof are required; production18.1 is not certified.");
    }
}
