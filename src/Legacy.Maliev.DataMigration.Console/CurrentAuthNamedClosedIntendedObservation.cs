using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Independent intended target observations. This type has no future closed-proof
// hashes, signed permission, authorization, reservation, DDL or recovery waiver.
internal sealed record CurrentAuthNamedClosedIntendedFacts(Guid OperationId, string SourceCommitSha,
    string SourceSchemaPlanSha256, DeltaTargetAuthority Target, string TargetNamespace, string TargetCluster,
    string TargetGeneration, string TargetObservationSha256, string RunBindingSha256,
    IReadOnlyDictionary<string, string> BeforeDatabaseSha256, string GlobalPreservationSha256,
    CurrentAppOwnedMaintenancePin Maintenance, string DefinitionPrecursorSha256);
internal sealed record CurrentAuthNamedClosedIntendedObservation(string Kind,
    CurrentAuthNamedClosedIntendedFacts Facts, string AuthOwnerCommitSha, string AuthOwnerSourcePinsSha256,
    string AuthClosureSha256, string BeforeSchemaSha256, string AfterSchemaSha256, string OperationSha256,
    string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256,
    string RunBindingPath, string SourcePath, string TargetPinsPath, CurrentAuthProofArtifact NativeBefore,
    CurrentAuthProofArtifact FreshFleet, DateTimeOffset ObservedAtUtc, DateTimeOffset ExpiresAtUtc,
    int ServerVersionNumber, string KeyId, string? Signature);
internal sealed record CurrentAuthNamedClosedIntendedConfiguration(string RunBindingPath, string FactsPath,
    string SourcePath, string TargetPinsPath, string GlobalBeforePath, string OperatorConnectionPath,
    string OrdinaryConnectionPath, string SigningPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string ReviewPrivateKeyPath, string TestAssemblyPath, CurrentAuthClosedBootstrapEvidence CompletedComponents,
    string OutputPath);
internal sealed record CurrentAuthNamedClosedIntendedEvidence(string RunBindingPath, string SigningPinsPath,
    IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys, CurrentAuthProofArtifact Observation);

internal static class CurrentAuthNamedClosedIntent
{
    internal static void RequireCandidate(CurrentAuthNamedClosedIntendedFacts facts, FreshSchemaPlan source,
        LocalExecutionBinding binding, DateTimeOffset now)
    {
        ProductionSchemaCatalogInspector.ValidatePlan(source, now);
        if (facts.Target is null || facts.Maintenance is null || facts.BeforeDatabaseSha256 is null ||
            facts.Target.Kind is not (DeltaTargetAuthorityKind.LocalAspire or DeltaTargetAuthorityKind.ProductionCloudNativePg) ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(facts.Target, facts.TargetNamespace, facts.TargetCluster) ||
            facts.SourceCommitSha != source.SourceCommitSha || facts.SourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) ||
            facts.RunBindingSha256 != binding.ComputeSha256() || facts.OperationId == Guid.Empty ||
            facts.BeforeDatabaseSha256.Count != (facts.Target.Kind == DeltaTargetAuthorityKind.LocalAspire ? 26 : 53) ||
            facts.BeforeDatabaseSha256.Values.Any(x => !CurrentAuthRepairPermit.HashShape(x)) ||
            facts.GlobalPreservationSha256 != CurrentAuthRepairPermit.FleetSha256(facts.BeforeDatabaseSha256) ||
            !CurrentAuthRepairPermit.HashShape(facts.DefinitionPrecursorSha256) || !CurrentAuthRepairPermit.HashShape(facts.TargetObservationSha256) ||
            !ApprovedConsumerOverlaySelection.IsApproved(source) || source.Databases.Count != 23 || source.Databases.Sum(x => x.Tables.Count) != 100 ||
            !source.Databases.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal)) ||
            source.Databases.Any(x => x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)) ||
            source.Databases.Single(x => x.Database == "Quotation").SourceDispositionProfile != ApprovedSourceDispositionManifest.QuotationOutboxesV1 ||
            !DatabaseInventory.ActiveDatabases.All(facts.BeforeDatabaseSha256.ContainsKey) || !facts.BeforeDatabaseSha256.ContainsKey("Auth") ||
            !facts.BeforeDatabaseSha256.ContainsKey("postgres") || (facts.Target.Kind == DeltaTargetAuthorityKind.LocalAspire && !facts.BeforeDatabaseSha256.ContainsKey("legacy_local")) ||
            facts.Maintenance.IssuedAtUtc > now || facts.Maintenance.ExpiresAtUtc <= now || facts.Maintenance.ExpiresAtUtc - facts.Maintenance.IssuedAtUtc > TimeSpan.FromHours(4))
        { throw CurrentAuthRepairPermit.Invalid(); }
    }
    internal static byte[] Payload(CurrentAuthNamedClosedIntendedObservation value) =>
        [.. "Legacy.Maliev.CurrentAuth.ClosedIntendedObservation.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(value with { Signature = null })];
    internal static string Subject(CurrentAuthNamedClosedIntendedObservation value) => CurrentAppOwnedSnapshotSerialization.Sha256(new
    { Domain = "Legacy.Maliev.CurrentAuth.ClosedIntendedSubject.v1", Observation = value with { Signature = null } });
    internal static void Require(CurrentAuthNamedClosedIntendedObservation value, FreshSchemaPlan source,
        IReceiptAttestationTrustStore trust, CurrentAuthRepairSigningPins pins, DateTimeOffset now)
    {
        var facts = value.Facts;
        if (value.Kind != "current-auth-observed-closed-intended-subject-v1" || facts.SourceCommitSha != source.SourceCommitSha ||
            facts.SourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) ||
            value.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit || value.AuthOwnerSourcePinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
            value.AuthClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 || value.BeforeSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(false) ||
            value.AfterSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) || value.OperationSha256 != CurrentAuthRepairPermit.OperationSha256(source, facts.DefinitionPrecursorSha256) ||
            facts.OperationId == Guid.Empty || facts.BeforeDatabaseSha256.Count != (facts.Target.Kind == DeltaTargetAuthorityKind.LocalAspire ? 26 : 53) ||
            !DatabaseInventory.ActiveDatabases.All(facts.BeforeDatabaseSha256.ContainsKey) || !facts.BeforeDatabaseSha256.ContainsKey("Auth") ||
            !facts.BeforeDatabaseSha256.ContainsKey("postgres") || (facts.Target.Kind == DeltaTargetAuthorityKind.LocalAspire && !facts.BeforeDatabaseSha256.ContainsKey("legacy_local")) ||
            facts.GlobalPreservationSha256 != CurrentAuthRepairPermit.FleetSha256(facts.BeforeDatabaseSha256) ||
            new[] { facts.DefinitionPrecursorSha256, facts.TargetObservationSha256, facts.RunBindingSha256, value.TestAssemblySha256, value.ConsoleAssemblySha256, value.CoreAssemblySha256 }.Any(x => !CurrentAuthRepairPermit.HashShape(x)) ||
            facts.BeforeDatabaseSha256.Values.Any(x => !CurrentAuthRepairPermit.HashShape(x)) || value.ObservedAtUtc.Offset != TimeSpan.Zero || value.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            now.Offset != TimeSpan.Zero || value.ObservedAtUtc > now || value.ExpiresAtUtc <= now || value.ExpiresAtUtc <= value.ObservedAtUtc ||
            value.ExpiresAtUtc - value.ObservedAtUtc > TimeSpan.FromHours(2) || value.ExpiresAtUtc > facts.Maintenance.ExpiresAtUtc ||
            value.KeyId != pins.ReviewKeyId || !trust.TryGetPublicKeyFingerprintSha256(value.KeyId, out string fingerprint) || fingerprint != pins.ReviewFingerprint ||
            string.IsNullOrWhiteSpace(value.Signature) || !trust.Verify(value.KeyId, Payload(value), Convert.FromBase64String(value.Signature)))
        { throw CurrentAuthRepairPermit.Invalid(); }
    }
    internal static Task<CurrentAuthNamedClosedIntendedObservation> ReadHeldAsync(CurrentAuthNamedClosedIntendedEvidence evidence,
        FreshSchemaPlan source, CancellationToken ct) => ReadCoreAsync(evidence, source, null, ct);
    internal static Task<CurrentAuthNamedClosedIntendedObservation> ReadThroughOperationalCustodyAsync(CurrentAuthNamedClosedIntendedEvidence evidence,
        FreshSchemaPlan source, CurrentAppOwnedRepairCustody heldOperationalFiles, CancellationToken ct) => ReadCoreAsync(evidence, source, heldOperationalFiles, ct);
    private static async Task<CurrentAuthNamedClosedIntendedObservation> ReadCoreAsync(CurrentAuthNamedClosedIntendedEvidence evidence,
        FreshSchemaPlan source, CurrentAppOwnedRepairCustody? existing, CancellationToken ct)
    {
        var binding = CurrentAuthNamedClosedProofProducer.ReadBinding(evidence.RunBindingPath);
        using var authority = existing is null ? WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding) : null;
        using var ownedFiles = authority is null ? null : new CurrentAppOwnedRepairCustody(authority);
        var files = existing ?? ownedFiles ?? throw CurrentAuthRepairPermit.Invalid();
        if (MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(files.Read(evidence.RunBindingPath, sharedReader: true, maximumBytes: 65536)) != binding || evidence.TrustedKeys.Count != 3)
        { throw CurrentAuthRepairPermit.Invalid(); }
        var pins = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairSigningPins>(files.Read(evidence.SigningPinsPath, sharedReader: true, maximumBytes: 65536));
        var trust = new ReceiptAttestationTrustStore(evidence.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        byte[] bytes = files.Read(evidence.Observation.Path, sharedReader: true, maximumBytes: 1024 * 1024);
        if (CurrentAuthRepairPermit.Hash(bytes) != evidence.Observation.Sha256) { throw CurrentAuthRepairPermit.Invalid(); }
        var value = MigrationConsole.DecodeAuthRepair<CurrentAuthNamedClosedIntendedObservation>(bytes);
        Require(value, source, trust, pins, DateTimeOffset.UtcNow);
        if (value.Facts.RunBindingSha256 != binding.ComputeSha256() || value.RunBindingPath != evidence.RunBindingPath ||
            CurrentAppOwnedSnapshotSerialization.Sha256(MigrationConsole.DecodeAuthRepair<CurrentAppOwnedRepairTargetPins>(files.Read(value.TargetPinsPath, sharedReader: true, maximumBytes: 1024 * 1024))) != value.Facts.TargetObservationSha256 ||
            SchemaPlanCanonicalizer.ComputeSha256(MigrationConsole.DecodeAuthRepair<FreshSchemaPlan>(files.Read(value.SourcePath, sharedReader: true, maximumBytes: 32 * 1024 * 1024))) != value.Facts.SourceSchemaPlanSha256)
        { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] nativeBytes = files.Read(value.NativeBefore.Path, sharedReader: true, maximumBytes: 32 * 1024 * 1024);
        if (CurrentAuthRepairPermit.Hash(nativeBytes) != value.NativeBefore.Sha256) { throw CurrentAuthRepairPermit.Invalid(); }
        var native = MigrationConsole.DecodeAuthRepair<CurrentAuthProofNative>(nativeBytes).Observation(); CurrentAuthNativePreservation.RequireBefore(native);
        if (native.Snapshot.Sha256 != value.Facts.BeforeDatabaseSha256["Auth"]) { throw CurrentAuthRepairPermit.Invalid(); }
        FileStream fleetStream = files.BorrowReadStream(value.FreshFleet.Path);
        if (Convert.ToHexStringLower(await SHA256.HashDataAsync(fleetStream, ct).ConfigureAwait(false)) != value.FreshFleet.Sha256) { throw CurrentAuthRepairPermit.Invalid(); }
        var baseline = await files.ReadBaselineAsync(value.FreshFleet.Path, ct, sharedReader: true).ConfigureAwait(false);
        if (baseline.Length != value.Facts.BeforeDatabaseSha256.Count || baseline.Select(x => x.Database).Distinct().Count() != baseline.Length ||
            baseline.Any(x => !value.Facts.BeforeDatabaseSha256.TryGetValue(x.Database, out string? expected) || x.Sha256 != expected)) { throw CurrentAuthRepairPermit.Invalid(); }
        files.Require(); return value;
    }
    internal static void RequireRuntime(CurrentAuthNamedClosedIntendedObservation value, CurrentAuthRepairScope scope)
    {
        var facts = value.Facts;
        if (scope.ProofAdmission != CurrentAuthProofAdmission.ClosedConsole || scope.ComponentSubject is not null || scope.ClosedBootstrapSubject is not null ||
            facts.OperationId != scope.OperationId || facts.SourceCommitSha != scope.SourceCommitSha || facts.SourceSchemaPlanSha256 != scope.SourceSchemaPlanSha256 ||
            value.AuthOwnerCommitSha != scope.AuthOwnerCommitSha || value.AuthOwnerSourcePinsSha256 != scope.AuthOwnerSourcePinsSha256 || value.AuthClosureSha256 != scope.AuthClosureSha256 ||
            value.BeforeSchemaSha256 != scope.AuthBeforeSchemaSha256 || value.AfterSchemaSha256 != scope.AuthAfterSchemaSha256 || value.OperationSha256 != scope.OperationSha256 ||
            facts.DefinitionPrecursorSha256 != scope.AuthHelperProofSha256 || facts.Target != scope.Target || facts.TargetNamespace != scope.TargetNamespace || facts.TargetCluster != scope.TargetCluster ||
            facts.TargetGeneration != scope.TargetGeneration || facts.TargetObservationSha256 != scope.TargetObservationSha256 || facts.RunBindingSha256 != scope.RunBindingSha256 ||
            facts.GlobalPreservationSha256 != scope.GlobalPreservationSha256 || JsonSerializer.Serialize(facts.BeforeDatabaseSha256) != JsonSerializer.Serialize(scope.BeforeDatabaseSha256) ||
            facts.Maintenance != scope.Maintenance)
        { throw CurrentAuthRepairPermit.Invalid(); }
        // The currently implemented named fixture is18.4. It cannot certify actual production18.1.
        if (value.ServerVersionNumber != 180004 || scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire)
        { throw CurrentAuthRepairPermit.Invalid(); }
    }
}

public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthNamedClosedIntentAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            CurrentAuthRepairCapacity.Require(admission: true); string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
            var config = await ReadProtectedJsonAsync<CurrentAuthNamedClosedIntendedConfiguration>(configPath, "auth_closed_intent_config_unprotected", ct).ConfigureAwait(false);
            var binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(config.RunBindingPath, "auth_closed_intent_binding_unprotected", ct).ConfigureAwait(false);
            using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding); using var files = new CurrentAppOwnedRepairCustody(authority);
            T Read<T>(string path) => DecodeAuthRepair<T>(files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
            if (JsonSerializer.Serialize(Read<CurrentAuthNamedClosedIntendedConfiguration>(configPath)) != JsonSerializer.Serialize(config)) { throw CurrentAuthRepairPermit.Invalid(); }
            var facts = Read<CurrentAuthNamedClosedIntendedFacts>(config.FactsPath); var source = Read<FreshSchemaPlan>(config.SourcePath);
            CurrentAuthNamedClosedIntent.RequireCandidate(facts, source, binding, DateTimeOffset.UtcNow);
            var target = Read<CurrentAppOwnedRepairTargetPins>(config.TargetPinsPath); var pins = Read<CurrentAuthRepairSigningPins>(config.SigningPinsPath);
            if (facts.SourceCommitSha != accepted || source.SourceCommitSha != accepted || facts.SourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) ||
                facts.RunBindingSha256 != binding.ComputeSha256() || facts.TargetObservationSha256 != CurrentAppOwnedSnapshotSerialization.Sha256(target) ||
                facts.DefinitionPrecursorSha256 != config.CompletedComponents.Definition.Sha256 || config.TrustedKeys.Count != 3)
            { throw CurrentAuthRepairPermit.Invalid(); }
            if (CurrentAuthNamedClosedProofProducer.ReadBinding(config.CompletedComponents.PrecursorRunBindingPath).ComputeSha256() == binding.ComputeSha256())
            { throw CurrentAuthRepairPermit.Invalid(); }
            var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(x => new TrustedAttestationKey(x.KeyId,
                files.Read(x.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
            using var signer = new P256MigrationEvidenceSigner(pins.ReviewKeyId, Encoding.UTF8.GetString(files.Read(config.ReviewPrivateKeyPath, sharedReader: true, maximumBytes: 65536)));
            if (signer.PublicKeyFingerprintSha256 != pins.ReviewFingerprint) { throw CurrentAuthRepairPermit.Invalid(); }
            string testSha = CurrentAuthTypedHostProducer.ImageHash(config.TestAssemblyPath), consoleSha = CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location), coreSha = CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location);
            await CurrentAuthClosedBootstrapReadback.RequireCompletedForHostAsync(config.CompletedComponents, source, testSha, consoleSha, coreSha, ct).ConfigureAwait(false);
            CurrentAuthRepairCapacity.Require(admission: true);
            var baseline = await files.ReadBaselineAsync(config.GlobalBeforePath, ct, sharedReader: true).ConfigureAwait(false);
            // Empty future proof fields make this context unadmittable. It is used only
            // by the accepted environment's read-only observations; no issuer/provider exists here.
            var context = new CurrentAuthRepairScope(facts.OperationId, CurrentAuthRepairOperation.SixteenSameTypeTextCollations, accepted,
                facts.SourceSchemaPlanSha256, ApprovedCurrentAuthSchema.AuthServiceCommit, CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256,
                ApprovedCurrentAuthSchema.PhysicalSha256(false), ApprovedCurrentAuthSchema.PhysicalSha256(true), CurrentAuthRepairPermit.OperationSha256(source, facts.DefinitionPrecursorSha256),
                facts.DefinitionPrecursorSha256, CurrentAuthRepairPermit.MaintenanceValidator, facts.Target, facts.TargetNamespace, facts.TargetCluster, facts.TargetGeneration,
                facts.TargetObservationSha256, facts.RunBindingSha256, facts.BeforeDatabaseSha256, facts.GlobalPreservationSha256, string.Empty, string.Empty, string.Empty, facts.Maintenance);
            string operatorConnection = Encoding.UTF8.GetString(files.Read(config.OperatorConnectionPath, sharedReader: true, maximumBytes: 65536));
            string ordinary = Encoding.UTF8.GetString(files.Read(config.OrdinaryConnectionPath, sharedReader: true, maximumBytes: 65536));
            using var environment = new CurrentAuthRepairEnvironment(authority, files, target, operatorConnection, ordinary, baseline, source, context, trust, pins,
                CurrentAppOwnedSnapshotSerialization.Sha256(facts)); // observation context digest, never an authorization claim
            await environment.RequireFreshOperationAsync(context, ct).ConfigureAwait(false);
            await environment.RequireSourceAsync(accepted, ct).ConfigureAwait(false); await environment.RequireAuthOwnerSourceAsync(context, ct).ConfigureAwait(false);
            await environment.RequireSource23PhysicalBaselineAsync(source, ct).ConfigureAwait(false); await environment.RequireResourceAndCustodyAsync(context, ct).ConfigureAwait(false);
            var fresh = (await environment.InspectFleetAsync(context, ct).ConfigureAwait(false)).ToArray();
            var native = await environment.GetAuthPreimageAsync(ct).ConfigureAwait(false); CurrentAuthNativePreservation.RequireBefore(native);
            int version;
            await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(operatorConnection) { Database = "postgres", Pooling = false }.ConnectionString))
            {
                await connection.OpenAsync(ct).ConfigureAwait(false); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
                await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx)) { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
                await using var command = new NpgsqlCommand("SELECT current_setting('server_version_num')::integer;", connection, tx);
                version = Convert.ToInt32(await command.ExecuteScalarAsync(ct).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture); await tx.RollbackAsync(ct).ConfigureAwait(false);
            }
            string root = binding.ArtifactRootCanonicalPath, nativePath = Path.Combine(root, "auth-closed-intended-native.json"), fleetPath = Path.Combine(root, "auth-closed-intended-fleet.json");
            byte[] nativeBytes = JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthProofNative(native.Snapshot, native.CopyTuples(), native.CopyStorage().ToDictionary(x => x.Key,
                x => new CurrentAuthProofStorage(x.Value.FileNode, x.Value.Blocks), StringComparer.Ordinal), native.CopyExpressions()));
            if (nativeBytes.Length > 32 * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
            await files.WriteNewAsync(nativePath, nativeBytes, ct).ConfigureAwait(false); await files.WriteBaselineNewAsync(fleetPath, fresh, ct).ConfigureAwait(false);
            FileStream fleetStream = files.BorrowReadStream(fleetPath); string fleetSha = Convert.ToHexStringLower(await SHA256.HashDataAsync(fleetStream, ct).ConfigureAwait(false));
            DateTimeOffset now = DateTimeOffset.UtcNow, expires = now.AddHours(2) < facts.Maintenance.ExpiresAtUtc ? now.AddHours(2) : facts.Maintenance.ExpiresAtUtc;
            var observation = new CurrentAuthNamedClosedIntendedObservation("current-auth-observed-closed-intended-subject-v1", facts,
                ApprovedCurrentAuthSchema.AuthServiceCommit, CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256,
                ApprovedCurrentAuthSchema.PhysicalSha256(false), ApprovedCurrentAuthSchema.PhysicalSha256(true), context.OperationSha256,
                testSha, consoleSha, coreSha, config.RunBindingPath, config.SourcePath, config.TargetPinsPath,
                new(nativePath, CurrentAuthRepairPermit.Hash(nativeBytes)), new(fleetPath, fleetSha), now, expires, version, signer.KeyId, null);
            await environment.RequireResourceAndCustodyAsync(context, ct).ConfigureAwait(false);
            if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != accepted) { throw CurrentAuthRepairPermit.Invalid(); }
            observation = observation with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthNamedClosedIntent.Payload(observation))) };
            CurrentAuthNamedClosedIntent.Require(observation, source, trust, pins, DateTimeOffset.UtcNow);
            await files.WriteNewAsync(config.OutputPath, JsonSerializer.SerializeToUtf8Bytes(observation), ct).ConfigureAwait(false);
            CurrentAuthNamedClosedIntent.Require(Read<CurrentAuthNamedClosedIntendedObservation>(config.OutputPath), source, trust, pins, DateTimeOffset.UtcNow);
            await output.WriteLineAsync("current_auth_intended_target_observed_no_authority").ConfigureAwait(false); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or JsonException or CryptographicException or InvalidOperationException or NpgsqlException)
        { await error.WriteLineAsync("current_auth_intended_observation_failed").ConfigureAwait(false); return 1; }
    }
}
