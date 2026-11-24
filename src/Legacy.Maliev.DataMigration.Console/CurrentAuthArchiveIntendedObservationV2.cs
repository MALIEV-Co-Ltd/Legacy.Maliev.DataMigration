using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveIntendedObservationInputV2(CurrentAuthArchiveProofArtifact LocalBinding,
    CurrentAuthArchiveProofArtifact ComparisonBinding, CurrentAuthArchiveProofArtifact Descriptor,
    CurrentAuthArchiveProofArtifact LocalTarget, CurrentAuthArchiveProofArtifact ComparisonTarget,
    CurrentAuthArchiveProofArtifact LocalOperator, CurrentAuthArchiveProofArtifact ComparisonOperator,
    CurrentAuthArchiveProofArtifact LocalOrdinary, CurrentAuthArchiveProofArtifact ComparisonOrdinary);
internal sealed record CurrentAuthArchiveIntendedObservationEvidenceV2(string Kind, string SourceFullSha256,
    string SourceIdentitySha256, string SourceDefinitionSha256, string LocalIdentitySha256, string ComparisonIdentitySha256,
    string LocalAuthRowsSha256, int LocalAuthRows, CurrentAuthRepairScope LocalPolicy, CurrentAuthRepairScope ComparisonPolicy,
    CurrentAuthArchiveIntendedFleetV2 Local, CurrentAuthArchiveIntendedFleetV2 Comparison,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc);
internal sealed record CurrentAuthArchiveIntendedFleetV2(CurrentAuthArchiveNativeCommitmentV2 Auth, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> Databases,
    CurrentAuthArchiveFleetCatalogs Catalogs, DateTimeOffset BeganAtUtc, DateTimeOffset EndedAtUtc);
internal sealed record CurrentAuthArchiveIntendedDescriptorV2(string Kind, CurrentAuthRepairScope LocalPolicy, CurrentAuthRepairScope ComparisonPolicy);

// A live read-only observation only; no deserialized descriptor can construct this holder or grant a permit.
internal sealed class CurrentAuthArchiveIntendedObservationRuntimeV2
{
    internal CurrentAuthArchiveScope ObservationScope { get; }
    internal CurrentAuthArchiveDeviceProof Devices { get; }
    internal CurrentAuthArchiveFleet Local { get; }
    internal CurrentAuthArchiveFleet Comparison { get; }
    internal CurrentAuthArchiveIntendedObservationEvidenceV2 Evidence { get; }
    internal CurrentAuthArchiveProofAudienceV2 Audience { get; }
    private CurrentAuthArchiveIntendedObservationRuntimeV2(CurrentAuthArchiveIntendedObservationEvidenceV2 evidence, CurrentAuthArchiveProofAudienceV2 audience,
        CurrentAuthArchiveScope scope, CurrentAuthArchiveDeviceProof devices, CurrentAuthArchiveFleet local, CurrentAuthArchiveFleet comparison)
    { Evidence = evidence; Audience = audience; ObservationScope = scope; Devices = devices; Local = local; Comparison = comparison; }
    internal static async Task<CurrentAuthArchiveIntendedObservationRuntimeV2> ObserveAsync(CurrentAuthArchiveIntendedObservationInputV2 input,
        CurrentReviewedCapture source, CurrentAuthArchiveClaim audienceClaim, IReceiptAttestationTrustStore trust,
        CurrentAuthArchivePins pins, CancellationToken ct)
    {
        await source.RequireAsync(ct); DateTimeOffset began = DateTimeOffset.UtcNow;
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveProofAudienceV2>(audienceClaim,
            CurrentAuthArchiveRecoveryV2.AudienceDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        RequireAudienceCapture(audience, source.Evidence, pins, began);
        LocalExecutionBinding localBinding = ReadBinding(input.LocalBinding), comparisonBinding = ReadBinding(input.ComparisonBinding);
        if (StringComparer.OrdinalIgnoreCase.Equals(localBinding.ArtifactRootCanonicalPath, comparisonBinding.ArtifactRootCanonicalPath)) { throw Invalid(); }
        using var localAuthority = WindowsLocalRunAuthority.AcquireResume(localBinding.ArtifactRootCanonicalPath, localBinding);
        using var comparisonAuthority = WindowsLocalRunAuthority.AcquireResume(comparisonBinding.ArtifactRootCanonicalPath, comparisonBinding);
        using var localFiles = new CurrentAppOwnedRepairCustody(localAuthority); using var comparisonFiles = new CurrentAppOwnedRepairCustody(comparisonAuthority);
        var descriptor = Decode<CurrentAuthArchiveIntendedDescriptorV2>(Read(localFiles, input.Descriptor, 1024 * 1024));
        var context = CreateUnadmittedObservation(descriptor, source.Evidence, localBinding, comparisonBinding, audience, began);
        var localPolicy = context.LocalObservationPolicy; var comparisonPolicy = context.ProductionObservationPolicy;
        CurrentAuthLocalSessionArchiveEnvironment.RequireObservationPolicies(context, began);
        var localTarget = Decode<CurrentAppOwnedRepairTargetPins>(Read(localFiles, input.LocalTarget, 1024 * 1024));
        var comparisonTarget = Decode<CurrentAppOwnedRepairTargetPins>(Read(comparisonFiles, input.ComparisonTarget, 1024 * 1024));
        var devices = await CurrentAuthLocalSessionArchiveDeviceProcess.ObserveVersionedContextAsync(context, localBinding.ArtifactRootCanonicalPath,
            comparisonBinding.ArtifactRootCanonicalPath, localFiles, comparisonFiles, ct);
        context = context with { RecoveryDeviceProofSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(devices) };
        using var environment = new CurrentAuthLocalSessionArchiveEnvironment(localFiles, comparisonFiles, localAuthority, comparisonAuthority,
            context, source.Evidence.Plan, localTarget, comparisonTarget,
            Encoding.UTF8.GetString(Read(localFiles, input.LocalOperator, 65536)), Encoding.UTF8.GetString(Read(comparisonFiles, input.ComparisonOperator, 65536)),
            Encoding.UTF8.GetString(Read(localFiles, input.LocalOrdinary, 65536)), Encoding.UTF8.GetString(Read(comparisonFiles, input.ComparisonOrdinary, 65536)),
            devices, trust, pins, CurrentAuthLocalSessionArchivePolicy.Hash(audience));
        var observed = await environment.ObserveArchiveIntendedAfterCAsync(context, ct);
        byte[] rows = CurrentAuthLocalSessionArchivePolicy.EncodeRows(observed.Local.Auth.Sessions);
        string rowsSha;
        try { rowsSha = CurrentAuthLocalSessionArchivePolicy.HashBytes(rows); }
        finally { CryptographicOperations.ZeroMemory(rows); }
        var evidence = new CurrentAuthArchiveIntendedObservationEvidenceV2("current-auth-archive-intended-after-c-observation-v2",
            source.Evidence.FullPlanSha256, source.Evidence.SourceIdentitySha256, source.Evidence.DefinitionSha256,
            Identity(localPolicy), Identity(comparisonPolicy), rowsSha, observed.Local.Auth.Sessions.Count, localPolicy, comparisonPolicy,
            Retained(observed.Local), Retained(observed.Comparison), began, DateTimeOffset.UtcNow);
        if (evidence.LocalIdentitySha256 != audience.IntendedLocalIdentitySha256 || evidence.ComparisonIdentitySha256 != audience.IntendedComparisonIdentitySha256 ||
            rowsSha != audience.IntendedAuthRowsSha256 || evidence.LocalAuthRows != audience.IntendedAuthRows || evidence.CompletedAtUtc >= context.ExpiresAtUtc)
        { throw Invalid(); }
        await source.RequireAsync(ct); return new(evidence, audience, context, devices, observed.Local, observed.Comparison);
    }
    internal static CurrentAuthArchiveScope CreateUnadmittedObservation(CurrentAuthArchiveIntendedDescriptorV2 descriptor,
        CurrentAuthArchiveRecoverySourceEvidence source, LocalExecutionBinding local, LocalExecutionBinding comparison,
        CurrentAuthArchiveProofAudienceV2 audience, DateTimeOffset now)
    {
        if (descriptor.Kind != "current-auth-archive-intended-after-c-descriptor-v2" || now.Offset != TimeSpan.Zero ||
            descriptor.LocalPolicy.RunBindingSha256 != local.ComputeSha256() || descriptor.ComparisonPolicy.RunBindingSha256 != comparison.ComputeSha256() ||
            descriptor.LocalPolicy.Target.Kind != DeltaTargetAuthorityKind.LocalAspire || descriptor.ComparisonPolicy.Target.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg ||
            descriptor.LocalPolicy.Maintenance.ExpiresAtUtc <= now.AddMinutes(2) || descriptor.ComparisonPolicy.Maintenance.ExpiresAtUtc <= now.AddMinutes(2)) { throw Invalid(); }
        Guid operation = Guid.NewGuid();
        var left = descriptor.LocalPolicy with { OperationId = operation, SourceCommitSha = source.Plan.SourceCommitSha, SourceSchemaPlanSha256 = source.FullPlanSha256 };
        var right = descriptor.ComparisonPolicy with { OperationId = operation, SourceCommitSha = source.Plan.SourceCommitSha, SourceSchemaPlanSha256 = source.FullPlanSha256 };
        string prefix = "archive-intended-observation-" + operation.ToString("N");
        var paths = new CurrentAuthArchivePaths(Path.Combine(local.ArtifactRootCanonicalPath, prefix + "-first.cipher"),
            Path.Combine(comparison.ArtifactRootCanonicalPath, prefix + "-second.cipher"), Path.Combine(local.ArtifactRootCanonicalPath, prefix + "-first.key"),
            Path.Combine(comparison.ArtifactRootCanonicalPath, prefix + "-second.key"));
        // This NEW read-only context has no executable proof slots. No historical scope, expiry or native role lease is extended.
        var context = new CurrentAuthArchiveScope(operation, left, right, audience.IntendedAuthRowsSha256, audience.IntendedAuthRows,
            new string('0', 64), paths, new string('0', 64), string.Empty, string.Empty, string.Empty, string.Empty, now, now.AddMinutes(2),
            CurrentAuthLocalSessionArchiveDeviceProcess.IntendedObservationMode);
        CurrentAuthLocalSessionArchiveEnvironment.RequireObservationPolicies(context, now);
        return context;
    }
    internal void RequireFreshForDefinition(CurrentReviewedCapture source, CurrentAuthArchiveDefinitionSigningInputs signing, CurrentAuthArchiveProofArtifact tests)
    {
        var pins = new CurrentAuthArchivePins(signing.Pins.ReviewKeyId, signing.Pins.ReviewFingerprint, signing.Pins.AuthorizationKeyId,
            signing.Pins.AuthorizationFingerprint, signing.Pins.ReceiptKeyId, signing.Pins.ReceiptFingerprint);
        RequireAudienceCapture(Audience, source.Evidence, pins, DateTimeOffset.UtcNow);
        if (Evidence.SourceFullSha256 != source.Evidence.FullPlanSha256 || Audience.TestsImageSha256 != tests.Sha256 ||
            DateTimeOffset.UtcNow - Evidence.CompletedAtUtc > TimeSpan.FromMinutes(2)) { throw Invalid(); }
    }
    private static void RequireAudienceCapture(CurrentAuthArchiveProofAudienceV2 audience, CurrentAuthArchiveRecoverySourceEvidence source,
        CurrentAuthArchivePins pins, DateTimeOffset now)
    {
        if (audience.Kind != "current-auth-archive-proof-audience-v2" || audience.AudienceId == Guid.Empty ||
            audience.AcceptedCommitSha != source.Plan.SourceCommitSha || audience.SourceIdentitySha256 != source.SourceIdentitySha256 ||
            audience.SourceDefinitionSha256 != source.DefinitionSha256 || audience.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
            audience.ClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 || audience.SigningPinsSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(pins) ||
            audience.CaseInventorySha256 != CurrentAuthLocalSessionArchivePolicy.Hash(CurrentAuthArchiveGenuineCases.Inventory()) ||
            audience.CoreImageSha256 != CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location) ||
            audience.ConsoleImageSha256 != CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location) ||
            audience.IssuedAtUtc.Offset != TimeSpan.Zero || audience.ExpiresAtUtc.Offset != TimeSpan.Zero || audience.IssuedAtUtc > now ||
            audience.ExpiresAtUtc <= now || audience.ExpiresAtUtc - audience.IssuedAtUtc > TimeSpan.FromHours(12)) { throw Invalid(); }
        CurrentAuthArchiveRecoveryV2.RequireSource(source, audience.AcceptedCommitSha, audience.SourceIdentitySha256, audience.SourceDefinitionSha256, now);
    }
    internal static string Identity(CurrentAuthRepairScope policy)
    {
        return CurrentAuthLocalSessionArchivePolicy.Hash(new
        {
            Domain = "Legacy.Maliev.CurrentAuth.ArchiveIntendedTargetIdentity.v2",
            policy.Target,
            policy.TargetNamespace,
            policy.TargetCluster,
            policy.TargetGeneration,
            policy.TargetObservationSha256
        });
    }

    private static CurrentAuthArchiveIntendedFleetV2 Retained(CurrentAuthArchiveFleet fleet)
    {
        return new(
            CurrentAuthArchiveNativeCommitmentV2.Capture(fleet.Auth.Native),
            fleet.Databases, fleet.Catalogs ?? throw Invalid(), fleet.BeganAtUtc, fleet.EndedAtUtc);
    }

    private static LocalExecutionBinding ReadBinding(CurrentAuthArchiveProofArtifact artifact)
    {
        byte[] bytes = CurrentAuthArchiveHelperHost.Read(artifact.Path, 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256) { throw Invalid(); }
        var binding = Decode<LocalExecutionBinding>(bytes);
        return Path.GetDirectoryName(artifact.Path) != binding.ArtifactRootCanonicalPath ? throw Invalid() : binding;
    }
    private static byte[] Read(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact artifact, int maximum)
    { byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum); return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw Invalid(); }
    private static T Decode<T>(byte[] bytes)
    {
        return MigrationConsole.DecodeAuthRepair<T>(bytes);
    }

    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}

internal sealed partial class CurrentAuthLocalSessionArchiveEnvironment
{
    // This appended entry exposes only observed native facts. No generic callback, writer, signer or permit leaves it.
    internal async Task<(CurrentAuthArchiveFleet Local, CurrentAuthArchiveFleet Comparison)> ObserveArchiveIntendedAfterCAsync(CurrentAuthArchiveScope context, CancellationToken ct)
    {
        RequireHealthy(); Match(context); RequireObservationPolicies(context, DateTimeOffset.UtcNow);
        ProductionSchemaCatalogInspector.ValidatePlan(_source, DateTimeOffset.UtcNow);
        if (context.ArchiveHelperProofSha256.Length != 0 || context.ArchiveNativeProofSha256.Length != 0 || context.ExactDeleteReviewSha256.Length != 0 ||
            context.RecoveryReviewSha256.Length != 0 || context.ProofAdmission != CurrentAuthLocalSessionArchiveDeviceProcess.IntendedObservationMode ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != _source.SourceCommitSha) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        await CurrentAuthOwnerSourceReader.RequireAsync(resource => FrameAsync("intended-owner", resource), ct);
        _ = await RequireTargetsAsync(ct);
        var local = await CaptureCoreAsync(context, true, null, null, ct); var comparison = await CaptureCoreAsync(context, false, null, null, ct);
        foreach (var (Fleet, Policy) in new[] { (Fleet: local, Policy: context.LocalObservationPolicy), (Fleet: comparison, Policy: context.ProductionObservationPolicy) })
        {
            if (Fleet.Databases.Any(database => !Policy.BeforeDatabaseSha256.TryGetValue(database.Database, out string? expected) || expected != database.Sha256) ||
                Fleet.Databases.Count != Policy.BeforeDatabaseSha256.Count) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        }
        _ = await RequireTargetsAsync(ct); RequireHealthy(); return (local, comparison);
    }
}
