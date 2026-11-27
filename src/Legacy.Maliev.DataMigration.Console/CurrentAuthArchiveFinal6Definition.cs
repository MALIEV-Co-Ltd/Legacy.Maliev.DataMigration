using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveFinal6Definition(string Kind, Guid AnchorOperationId, string ParentBindingSha256,
    string AudienceSha256, string SourceFullSha256, CurrentAuthArchiveFreshDefinition NativeDefinition,
    CurrentAuthArchiveGenuineArtifact AnchorBaseline, CurrentAuthArchiveProofArtifact AnchorNative,
    CurrentAuthArchiveProofArtifact AnchorIntent, CurrentAuthArchiveProofArtifact CreatedContainer,
    CurrentAuthArchiveProofArtifact CreatedVolume, CurrentAuthArchiveProofArtifact Absence,
    IReadOnlyList<CurrentAuthArchiveProofArtifact> SourcePhysical, DateTimeOffset PublishedAtUtc);
internal sealed record CurrentAuthArchiveFinal6DefinitionOwnerCopies(LocalExecutionBinding OriginalParentBinding,
    CurrentAuthArchiveProofArtifact AnchorIntent, CurrentAuthArchiveProofArtifact CreatedContainer,
    CurrentAuthArchiveProofArtifact CreatedVolume, CurrentAuthArchiveProofArtifact Absence);

// Separate source6 binding around the unchanged seven source-independent native Auth definition cases.
// This reader creates no Auth16 repair permit and no complete eighteen-case archive proof.
internal static class CurrentAuthArchiveFinal6DefinitionReader
{
    internal const string Kind = "current-auth-archive-final6-native-definition-v1";
    internal const string Domain = "Legacy.Maliev.CurrentAuth.Final6.NativeDefinition.v1";

    internal static void RequireHeader(CurrentAuthArchiveFinal6Definition definition, LocalExecutionBinding parent,
        CurrentAuthArchiveFinal6SourceEvidence source, string audienceSha256, DateTimeOffset before)
    {
        if (definition.Kind != Kind || definition.AnchorOperationId == Guid.Empty || definition.ParentBindingSha256 != parent.ComputeSha256() ||
            definition.AudienceSha256 != audienceSha256 || !CurrentAuthRepairPermit.HashShape(audienceSha256) ||
            definition.SourceFullSha256 != source.Capture.FullPlanSha256 || definition.PublishedAtUtc.Offset != TimeSpan.Zero ||
            before.Offset != TimeSpan.Zero || definition.PublishedAtUtc < source.Capture.CompletedAtUtc || definition.PublishedAtUtc > before ||
            before - source.Capture.BeganAtUtc > TimeSpan.FromMinutes(5)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        string root = Path.Combine(parent.ArtifactRootCanonicalPath, "auth-definition-anchor-" + definition.AnchorOperationId.ToString("N"));
        var native = definition.NativeDefinition;
        string[] paths = [native.RunBinding.Path, native.CompletedScope.Path, native.Source.Path, native.Definition.Path, definition.AnchorBaseline.Path, definition.AnchorNative.Path];
        if (paths.Any(path => !Path.IsPathFullyQualified(path) || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(path), root)) ||
            paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length ||
            new[] { native.RunBinding.Sha256, native.CompletedScope.Sha256, native.Source.Sha256, native.Definition.Sha256, native.SubjectSha256,
                definition.AnchorBaseline.Sha256, definition.AnchorNative.Sha256 }.Any(hash => !CurrentAuthRepairPermit.HashShape(hash)))
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        string prefix = Path.Combine(parent.ArtifactRootCanonicalPath, "archive-definition-anchor-" + definition.AnchorOperationId.ToString("N"));
        if (definition.AnchorIntent.Path != prefix + "-intent.json" || definition.CreatedContainer.Path != prefix + "-container.json" ||
            definition.CreatedVolume.Path != prefix + "-volume.json" || definition.Absence.Path != prefix + "-absence.json" ||
            new[] { definition.AnchorIntent.Sha256, definition.CreatedContainer.Sha256, definition.CreatedVolume.Sha256, definition.Absence.Sha256 }
                .Any(hash => !CurrentAuthRepairPermit.HashShape(hash))) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        if (definition.SourcePhysical.Count != 23 || !definition.SourcePhysical.Select(value => value.Path).SequenceEqual(
            DatabaseInventory.ActiveDatabases.Select(database => Path.Combine(root, "auth-final6-template-physical-" + database + ".json")), StringComparer.OrdinalIgnoreCase) ||
            definition.SourcePhysical.Any(value => !CurrentAuthRepairPermit.HashShape(value.Sha256))) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
    }

    internal static Task<CurrentAuthArchiveFreshDefinition> RequireAsync(CurrentAppOwnedRepairCustody parentFiles, LocalExecutionBinding parent,
        CurrentAuthArchiveProofArtifact artifact, CurrentAuthArchiveFinal6SourceEvidence source, CurrentAuthArchiveClaim audienceClaim,
        CurrentAuthRepairSigningPins signing, IReceiptAttestationTrustStore trust, DateTimeOffset actualCaseUtc, CancellationToken ct)
    { return RequireCoreAsync(parentFiles, parent, artifact, source, audienceClaim, signing, trust, actualCaseUtc, null, ct); }

    internal static Task<CurrentAuthArchiveFreshDefinition> RequireCopiedAsync(CurrentAppOwnedRepairCustody caseFiles,
        CurrentAuthArchiveFinal6DefinitionOwnerCopies copies, CurrentAuthArchiveProofArtifact artifact,
        CurrentAuthArchiveFinal6SourceEvidence source, CurrentAuthArchiveClaim audienceClaim, CurrentAuthRepairSigningPins signing,
        IReceiptAttestationTrustStore trust, DateTimeOffset actualCaseUtc, CancellationToken ct)
    { return RequireCoreAsync(caseFiles, copies.OriginalParentBinding, artifact, source, audienceClaim, signing, trust, actualCaseUtc, copies, ct); }

    private static async Task<CurrentAuthArchiveFreshDefinition> RequireCoreAsync(CurrentAppOwnedRepairCustody parentFiles, LocalExecutionBinding parent,
        CurrentAuthArchiveProofArtifact artifact, CurrentAuthArchiveFinal6SourceEvidence source, CurrentAuthArchiveClaim audienceClaim,
        CurrentAuthRepairSigningPins signing, IReceiptAttestationTrustStore trust, DateTimeOffset actualCaseUtc,
        CurrentAuthArchiveFinal6DefinitionOwnerCopies? copies, CancellationToken ct)
    {
        parentFiles.Require();
        var pins = new CurrentAuthArchivePins(signing.ReviewKeyId, signing.ReviewFingerprint, signing.AuthorizationKeyId,
            signing.AuthorizationFingerprint, signing.ReceiptKeyId, signing.ReceiptFingerprint);
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(audienceClaim,
            CurrentAuthArchiveFinal6AudiencePolicy.Domain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthArchiveFinal6AudiencePolicy.Require(audience, pins, actualCaseUtc);
        CurrentAuthArchiveFinal6Source.Require(source, audience.AcceptedCommitSha, audience.SourceIdentitySha256, audience.SourceDefinitionSha256, actualCaseUtc);
        var claim = Decode<CurrentAuthArchiveClaim>(Read(parentFiles, artifact, 65536));
        var definition = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Definition>(claim, Domain,
            pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
        RequireHeader(definition, parent, source, CurrentAuthLocalSessionArchivePolicy.Hash(audienceClaim), actualCaseUtc);
        var native = definition.NativeDefinition;
        string root = Path.GetDirectoryName(native.RunBinding.Path)!;
        byte[] bindingBytes = CurrentAuthArchiveHelperHost.Read(native.RunBinding.Path, 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bindingBytes) != native.RunBinding.Sha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var binding = Decode<LocalExecutionBinding>(bindingBytes);
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        if (!Read(files, native.RunBinding, 65536).AsSpan().SequenceEqual(bindingBytes) || binding.ComputeSha256() == parent.ComputeSha256())
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var plan = Decode<FreshSchemaPlan>(Read(files, native.Source, 32 * 1024 * 1024));
        var scope = Decode<CurrentAuthRepairScope>(Read(files, native.CompletedScope, 1024 * 1024));
        if (SchemaPlanCanonicalizer.ComputeSha256(plan) != source.Capture.FullPlanSha256 || scope.SourceSchemaPlanSha256 != source.Capture.FullPlanSha256 ||
            scope.SourceCommitSha != audience.AcceptedCommitSha || scope.OperationId != definition.AnchorOperationId || scope.RunBindingSha256 != binding.ComputeSha256() ||
            scope.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeBootstrap || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) ||
            scope.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit || scope.AuthOwnerSourcePinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
            scope.AuthClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 || scope.AuthBeforeSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(false) ||
            scope.AuthAfterSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) || scope.AuthHelperProofSha256 != native.Definition.Sha256 ||
            native.SubjectSha256 != CurrentAuthRepairProofReader.Subject(scope)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        await CurrentAuthRepairProofReader.RequireAsync(files, new(native.Definition.Path, native.Definition.Sha256), native.Definition.Sha256,
            "helper", scope, trust, signing, plan, ct).ConfigureAwait(false);
        var baseline = await CurrentAuthArchiveStreamedBaselineV2.ReadAsync(files, definition.AnchorBaseline, ct).ConfigureAwait(false);
        if (!ReviewedProductionRepairInventory.MatchesKeys(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(false), baseline.Select(value => value.Database)) ||
            baseline.Length != scope.BeforeDatabaseSha256.Count || baseline.Any(value => scope.BeforeDatabaseSha256[value.Database] != CurrentAppOwnedSnapshotSerialization.Sha256(value)))
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var anchorNative = Decode<CurrentAuthProofNative>(Read(files, definition.AnchorNative, 32 * 1024 * 1024)).Observation();
        CurrentAuthNativePreservation.RequireBefore(anchorNative);
        if (anchorNative.Snapshot.Sha256 != baseline.Single(value => value.Database == "Auth").Sha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        foreach (var (database, physicalArtifact) in plan.Databases.Zip(definition.SourcePhysical))
        {
            using var physical = JsonDocument.Parse(Read(files, physicalArtifact, 65536));
            var value = physical.RootElement;
            if (value.GetProperty("Database").GetString() != database.Database || value.GetProperty("SourceSchemaPlanSha256").GetString() != source.Capture.FullPlanSha256 ||
                value.GetProperty("TargetExtensionProfile").GetString() != database.TargetExtensionProfile || value.GetProperty("ObservedSchemaSha256").GetString() != database.TargetSchemaSha256 ||
                value.GetProperty("BeganAtUtc").GetDateTimeOffset() < source.Capture.CompletedAtUtc ||
                value.GetProperty("CompletedAtUtc").GetDateTimeOffset() > definition.PublishedAtUtc) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        }
        var intent = Decode<CurrentAuthArchiveDefinitionAnchorIntent>(ReadOwner(definition.AnchorIntent, copies?.AnchorIntent, 2 * 1024 * 1024));
        using var container = JsonDocument.Parse(ReadOwner(definition.CreatedContainer, copies?.CreatedContainer, 2 * 1024 * 1024));
        using var volume = JsonDocument.Parse(ReadOwner(definition.CreatedVolume, copies?.CreatedVolume, 65536));
        using var absence = JsonDocument.Parse(ReadOwner(definition.Absence, copies?.Absence, 2 * 1024 * 1024));
        CurrentAuthArchiveDefinitionAnchorOwner.RequireContainer(container.RootElement, volume.RootElement, intent);
        var template = Decode<CurrentAuthClosedTemplateCapture>(files.Read(Path.Combine(root, "auth-template-capture.json"), sharedReader: true, maximumBytes: 2 * 1024 * 1024));
        if (intent.OperationId != definition.AnchorOperationId || intent.ParentBindingSha256 != parent.ComputeSha256() || intent.Binding != binding ||
            CurrentAppOwnedSnapshotSerialization.Sha256(template.TargetPins) != scope.TargetObservationSha256 ||
            template.TargetPins.DockerContainerId != container.RootElement.GetProperty("Id").GetString() ||
            template.State.TargetGeneration != scope.TargetGeneration || template.State.SourceCommitSha != scope.SourceCommitSha ||
            template.Target != scope.Target || template.Maintenance != scope.Maintenance || template.Maintenance.ExpiresAtUtc <= actualCaseUtc ||
            template.FleetSha256 != scope.GlobalPreservationSha256 || template.BeforeDatabaseSha256.Count != scope.BeforeDatabaseSha256.Count ||
            template.BeforeDatabaseSha256.Any(value => !scope.BeforeDatabaseSha256.TryGetValue(value.Key, out string? hash) || hash != value.Value) ||
            absence.RootElement.GetProperty("ObservedAtUtc").GetDateTimeOffset() > definition.PublishedAtUtc ||
            absence.RootElement.GetProperty("ObservedAtUtc").GetDateTimeOffset() < intent.BeganAtUtc ||
            absence.RootElement.GetProperty("Operation").GetGuid() != definition.AnchorOperationId)
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        CurrentAuthArchiveDefinitionAnchorOwner.RequireRecordedContainerAbsent(template.TargetPins.DockerContainerId!,
            absence.RootElement.GetProperty("Containers").EnumerateArray().Select(value => value.GetString()!).ToArray());
        int port = int.Parse(container.RootElement.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp")[0].GetProperty("HostPort").GetString()!,
            System.Globalization.CultureInfo.InvariantCulture);
        return absence.RootElement.GetProperty("Volumes").EnumerateArray().Any(value => value.GetString() == template.TargetPins.DockerVolume) ||
            absence.RootElement.GetProperty("Listeners").EnumerateArray().Any(value => value.GetInt32() == port) ||
            File.Exists(Path.Combine(root, "operator.txt")) || File.Exists(Path.Combine(root, "ordinary.txt"))
            ? throw CurrentAuthArchiveFinal6Source.Invalid()
            : native;
        byte[] ReadOwner(CurrentAuthArchiveProofArtifact original, CurrentAuthArchiveProofArtifact? copy, int maximum)
        {
            if (copies is null) { return Read(parentFiles, original, maximum); }
            // Four fixed data copies only. The original parent binding is checked as signed provenance, never reacquired as authority.
            return copy is null || copy.Sha256 != original.Sha256
                ? throw CurrentAuthArchiveFinal6Source.Invalid()
                : Read(parentFiles, copy, maximum);
        }
    }

    private static T Decode<T>(byte[] bytes)
    {
        return MigrationConsole.DecodeAuthRepair<T>(bytes);
    }

    private static byte[] Read(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact artifact, int maximum)
    {
        byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum);
        return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw CurrentAuthArchiveFinal6Source.Invalid();
    }
}
