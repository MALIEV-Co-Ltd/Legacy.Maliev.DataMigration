using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthClosedBootstrapEvidence(string PrecursorRunBindingPath,
    string PrecursorScopePath, string PrecursorSourcePath, string PrecursorSigningPinsPath,
    IReadOnlyList<DeltaTrustedKeyReference> PrecursorTrustedKeys,
    CurrentAuthProofArtifact Definition, CurrentAuthProofArtifact NativeComponent,
    CurrentAuthProofArtifact RecoveryComponent, CurrentAuthProofArtifact MaintenanceComponent,
    CurrentAuthClosedBootstrapSeed Seed);

/// <summary>Actual held completed precursor readback for the named disposable bootstrap only.</summary>
internal static class CurrentAuthClosedBootstrapReadback
{
    // Before any child gate or target creation: authenticate the completed precursor
    // independently. No case seed or operational claims exist at this point.
    internal static async Task RequireCompletedForHostAsync(CurrentAuthClosedBootstrapEvidence evidence,
        FreshSchemaPlan source, string testImageSha256, string consoleImageSha256, string coreImageSha256,
        CancellationToken ct)
    {
        using var input = SecureLocalFile.OpenReadShared(evidence.PrecursorRunBindingPath);
        if (input.Length is < 1 or > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] bytes = new byte[checked((int)input.Length)]; input.ReadExactly(bytes);
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bytes);
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        if (!files.Read(evidence.PrecursorRunBindingPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes))
        { throw CurrentAuthRepairPermit.Invalid(); }
        T Read<T>(string path) => MigrationConsole.DecodeAuthRepair<T>(files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
        var precursor = Read<CurrentAuthRepairScope>(evidence.PrecursorScopePath);
        var heldSource = Read<FreshSchemaPlan>(evidence.PrecursorSourcePath);
        var pins = Read<CurrentAuthRepairSigningPins>(evidence.PrecursorSigningPinsPath);
        if (precursor.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeBootstrap ||
            precursor.RunBindingSha256 != binding.ComputeSha256() || precursor.SourceCommitSha != source.SourceCommitSha ||
            precursor.SourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) ||
            SchemaPlanCanonicalizer.ComputeSha256(heldSource) != precursor.SourceSchemaPlanSha256 ||
            precursor.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit ||
            precursor.AuthOwnerSourcePinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
            precursor.AuthClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
            evidence.PrecursorTrustedKeys.Count != 3 || evidence.PrecursorTrustedKeys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != 3 ||
            new[] { evidence.Definition.Sha256, evidence.NativeComponent.Sha256, evidence.RecoveryComponent.Sha256, evidence.MaintenanceComponent.Sha256 }.Distinct(StringComparer.Ordinal).Count() != 4 ||
            AssemblyHash(typeof(MigrationConsole).Assembly.Location) != consoleImageSha256 ||
            AssemblyHash(typeof(CurrentAuthRepairPermit).Assembly.Location) != coreImageSha256)
        { throw CurrentAuthRepairPermit.Invalid(); }
        var trust = new ReceiptAttestationTrustStore(evidence.PrecursorTrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))).ToArray());
        foreach ((CurrentAuthProofArtifact artifact, string phase) in new[]
        { (evidence.Definition, "helper"), (evidence.NativeComponent, "native"), (evidence.RecoveryComponent, "recovery"), (evidence.MaintenanceComponent, "maintenance") })
        {
            await CurrentAuthRepairProofReader.RequireComponentAsync(files, new(artifact.Path, artifact.Sha256), artifact.Sha256,
                phase, precursor, trust, pins, heldSource, ct).ConfigureAwait(false);
            var report = Read<CurrentAuthClosedProof>(artifact.Path);
            if (report.Cases.Any(x => x.Invocation.TestAssemblySha256 != testImageSha256) ||
                report.ConsoleAssemblySha256 != consoleImageSha256 || report.CoreAssemblySha256 != coreImageSha256)
            { throw CurrentAuthRepairPermit.Invalid(); }
        }
        files.Require();
    }
    internal static Task RequireAsync(CurrentAuthClosedBootstrapEvidence evidence,
        CurrentAuthRepairScope namedScope, FreshSchemaPlan namedSource, CancellationToken ct) =>
        RequireCoreAsync(evidence, namedScope, namedSource, requireSignature: true, ct);
    // Returns observation validation only. It cannot be called by a Console admission branch.
    internal static Task RequireUnsignedForProducerAsync(CurrentAuthClosedBootstrapEvidence evidence,
        CurrentAuthRepairScope namedScope, FreshSchemaPlan namedSource, CancellationToken ct) =>
        RequireCoreAsync(evidence, namedScope, namedSource, requireSignature: false, ct);
    private static async Task RequireCoreAsync(CurrentAuthClosedBootstrapEvidence evidence,
        CurrentAuthRepairScope namedScope, FreshSchemaPlan namedSource, bool requireSignature, CancellationToken ct)
    {
        if ((int)namedScope.ProofAdmission != 3 || namedScope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(namedScope.Target)) { throw CurrentAuthRepairPermit.Invalid(); }
        // A supplied summary cannot bypass actual owner-only custody; no key, baseline or callback is imported from it.
        using var bindingInput = SecureLocalFile.OpenReadShared(evidence.PrecursorRunBindingPath);
        if (bindingInput.Length is < 1 or > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
        string identity = SecureLocalFile.GetHandleIdentity(bindingInput);
        byte[] bindingBytes = new byte[checked((int)bindingInput.Length)]; bindingInput.ReadExactly(bindingBytes);
        LocalExecutionBinding binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bindingBytes);
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(evidence.PrecursorRunBindingPath),
            Path.Combine(binding.ArtifactRootCanonicalPath, Path.GetFileName(evidence.PrecursorRunBindingPath))) ||
            !files.Read(evidence.PrecursorRunBindingPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bindingBytes) ||
            identity != SecureLocalFile.GetHandleIdentity(bindingInput)) { throw CurrentAuthRepairPermit.Invalid(); }
        T Read<T>(string path) => MigrationConsole.DecodeAuthRepair<T>(files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
        var precursor = Read<CurrentAuthRepairScope>(evidence.PrecursorScopePath);
        var source = Read<FreshSchemaPlan>(evidence.PrecursorSourcePath);
        var pins = Read<CurrentAuthRepairSigningPins>(evidence.PrecursorSigningPinsPath);
        if (precursor.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeBootstrap ||
            precursor.RunBindingSha256 != binding.ComputeSha256() ||
            precursor.SourceCommitSha != namedScope.SourceCommitSha || source.SourceCommitSha != namedScope.SourceCommitSha ||
            SchemaPlanCanonicalizer.ComputeSha256(source) != namedScope.SourceSchemaPlanSha256 ||
            SchemaPlanCanonicalizer.ComputeSha256(namedSource) != namedScope.SourceSchemaPlanSha256 ||
            CurrentAuthRepairProofReader.Subject(precursor) != evidence.Seed.PrecursorSubjectSha256 ||
            precursor.AuthHelperProofSha256 != evidence.Definition.Sha256 ||
            new[] { evidence.Definition.Sha256, evidence.NativeComponent.Sha256, evidence.RecoveryComponent.Sha256,
                evidence.MaintenanceComponent.Sha256 }.Distinct(StringComparer.Ordinal).Count() != 4 ||
            evidence.Seed.DefinitionPrecursorSha256 != evidence.Definition.Sha256 ||
            evidence.Seed.NativeComponentSha256 != evidence.NativeComponent.Sha256 ||
            evidence.Seed.RecoveryComponentSha256 != evidence.RecoveryComponent.Sha256 ||
            evidence.Seed.MaintenanceComponentSha256 != evidence.MaintenanceComponent.Sha256 ||
            evidence.PrecursorTrustedKeys.Count != 3 || evidence.PrecursorTrustedKeys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != 3)
        { throw CurrentAuthRepairPermit.Invalid(); }
        // Producer precursor public-key files contain exact DER bytes, unlike normal closed config's base64 files.
        var trust = new ReceiptAttestationTrustStore(evidence.PrecursorTrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))).ToArray());
        CurrentAuthClosedBootstrap.RequireScope(evidence.Seed, namedScope, namedSource, trust,
            pins.ReviewKeyId, pins.ReviewFingerprint, DateTimeOffset.UtcNow, requireSignature);
        if (AssemblyHash(typeof(CurrentAuthRepairPermit).Assembly.Location) != evidence.Seed.CoreAssemblySha256 ||
            AssemblyHash(typeof(MigrationConsole).Assembly.Location) != evidence.Seed.ConsoleAssemblySha256)
        { throw CurrentAuthRepairPermit.Invalid(); }
        foreach ((CurrentAuthProofArtifact artifact, string phase) in new[]
        {
            (evidence.Definition, "helper"), (evidence.NativeComponent, "native"),
            (evidence.RecoveryComponent, "recovery"), (evidence.MaintenanceComponent, "maintenance")
        })
        {
            CurrentAuthRepairCapacity.Require(admission: false);
            await CurrentAuthRepairProofReader.RequireComponentAsync(files, new(artifact.Path, artifact.Sha256), artifact.Sha256,
                phase, precursor, trust, pins, source, ct).ConfigureAwait(false);
            var report = Read<CurrentAuthClosedProof>(artifact.Path);
            if (report.Cases.Any(x => x.Invocation.TestAssemblySha256 != evidence.Seed.TestAssemblySha256))
            { throw CurrentAuthRepairPermit.Invalid(); }
        }
        files.Require();
    }

    private static string AssemblyHash(string path)
    {
        using var image = SecureLocalFile.OpenReadShared(path);
        if (image.Length is < 1 or > 128 * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
        return Convert.ToHexStringLower(SHA256.HashData(image));
    }
}
