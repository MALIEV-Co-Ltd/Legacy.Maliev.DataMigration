namespace Legacy.Maliev.DataMigration.Console;

internal sealed record IsoClosedBootstrapInputs(string BindingPath, string DefinitionSubjectPath, string DefinitionProofPath,
    string DefinitionBindingPath, string DefinitionPublicKeyPath, string NativeComponentPath, string MaintenanceComponentPath,
    string ComponentPublicKeyPath);
internal static class IsoClosedBootstrapReadback
{
    // The precursor root is separate from active named target custody; no recursive mutex lock.
    // Persistent mode never calls this reader as a replacement for completed closed Console proof.
    internal static async Task RequireAsync(CurrentAppOwnedRepairCustody activeFiles, LocalExecutionBinding activeBinding, CurrentOwnerIsoRepairScope scope,
        IsoClosedBootstrapInputs inputs, CancellationToken ct)
    {
        if (scope.ProofAdmission != CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap || scope.BootstrapSubject is not { } bootstrap ||
            bootstrap.ClosedPrecursorPins is not { } pins || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) ||
            DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target)) { throw Invalid(); }
        activeFiles.Require();
        using var heldBinding = SecureLocalFile.OpenReadShared(inputs.BindingPath); if (heldBinding.Length is < 1 or > 65536) { throw Invalid(); }
        byte[] bytes = new byte[(int)heldBinding.Length]; heldBinding.ReadExactly(bytes);
        var binding = MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(bytes);
        if (activeBinding.ComputeSha256() != scope.RunBindingSha256 || binding.ComputeSha256() != pins.RootBindingSha256 ||
    StringComparer.OrdinalIgnoreCase.Equals(binding.ArtifactRootCanonicalPath, activeBinding.ArtifactRootCanonicalPath)) { throw Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        if (!files.Read(inputs.BindingPath, maximumBytes: 65536, sharedReader: true).AsSpan().SequenceEqual(bytes)) { throw Invalid(); }
        byte[] publicKey = files.Read(inputs.ComponentPublicKeyPath, maximumBytes: 4096, sharedReader: true);
        byte[] definitionPublicKey = files.Read(inputs.DefinitionPublicKeyPath, maximumBytes: 4096, sharedReader: true);
        var trust = new ReceiptAttestationTrustStore([new(pins.ProofKeyId, publicKey), new(pins.DefinitionKeyId, definitionPublicKey)]);
        if (!trust.TryGetPublicKeyFingerprintSha256(pins.ProofKeyId, out string proofFingerprint) || proofFingerprint != pins.ProofFingerprint ||
            !trust.TryGetPublicKeyFingerprintSha256(pins.DefinitionKeyId, out string definitionFingerprint) || definitionFingerprint != pins.DefinitionFingerprint) { throw Invalid(); }
        var intended = MigrationConsole.DecodeOwnerIso<IsoDefinitionSubject>(Artifact(inputs.DefinitionSubjectPath, pins.DefinitionSubjectSha256));
        if (intended.SourceCommitSha != scope.SourceCommitSha || intended.SourceCatalogSha256 != scope.SourceCatalogSha256 || intended.SourceSchemaPlanSha256 != scope.BeforeSchemaPlanSha256 ||
            intended.OwnerSourcesSha256 != scope.OwnerSourcesSha256 || intended.ContractSha256 != scope.ContractSha256 || intended.ConsoleAssemblySha256 != bootstrap.Claim.Subject.ConsoleAssemblySha256 ||
            intended.CoreAssemblySha256 != bootstrap.Claim.Subject.CoreAssemblySha256 || intended.TestAssemblySha256 != bootstrap.Claim.Subject.TestAssemblySha256) { throw Invalid(); }
        _ = Artifact(inputs.DefinitionProofPath, pins.DefinitionProofSha256);
        var native = MigrationConsole.DecodeOwnerIso<IsoComponentProof>(Artifact(inputs.NativeComponentPath, bootstrap.ComponentNativeSha256 ?? throw Invalid()));
        var maintenance = MigrationConsole.DecodeOwnerIso<IsoComponentProof>(Artifact(inputs.MaintenanceComponentPath, bootstrap.ComponentMaintenanceSha256 ?? throw Invalid()));
        if (native.Phase != IsoComponentProofPhase.Native || maintenance.Phase != IsoComponentProofPhase.Maintenance || native.Definition.Sha256 != pins.DefinitionProofSha256 || maintenance.Definition.Sha256 != pins.DefinitionProofSha256) { throw Invalid(); }
        string definitionBindingHash = CurrentAppOwnedRepairPermit.Hash(files.Read(inputs.DefinitionBindingPath, maximumBytes: 65536, sharedReader: true));
        if (native.DefinitionBinding.Sha256 != definitionBindingHash || maintenance.DefinitionBinding.Sha256 != definitionBindingHash) { throw Invalid(); }
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await IsoComponentProofReader.RequireAsync(files, native, intended, trust, pins.ProofKeyId, pins.ProofFingerprint, pins.DefinitionKeyId, pins.DefinitionFingerprint, now, ct);
        await IsoComponentProofReader.RequireAsync(files, maintenance, intended, trust, pins.ProofKeyId, pins.ProofFingerprint, pins.DefinitionKeyId, pins.DefinitionFingerprint, DateTimeOffset.UtcNow, ct);
        files.Require(); activeFiles.Require();
        byte[] Artifact(string path, string sha) { byte[] actual = files.Read(path, maximumBytes: 8_000_000, sharedReader: true); return CurrentAppOwnedRepairPermit.Hash(actual) != sha ? throw Invalid() : actual; }
    }
    private static MigrationExecutionException Invalid()
    {
        return new("iso_closed_bootstrap_precursor_invalid", "Actual independently completed disposable precursors must be held under their own source, image and custody identity.");
    }
}
