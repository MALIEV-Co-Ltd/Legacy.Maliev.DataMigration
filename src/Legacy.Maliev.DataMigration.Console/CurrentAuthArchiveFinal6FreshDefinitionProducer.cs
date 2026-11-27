using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static async Task<CurrentAuthArchiveProofArtifact> ProduceCurrentAuthArchiveFinal6FreshDefinitionAsync(
        CurrentAppOwnedRepairCustody parentFiles, WindowsLocalRunAuthority parentAuthority, CurrentAuthArchiveFinal6SourceCapture.Captured source,
        CurrentAuthArchiveFinal6IntendedObservationRuntime intended, CurrentAuthArchiveProofArtifact qualifiedTests,
        CurrentAuthArchiveDefinitionSigningInputs signing, CurrentAppOwnedRepairCustody signingFiles,
        CurrentAuthArchiveClaim audienceClaim, CancellationToken ct)
    {
        await source.RequireAsync(ct); RequireDefinitionSigningInputs(signingFiles, signing);
        var pins = new CurrentAuthArchivePins(signing.Pins.ReviewKeyId, signing.Pins.ReviewFingerprint, signing.Pins.AuthorizationKeyId,
            signing.Pins.AuthorizationFingerprint, signing.Pins.ReceiptKeyId, signing.Pins.ReceiptFingerprint);
        var trust = new ReceiptAttestationTrustStore(signing.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            signingFiles.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(audienceClaim,
            CurrentAuthArchiveFinal6AudiencePolicy.Domain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        if (audience != source.Audience || audience != intended.Audience) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var native = await ProduceCurrentAuthArchiveFinal6NativeDefinitionAsync(parentFiles, parentAuthority, source, intended, qualifiedTests, signing, signingFiles, ct);
        await source.RequireAsync(ct); parentFiles.Require(); parentAuthority.ValidateHeld();
        string root = Path.GetDirectoryName(native.RunBinding.Path)!;
        byte[] bindingBytes = CurrentAuthArchiveHelperHost.Read(native.RunBinding.Path, 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bindingBytes) != native.RunBinding.Sha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var binding = DecodeAuthRepair<LocalExecutionBinding>(bindingBytes);
        CurrentAuthRepairScope scope; CurrentAuthArchiveGenuineArtifact baseline; CurrentAuthArchiveProofArtifact before;
        var physical = new List<CurrentAuthArchiveProofArtifact>();
        using (var authority = WindowsLocalRunAuthority.AcquireResume(root, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            byte[] scopeBytes = files.Read(native.CompletedScope.Path, sharedReader: true, maximumBytes: 1024 * 1024);
            if (CurrentAuthLocalSessionArchivePolicy.HashBytes(scopeBytes) != native.CompletedScope.Sha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            scope = DecodeAuthRepair<CurrentAuthRepairScope>(scopeBytes);
            string baselinePath = Path.Combine(root, "auth-template-global-before.json");
            FileStream held = files.BorrowReadStream(baselinePath); held.Position = 0;
            baseline = new(baselinePath, Convert.ToHexStringLower(await SHA256.HashDataAsync(held, ct)));
            string beforePath = Path.Combine(root, "auth-template-native-before.json");
            before = new(beforePath, CurrentAuthLocalSessionArchivePolicy.HashBytes(files.Read(beforePath, sharedReader: true, maximumBytes: 32 * 1024 * 1024)));
            foreach (string database in DatabaseInventory.ActiveDatabases)
            {
                string physicalPath = Path.Combine(root, "auth-final6-template-physical-" + database + ".json");
                physical.Add(new(physicalPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(files.Read(physicalPath, sharedReader: true, maximumBytes: 65536))));
            }
        }
        string prefix = Path.Combine(parentAuthority.Binding.ArtifactRootCanonicalPath, "archive-definition-anchor-" + scope.OperationId.ToString("N"));
        CurrentAuthArchiveProofArtifact Parent(string suffix, int maximum)
        {
            string path = prefix + suffix;
            return new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(parentFiles.Read(path, sharedReader: true, maximumBytes: maximum)));
        }
        var definition = new CurrentAuthArchiveFinal6Definition(CurrentAuthArchiveFinal6DefinitionReader.Kind, scope.OperationId,
            parentAuthority.Binding.ComputeSha256(), CurrentAuthLocalSessionArchivePolicy.Hash(audienceClaim), source.Evidence.Capture.FullPlanSha256,
            native, baseline, before, Parent("-intent.json", 2 * 1024 * 1024), Parent("-container.json", 2 * 1024 * 1024),
            Parent("-volume.json", 65536), Parent("-absence.json", 2 * 1024 * 1024), physical.AsReadOnly(), DateTimeOffset.UtcNow);
        byte[] key = signingFiles.Read(signing.EvidencePrivateKey.Path, sharedReader: true, maximumBytes: 65536);
        byte[] bytes;
        try
        {
            if (CurrentAuthLocalSessionArchivePolicy.HashBytes(key) != signing.EvidencePrivateKey.Sha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            using var signer = new P256MigrationEvidenceSigner(pins.EvidenceKeyId, Encoding.UTF8.GetString(key));
            if (signer.PublicKeyFingerprintSha256 != pins.EvidenceFingerprint) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            bytes = JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveFinal6DefinitionReader.Domain, definition, signer));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        string output = Path.Combine(parentAuthority.Binding.ArtifactRootCanonicalPath, "archive-final6-definition-" + scope.OperationId.ToString("N") + ".json");
        await parentFiles.WriteNewAsync(output, bytes, ct);
        var artifact = new CurrentAuthArchiveProofArtifact(output, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
        _ = await CurrentAuthArchiveFinal6DefinitionReader.RequireAsync(parentFiles, parentAuthority.Binding, artifact, source.Evidence,
            audienceClaim, signing.Pins, trust, DateTimeOffset.UtcNow, ct);
        return artifact;
    }

    // This is composition of the existing genuine definition host/reader. It cannot accept a historical scope or supplied positive result.
    private static async Task<CurrentAuthArchiveFreshDefinition> ProduceCurrentAuthArchiveFinal6NativeDefinitionAsync(
        CurrentAppOwnedRepairCustody parentFiles, WindowsLocalRunAuthority parentAuthority, CurrentAuthArchiveFinal6SourceCapture.Captured source,
        CurrentAuthArchiveFinal6IntendedObservationRuntime intended, CurrentAuthArchiveProofArtifact qualifiedTests,
        CurrentAuthArchiveDefinitionSigningInputs signing, CurrentAppOwnedRepairCustody signingFiles, CancellationToken ct)
    {
        await source.RequireAsync(ct); parentFiles.Require(); parentAuthority.ValidateHeld();
        if (signing.TrustedKeys.Count != 3) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        RequireDefinitionSigningInputs(signingFiles, signing);
        intended.RequireFreshForDefinition(source, signing, qualifiedTests);
        var owner = await CurrentAuthArchiveDefinitionAnchorOwner.BeginAsync(parentFiles, parentAuthority, ct);
        var anchor = await CurrentAuthArchiveFinal6DefinitionAnchorSession.OpenAsync(owner, source, qualifiedTests, ct);
        CurrentAuthArchiveFreshDefinition? completedDefinition = null;
        var failures = new List<Exception>();
        try { completedDefinition = await ProduceHeldAsync(); } catch (Exception failure) { failures.Add(failure); }
        try { await anchor.DisposeAsync(); } catch (Exception cleanup) { failures.Add(cleanup); }
        if (failures.Count > 1) { throw new AggregateException("The genuine definition operation and exact anchor cleanup failed.", failures); }
        if (failures.Count == 1) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failures[0]).Throw(); }
        return completedDefinition ?? throw CurrentAuthArchiveRecoveryV2.Invalid();

        async Task<CurrentAuthArchiveFreshDefinition> ProduceHeldAsync()
        {
            await CurrentAuthArchiveDefinitionCodeCopy.CopyFinal6Async(Path.GetDirectoryName(qualifiedTests.Path)!, anchor, ct);
            string root = anchor.Binding.ArtifactRootCanonicalPath;
            string bindingPath = Path.Combine(root, "fixture-binding.json"), intentPath = Path.Combine(root, "archive-definition-intent.json");
            string pinsPath = Path.Combine(root, "archive-definition-pins.json"), reviewPath = Path.Combine(root, "auth-closed-review-" + owner.Operation.ToString("N") + ".private.pem");
            string receiptPath = Path.Combine(root, "auth-closed-receipt-" + owner.Operation.ToString("N") + ".private.pem");
            string configPath = Path.Combine(root, "archive-definition-host.json"), hostPath = Path.Combine(root, "archive-definition-host-result.json");
            string proofPath = Path.Combine(root, "archive-definition-proof.json"), completedPath = Path.Combine(root, "archive-definition-completed-scope.json");
            var keyReferences = new List<DeltaTrustedKeyReference>();
            using (var authority = WindowsLocalRunAuthority.AcquireResume(root, anchor.Binding))
            using (var files = new CurrentAppOwnedRepairCustody(authority))
            {
                await files.WriteNewAsync(pinsPath, JsonSerializer.SerializeToUtf8Bytes(signing.Pins), ct);
                int ordinal = 0;
                foreach (var key in signing.TrustedKeys)
                {
                    string path = Path.Combine(root, "archive-definition-public-" + ordinal++.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".spki");
                    await files.WriteNewAsync(path, signingFiles.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536), ct);
                    keyReferences.Add(new(key.KeyId, path));
                }
                var trust = new ReceiptAttestationTrustStore(keyReferences.Select(key => new TrustedAttestationKey(key.KeyId,
                    files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
                RequireDefinitionKey(signing.Pins.ReviewKeyId, signing.Pins.ReviewFingerprint);
                RequireDefinitionKey(signing.Pins.AuthorizationKeyId, signing.Pins.AuthorizationFingerprint);
                RequireDefinitionKey(signing.Pins.ReceiptKeyId, signing.Pins.ReceiptFingerprint);
                await CopyPrivate(signing.ReviewPrivateKey, reviewPath, signing.Pins.ReviewKeyId, signing.Pins.ReviewFingerprint);
                await CopyPrivate(signing.EvidencePrivateKey, receiptPath, signing.Pins.ReceiptKeyId, signing.Pins.ReceiptFingerprint);
                string testsPath = Path.Combine(root, "Legacy.Maliev.DataMigration.Tests.dll");
                var config = new CurrentAuthTypedHostConfiguration(bindingPath, intentPath, pinsPath, reviewPath,
                    keyReferences.Single(key => key.KeyId == signing.Pins.ReviewKeyId).SubjectPublicKeyInfoPath,
                    testsPath, qualifiedTests.Sha256, CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location),
                    CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location), "definition", hostPath,
                    anchor.SourcePath, keyReferences);
                await files.WriteNewAsync(configPath, JsonSerializer.SerializeToUtf8Bytes(config), ct);
                void RequireDefinitionKey(string keyId, string fingerprint)
                { if (!trust.TryGetPublicKeyFingerprintSha256(keyId, out string actual) || actual != fingerprint) { throw CurrentAuthArchiveRecoveryV2.Invalid(); } }
                async Task CopyPrivate(CurrentAuthArchiveProofArtifact artifact, string destination, string keyId, string fingerprint)
                {
                    byte[] bytes = signingFiles.Read(artifact.Path, sharedReader: true, maximumBytes: 65536);
                    try
                    {
                        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
                        using var signer = new P256MigrationEvidenceSigner(keyId, Encoding.UTF8.GetString(bytes));
                        if (signer.PublicKeyFingerprintSha256 != fingerprint) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
                        await files.WriteNewAsync(destination, bytes, ct);
                    }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }
            }
            // Release the anchor-root exclusive authority before the existing producer takes that same root.
            await anchor.RequireAsync(ct);
            using var output = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
            using var error = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
            int exit = await RunCurrentAuthTypedHostProducerAsync(configPath, output, error, ct);
            if (exit != 0) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
            await anchor.RequireAsync(ct); await source.RequireAsync(ct);
            using var resultAuthority = WindowsLocalRunAuthority.AcquireResume(root, anchor.Binding);
            using var resultFiles = new CurrentAppOwnedRepairCustody(resultAuthority);
            var resultTrust = new ReceiptAttestationTrustStore(keyReferences.Select(key => new TrustedAttestationKey(key.KeyId,
                resultFiles.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
            using var evidenceSigner = new P256MigrationEvidenceSigner(signing.Pins.ReceiptKeyId,
                Encoding.UTF8.GetString(resultFiles.Read(receiptPath, sharedReader: true, maximumBytes: 65536)));
            var hostArtifact = new CurrentAuthProofArtifact(hostPath, CurrentAuthRepairPermit.Hash(resultFiles.Read(hostPath, sharedReader: true, maximumBytes: 1024 * 1024)));
            var proof = await CurrentAuthTypedProofAssembler.AssembleAsync(resultFiles, anchor.Binding, hostArtifact, "helper", anchor.Intent,
                source.Evidence.Capture.Plan, signing.Pins, resultTrust, evidenceSigner, proofPath, ct);
            var completed = anchor.Intent with { AuthHelperProofSha256 = proof.Sha256, OperationSha256 = CurrentAuthRepairPermit.OperationSha256(source.Evidence.Capture.Plan, proof.Sha256) };
            if (CurrentAuthRepairProofReader.Subject(completed) != CurrentAuthRepairProofReader.Subject(anchor.Intent)) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
            await resultFiles.WriteNewAsync(completedPath, JsonSerializer.SerializeToUtf8Bytes(completed), ct);
            await CurrentAuthRepairProofReader.RequireAsync(resultFiles, new(proof.Path, proof.Sha256), proof.Sha256, "helper", completed,
                resultTrust, signing.Pins, source.Evidence.Capture.Plan, ct);
            return new(Artifact(bindingPath, 65536), Artifact(completedPath, 1024 * 1024), Artifact(anchor.SourcePath, 32 * 1024 * 1024),
                new(proof.Path, proof.Sha256), CurrentAuthRepairProofReader.Subject(completed));

            CurrentAuthArchiveProofArtifact Artifact(string path, int maximum)
            {
                return new(path,
                CurrentAuthRepairPermit.Hash(resultFiles.Read(path, sharedReader: true, maximumBytes: maximum)));
            }
        }
    }

}
