using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveDefinitionSigningInputs(CurrentAuthRepairSigningPins Pins,
    IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys, CurrentAuthArchiveProofArtifact ReviewPrivateKey,
    CurrentAuthArchiveProofArtifact EvidencePrivateKey);
internal sealed record CurrentAuthArchiveFreshDefinition(CurrentAuthArchiveProofArtifact RunBinding,
    CurrentAuthArchiveProofArtifact CompletedScope, CurrentAuthArchiveProofArtifact Source,
    CurrentAuthArchiveProofArtifact Definition, string SubjectSha256);

public static partial class MigrationConsole
{
    // This is composition of the existing genuine definition host/reader. It cannot accept a historical scope or supplied positive result.
    internal static async Task<CurrentAuthArchiveFreshDefinition> ProduceCurrentAuthArchiveFreshDefinitionAsync(
        CurrentAppOwnedRepairCustody parentFiles, WindowsLocalRunAuthority parentAuthority, CurrentReviewedCapture source,
        CurrentAuthArchiveIntendedObservationRuntimeV2 intended, CurrentAuthArchiveProofArtifact qualifiedTests,
        CurrentAuthArchiveDefinitionSigningInputs signing, CurrentAppOwnedRepairCustody signingFiles, CancellationToken ct)
    {
        await source.RequireAsync(ct); parentFiles.Require(); parentAuthority.ValidateHeld();
        if (signing.TrustedKeys.Count != 3) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        RequireDefinitionSigningInputs(signingFiles, signing);
        intended.RequireFreshForDefinition(source, signing, qualifiedTests);
        var owner = await CurrentAuthArchiveDefinitionAnchorOwner.BeginAsync(parentFiles, parentAuthority, ct);
        var anchor = await CurrentAuthArchiveDefinitionAnchorSession.OpenAsync(owner, source, qualifiedTests, ct);
        CurrentAuthArchiveFreshDefinition? completedDefinition = null;
        var failures = new List<Exception>();
        try { completedDefinition = await ProduceHeldAsync(); } catch (Exception failure) { failures.Add(failure); }
        try { await anchor.DisposeAsync(); } catch (Exception cleanup) { failures.Add(cleanup); }
        if (failures.Count > 1) { throw new AggregateException("The genuine definition operation and exact anchor cleanup failed.", failures); }
        if (failures.Count == 1) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failures[0]).Throw(); }
        return completedDefinition ?? throw CurrentAuthArchiveRecoveryV2.Invalid();

        async Task<CurrentAuthArchiveFreshDefinition> ProduceHeldAsync()
        {
            await CurrentAuthArchiveDefinitionCodeCopy.CopyAsync(Path.GetDirectoryName(qualifiedTests.Path)!, anchor, ct);
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
                    finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
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
                source.Evidence.Plan, signing.Pins, resultTrust, evidenceSigner, proofPath, ct);
            var completed = anchor.Intent with { AuthHelperProofSha256 = proof.Sha256, OperationSha256 = CurrentAuthRepairPermit.OperationSha256(source.Evidence.Plan, proof.Sha256) };
            if (CurrentAuthRepairProofReader.Subject(completed) != CurrentAuthRepairProofReader.Subject(anchor.Intent)) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
            await resultFiles.WriteNewAsync(completedPath, JsonSerializer.SerializeToUtf8Bytes(completed), ct);
            await CurrentAuthRepairProofReader.RequireAsync(resultFiles, new(proof.Path, proof.Sha256), proof.Sha256, "helper", completed,
                resultTrust, signing.Pins, source.Evidence.Plan, ct);
            return new(Artifact(bindingPath, 65536), Artifact(completedPath, 1024 * 1024), Artifact(anchor.SourcePath, 32 * 1024 * 1024),
                new(proof.Path, proof.Sha256), CurrentAuthRepairProofReader.Subject(completed));

            CurrentAuthArchiveProofArtifact Artifact(string path, int maximum)
            {
                return new(path,
                CurrentAuthRepairPermit.Hash(resultFiles.Read(path, sharedReader: true, maximumBytes: maximum)));
            }
        }
    }

    private static void RequireDefinitionSigningInputs(CurrentAppOwnedRepairCustody parent, CurrentAuthArchiveDefinitionSigningInputs signing)
    {
        var trust = new ReceiptAttestationTrustStore(signing.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            parent.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        RequireKey(signing.Pins.ReviewKeyId, signing.Pins.ReviewFingerprint);
        RequireKey(signing.Pins.AuthorizationKeyId, signing.Pins.AuthorizationFingerprint);
        RequireKey(signing.Pins.ReceiptKeyId, signing.Pins.ReceiptFingerprint);
        RequirePrivate(signing.ReviewPrivateKey, signing.Pins.ReviewKeyId, signing.Pins.ReviewFingerprint);
        RequirePrivate(signing.EvidencePrivateKey, signing.Pins.ReceiptKeyId, signing.Pins.ReceiptFingerprint);
        void RequireKey(string keyId, string expected)
        { if (!trust.TryGetPublicKeyFingerprintSha256(keyId, out string fingerprint) || fingerprint != expected) { throw CurrentAuthArchiveRecoveryV2.Invalid(); } }
        void RequirePrivate(CurrentAuthArchiveProofArtifact artifact, string keyId, string expected)
        {
            byte[] bytes = parent.Read(artifact.Path, sharedReader: true, maximumBytes: 65536);
            try
            {
                if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(keyId, Encoding.UTF8.GetString(bytes));
                if (signer.PublicKeyFingerprintSha256 != expected) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}
