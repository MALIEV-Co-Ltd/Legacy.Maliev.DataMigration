using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static async Task<CurrentAuthArchiveGeneratedCaseV2> GenerateCurrentAuthArchiveCaseV2Async(
        CurrentAppOwnedRepairCustody parentFiles, WindowsLocalRunAuthority parentAuthority,
        CurrentAuthArchiveGeneratedCaseInputV2 input, CurrentAuthArchiveProofCaseV2 selected, CancellationToken ct)
    {
        var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(selected);
        parentFiles.Require(); parentAuthority.ValidateHeld();
        var (Authority, Files) = CurrentAuthArchiveCaseCustodyV2.OpenQualified(input.QualifiedInputBinding, parentAuthority.Binding.ArtifactRootCanonicalPath);
        using var qualifiedAuthority = Authority;
        using var qualifiedFiles = Files;
        RequireDefinitionSigningInputs(qualifiedFiles, input.Signing);
        var archivePins = new CurrentAuthArchivePins(input.Signing.Pins.ReviewKeyId, input.Signing.Pins.ReviewFingerprint,
            input.Signing.Pins.AuthorizationKeyId, input.Signing.Pins.AuthorizationFingerprint, input.Signing.Pins.ReceiptKeyId, input.Signing.Pins.ReceiptFingerprint);
        var trust = new ReceiptAttestationTrustStore(input.Signing.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            qualifiedFiles.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        var audienceClaim = DecodeAuthRepair<CurrentAuthArchiveClaim>(ReadParent(input.Audience, 65536));
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveProofAudienceV2>(audienceClaim,
            CurrentAuthArchiveRecoveryV2.AudienceDomain, archivePins.ReviewKeyId, archivePins.ReviewFingerprint, trust);
        byte[] bindingBytes = ReadParent(input.QualifiedInputBinding, 65536);
        var binding = DecodeAuthRepair<LocalExecutionBinding>(bindingBytes); string root = binding.ArtifactRootCanonicalPath;
        if (Path.GetDirectoryName(input.TestImage.Path) != root || Path.GetDirectoryName(input.QualifiedInputBinding.Path) != root ||
            Path.GetDirectoryName(input.Audience.Path) != root || Path.GetDirectoryName(input.SourceCredential.Path) != root ||
            !root.StartsWith(Path.TrimEndingDirectorySeparator(parentAuthority.Binding.ArtifactRootCanonicalPath) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            input.Signing.TrustedKeys.Any(key => Path.GetDirectoryName(key.SubjectPublicKeyInfoPath) != root) ||
            root == parentAuthority.Binding.ArtifactRootCanonicalPath || input.TestImage.Sha256 != audience.TestsImageSha256 ||
            input.Signing.ReviewPrivateKey.Path != Path.Combine(root, CurrentAuthArchiveGenuineDualInputContract.ReviewKeyName) ||
            input.Signing.EvidencePrivateKey.Path != Path.Combine(root, CurrentAuthArchiveGenuineDualInputContract.EvidenceKeyName) ||
            input.AuthorizationPrivateKey.Path != Path.Combine(root, CurrentAuthArchiveGenuineDualInputContract.AuthorizationKeyName)) { throw InvalidGenerated(); }
        RequireAuthorizationPrivate();
        CurrentAuthArchiveDefinitionCodeCopy.RequireBoundedInventory(root, ct);
        using var qualified = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(root, ct);
        byte[] credential = ReadParent(input.SourceCredential, 65536);
        CurrentReviewedCapture source;
        try { source = await CurrentReviewedCapture.CaptureAsync(Encoding.UTF8.GetString(credential), audience, ct); }
        finally { CryptographicOperations.ZeroMemory(credential); }
        var intended = await CurrentAuthArchiveIntendedObservationRuntimeV2.ObserveAsync(input.Intended, source, audienceClaim, trust, archivePins, ct);
        var initialIntended = await CurrentAuthArchiveIntendedRetentionV2.RetainAsync(parentFiles, Path.Combine(parentAuthority.Binding.ArtifactRootCanonicalPath,
            "archive-pre-definition-intended-" + Guid.NewGuid().ToString("N") + ".json"), intended.Evidence, ct);
        var definition = await ProduceCurrentAuthArchiveFreshDefinitionAsync(parentFiles, parentAuthority, source, intended,
            input.TestImage, input.Signing, qualifiedFiles, ct);
        // The definition run may take time. A second genuine observation supplies the case's own actual target window.
        intended = await CurrentAuthArchiveIntendedObservationRuntimeV2.ObserveAsync(input.Intended, source, audienceClaim, trust, archivePins, ct);
        await source.RequireAsync(ct); qualified.Require();
        Guid operation = Guid.NewGuid(); DateTimeOffset now = DateTimeOffset.UtcNow;
        string prefix = "archive-generated-" + operation.ToString("N") + "-";
        CurrentAuthArchiveProofArtifact sourceArtifact, intendedArtifact, seedArtifact, packetArtifact, bindingArtifact;
        {
            var files = qualifiedFiles;
            if (!files.Read(input.QualifiedInputBinding.Path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bindingBytes)) { throw InvalidGenerated(); }
            sourceArtifact = await Write("source-plan.json", JsonSerializer.SerializeToUtf8Bytes(source.Evidence.Plan));
            var captureArtifact = await Write("source-capture.json", JsonSerializer.SerializeToUtf8Bytes(source.Evidence));
            intendedArtifact = await CurrentAuthArchiveIntendedRetentionV2.RetainAsync(files, Path.Combine(root, prefix + "intended-after-c.json"), intended.Evidence, ct);
            var seed = new CurrentAuthArchiveComponentBootstrapSeed("current-auth-genuine-archive-component-seed-v1", operation, identity.CaseId,
                source.Evidence.Plan.SourceCommitSha, source.Evidence.FullPlanSha256, ApprovedCurrentAuthSchema.AuthServiceCommit,
                CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256, definition.Definition.Sha256,
                definition.SubjectSha256, binding.ComputeSha256(), input.TestImage.Sha256, audience.ConsoleImageSha256, audience.CoreImageSha256,
                CurrentAuthLocalSessionArchivePolicy.Hash(archivePins), now, now.AddMinutes(8), archivePins.ReviewKeyId, null);
            using var reviewer = Signer(input.Signing.ReviewPrivateKey, archivePins.ReviewKeyId, archivePins.ReviewFingerprint);
            seed = seed with { Signature = Convert.ToBase64String(reviewer.Sign(CurrentAuthArchiveComponentBootstrap.SeedPayload(seed))) };
            seedArtifact = await Write("seed.json", JsonSerializer.SerializeToUtf8Bytes(seed));
            var archivePinsArtifact = await Write("signing-pins.json", JsonSerializer.SerializeToUtf8Bytes(archivePins));
            string precursorRoot = Path.GetDirectoryName(definition.RunBinding.Path)!;
            var precursorKeys = input.Signing.TrustedKeys.Select((key, index) => new DeltaTrustedKeyReference(key.KeyId,
                Path.Combine(precursorRoot, "archive-definition-public-" + index.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".spki"))).ToArray();
            var readback = new CurrentAuthArchiveComponentReadbackInput(input.QualifiedInputBinding, seedArtifact, null, sourceArtifact,
                archivePinsArtifact, input.Signing.TrustedKeys, input.TestImage,
                new(typeof(MigrationConsole).Assembly.Location, audience.ConsoleImageSha256),
                new(typeof(CurrentAuthRepairPermit).Assembly.Location, audience.CoreImageSha256),
                definition.RunBinding, definition.CompletedScope, definition.Source,
                HeldArtifact(Path.Combine(precursorRoot, "archive-definition-pins.json"), 65536), precursorKeys, definition.Definition);
            var request = new CurrentAuthArchiveGenuineHostConfiguration(CurrentAuthArchiveGenuineHost.ProviderKind, identity.Phase, identity.CaseId,
                readback, input.FirstFixtureParent, input.SecondFixtureParent);
            CurrentAuthArchiveGenuineHost.RequireInput(request);
            byte[] packet;
            if (selected is CurrentAuthArchiveProofCaseV2.FirstRestore or CurrentAuthArchiveProofCaseV2.SecondRestore)
            {
                var recoveryBinding = new CurrentAuthArchiveRecoveryCaseBindingV2("current-auth-archive-recovery-case-binding-v2",
                    CurrentAuthLocalSessionArchivePolicy.Hash(audienceClaim), CurrentAuthLocalSessionArchivePolicy.Hash(seed), operation, identity.CaseId,
                    source.Evidence.FullPlanSha256, now, seed.ExpiresAtUtc);
                var signed = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveRecoveryV2.CaseDomain, recoveryBinding, reviewer);
                var artifact = await Write("recovery-binding.json", JsonSerializer.SerializeToUtf8Bytes(signed));
                packet = JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveRecoveryV2Input("current-auth-archive-recovery-input-v2", request,
                    input.Audience, artifact, input.SourceCredential));
            }
            else
            {
                packet = selected is CurrentAuthArchiveProofCaseV2.HostUnprobed or CurrentAuthArchiveProofCaseV2.LocalTrust
                ? JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveGenuinePreflightInput(CurrentAuthArchiveGenuinePreflightInputContract.Kind, request))
                : identity.Phase == "helper"
                    ? selected == CurrentAuthArchiveProofCaseV2.Dual
                    ? JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveGenuineDualInput(CurrentAuthArchiveGenuineDualInputContract.Kind, request))
                    : JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveGenuineRecoveryHelpersInput("current-auth-archive-genuine-recovery-helper-input-v1", request))
                    : JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveGenuineExecutionInput(CurrentAuthArchiveGenuineExecutionInputContract.Kind, request));
            }
            packetArtifact = await Write("input.json", packet);
            var caseBinding = new CurrentAuthArchiveGeneratedBindingV2("current-auth-archive-generated-case-binding-v2", input.Audience.Sha256,
                identity.Phase, identity.CaseId, operation, seedArtifact.Sha256, source.Evidence.FullPlanSha256, source.Evidence.SourceIdentitySha256,
                source.Evidence.DefinitionSha256, definition.Definition.Sha256, intendedArtifact.Sha256, initialIntended.Sha256,
                packetArtifact.Sha256, string.Empty, now, seed.ExpiresAtUtc);
            string controlRoot = Path.Combine(parentAuthority.Binding.ArtifactRootCanonicalPath, "archive-case-host-" + operation.ToString("N"));
            if (Directory.Exists(controlRoot) || File.Exists(controlRoot)) { throw InvalidGenerated(); }
            SecureSnapshotFileCreation.CreateRestrictedDirectory(controlRoot);
            CurrentAuthArchiveProofArtifact hostArtifact;
            using (var controlAuthority = WindowsLocalRunAuthority.AcquireFresh(controlRoot))
            using (var controlFiles = new CurrentAppOwnedRepairCustody(controlAuthority))
            {
                string controlBindingPath = Path.Combine(controlRoot, "fixture-binding.json"); byte[] controlBytes = JsonSerializer.SerializeToUtf8Bytes(controlAuthority.Binding);
                await controlFiles.WriteNewAsync(controlBindingPath, controlBytes, ct);
                var controlArtifact = new CurrentAuthArchiveProofArtifact(controlBindingPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(controlBytes));
                byte[] host = identity.Phase == "helper"
                    ? JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveHelperHostConfiguration("current-auth-archive-helper-host-v1", controlArtifact, packetArtifact, CurrentAuthArchiveGeneratedCasesV2.Helper(selected)))
                    : selected is CurrentAuthArchiveProofCaseV2.HostUnprobed or CurrentAuthArchiveProofCaseV2.LocalTrust
                    ? JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchivePreflightHostConfiguration("current-auth-archive-preflight-host-v1", controlArtifact, packetArtifact, CurrentAuthArchiveGeneratedCasesV2.Preflight(selected)))
                    : identity.Phase == "recovery"
                    ? JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveRecoveryV2HostConfiguration("current-auth-archive-recovery-host-v2", controlArtifact, packetArtifact, CurrentAuthArchiveGeneratedCasesV2.Recovery(selected)))
                    : JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthArchiveExecutionHostConfiguration("current-auth-archive-execution-host-v1", controlArtifact, packetArtifact, CurrentAuthArchiveGeneratedCasesV2.Execution(selected)));
                string path = Path.Combine(controlRoot, "case-host.json"); await controlFiles.WriteNewAsync(path, host, ct); hostArtifact = new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(host));
            }
            caseBinding = caseBinding with { HostConfigurationSha256 = hostArtifact.Sha256 };
            bindingArtifact = await Write("case-binding.json", JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(
                CurrentAuthArchiveGeneratedCasesV2.BindingDomain, caseBinding, reviewer)));
            return new(selected, operation, input.QualifiedInputBinding, bindingArtifact, captureArtifact, intendedArtifact, initialIntended, seedArtifact, packetArtifact, hostArtifact, definition, input.Audience);

            async Task<CurrentAuthArchiveProofArtifact> Write(string name, byte[] bytes)
            {
                string path = Path.Combine(root, prefix + name); await files.WriteNewAsync(path, bytes, ct);
                return new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
            }
        }
        byte[] ReadParent(CurrentAuthArchiveProofArtifact artifact, int maximum)
        { byte[] bytes = qualifiedFiles.Read(artifact.Path, sharedReader: true, maximumBytes: maximum); return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw InvalidGenerated(); }
        P256MigrationEvidenceSigner Signer(CurrentAuthArchiveProofArtifact artifact, string keyId, string fingerprint)
        {
            byte[] bytes = ReadParent(artifact, 65536);
            try
            {
                var signer = new P256MigrationEvidenceSigner(keyId, Encoding.UTF8.GetString(bytes));
                if (signer.PublicKeyFingerprintSha256 == fingerprint) { return signer; }
                signer.Dispose(); throw InvalidGenerated();
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        void RequireAuthorizationPrivate() { using var signer = Signer(input.AuthorizationPrivateKey, archivePins.AuthorizationKeyId, archivePins.AuthorizationFingerprint); }
        CurrentAuthArchiveProofArtifact HeldArtifact(string path, int maximum)
        {
            var held = CurrentAuthArchiveCaseCustodyV2.OpenQualified(definition.RunBinding, parentAuthority.Binding.ArtifactRootCanonicalPath);
            using (held.Authority)
            using (held.Files)
            {
                byte[] bytes = held.Files.Read(path, sharedReader: true, maximumBytes: maximum);
                return new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
            }
        }
    }
    private static MigrationExecutionException InvalidGenerated()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
