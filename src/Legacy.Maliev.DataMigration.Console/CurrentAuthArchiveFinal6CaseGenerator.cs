using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveFinal6GeneratorInput(CurrentAuthArchiveProofArtifact Audience,
    CurrentAuthArchiveProofArtifact SourceCredential, CurrentAuthArchiveFinal6IntendedObservationInput Intended,
    CurrentAuthArchiveProofArtifact QualifiedInputBinding, CurrentAuthArchiveProofArtifact TestImage,
    CurrentAuthArchiveDefinitionSigningInputs Signing, CurrentAuthArchiveProofArtifact AuthorizationPrivateKey,
    string FirstFixtureParent, string SecondFixtureParent);

public static partial class MigrationConsole
{
    internal static async Task<CurrentAuthArchiveFinal6GeneratedCase> GenerateCurrentAuthArchiveFinal6CaseAsync(
        CurrentAppOwnedRepairCustody parent, WindowsLocalRunAuthority authority, CurrentAuthArchiveFinal6GeneratorInput input,
        CurrentAuthArchiveProofCaseV2 selected, CancellationToken ct)
    {
        var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(selected);
        parent.Require(); authority.ValidateHeld();
        var (Authority, Files) = CurrentAuthArchiveFinal6CaseCustody.OpenQualified(input.QualifiedInputBinding, authority.Binding.ArtifactRootCanonicalPath);
        using var qualifiedAuthority = Authority; using var files = Files;
        RequireDefinitionSigningInputs(files, input.Signing);
        var pins = new CurrentAuthArchivePins(input.Signing.Pins.ReviewKeyId, input.Signing.Pins.ReviewFingerprint,
            input.Signing.Pins.AuthorizationKeyId, input.Signing.Pins.AuthorizationFingerprint, input.Signing.Pins.ReceiptKeyId, input.Signing.Pins.ReceiptFingerprint);
        var trust = new ReceiptAttestationTrustStore(input.Signing.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        var audienceClaim = DecodeAuthRepair<CurrentAuthArchiveClaim>(Read(input.Audience, 65536));
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(audienceClaim,
            CurrentAuthArchiveFinal6AudiencePolicy.Domain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthArchiveFinal6AudiencePolicy.Require(audience, pins, DateTimeOffset.UtcNow);
        string root = qualifiedAuthority.Binding.ArtifactRootCanonicalPath;
        if (Path.GetDirectoryName(input.TestImage.Path) != root || input.TestImage.Sha256 != audience.TestsImageSha256 ||
            input.Signing.ReviewPrivateKey.Path != Path.Combine(root, CurrentAuthArchiveGenuineDualInputContract.ReviewKeyName) ||
            input.Signing.EvidencePrivateKey.Path != Path.Combine(root, CurrentAuthArchiveGenuineDualInputContract.EvidenceKeyName) ||
            input.AuthorizationPrivateKey.Path != Path.Combine(root, CurrentAuthArchiveGenuineDualInputContract.AuthorizationKeyName)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        using (var authorization = Signer(input.AuthorizationPrivateKey, pins.AuthorizationKeyId, pins.AuthorizationFingerprint)) { }
        CurrentAuthArchiveDefinitionCodeCopy.RequireBoundedInventory(root, ct);
        using var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(root, ct);
        byte[] credential = Read(input.SourceCredential, 65536);
        CurrentAuthArchiveFinal6SourceCapture.Captured source;
        try { source = await CurrentAuthArchiveFinal6SourceCapture.Captured.CaptureAsync(new UTF8Encoding(false, true).GetString(credential), audienceClaim, pins, trust, ct); }
        finally { CryptographicOperations.ZeroMemory(credential); }
        var intended = await CurrentAuthArchiveFinal6IntendedObservationRuntime.ObserveAsync(input.Intended, source, audienceClaim, trust, pins, ct);
        var preIntended = await CurrentAuthArchiveFinal6IntendedRetention.RetainAsync(parent,
            Path.Combine(authority.Binding.ArtifactRootCanonicalPath, "final6-pre-definition-intended-" + Guid.NewGuid().ToString("N") + ".json"), intended.Evidence, ct);
        var definitionOriginal = await ProduceCurrentAuthArchiveFinal6FreshDefinitionAsync(parent, authority, source, intended,
            input.TestImage, input.Signing, files, audienceClaim, ct);
        byte[] definitionBytes = parent.Read(definitionOriginal.Path, sharedReader: true, maximumBytes: 65536);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(definitionBytes) != definitionOriginal.Sha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        var envelope = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Definition>(DecodeAuthRepair<CurrentAuthArchiveClaim>(definitionBytes),
            CurrentAuthArchiveFinal6DefinitionReader.Domain, pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
        var definition = envelope.NativeDefinition;
        intended = await CurrentAuthArchiveFinal6IntendedObservationRuntime.ObserveAsync(input.Intended, source, audienceClaim, trust, pins, ct);
        await source.RequireAsync(ct); bundle.Require();
        Guid operation = Guid.NewGuid(); DateTimeOffset now = DateTimeOffset.UtcNow;
        string prefix = "final6-generated-" + operation.ToString("N") + "-";
        var sourcePlan = await Write("source-plan.json", JsonSerializer.SerializeToUtf8Bytes(source.Evidence.Capture.Plan));
        var capture = await Write("source-capture.json", JsonSerializer.SerializeToUtf8Bytes(source.Evidence));
        var intendedRef = await CurrentAuthArchiveFinal6IntendedRetention.RetainAsync(files, Path.Combine(root, prefix + "intended.json"), intended.Evidence, ct);
        var definitionRef = await Write("definition.json", definitionBytes);
        var copies = new CurrentAuthArchiveFinal6DefinitionOwnerCopies(authority.Binding,
            await CopyOwner("anchor-intent.json", envelope.AnchorIntent), await CopyOwner("anchor-created-container.json", envelope.CreatedContainer),
            await CopyOwner("anchor-created-volume.json", envelope.CreatedVolume), await CopyOwner("anchor-absence.json", envelope.Absence));
        var seed = new CurrentAuthArchiveComponentBootstrapSeed("current-auth-genuine-archive-component-seed-v1", operation, identity.CaseId,
            source.Evidence.Capture.Plan.SourceCommitSha, source.Evidence.Capture.FullPlanSha256, ApprovedCurrentAuthSchema.AuthServiceCommit,
            CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256, definition.Definition.Sha256, definition.SubjectSha256,
            qualifiedAuthority.Binding.ComputeSha256(), input.TestImage.Sha256, audience.ConsoleImageSha256, audience.CoreImageSha256,
            CurrentAuthLocalSessionArchivePolicy.Hash(pins), now, new[] { now.AddMinutes(8), audience.ExpiresAtUtc }.Min(), pins.ReviewKeyId, null);
        using var reviewer = Signer(input.Signing.ReviewPrivateKey, pins.ReviewKeyId, pins.ReviewFingerprint);
        seed = seed with { Signature = Convert.ToBase64String(reviewer.Sign(CurrentAuthArchiveComponentBootstrap.SeedPayload(seed))) };
        var seedRef = await Write("seed.json", JsonSerializer.SerializeToUtf8Bytes(seed));
        var pinsRef = await Write("pins.json", JsonSerializer.SerializeToUtf8Bytes(pins));
        string anchorRoot = Path.GetDirectoryName(definition.RunBinding.Path)!;
        var anchorKeys = input.Signing.TrustedKeys.Select((key, index) => new DeltaTrustedKeyReference(key.KeyId,
            Path.Combine(anchorRoot, "archive-definition-public-" + index.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".spki"))).ToArray();
        var precursorPins = HeldAnchor(Path.Combine(anchorRoot, "archive-definition-pins.json"));
        var readback = new CurrentAuthArchiveComponentReadbackInput(input.QualifiedInputBinding, seedRef, null, sourcePlan, pinsRef,
            input.Signing.TrustedKeys, input.TestImage, new(typeof(MigrationConsole).Assembly.Location, audience.ConsoleImageSha256),
            new(typeof(CurrentAuthRepairPermit).Assembly.Location, audience.CoreImageSha256), definition.RunBinding, definition.CompletedScope,
            definition.Source, precursorPins, anchorKeys, definition.Definition);
        var request = new CurrentAuthArchiveGenuineHostConfiguration(CurrentAuthArchiveGenuineHost.ProviderKind, identity.Phase, identity.CaseId,
            readback, input.FirstFixtureParent, input.SecondFixtureParent);
        CurrentAuthArchiveGenuineHost.RequireInput(request);
        var caseBinding = new CurrentAuthArchiveFinal6CaseBinding(CurrentAuthArchiveFinal6CasePolicy.Kind, input.Audience.Sha256, identity.Phase, identity.CaseId,
            operation, seedRef.Sha256, source.Evidence.Capture.FullPlanSha256, definitionRef.Sha256, now, seed.ExpiresAtUtc);
        var caseRef = await Write("case-binding.json", JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveFinal6CasePolicy.Domain, caseBinding, reviewer)));
        var packet = new CurrentAuthArchiveFinal6CaseInput("current-auth-archive-final6-case-input-v1", request, capture, input.Audience,
            definitionRef, copies, input.SourceCredential, caseRef);
        CurrentAuthArchiveFinal6Host.RequirePacket(packet, selected);
        var packetRef = await Write("input.json", JsonSerializer.SerializeToUtf8Bytes(packet));
        string controlRoot = Path.Combine(authority.Binding.ArtifactRootCanonicalPath, "archive-case-host-" + operation.ToString("N"));
        if (Directory.Exists(controlRoot) || File.Exists(controlRoot)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(controlRoot);
        CurrentAuthArchiveProofArtifact hostRef;
        using (var control = WindowsLocalRunAuthority.AcquireFresh(controlRoot))
        using (var controlFiles = new CurrentAppOwnedRepairCustody(control))
        {
            byte[] binding = JsonSerializer.SerializeToUtf8Bytes(control.Binding);
            string bindingPath = Path.Combine(controlRoot, "fixture-binding.json"); await controlFiles.WriteNewAsync(bindingPath, binding, ct);
            var host = new CurrentAuthArchiveFinal6HostConfiguration("current-auth-archive-final6-host-v1",
                new(bindingPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(binding)), packetRef, selected);
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(host); string path = Path.Combine(controlRoot, "case-host.json");
            await controlFiles.WriteNewAsync(path, bytes, ct); hostRef = new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
        }
        var generation = new CurrentAuthArchiveFinal6GenerationBinding("current-auth-archive-final6-generated-binding-v1", selected, operation,
            input.Audience.Sha256, seedRef.Sha256, caseRef.Sha256, capture.Sha256, definitionRef.Sha256, packetRef.Sha256, hostRef.Sha256,
            intendedRef.Sha256, preIntended.Sha256, now, seed.ExpiresAtUtc);
        var generatedRef = await Write("generation.json", JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveFinal6GenerationPolicy.Domain, generation, reviewer)));
        return new(selected, operation, input.QualifiedInputBinding, generatedRef, caseRef, capture, intendedRef, preIntended,
            seedRef, packetRef, hostRef, definitionRef, input.Audience);

        byte[] Read(CurrentAuthArchiveProofArtifact artifact, int maximum)
        { byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum); return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw CurrentAuthArchiveFinal6Source.Invalid(); }
        async Task<CurrentAuthArchiveProofArtifact> Write(string suffix, byte[] bytes)
        { string path = Path.Combine(root, prefix + suffix); await files.WriteNewAsync(path, bytes, ct); return new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes)); }
        Task<CurrentAuthArchiveProofArtifact> CopyOwner(string suffix, CurrentAuthArchiveProofArtifact artifact)
        {
            byte[] bytes = parent.Read(artifact.Path, sharedReader: true, maximumBytes: 2 * 1024 * 1024);
            return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256
                ? throw CurrentAuthArchiveFinal6Source.Invalid()
                : Write(suffix, bytes);
        }
        CurrentAuthArchiveProofArtifact HeldAnchor(string path)
        {
            var anchor = CurrentAuthArchiveFinal6CaseCustody.OpenQualified(definition.RunBinding, authority.Binding.ArtifactRootCanonicalPath);
            using (anchor.Authority) using (anchor.Files)
            { return new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(anchor.Files.Read(path, sharedReader: true, maximumBytes: 65536))); }
        }
        P256MigrationEvidenceSigner Signer(CurrentAuthArchiveProofArtifact artifact, string keyId, string fingerprint)
        {
            byte[] bytes = Read(artifact, 65536);
            try
            {
                var signer = new P256MigrationEvidenceSigner(keyId, Encoding.UTF8.GetString(bytes));
                if (signer.PublicKeyFingerprintSha256 == fingerprint) { return signer; }
                signer.Dispose(); throw CurrentAuthArchiveFinal6Source.Invalid();
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}
