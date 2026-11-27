using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static async Task<CurrentAuthArchiveFinal6ProofResult> ProduceCurrentAuthArchiveFinal6ProofAsync(
        CurrentAppOwnedRepairCustody files, WindowsLocalRunAuthority authority, CurrentAuthArchiveFinal6GeneratorInput input, CancellationToken ct)
    {
        files.Require(); authority.ValidateHeld();
        Guid batch = Guid.NewGuid(); DateTimeOffset began = DateTimeOffset.UtcNow;
        string prefix = Path.Combine(authority.Binding.ArtifactRootCanonicalPath, "auth-final6-proof-" + batch.ToString("N"));
        var pins = new CurrentAuthArchivePins(input.Signing.Pins.ReviewKeyId, input.Signing.Pins.ReviewFingerprint,
            input.Signing.Pins.AuthorizationKeyId, input.Signing.Pins.AuthorizationFingerprint, input.Signing.Pins.ReceiptKeyId, input.Signing.Pins.ReceiptFingerprint);
        ReceiptAttestationTrustStore trust; CurrentAuthArchiveClaim audienceClaim;
        var (Authority, Files) = CurrentAuthArchiveFinal6CaseCustody.OpenQualified(input.QualifiedInputBinding, authority.Binding.ArtifactRootCanonicalPath);
        using (Authority) using (Files)
        {
            RequireDefinitionSigningInputs(Files, input.Signing);
            trust = new ReceiptAttestationTrustStore(input.Signing.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
                Files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
            audienceClaim = DecodeAuthRepair<CurrentAuthArchiveClaim>(CurrentAuthArchiveFinal6ProofAssembly.Read(Files, input.Audience, 65536));
        }
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(audienceClaim,
            CurrentAuthArchiveFinal6AudiencePolicy.Domain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthArchiveFinal6AudiencePolicy.Require(audience, pins, began);
        await files.WriteNewAsync(prefix + "-attempt.json", JsonSerializer.SerializeToUtf8Bytes(new
        { BatchId = batch, AudienceSha256 = input.Audience.Sha256, BeganAtUtc = began, PhaseProofComplete = false }), ct);
        var cases = new List<CurrentAuthArchiveFinal6CaseRun>();
        try
        {
            foreach (var selected in Enum.GetValues<CurrentAuthArchiveProofCaseV2>())
            {
                ct.ThrowIfCancellationRequested();
                // Each case obtains its own real capture, read-only intended context and newly executed definition anchor.
                var generated = await GenerateCurrentAuthArchiveFinal6CaseAsync(files, authority, input, selected, ct);
                var completed = await RunCurrentAuthArchiveFinal6GeneratedCaseAsync(generated, pins, trust, ct);
                _ = await CurrentAuthArchiveFinal6CaseReadback.RequireAsync(files, completed, audienceClaim, pins, trust, ct);
                cases.Add(completed);
                await files.WriteNewAsync(prefix + "-case-" + ((int)selected).ToString("D2", System.Globalization.CultureInfo.InvariantCulture) + ".json",
                    JsonSerializer.SerializeToUtf8Bytes(completed), ct);
            }
            var proof = new CurrentAuthArchiveFinal6Proof(CurrentAuthArchiveFinal6ProofAssembly.Kind, batch, input.Audience.Sha256,
                audience.AcceptedCommitSha, audience.SourceIdentitySha256, audience.SourceDefinitionSha256, audience.CoreImageSha256,
                audience.ConsoleImageSha256, audience.TestsImageSha256, began, DateTimeOffset.UtcNow, audience.ExpiresAtUtc, cases.ToArray());
            await CurrentAuthArchiveFinal6ProofAssembly.RequireCasesAsync(files, proof, audienceClaim, pins, trust, ct);
            using var evidence = Signer(input.Signing.EvidencePrivateKey, pins.EvidenceKeyId, pins.EvidenceFingerprint);
            byte[] proofBytes = JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveFinal6ProofAssembly.Domain, proof, evidence));
            string proofPath = prefix + ".json"; await files.WriteNewAsync(proofPath, proofBytes, ct);
            var proofArtifact = new CurrentAuthArchiveProofArtifact(proofPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(proofBytes));
            byte[] credential = ReadQualified(input.SourceCredential);
            CurrentAuthArchiveFinal6SourceCapture.Captured fresh;
            try { fresh = await CurrentAuthArchiveFinal6SourceCapture.Captured.CaptureAsync(new UTF8Encoding(false, true).GetString(credential), audienceClaim, pins, trust, ct); }
            finally { CryptographicOperations.ZeroMemory(credential); }
            var intended = await CurrentAuthArchiveFinal6IntendedObservationRuntime.ObserveAsync(input.Intended, fresh, audienceClaim, trust, pins, ct);
            byte[] sourceBytes = JsonSerializer.SerializeToUtf8Bytes(fresh.Evidence); string sourcePath = prefix + "-final-source.json";
            await files.WriteNewAsync(sourcePath, sourceBytes, ct);
            var sourceArtifact = new CurrentAuthArchiveProofArtifact(sourcePath, CurrentAuthLocalSessionArchivePolicy.HashBytes(sourceBytes));
            var intendedArtifact = await CurrentAuthArchiveFinal6IntendedRetention.RetainAsync(files, prefix + "-final-intended.json", intended.Evidence, ct);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var final = new CurrentAuthArchiveFinal6FinalReadback("current-auth-archive-final6-final-intended-readback-v1", proofArtifact.Sha256,
                input.Audience.Sha256, fresh.Evidence.Capture.FullPlanSha256, sourceArtifact, intendedArtifact, now,
                new[] { now.AddMinutes(2), audience.ExpiresAtUtc }.Min());
            using var reviewer = Signer(input.Signing.ReviewPrivateKey, pins.ReviewKeyId, pins.ReviewFingerprint);
            byte[] reviewBytes = JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveFinal6ProofAssembly.IntendedDomain, final, reviewer));
            string reviewPath = prefix + "-final-readback.json"; await files.WriteNewAsync(reviewPath, reviewBytes, ct);
            string audiencePath = prefix + "-audience.json"; await files.WriteNewAsync(audiencePath, ReadQualified(input.Audience), ct);
            var result = new CurrentAuthArchiveFinal6ProofResult(proofArtifact, new(reviewPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(reviewBytes)));
            await CurrentAuthArchiveFinal6ProofAssembly.RequirePublishedAsync(files, result, new(audiencePath, input.Audience.Sha256), pins, trust, ct);
            return result;
        }
        catch (Exception primary)
        {
            using var retention = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await files.WriteNewAsync(prefix + "-failure.json", JsonSerializer.SerializeToUtf8Bytes(new
                {
                    BatchId = batch,
                    AudienceSha256 = input.Audience.Sha256,
                    BeganAtUtc = began,
                    FailedAtUtc = DateTimeOffset.UtcNow,
                    CompletedCases = cases.Select(value => value.Generated.Case).ToArray(),
                    FailureType = primary.GetType().Name,
                    PhaseProofComplete = false
                }), retention.Token);
            }
            catch (Exception failure) { throw new AggregateException("Final6 proof production and factual failure retention failed.", primary, failure); }
            throw;
        }
        byte[] ReadQualified(CurrentAuthArchiveProofArtifact artifact)
        {
            var held = CurrentAuthArchiveFinal6CaseCustody.OpenQualified(input.QualifiedInputBinding, authority.Binding.ArtifactRootCanonicalPath);
            using (held.Authority) using (held.Files) { return CurrentAuthArchiveFinal6ProofAssembly.Read(held.Files, artifact, 65536); }
        }
        P256MigrationEvidenceSigner Signer(CurrentAuthArchiveProofArtifact artifact, string keyId, string fingerprint)
        {
            byte[] bytes = ReadQualified(artifact);
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
