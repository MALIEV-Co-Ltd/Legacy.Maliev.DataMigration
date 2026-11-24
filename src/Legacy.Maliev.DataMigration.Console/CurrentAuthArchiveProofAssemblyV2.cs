using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveProofV2(string Kind, Guid BatchId, string AudienceSha256, string SourceCommitSha,
    string SourceIdentitySha256, string ApprovedDefinitionSha256, string CoreImageSha256, string ConsoleImageSha256, string TestsImageSha256,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc, IReadOnlyList<CurrentAuthArchiveGeneratedCaseRunV2> Cases);
internal sealed record CurrentAuthArchiveFinalIntendedReadbackV2(string Kind, string ProofSha256, string AudienceSha256,
    string CurrentSourceFullSha256, CurrentAuthArchiveProofArtifact CurrentSourceCapture, CurrentAuthArchiveProofArtifact CurrentIntendedObservation,
    DateTimeOffset ObservedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentAuthArchiveProofAssemblyResultV2(CurrentAuthArchiveProofArtifact Proof, CurrentAuthArchiveProofArtifact FinalIntendedReadback);

internal static class CurrentAuthArchiveProofAssemblyV2
{
    internal const string Domain = "Legacy.Maliev.CurrentAuth.ArchiveCompleteEighteenProof.v2";
    internal const string IntendedDomain = "Legacy.Maliev.CurrentAuth.ArchiveFinalIntendedReadback.v2";
    internal static async Task RequirePublishedAsync(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofAssemblyResultV2 artifacts,
        CurrentAuthArchiveProofArtifact audienceArtifact, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        files.Require(); CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        T Verify<T>(CurrentAuthArchiveProofArtifact artifact, string domain, bool review)
        {
            var claim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(Read(files, artifact, 32 * 1024 * 1024));
            return CurrentAuthLocalSessionArchivePolicy.Verify<T>(claim, domain, review ? pins.ReviewKeyId : pins.EvidenceKeyId,
                review ? pins.ReviewFingerprint : pins.EvidenceFingerprint, trust);
        }
        var audience = Verify<CurrentAuthArchiveProofAudienceV2>(audienceArtifact, CurrentAuthArchiveRecoveryV2.AudienceDomain, true);
        var proof = Verify<CurrentAuthArchiveProofV2>(artifacts.Proof, Domain, false);
        if (proof.AudienceSha256 != audienceArtifact.Sha256 || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != audience.AcceptedCommitSha) { throw Invalid(); }
        await RequireCasesAsync(files, proof, audience, pins, trust, ct);
        var final = Verify<CurrentAuthArchiveFinalIntendedReadbackV2>(artifacts.FinalIntendedReadback, IntendedDomain, true);
        RequireFinalHeader(final, artifacts.Proof.Sha256, audienceArtifact.Sha256, proof.CompletedAtUtc, audience.ExpiresAtUtc, DateTimeOffset.UtcNow);
        var source = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveRecoverySourceEvidence>(Read(files, final.CurrentSourceCapture, 32 * 1024 * 1024));
        CurrentAuthArchiveRecoveryV2.RequireSource(source, audience.AcceptedCommitSha, audience.SourceIdentitySha256, audience.SourceDefinitionSha256, DateTimeOffset.UtcNow);
        if (source.FullPlanSha256 != final.CurrentSourceFullSha256 || source.BeganAtUtc < proof.CompletedAtUtc || source.CompletedAtUtc > final.ObservedAtUtc) { throw Invalid(); }
        _ = await RequireIntendedAsync(files, final.CurrentIntendedObservation, source, audience, final.ObservedAtUtc, ct);
        files.Require();
    }
    internal static void RequireFinalHeader(CurrentAuthArchiveFinalIntendedReadbackV2 final, string proof, string audience,
        DateTimeOffset proofCompleted, DateTimeOffset audienceExpiry, DateTimeOffset now)
    {
        if (final.Kind != "current-auth-archive-final-intended-readback-v2" || final.ProofSha256 != proof || final.AudienceSha256 != audience ||
            final.ObservedAtUtc.Offset != TimeSpan.Zero || final.ExpiresAtUtc.Offset != TimeSpan.Zero || final.ObservedAtUtc < proofCompleted ||
            final.ObservedAtUtc > now || final.ExpiresAtUtc <= now || final.ExpiresAtUtc <= final.ObservedAtUtc ||
            final.ExpiresAtUtc > final.ObservedAtUtc.AddMinutes(2) || final.ExpiresAtUtc > audienceExpiry) { throw Invalid(); }
    }
    internal static void RequireInventory(IReadOnlyList<CurrentAuthArchiveGeneratedCaseRunV2> cases)
    {
        var expected = Enum.GetValues<CurrentAuthArchiveProofCaseV2>();
        if (cases.Count != 18 || !cases.Select(item => item.Generated.Case).Order().SequenceEqual(expected.Order()) ||
            cases.Select(item => item.Generated.OperationId).Distinct().Count() != 18 || cases.Any(item => item.PhaseProofComplete)) { throw Invalid(); }
    }
    internal static async Task RequireCasesAsync(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofV2 proof,
        CurrentAuthArchiveProofAudienceV2 audience, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        RequireInventory(proof.Cases);
        if (proof.Kind != "current-auth-archive-complete-eighteen-proof-v2" || proof.BatchId == Guid.Empty ||
            proof.SourceCommitSha != audience.AcceptedCommitSha || proof.SourceIdentitySha256 != audience.SourceIdentitySha256 ||
            proof.ApprovedDefinitionSha256 != audience.SourceDefinitionSha256 || proof.CoreImageSha256 != audience.CoreImageSha256 ||
            proof.ConsoleImageSha256 != audience.ConsoleImageSha256 || proof.TestsImageSha256 != audience.TestsImageSha256 ||
            proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.BeganAtUtc > proof.CompletedAtUtc ||
            proof.CompletedAtUtc > DateTimeOffset.UtcNow || proof.ExpiresAtUtc > audience.ExpiresAtUtc || proof.ExpiresAtUtc <= DateTimeOffset.UtcNow ||
            proof.CoreImageSha256 != CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location) ||
            proof.ConsoleImageSha256 != CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location)) { throw Invalid(); }
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var run in proof.Cases)
        {
            ct.ThrowIfCancellationRequested(); CurrentAuthRepairCapacity.Require(admission: false);
            if (run.Generated.Audience.Sha256 != proof.AudienceSha256 || run.BeganAtUtc < proof.BeganAtUtc || run.CompletedAtUtc > proof.CompletedAtUtc) { throw Invalid(); }
            var facts = await CurrentAuthArchiveCaseReadbackV2.RequireAsync(files, run, audience, pins, trust, ct);
            using var roots = CurrentAuthArchiveCaseCustodyV2.Open(files, run.Generated);
            if (!ids.Add(facts.Scope.ComponentSubject!.Local.ContainerId) || !ids.Add(facts.Scope.ComponentSubject.Comparison.ContainerId)) { throw Invalid(); }
            _ = await RequireIntendedAsync(roots.For(run.Generated.IntendedObservation.Path), run.Generated.IntendedObservation, facts.Source, audience, run.BeganAtUtc, ct);
            var before = await RequireIntendedAsync(files, run.Generated.PreDefinitionIntendedObservation, facts.Source, audience, run.BeganAtUtc, ct);
            var precursor = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairScope>(roots.Read(run.Generated.Definition.CompletedScope, 1024 * 1024));
            string parent = Path.GetDirectoryName(Path.GetDirectoryName(run.Generated.Definition.RunBinding.Path)!)!;
            string prefix = Path.Combine(parent, "archive-definition-anchor-" + precursor.OperationId.ToString("N"));
            var intent = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveDefinitionAnchorIntent>(files.Read(prefix + "-intent.json", sharedReader: true, maximumBytes: 2 * 1024 * 1024));
            using var absence = JsonDocument.Parse(files.Read(prefix + "-absence.json", sharedReader: true, maximumBytes: 2 * 1024 * 1024));
            using var container = JsonDocument.Parse(files.Read(prefix + "-container.json", sharedReader: true, maximumBytes: 2 * 1024 * 1024));
            if (before.CompletedAtUtc > intent.BeganAtUtc || absence.RootElement.GetProperty("ObservedAtUtc").GetDateTimeOffset() > run.BeganAtUtc) { throw Invalid(); }
            CurrentAuthArchiveDefinitionAnchorOwner.RequireRecordedContainerAbsent(container.RootElement.GetProperty("Id").GetString()!,
                absence.RootElement.GetProperty("Containers").EnumerateArray().Select(item => item.GetString()!).ToArray());
        }
    }
    internal static async Task<CurrentAuthArchiveIntendedRetainedEvidenceV2> RequireIntendedAsync(CurrentAppOwnedRepairCustody files,
        CurrentAuthArchiveProofArtifact artifact, CurrentAuthArchiveRecoverySourceEvidence source, CurrentAuthArchiveProofAudienceV2 audience,
        DateTimeOffset before, CancellationToken ct)
    {
        var evidence = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveIntendedRetainedEvidenceV2>(Read(files, artifact, 1024 * 1024));
        if (evidence.Kind != "current-auth-archive-intended-after-c-observation-v2" || evidence.SourceFullSha256 != source.FullPlanSha256 ||
            evidence.SourceIdentitySha256 != audience.SourceIdentitySha256 || evidence.SourceDefinitionSha256 != audience.SourceDefinitionSha256 ||
            evidence.LocalIdentitySha256 != audience.IntendedLocalIdentitySha256 || evidence.ComparisonIdentitySha256 != audience.IntendedComparisonIdentitySha256 ||
            CurrentAuthArchiveIntendedObservationRuntimeV2.Identity(evidence.LocalPolicy) != evidence.LocalIdentitySha256 ||
            CurrentAuthArchiveIntendedObservationRuntimeV2.Identity(evidence.ComparisonPolicy) != evidence.ComparisonIdentitySha256 ||
            evidence.LocalAuthRowsSha256 != audience.IntendedAuthRowsSha256 || evidence.LocalAuthRows != audience.IntendedAuthRows ||
            evidence.BeganAtUtc.Offset != TimeSpan.Zero || evidence.CompletedAtUtc.Offset != TimeSpan.Zero || evidence.BeganAtUtc > evidence.CompletedAtUtc || evidence.CompletedAtUtc > before)
        { throw Invalid(); }
        foreach (bool comparison in new[] { false, true })
        {
            var value = comparison ? evidence.Comparison : evidence.Local; var policy = comparison ? evidence.ComparisonPolicy : evidence.LocalPolicy;
            var databases = await CurrentAuthArchiveStreamedBaselineV2.ReadAsync(files, value.Databases, ct);
            var native = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveNativeCommitmentV2>(Read(files, new(value.Native.Path, value.Native.Sha256), 32 * 1024 * 1024)); native.Require();
            if (policy.SourceSchemaPlanSha256 != source.FullPlanSha256 || policy.SourceCommitSha != source.Plan.SourceCommitSha ||
                policy.AuthBeforeSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) || policy.AuthAfterSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) ||
                native.Snapshot.Sha256 != databases.Single(item => item.Database == "Auth").Sha256 ||
                !ReviewedProductionRepairInventory.MatchesKeys(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(comparison), databases.Select(item => item.Database)) ||
                databases.Any(item => !policy.BeforeDatabaseSha256.TryGetValue(item.Database, out string? expected) || expected != item.Sha256) || databases.Length != policy.BeforeDatabaseSha256.Count)
            { throw Invalid(); }
            CurrentAuthLocalSessionArchivePolicy.RequireCatalogs(value.Catalogs, policy, comparison, databases.Select(item => item.Database), evidence.BeganAtUtc, evidence.CompletedAtUtc);
        }
        return evidence;
    }
    internal static byte[] Read(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact artifact, int maximum)
    { byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum); return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw Invalid(); }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}

public static partial class MigrationConsole
{
    // Publishes only after actual eighteen-case semantic readback. This adds no archive execution permit or persistent restore API.
    internal static async Task<CurrentAuthArchiveProofAssemblyResultV2> AssembleCurrentAuthArchiveProofV2Async(CurrentAppOwnedRepairCustody files,
        WindowsLocalRunAuthority authority, CurrentAuthArchiveObservedBatchV2 observed, CurrentAuthArchiveGeneratedCaseInputV2 input, CancellationToken ct)
    {
        files.Require(); authority.ValidateHeld();
        var pins = new CurrentAuthArchivePins(input.Signing.Pins.ReviewKeyId, input.Signing.Pins.ReviewFingerprint, input.Signing.Pins.AuthorizationKeyId,
            input.Signing.Pins.AuthorizationFingerprint, input.Signing.Pins.ReceiptKeyId, input.Signing.Pins.ReceiptFingerprint);
        ReceiptAttestationTrustStore trust; CurrentAuthArchiveClaim audienceClaim;
        var (Authority, Files) = CurrentAuthArchiveCaseCustodyV2.OpenQualified(input.QualifiedInputBinding, authority.Binding.ArtifactRootCanonicalPath);
        using (Authority)
        using (Files)
        {
            RequireDefinitionSigningInputs(Files, input.Signing);
            trust = new ReceiptAttestationTrustStore(input.Signing.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
                Files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
            audienceClaim = DecodeAuthRepair<CurrentAuthArchiveClaim>(CurrentAuthArchiveProofAssemblyV2.Read(Files, input.Audience, 65536));
        }
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveProofAudienceV2>(audienceClaim, CurrentAuthArchiveRecoveryV2.AudienceDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        if (observed.Kind != "current-auth-archive-actual-eighteen-observations-v2" || observed.PhaseProofComplete || observed.AudienceSha256 != input.Audience.Sha256 ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != audience.AcceptedCommitSha) { throw InvalidGenerated(); }
        var proof = new CurrentAuthArchiveProofV2("current-auth-archive-complete-eighteen-proof-v2", observed.BatchId, input.Audience.Sha256,
            audience.AcceptedCommitSha, audience.SourceIdentitySha256, audience.SourceDefinitionSha256, audience.CoreImageSha256, audience.ConsoleImageSha256,
            audience.TestsImageSha256, observed.BeganAtUtc, DateTimeOffset.UtcNow, audience.ExpiresAtUtc, observed.ActualCases);
        await CurrentAuthArchiveProofAssemblyV2.RequireCasesAsync(files, proof, audience, pins, trust, ct);
        string prefix = Path.Combine(authority.Binding.ArtifactRootCanonicalPath, "archive-proof-v2-" + observed.BatchId.ToString("N"));
        using var evidence = CreateSigner(input.Signing.EvidencePrivateKey, pins.EvidenceKeyId, pins.EvidenceFingerprint);
        byte[] proofBytes = JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveProofAssemblyV2.Domain, proof, evidence));
        string proofPath = prefix + ".json"; await files.WriteNewAsync(proofPath, proofBytes, ct);
        var proofArtifact = new CurrentAuthArchiveProofArtifact(proofPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(proofBytes));
        byte[] credential = ReadQualified(input.SourceCredential);
        CurrentReviewedCapture fresh;
        try { fresh = await CurrentReviewedCapture.CaptureAsync(Encoding.UTF8.GetString(credential), audience, ct); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(credential); }
        var intended = await CurrentAuthArchiveIntendedObservationRuntimeV2.ObserveAsync(input.Intended, fresh, audienceClaim, trust, pins, ct);
        string sourcePath = prefix + "-final-source.json"; byte[] sourceBytes = JsonSerializer.SerializeToUtf8Bytes(fresh.Evidence); await files.WriteNewAsync(sourcePath, sourceBytes, ct);
        var sourceArtifact = new CurrentAuthArchiveProofArtifact(sourcePath, CurrentAuthLocalSessionArchivePolicy.HashBytes(sourceBytes));
        var intendedArtifact = await CurrentAuthArchiveIntendedRetentionV2.RetainAsync(files, prefix + "-final-intended.json", intended.Evidence, ct);
        _ = await CurrentAuthArchiveProofAssemblyV2.RequireIntendedAsync(files, intendedArtifact, fresh.Evidence, audience, DateTimeOffset.UtcNow, ct);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var review = new CurrentAuthArchiveFinalIntendedReadbackV2("current-auth-archive-final-intended-readback-v2", proofArtifact.Sha256, input.Audience.Sha256,
            fresh.Evidence.FullPlanSha256, sourceArtifact, intendedArtifact, now, now.AddMinutes(2) < audience.ExpiresAtUtc ? now.AddMinutes(2) : audience.ExpiresAtUtc);
        using var reviewer = CreateSigner(input.Signing.ReviewPrivateKey, pins.ReviewKeyId, pins.ReviewFingerprint);
        byte[] reviewBytes = JsonSerializer.SerializeToUtf8Bytes(CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveProofAssemblyV2.IntendedDomain, review, reviewer));
        string reviewPath = prefix + "-final-readback.json"; await files.WriteNewAsync(reviewPath, reviewBytes, ct);
        var result = new CurrentAuthArchiveProofAssemblyResultV2(proofArtifact, new(reviewPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(reviewBytes)));
        var publishedInputs = CurrentAuthArchiveCaseCustodyV2.OpenQualified(input.QualifiedInputBinding, authority.Binding.ArtifactRootCanonicalPath);
        string audiencePath = prefix + "-audience.json";
        using (publishedInputs.Authority)
        using (publishedInputs.Files)
        {
            // Audience bytes are independently authenticated in their own root; the final reader receives a direct-parent immutable copy.
            byte[] bytes = CurrentAuthArchiveProofAssemblyV2.Read(publishedInputs.Files, input.Audience, 65536);
            await files.WriteNewAsync(audiencePath, bytes, ct);
        }
        await CurrentAuthArchiveProofAssemblyV2.RequirePublishedAsync(files, result, new(audiencePath, input.Audience.Sha256), pins, trust, ct);
        return result;
        P256MigrationEvidenceSigner CreateSigner(CurrentAuthArchiveProofArtifact artifact, string keyId, string expected)
        {
            byte[] bytes = ReadQualified(artifact);
            try
            {
                var signer = new P256MigrationEvidenceSigner(keyId, Encoding.UTF8.GetString(bytes));
                if (signer.PublicKeyFingerprintSha256 == expected) { return signer; }
                signer.Dispose(); throw InvalidGenerated();
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
        }
        byte[] ReadQualified(CurrentAuthArchiveProofArtifact artifact)
        {
            var held = CurrentAuthArchiveCaseCustodyV2.OpenQualified(input.QualifiedInputBinding, authority.Binding.ArtifactRootCanonicalPath);
            using (held.Authority)
            using (held.Files) { return CurrentAuthArchiveProofAssemblyV2.Read(held.Files, artifact, 65536); }
        }
    }
}
