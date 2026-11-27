using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveFinal6Proof(string Kind, Guid BatchId, string AudienceSha256,
    string SourceCommitSha, string SourceIdentitySha256, string ApprovedDefinitionSha256,
    string CoreImageSha256, string ConsoleImageSha256, string TestsImageSha256,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc, IReadOnlyList<CurrentAuthArchiveFinal6CaseRun> Cases);
internal sealed record CurrentAuthArchiveFinal6FinalReadback(string Kind, string ProofSha256, string AudienceSha256,
    string CurrentSourceFullSha256, CurrentAuthArchiveProofArtifact CurrentSourceCapture, CurrentAuthArchiveProofArtifact CurrentIntendedObservation,
    DateTimeOffset ObservedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentAuthArchiveFinal6ProofResult(CurrentAuthArchiveProofArtifact Proof, CurrentAuthArchiveProofArtifact FinalIntendedReadback);

internal static class CurrentAuthArchiveFinal6ProofAssembly
{
    internal const string Domain = "Legacy.Maliev.CurrentAuth.Final6.CompleteEighteenProof.v1";
    internal const string IntendedDomain = "Legacy.Maliev.CurrentAuth.Final6.FinalIntendedReadback.v1";
    internal const string Kind = "current-auth-archive-final6-complete-eighteen-proof-v1";

    internal static void RequireInventory(IReadOnlyList<CurrentAuthArchiveFinal6CaseRun> cases)
    {
        if (cases.Count != 18 || !cases.Select(value => value.Generated.Case).Order().SequenceEqual(Enum.GetValues<CurrentAuthArchiveProofCaseV2>().Order()) ||
            cases.Select(value => value.Generated.OperationId).Distinct().Count() != 18 || cases.Any(value => value.PhaseProofComplete)) { throw Invalid(); }
    }

    internal static async Task RequireCasesAsync(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveFinal6Proof proof,
        CurrentAuthArchiveClaim audienceClaim, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        RequireInventory(proof.Cases);
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(audienceClaim,
            CurrentAuthArchiveFinal6AudiencePolicy.Domain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        CurrentAuthArchiveFinal6AudiencePolicy.Require(audience, pins, DateTimeOffset.UtcNow);
        if (proof.Kind != Kind || proof.BatchId == Guid.Empty || proof.AudienceSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(audienceClaim) ||
            proof.SourceCommitSha != audience.AcceptedCommitSha || proof.SourceIdentitySha256 != audience.SourceIdentitySha256 ||
            proof.ApprovedDefinitionSha256 != audience.SourceDefinitionSha256 || proof.CoreImageSha256 != audience.CoreImageSha256 ||
            proof.ConsoleImageSha256 != audience.ConsoleImageSha256 || proof.TestsImageSha256 != audience.TestsImageSha256 ||
            proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            proof.BeganAtUtc < audience.IssuedAtUtc || proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > DateTimeOffset.UtcNow ||
            proof.ExpiresAtUtc <= DateTimeOffset.UtcNow || proof.ExpiresAtUtc > audience.ExpiresAtUtc ||
            proof.CoreImageSha256 != CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location) ||
            proof.ConsoleImageSha256 != CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location)) { throw Invalid(); }
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var run in proof.Cases)
        {
            ct.ThrowIfCancellationRequested(); CurrentAuthRepairCapacity.Require(admission: false);
            if (run.Generated.Audience.Sha256 != proof.AudienceSha256 || run.BeganAtUtc < proof.BeganAtUtc || run.CompletedAtUtc > proof.CompletedAtUtc) { throw Invalid(); }
            var facts = await CurrentAuthArchiveFinal6CaseReadback.RequireAsync(files, run, audienceClaim, pins, trust, ct);
            if (!ids.Add(facts.Scope.ComponentSubject!.Local.ContainerId) || !ids.Add(facts.Scope.ComponentSubject.Comparison.ContainerId)) { throw Invalid(); }
            using var roots = CurrentAuthArchiveFinal6CaseCustody.Open(files, run.Generated);
            var original = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveFinal6SourceEvidence>(roots.Read(run.Generated.SourceCapture, 32 * 1024 * 1024));
            var before = await RequireIntendedAsync(files, run.Generated.PreDefinitionIntendedObservation, original, audience, run.BeganAtUtc, ct);
            _ = await RequireIntendedAsync(roots.For(run.Generated.IntendedObservation.Path), run.Generated.IntendedObservation,
                original, audience, run.BeganAtUtc, ct);
            var packet = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveFinal6CaseInput>(roots.Read(run.Generated.Input, 65536));
            var intent = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveDefinitionAnchorIntent>(roots.Read(packet.DefinitionOwnerCopies.AnchorIntent, 2 * 1024 * 1024));
            using var absence = JsonDocument.Parse(roots.Read(packet.DefinitionOwnerCopies.Absence, 2 * 1024 * 1024));
            if (before.CompletedAtUtc > intent.BeganAtUtc || absence.RootElement.GetProperty("ObservedAtUtc").GetDateTimeOffset() > run.BeganAtUtc) { throw Invalid(); }
        }
    }

    internal static async Task RequirePublishedAsync(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveFinal6ProofResult artifacts,
        CurrentAuthArchiveProofArtifact audienceArtifact, CurrentAuthArchivePins pins, IReceiptAttestationTrustStore trust, CancellationToken ct)
    {
        files.Require(); CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        var audienceClaim = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(Read(files, audienceArtifact, 65536));
        var audience = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Audience>(audienceClaim,
            CurrentAuthArchiveFinal6AudiencePolicy.Domain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        var proof = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6Proof>(MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(Read(files, artifacts.Proof, 32 * 1024 * 1024)),
            Domain, pins.EvidenceKeyId, pins.EvidenceFingerprint, trust);
        if (proof.AudienceSha256 != audienceArtifact.Sha256 || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != audience.AcceptedCommitSha) { throw Invalid(); }
        await RequireCasesAsync(files, proof, audienceClaim, pins, trust, ct);
        var final = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6FinalReadback>(MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveClaim>(Read(files, artifacts.FinalIntendedReadback, 65536)),
            IntendedDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
        RequireFinalHeader(final, artifacts.Proof.Sha256, audienceArtifact.Sha256, proof.CompletedAtUtc, audience.ExpiresAtUtc, DateTimeOffset.UtcNow);
        var source = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveFinal6SourceEvidence>(Read(files, final.CurrentSourceCapture, 32 * 1024 * 1024));
        CurrentAuthArchiveFinal6Source.Require(source, audience.AcceptedCommitSha, audience.SourceIdentitySha256, audience.SourceDefinitionSha256, DateTimeOffset.UtcNow);
        if (source.Capture.FullPlanSha256 != final.CurrentSourceFullSha256 || source.Capture.BeganAtUtc < proof.CompletedAtUtc || source.Capture.CompletedAtUtc > final.ObservedAtUtc) { throw Invalid(); }
        _ = await RequireIntendedAsync(files, final.CurrentIntendedObservation, source, audience, final.ObservedAtUtc, ct); files.Require();
    }

    internal static void RequireFinalHeader(CurrentAuthArchiveFinal6FinalReadback final, string proof, string audience,
        DateTimeOffset proofCompleted, DateTimeOffset audienceExpiry, DateTimeOffset now)
    {
        if (final.Kind != "current-auth-archive-final6-final-intended-readback-v1" || final.ProofSha256 != proof || final.AudienceSha256 != audience ||
            final.ObservedAtUtc.Offset != TimeSpan.Zero || final.ExpiresAtUtc.Offset != TimeSpan.Zero || final.ObservedAtUtc < proofCompleted || final.ObservedAtUtc > now ||
            final.ExpiresAtUtc <= now || final.ExpiresAtUtc <= final.ObservedAtUtc || final.ExpiresAtUtc > final.ObservedAtUtc.AddMinutes(2) ||
            final.ExpiresAtUtc > audienceExpiry) { throw Invalid(); }
    }

    internal static async Task<CurrentAuthArchiveFinal6IntendedRetainedEvidence> RequireIntendedAsync(CurrentAppOwnedRepairCustody files,
        CurrentAuthArchiveProofArtifact artifact, CurrentAuthArchiveFinal6SourceEvidence source, CurrentAuthArchiveFinal6Audience audience,
        DateTimeOffset before, CancellationToken ct)
    {
        var evidence = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveFinal6IntendedRetainedEvidence>(Read(files, artifact, 1024 * 1024));
        if (evidence.Kind != "current-auth-archive-final6-intended-after-c-observation-v1" || evidence.SourceFullSha256 != source.Capture.FullPlanSha256 ||
            evidence.SourceIdentitySha256 != audience.SourceIdentitySha256 || evidence.SourceDefinitionSha256 != audience.SourceDefinitionSha256 ||
            evidence.LocalIdentitySha256 != audience.IntendedLocalIdentitySha256 || evidence.ComparisonIdentitySha256 != audience.IntendedComparisonIdentitySha256 ||
            CurrentAuthArchiveFinal6IntendedObservationRuntime.Identity(evidence.LocalPolicy) != evidence.LocalIdentitySha256 ||
            CurrentAuthArchiveFinal6IntendedObservationRuntime.Identity(evidence.ComparisonPolicy) != evidence.ComparisonIdentitySha256 ||
            evidence.LocalAuthRowsSha256 != audience.IntendedAuthRowsSha256 || evidence.LocalAuthRows != audience.IntendedAuthRows ||
            evidence.BeganAtUtc.Offset != TimeSpan.Zero || evidence.CompletedAtUtc.Offset != TimeSpan.Zero || evidence.BeganAtUtc < source.Capture.CompletedAtUtc ||
            evidence.BeganAtUtc > evidence.CompletedAtUtc || evidence.CompletedAtUtc > before) { throw Invalid(); }
        foreach (bool comparison in new[] { false, true })
        {
            var value = comparison ? evidence.Comparison : evidence.Local; var policy = comparison ? evidence.ComparisonPolicy : evidence.LocalPolicy;
            var databases = await CurrentAuthArchiveStreamedBaselineV2.ReadAsync(files, value.Databases, ct);
            var native = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveNativeCommitmentV2>(Read(files, new(value.Native.Path, value.Native.Sha256), 32 * 1024 * 1024)); native.Require();
            if (policy.SourceSchemaPlanSha256 != source.Capture.FullPlanSha256 || policy.SourceCommitSha != source.Capture.Plan.SourceCommitSha ||
                policy.AuthBeforeSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) || policy.AuthAfterSchemaSha256 != ApprovedCurrentAuthSchema.PhysicalSha256(true) ||
                native.Snapshot.Sha256 != databases.Single(item => item.Database == "Auth").Sha256 ||
                !ReviewedProductionRepairInventory.MatchesKeys(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(comparison), databases.Select(item => item.Database)) ||
                databases.Length != policy.BeforeDatabaseSha256.Count || databases.Any(item => !policy.BeforeDatabaseSha256.TryGetValue(item.Database, out string? expected) || expected != item.Sha256))
            { throw Invalid(); }
            CurrentAuthLocalSessionArchivePolicy.RequireCatalogs(value.Catalogs, policy, comparison, databases.Select(item => item.Database), evidence.BeganAtUtc, evidence.CompletedAtUtc);
        }
        return evidence;
    }
    internal static byte[] Read(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact artifact, int maximum)
    { byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum); return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw Invalid(); }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveFinal6Source.Invalid();
    }
}
