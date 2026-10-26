using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthArchiveComponentBootstrapSeed(string Kind, Guid OperationId, string CaseId,
    string AcceptedSourceCommitSha, string SourceSchemaPlanSha256, string AuthOwnerCommitSha, string OwnerPinsSha256,
    string ClosureSha256, string DefinitionPrecursorSha256, string PrecursorSubjectSha256, string ParentRunBindingSha256,
    string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256, string SigningPinsSha256,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);
internal sealed record CurrentAuthArchiveComponentTargetSubject(string RunBindingSha256, string ContainerId,
    string ContainerName, string VolumeName, string ImageId, string PgData, string TargetGeneration,
    string TargetObservationSha256, string ContainerArtifactSha256, string VolumeArtifactSha256,
    string SystemIdentifierSha256, string FleetBeforeSha256, string AuthBeforeSha256, string CatalogsSha256, string InstalledPolicySha256);
internal sealed record CurrentAuthArchiveComponentBootstrapSubject(string Kind, CurrentAuthArchiveComponentBootstrapSeed Seed,
    CurrentAuthArchiveComponentTargetSubject Local, CurrentAuthArchiveComponentTargetSubject Comparison,
    string RecoveryDeviceProofSha256, string DeleteSetSha256, int DeleteCount,
    string ApplicationComparisonSha256, string RecoveryPathsSha256);

// Pure authentication/binding only. This does not read a precursor or observe a target, image or physical device.
internal static class CurrentAuthArchiveComponentBootstrap
{
    internal static byte[] SeedPayload(CurrentAuthArchiveComponentBootstrapSeed seed)
    {
        return [.. "Legacy.Maliev.CurrentAuth.ArchiveComponentBootstrapSeed.v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(seed with { Signature = null })];
    }

    internal static void RequireStructure(CurrentAuthArchiveScope scope, DateTimeOffset now)
    {
        var subject = scope.ComponentSubject ?? throw Invalid();
        var seed = subject.Seed ?? throw Invalid();
        if (scope.ProofAdmission != CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap ||
            subject.Kind != "current-auth-actual-paired-archive-component-subject-v1" ||
            seed.Kind != "current-auth-genuine-archive-component-seed-v1" || seed.OperationId != scope.OperationId ||
            seed.CaseId is not ("dual-durable-readback" or "first-only-recovery" or "second-only-recovery" or "key-corruption" or "cipher-corruption" or
                "complete" or "prepared-publication" or "commit-ack-lost" or "terminal-publication" or "host-unprobed-sdk" or "local-trust" or
                "exact-reviewed-delete" or "CAS-field-drift" or "private-journal-drift" or "sequence-drift" or "production-drift" or
                "first-only-decrypt-insert-readback" or "second-only-decrypt-insert-readback") ||
            seed.AcceptedSourceCommitSha != scope.LocalObservationPolicy.SourceCommitSha ||
            seed.SourceSchemaPlanSha256 != scope.LocalObservationPolicy.SourceSchemaPlanSha256 ||
            seed.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit || seed.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 ||
            seed.ClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
            new[] { seed.SourceSchemaPlanSha256, seed.DefinitionPrecursorSha256, seed.PrecursorSubjectSha256,
                seed.ParentRunBindingSha256, seed.TestAssemblySha256, seed.ConsoleAssemblySha256, seed.CoreAssemblySha256,
                seed.SigningPinsSha256 }.Any(x => !Hash(x)) ||
            seed.ParentRunBindingSha256 == scope.LocalObservationPolicy.RunBindingSha256 || seed.ParentRunBindingSha256 == scope.ProductionObservationPolicy.RunBindingSha256 ||
            now.Offset != TimeSpan.Zero || seed.IssuedAtUtc.Offset != TimeSpan.Zero || seed.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            seed.IssuedAtUtc > now || seed.IssuedAtUtc > scope.CapturedAtUtc || seed.ExpiresAtUtc <= now ||
            seed.ExpiresAtUtc < scope.ExpiresAtUtc || seed.ExpiresAtUtc <= seed.IssuedAtUtc || seed.ExpiresAtUtc - seed.IssuedAtUtc > TimeSpan.FromMinutes(8) ||
            subject.RecoveryDeviceProofSha256 != scope.RecoveryDeviceProofSha256 || subject.DeleteSetSha256 != scope.DeleteSetSha256 ||
            subject.DeleteCount != scope.DeleteCount || subject.ApplicationComparisonSha256 != scope.ApplicationComparisonSha256 ||
            subject.RecoveryPathsSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(scope.Paths)) { throw Invalid(); }
        RequireTarget(subject.Local, scope.LocalObservationPolicy, scope.OperationId, false);
        RequireTarget(subject.Comparison, scope.ProductionObservationPolicy, scope.OperationId, true);
        if (subject.Local.ContainerId == subject.Comparison.ContainerId || subject.Local.VolumeName == subject.Comparison.VolumeName ||
            subject.Local.SystemIdentifierSha256 == subject.Comparison.SystemIdentifierSha256) { throw Invalid(); }
    }

    internal static void RequireClaims(CurrentAuthArchiveScope scope, IReceiptAttestationTrustStore trust,
        CurrentAuthArchivePins pins, DateTimeOffset now)
    {
        CurrentAuthLocalSessionArchivePolicy.RequireScope(scope, now);
        if (new[] { pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.EvidenceFingerprint }.Any(x => !Hash(x)) ||
            new[] { pins.ReviewKeyId, pins.AuthorizationKeyId, pins.EvidenceKeyId }.Any(string.IsNullOrWhiteSpace)) { throw Invalid(); }
        CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
        var seed = scope.ComponentSubject!.Seed;
        if (seed.KeyId != pins.ReviewKeyId || seed.SigningPinsSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(pins) ||
            string.IsNullOrWhiteSpace(seed.Signature)) { throw Invalid(); }
        try
        {
            if (!trust.Verify(pins.ReviewKeyId, SeedPayload(seed), Convert.FromBase64String(seed.Signature))) { throw Invalid(); }
        }
        catch (FormatException) { throw Invalid(); }
    }

    // Only a fixed observer may supply observed; claimed fields must never be passed here as independently observed facts.
    internal static void RequireScope(CurrentAuthArchiveScope scope, CurrentAuthArchiveComponentBootstrapSubject observed,
        IReceiptAttestationTrustStore trust, CurrentAuthArchivePins pins, string acceptedSourceCommitSha,
        string sourceSchemaPlanSha256, string parentRunBindingSha256, string testImageSha256,
        string consoleImageSha256, string coreImageSha256, DateTimeOffset now)
    {
        RequireClaims(scope, trust, pins, now);
        var subject = scope.ComponentSubject!; var seed = subject.Seed;
        if (observed is null || subject != observed || seed.AcceptedSourceCommitSha != acceptedSourceCommitSha ||
            seed.SourceSchemaPlanSha256 != sourceSchemaPlanSha256 || seed.ParentRunBindingSha256 != parentRunBindingSha256 ||
            seed.TestAssemblySha256 != testImageSha256 || seed.ConsoleAssemblySha256 != consoleImageSha256 || seed.CoreAssemblySha256 != coreImageSha256)
        { throw Invalid(); }
    }

    private static void RequireTarget(CurrentAuthArchiveComponentTargetSubject target, CurrentAuthRepairScope policy, Guid operation, bool comparison)
    {
        string name = "legacy-delta-proof-" + operation.ToString("N") + (comparison ? "-comparison" : string.Empty);
        if (target is null || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(policy.Target) ||
            !Hash(target.ContainerId) || policy.Target.AuthorityId != "aspire://legacy-postgres-main-local/disposable-" + target.ContainerId[..12] ||
            target.ContainerName != name || target.VolumeName != name || target.PgData != "/var/lib/postgresql/18/docker" ||
            target.ImageId is null || !target.ImageId.StartsWith("sha256:", StringComparison.Ordinal) || !Hash(target.ImageId[7..]) ||
            target.RunBindingSha256 != policy.RunBindingSha256 || target.TargetGeneration != policy.TargetGeneration ||
            target.TargetObservationSha256 != policy.TargetObservationSha256 || target.SystemIdentifierSha256 != policy.Target.SystemIdentifierSha256 ||
            target.FleetBeforeSha256 != policy.GlobalPreservationSha256 || target.AuthBeforeSha256 != policy.BeforeDatabaseSha256["Auth"] ||
            new[] { target.RunBindingSha256, target.TargetObservationSha256, target.SystemIdentifierSha256, target.FleetBeforeSha256,
                target.AuthBeforeSha256, target.ContainerArtifactSha256, target.VolumeArtifactSha256, target.CatalogsSha256,
                target.InstalledPolicySha256 }.Any(x => !Hash(x))) { throw Invalid(); }
    }

    private static bool Hash(string? value) { return value is not null && CurrentAuthRepairPermit.HashShape(value); }
    private static MigrationExecutionException Invalid() { return CurrentAuthLocalSessionArchivePolicy.Invalid(); }
}
