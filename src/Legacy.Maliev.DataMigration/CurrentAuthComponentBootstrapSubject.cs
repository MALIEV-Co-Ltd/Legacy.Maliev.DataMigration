using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

// A definition precursor may authorize only the isolated synthetic component fixture, never a closed Console target.
internal sealed record CurrentAuthComponentBootstrapSeed(string Kind, string AcceptedSourceCommitSha,
    string AcceptedSourceSchemaPlanSha256, string AuthOwnerCommitSha, string OwnerPinsSha256, string ClosureSha256,
    string DefinitionPrecursorSha256, string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256,
    string ParentRunBindingSha256, DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);
internal sealed record CurrentAuthComponentBootstrapSubject(string Kind, CurrentAuthComponentBootstrapSeed Seed,
    string CaseSourceEvidenceKind, string CaseSourceSchemaPlanSha256, string CaseRunBindingSha256,
    string ContainerId, string ContainerName, string AnonymousVolumeName, string ActualImageId, string PgData,
    string ActualTargetGeneration, string NativeBeforeSha256, string ContainerObservationSha256, string VolumeObservationSha256);

internal static class CurrentAuthComponentBootstrap
{
    internal static byte[] SeedPayload(CurrentAuthComponentBootstrapSeed value)
    {
        return [.. "Legacy.Maliev.CurrentAuth.ComponentBootstrapSeed.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(value with { Signature = null })];
    }

    internal static string SubjectSha256(CurrentAuthComponentBootstrapSubject value)
    {
        return CurrentAppOwnedSnapshotSerialization.Sha256(new
        { Domain = "Legacy.Maliev.CurrentAuth.ComponentBootstrapSubject.v1", Subject = value });
    }

    internal static void RequireSeed(CurrentAuthComponentBootstrapSeed seed, IReceiptAttestationTrustStore trust,
        string expectedKeyId, string expectedFingerprint, DateTimeOffset now)
    {
        if (seed.Kind != "current-auth-genuine-definition-component-seed-v1" || seed.KeyId != expectedKeyId ||
            !trust.TryGetPublicKeyFingerprintSha256(seed.KeyId, out string fingerprint) || fingerprint != expectedFingerprint ||
            seed.AcceptedSourceCommitSha.Length != 40 || seed.AcceptedSourceCommitSha.Any(x => x is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')) ||
            !CurrentAuthRepairPermit.HashShape(seed.AcceptedSourceSchemaPlanSha256) || seed.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit ||
            seed.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 || seed.ClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
            new[] { seed.DefinitionPrecursorSha256, seed.TestAssemblySha256, seed.ConsoleAssemblySha256, seed.CoreAssemblySha256, seed.ParentRunBindingSha256 }.Any(x => !CurrentAuthRepairPermit.HashShape(x)) ||
            seed.IssuedAtUtc.Offset != TimeSpan.Zero || seed.ExpiresAtUtc.Offset != TimeSpan.Zero || seed.IssuedAtUtc > now || seed.ExpiresAtUtc <= now ||
            seed.ExpiresAtUtc - seed.IssuedAtUtc > TimeSpan.FromHours(2) || seed.ExpiresAtUtc <= seed.IssuedAtUtc || string.IsNullOrWhiteSpace(seed.Signature) ||
            !trust.Verify(seed.KeyId, SeedPayload(seed), Convert.FromBase64String(seed.Signature))) { throw CurrentAuthRepairPermit.Invalid(); }
    }
    internal static void RequireSubject(CurrentAuthRepairScope scope, FreshSchemaPlan source, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        var subject = scope.ComponentSubject ?? throw CurrentAuthRepairPermit.Invalid();
        if (!scope.BeforeDatabaseSha256.TryGetValue("Auth", out string? authBefore)) { throw CurrentAuthRepairPermit.Invalid(); }
        if (!trust.TryGetPublicKeyFingerprintSha256(subject.Seed.KeyId, out string fingerprint)) { throw CurrentAuthRepairPermit.Invalid(); }
        RequireSeed(subject.Seed, trust, subject.Seed.KeyId, fingerprint, now);
        if (scope.ProofAdmission != CurrentAuthProofAdmission.DisposableNativeComponent ||
            subject.Kind != "current-auth-actual-anonymous-component-subject-v1" ||
            subject.CaseSourceEvidenceKind != "generated-synthetic-schema-physically-observed-not-accepted-source-capture" ||
            scope.SourceCommitSha != subject.Seed.AcceptedSourceCommitSha || source.SourceCommitSha != subject.Seed.AcceptedSourceCommitSha ||
            subject.CaseSourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) ||
            scope.RunBindingSha256 != subject.CaseRunBindingSha256 || !CurrentAuthRepairPermit.HashShape(subject.CaseRunBindingSha256) ||
            subject.ContainerId.Length != 64 || subject.ContainerId.Any(x => x is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')) ||
            subject.ContainerName.Length != "auth-guarded-provider-".Length + 32 || !subject.ContainerName.StartsWith("auth-guarded-provider-", StringComparison.Ordinal) ||
            !Guid.TryParseExact(subject.ContainerName["auth-guarded-provider-".Length..], "N", out _) ||
            subject.AnonymousVolumeName.Length != 64 || subject.AnonymousVolumeName.Any(x => x is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')) ||
            !subject.ActualImageId.StartsWith("sha256:", StringComparison.Ordinal) || !CurrentAuthRepairPermit.HashShape(subject.ActualImageId[7..]) ||
            subject.PgData != "/var/lib/postgresql/18/docker" || subject.ActualTargetGeneration != scope.TargetGeneration ||
            subject.NativeBeforeSha256 != authBefore ||
            new[] { subject.ContainerObservationSha256, subject.VolumeObservationSha256 }.Any(x => !CurrentAuthRepairPermit.HashShape(x)) ||
            scope.TargetObservationSha256 != subject.ContainerObservationSha256 ||
            scope.AuthHelperProofSha256 != subject.Seed.DefinitionPrecursorSha256 ||
            scope.OperationSha256 != SubjectSha256(subject) || scope.NativeProofSha256.Length != 0 ||
            scope.RecoveryReviewSha256.Length != 0 || scope.ExactRoleTransitionReviewSha256.Length != 0 ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target)) { throw CurrentAuthRepairPermit.Invalid(); }
    }
}
