using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

// Proposed enum3 is reserved for the actual named disposable closed Console fixture.
// This seed references completed genuine component artifacts; it never substitutes them for closed proof.
internal sealed record CurrentAuthClosedBootstrapSeed(string Kind, Guid OperationId, string CaseId,
    string SourceCommitSha, string SourceSchemaPlanSha256, string AuthOwnerCommitSha, string OwnerPinsSha256,
    string ClosureSha256, string DefinitionPrecursorSha256, string NativeComponentSha256,
    string RecoveryComponentSha256, string MaintenanceComponentSha256, string PrecursorSubjectSha256,
    string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256,
    string RunBindingSha256, string TargetObservationSha256, string TargetGeneration,
    string NativeBeforeSha256, string FleetBeforeSha256, DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);

internal static class CurrentAuthClosedBootstrap
{
    internal static byte[] Payload(CurrentAuthClosedBootstrapSeed seed)
    {
        return [.. Encoding.UTF8.GetBytes("Legacy.Maliev.CurrentAuth.NamedClosedBootstrapSeed.v1\0"),
            .. JsonSerializer.SerializeToUtf8Bytes(seed with { Signature = null })];
    }

    internal static string SubjectSha256(CurrentAuthClosedBootstrapSeed seed)
    {
        return CurrentAppOwnedSnapshotSerialization.Sha256(new
        { Domain = "Legacy.Maliev.CurrentAuth.NamedClosedBootstrapSubject.v1", Seed = seed with { Signature = null } });
    }

    internal static void RequireSeed(CurrentAuthClosedBootstrapSeed seed, IReceiptAttestationTrustStore trust,
        string expectedKey, string expectedFingerprint, DateTimeOffset now, bool requireSignature = true)
    {
        if (seed.Kind != "current-auth-genuine-named-closed-bootstrap-seed-v1" || seed.OperationId == Guid.Empty ||
            seed.CaseId is not ("success" or "prepared-publication" or "lost-commit-ack" or "terminal-publication" or
                "host-unprobed-sdk" or "local-ordinary-trust" or "final-fleet" or "replay") ||
            seed.SourceCommitSha.Length != 40 || seed.SourceCommitSha.Any(x => x is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')) ||
            seed.AuthOwnerCommitSha != ApprovedCurrentAuthSchema.AuthServiceCommit ||
            seed.OwnerPinsSha256 != CurrentAuthRepairPermit.OwnerPinsSha256 || seed.ClosureSha256 != ApprovedCurrentAuthSchema.ClosureSha256 ||
            new[] { seed.SourceSchemaPlanSha256, seed.DefinitionPrecursorSha256, seed.NativeComponentSha256,
                seed.RecoveryComponentSha256, seed.MaintenanceComponentSha256, seed.PrecursorSubjectSha256,
                seed.TestAssemblySha256, seed.ConsoleAssemblySha256, seed.CoreAssemblySha256, seed.RunBindingSha256,
                seed.TargetObservationSha256, seed.NativeBeforeSha256, seed.FleetBeforeSha256 }.Any(x => !CurrentAuthRepairPermit.HashShape(x)) ||
            string.IsNullOrWhiteSpace(seed.TargetGeneration) || seed.IssuedAtUtc.Offset != TimeSpan.Zero || seed.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            now.Offset != TimeSpan.Zero || seed.IssuedAtUtc > now || seed.ExpiresAtUtc <= now ||
            seed.ExpiresAtUtc <= seed.IssuedAtUtc || seed.ExpiresAtUtc - seed.IssuedAtUtc > TimeSpan.FromMinutes(8) ||
            seed.KeyId != expectedKey || !trust.TryGetPublicKeyFingerprintSha256(seed.KeyId, out string fingerprint) || fingerprint != expectedFingerprint ||
            (requireSignature && string.IsNullOrWhiteSpace(seed.Signature))) { throw CurrentAuthRepairPermit.Invalid(); }
        if (!requireSignature) { if (seed.Signature is not null) { throw CurrentAuthRepairPermit.Invalid(); } return; }
        string signature = seed.Signature ?? throw CurrentAuthRepairPermit.Invalid();
        try
        {
            if (!trust.Verify(seed.KeyId, Payload(seed), Convert.FromBase64String(signature)))
            { throw CurrentAuthRepairPermit.Invalid(); }
        }
        catch (FormatException) { throw CurrentAuthRepairPermit.Invalid(); }
    }

    // Pure binding only. Actual completed precursor readback, named target observation, custody and
    // full26/native/source23 maintenance observation remain required by the fixed closed Console route.
    internal static void RequireScope(CurrentAuthClosedBootstrapSeed seed, CurrentAuthRepairScope scope,
        FreshSchemaPlan source, IReceiptAttestationTrustStore trust, string key, string fingerprint, DateTimeOffset now, bool requireSignature = true)
    {
        RequireSeed(seed, trust, key, fingerprint, now, requireSignature);
        if ((int)scope.ProofAdmission != 3 || scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) ||
            seed.OperationId != scope.OperationId || seed.SourceCommitSha != scope.SourceCommitSha ||
            seed.SourceCommitSha != source.SourceCommitSha || seed.SourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) ||
            seed.SourceSchemaPlanSha256 != scope.SourceSchemaPlanSha256 || seed.RunBindingSha256 != scope.RunBindingSha256 ||
            seed.TargetObservationSha256 != scope.TargetObservationSha256 || seed.TargetGeneration != scope.TargetGeneration ||
            !scope.BeforeDatabaseSha256.TryGetValue("Auth", out string? auth) || auth != seed.NativeBeforeSha256 ||
            scope.GlobalPreservationSha256 != seed.FleetBeforeSha256 || scope.BeforeDatabaseSha256.Count != 26 ||
            scope.AuthHelperProofSha256 != seed.DefinitionPrecursorSha256 || scope.NativeProofSha256 != seed.NativeComponentSha256 ||
            scope.RecoveryReviewSha256 != seed.RecoveryComponentSha256 || scope.ExactRoleTransitionReviewSha256 != seed.MaintenanceComponentSha256 ||
            scope.OperationSha256 != SubjectSha256(seed) || scope.Maintenance.ExpiresAtUtc > seed.ExpiresAtUtc)
        { throw CurrentAuthRepairPermit.Invalid(); }
    }
}
