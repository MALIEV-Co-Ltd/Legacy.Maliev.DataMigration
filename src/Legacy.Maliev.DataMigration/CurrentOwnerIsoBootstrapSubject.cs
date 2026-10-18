using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

// Distinct precursor subject deliberately excludes own Native/Maintenance proof hashes.
// It is not a CurrentOwnerIsoRepairScope and cannot be passed to the persistent issuer.
internal sealed record CurrentOwnerIsoComponentSubject(Guid RunId, string DefinitionPrecursorSha256,
    string SourceCommitSha, string SourceCatalogSha256, string SourceSchemaPlanSha256,
    string OwnerSourcesSha256, string ContractSha256, string FixedOperationSha256,
    DeltaTargetAuthority IntendedTarget, string TargetObservationSha256, string RunBindingSha256,
    string ConsoleAssemblySha256, string CoreAssemblySha256, string TestAssemblySha256,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc);
internal sealed record CurrentOwnerIsoClosedBootstrapSubject(CurrentOwnerIsoComponentSubject Intended,
    string ComponentNativeProofSha256, string ComponentMaintenanceProofSha256,
    string NamedDisposableVolume, string ContainerId, string ContainerName,
    string DockerImage, int LoopbackPort);
internal sealed record CurrentOwnerIsoComponentSubjectClaim(string Kind, CurrentOwnerIsoComponentSubject Subject,
    string KeyId, string? Signature);

internal static class CurrentOwnerIsoBootstrapSubjectValidator
{
    internal const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    internal static byte[] Payload(CurrentOwnerIsoComponentSubjectClaim value)
    {
        return [.. "Legacy.Maliev.OwnerIso.ComponentSubject.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(value with { Signature = null })];
    }

    internal static void Require(CurrentOwnerIsoComponentSubjectClaim value, IReceiptAttestationTrustStore trust,
        string keyId, string fingerprint, DateTimeOffset now)
    {
        if (value.Kind != "current-owner-iso-component-subject-v1" || value.KeyId != keyId || string.IsNullOrWhiteSpace(value.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(keyId, out string actual) || actual != fingerprint) { throw Invalid(); }
        try { if (!trust.Verify(keyId, Payload(value), Convert.FromBase64String(value.Signature))) { throw Invalid(); } }
        catch (FormatException) { throw Invalid(); }
        RequireSubject(value.Subject, now);
    }
    internal static void RequireSubject(CurrentOwnerIsoComponentSubject x, DateTimeOffset now)
    {
        if (x.RunId == Guid.Empty || x.SourceCommitSha.Length != 40 || !x.SourceCommitSha.All(char.IsAsciiHexDigitLower) ||
            x.FixedOperationSha256 != PostgreSqlCurrentOwnerIsoRepair.OperationSha256 ||
            x.IntendedTarget.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(x.IntendedTarget) ||
            DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(x.IntendedTarget) ||
            !new[] { x.DefinitionPrecursorSha256, x.SourceCatalogSha256, x.SourceSchemaPlanSha256, x.OwnerSourcesSha256,
                x.ContractSha256, x.TargetObservationSha256, x.RunBindingSha256, x.ConsoleAssemblySha256,
                x.CoreAssemblySha256, x.TestAssemblySha256 }.All(CurrentAppOwnedRepairPermit.HashShape) ||
            x.IssuedAtUtc.Offset != TimeSpan.Zero || x.ExpiresAtUtc.Offset != TimeSpan.Zero || x.IssuedAtUtc > now || x.ExpiresAtUtc <= now ||
            x.ExpiresAtUtc <= x.IssuedAtUtc || x.ExpiresAtUtc - x.IssuedAtUtc > TimeSpan.FromHours(4)) { throw Invalid(); }
    }
    internal static void RequireClosedSubject(CurrentOwnerIsoClosedBootstrapSubject x, DateTimeOffset now)
    {
        RequireSubject(x.Intended, now);
        if (!CurrentAppOwnedRepairPermit.HashShape(x.ComponentNativeProofSha256) ||
            !CurrentAppOwnedRepairPermit.HashShape(x.ComponentMaintenanceProofSha256) ||
            x.ComponentNativeProofSha256 == x.ComponentMaintenanceProofSha256 || x.DockerImage != Image ||
            x.ContainerId.Length != 64 || !x.ContainerId.All(char.IsAsciiHexDigitLower) || x.LoopbackPort is < 1 or > 65535 ||
            x.ContainerName != "iso-closed-bootstrap-" + x.Intended.RunId.ToString("N") ||
            x.NamedDisposableVolume != "iso-closed-bootstrap-data-" + x.Intended.RunId.ToString("N")) { throw Invalid(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return new("iso_bootstrap_subject_invalid",
        "A distinct actual disposable precursor subject is required; this grants no persistent authority.");
    }
}
