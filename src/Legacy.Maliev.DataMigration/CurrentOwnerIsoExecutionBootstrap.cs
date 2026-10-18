using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentOwnerIsoExecutionBootstrap(string Kind, string CaseId,
    CurrentOwnerIsoComponentSubjectClaim Claim, string BootstrapKeyId, string BootstrapFingerprint,
    string TargetGeneration, string CountryNativeBeforeSha256, string MaterialNativeBeforeSha256,
    string FleetBeforeSha256, string SourceCanonicalSha256,
    string? ComponentNativeSha256 = null, string? ComponentMaintenanceSha256 = null,
    string? PrecursorSubjectSha256 = null, string? NamedVolume = null, string? ContainerId = null,
    string? ContainerName = null, int? LoopbackPort = null, CurrentOwnerIsoClosedPrecursorPins? ClosedPrecursorPins = null,
    DateTimeOffset? NamedCreatedAtUtc = null, DateTimeOffset? NamedVolumeCreatedAtUtc = null, DateTimeOffset? NamedLeaseExpiresAtUtc = null);

internal static class CurrentOwnerIsoExecutionBootstrapValidator
{
    internal static void Require(CurrentOwnerIsoExecutionBootstrap value, CurrentOwnerIsoRepairScope scope,
        FreshSchemaPlan source, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        CurrentOwnerIsoBootstrapSubjectValidator.Require(value.Claim, trust, value.BootstrapKeyId,
            value.BootstrapFingerprint, now);
        var subject = value.Claim.Subject;
        bool closed = scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap;
        if (scope.ProofAdmission is not (CurrentOwnerIsoProofAdmission.DisposableNativeComponent or CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap) ||
            value.Kind != (closed ? "current-owner-iso-closed-bootstrap-v1" : "current-owner-iso-component-bootstrap-v1") ||
            value.CaseId is not ("complete" or "prepared-publication" or "lost-commit-ack" or "terminal-publication" or
                "wrong-owner" or "fleet-drift" or "unsafe-host" or "local-trust" or "ordinary-all26" or "exclusive-policy" or "replay") ||
            scope.OperationId != subject.RunId || scope.SourceCommitSha != subject.SourceCommitSha ||
            scope.SourceCommitSha != source.SourceCommitSha || scope.SourceCatalogSha256 != subject.SourceCatalogSha256 ||
            scope.BeforeSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(source) ||
            value.SourceCanonicalSha256 != scope.BeforeSchemaPlanSha256 || subject.SourceSchemaPlanSha256 != value.SourceCanonicalSha256 || scope.OwnerSourcesSha256 != subject.OwnerSourcesSha256 ||
            scope.ContractSha256 != subject.ContractSha256 || scope.OperationSha256 != subject.FixedOperationSha256 ||
            JsonSerializer.Serialize(scope.Target) != JsonSerializer.Serialize(subject.IntendedTarget) ||
            scope.TargetObservationSha256 != subject.TargetObservationSha256 || scope.RunBindingSha256 != subject.RunBindingSha256 ||
            scope.TargetGeneration != value.TargetGeneration || string.IsNullOrWhiteSpace(value.TargetGeneration) ||
            scope.GlobalPreservationSha256 != value.FleetBeforeSha256 || scope.BeforeDatabaseSha256.Count != 26 ||
            !scope.BeforeDatabaseSha256.TryGetValue("Country", out string? country) || country != value.CountryNativeBeforeSha256 ||
            !scope.BeforeDatabaseSha256.TryGetValue("Material", out string? material) || material != value.MaterialNativeBeforeSha256 ||
            scope.Maintenance.ExpiresAtUtc > subject.ExpiresAtUtc) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        if (!closed)
        {
            if (scope.NativeProofSha256.Length != 0 || scope.MaintenanceProofSha256.Length != 0 || scope.RecoveryReviewSha256.Length != 0 ||
                scope.ExactRoleTransitionReviewSha256.Length != 0 || value.ComponentNativeSha256 is not null || value.ComponentMaintenanceSha256 is not null ||
                value.PrecursorSubjectSha256 is not null || value.NamedVolume is not null || value.ContainerId is not null || value.ContainerName is not null || value.LoopbackPort is not null || value.ClosedPrecursorPins is not null || value.NamedCreatedAtUtc is not null || value.NamedVolumeCreatedAtUtc is not null || value.NamedLeaseExpiresAtUtc is not null)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        }
        else if (value.NamedCreatedAtUtc is not { } created || value.NamedVolumeCreatedAtUtc is not { } volumeCreated || value.NamedLeaseExpiresAtUtc is not { } lease ||
            created.Offset != TimeSpan.Zero || volumeCreated.Offset != TimeSpan.Zero || lease.Offset != TimeSpan.Zero ||
            volumeCreated > created || created > now || lease <= now || lease <= created || lease - volumeCreated > TimeSpan.FromMinutes(8) || scope.Maintenance.ExpiresAtUtc > lease ||
            value.ClosedPrecursorPins is not { } pins || !CurrentAppOwnedRepairPermit.HashShape(pins.RootBindingSha256) ||
            !CurrentAppOwnedRepairPermit.HashShape(pins.DefinitionSubjectSha256) || !CurrentAppOwnedRepairPermit.HashShape(pins.DefinitionProofSha256) ||
            pins.DefinitionProofSha256 != subject.DefinitionPrecursorSha256 || value.PrecursorSubjectSha256 != pins.DefinitionSubjectSha256 ||
            string.IsNullOrWhiteSpace(pins.ProofKeyId) || string.IsNullOrWhiteSpace(pins.DefinitionKeyId) ||
            !CurrentAppOwnedRepairPermit.HashShape(pins.ProofFingerprint) || !CurrentAppOwnedRepairPermit.HashShape(pins.DefinitionFingerprint) ||
            !CurrentAppOwnedRepairPermit.HashShape(value.ComponentNativeSha256 ?? string.Empty) ||
            !CurrentAppOwnedRepairPermit.HashShape(value.ComponentMaintenanceSha256 ?? string.Empty) ||
            !CurrentAppOwnedRepairPermit.HashShape(value.PrecursorSubjectSha256 ?? string.Empty) ||
            value.ComponentNativeSha256 == value.ComponentMaintenanceSha256 || scope.NativeProofSha256 != value.ComponentNativeSha256 ||
            scope.MaintenanceProofSha256 != value.ComponentMaintenanceSha256 || scope.RecoveryReviewSha256.Length != 0 || scope.ExactRoleTransitionReviewSha256.Length != 0 ||
            value.ContainerId is not { Length: 64 } || !value.ContainerId.All(char.IsAsciiHexDigitLower) || value.LoopbackPort is not (>= 1 and <= 65535) ||
            value.ContainerName != "iso-closed-bootstrap-" + subject.RunId.ToString("N") || value.NamedVolume != "iso-closed-bootstrap-data-" + subject.RunId.ToString("N"))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
}
