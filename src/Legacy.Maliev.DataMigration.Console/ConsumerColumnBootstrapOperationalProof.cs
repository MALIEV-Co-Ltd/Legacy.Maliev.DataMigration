namespace Legacy.Maliev.DataMigration.Console;

internal sealed record ConsumerColumnBootstrapPreparationArtifact(string Kind, Guid OperationId, string LogicalSourcePlanSha256,
    string ContractSha256, string TargetObservationSha256, string RunBindingSha256, bool PreparationOnly, bool PersistentAdmission,
    DateTimeOffset ObservedAtUtc, DateTimeOffset ExpiresAtUtc, string? MaintenanceRole = null, string? OrdinaryRole = null);

/// <summary>Artifact custody; persistent evidence additionally requires the private actual-rehearsal acceptance.</summary>
internal static class ConsumerColumnBootstrapOperationalProof
{
    internal static void Require(CurrentAppOwnedRepairCustody files, ConsumerColumnBootstrapOperationalScope scope,
        CurrentAppOwnedRepairArtifact native, CurrentAppOwnedRepairArtifact recovery, CurrentAppOwnedRepairArtifact role,
        string ordinaryRole, DateTimeOffset now, ConsumerColumnBootstrapRehearsalAcceptance? rehearsal = null)
    {
        if (scope.Mode != ConsumerColumnBootstrapOperationalMode.PersistentReviewed)
        {
            if (rehearsal is not null) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            Check(native, scope.NativeCharacterizationSha256, "consumer-column-bootstrap-native-preparation-v1");
        }
        else
        {
            // Reading a report never creates acceptance. The token is minted only from the fixed
            // actual producer after independent native readback and verified resource absence.
            if (rehearsal is null || native.Sha256 != rehearsal.EvidenceSha256 || scope.NativeCharacterizationSha256 != rehearsal.EvidenceSha256 ||
                ConsumerColumnBootstrapOperationalContract.Hash(files.Read(native.Path, sharedReader: true, maximumBytes: 64 * 1024 * 1024)) != rehearsal.EvidenceSha256)
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        }
        if (scope.Mode != ConsumerColumnBootstrapOperationalMode.PersistentReviewed)
        {
            Check(recovery, scope.RecoveryReviewSha256, "consumer-column-bootstrap-recovery-preparation-v1");
            Check(role, scope.RoleTransitionReviewSha256, "consumer-column-bootstrap-role-preparation-v1");
        }
        else
        {
            Reference(recovery, scope.RecoveryReviewSha256); Reference(role, scope.RoleTransitionReviewSha256);
        }

        void Reference(CurrentAppOwnedRepairArtifact artifact, string expected)
        {
            // Existing review contracts require exact bytes/hash/custody only. This is a
            // metadata reference, never accepted restore or role-transition proof.
            if (artifact.Sha256 != expected || !ConsumerColumnBootstrapOperationalContract.IsHash(expected) ||
                ConsumerColumnBootstrapOperationalContract.Hash(files.Read(artifact.Path, sharedReader: true, maximumBytes: 12 * 1024 * 1024)) != expected)
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        }

        void Check(CurrentAppOwnedRepairArtifact artifact, string expected, string kind)
        {
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 65536);
            if (artifact.Sha256 != expected || ConsumerColumnBootstrapOperationalContract.Hash(bytes) != expected) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            var value = MigrationConsole.DecodeAuthRepair<ConsumerColumnBootstrapPreparationArtifact>(bytes);
            if (value.Kind != kind || value.OperationId != scope.OperationId || value.LogicalSourcePlanSha256 != scope.LogicalSourcePlanSha256 ||
                value.ContractSha256 != scope.ContractSha256 || value.TargetObservationSha256 != scope.TargetObservationSha256 || value.RunBindingSha256 != scope.RunBindingSha256 ||
                !value.PreparationOnly || value.PersistentAdmission || value.ObservedAtUtc.Offset != TimeSpan.Zero || value.ExpiresAtUtc.Offset != TimeSpan.Zero ||
                value.ObservedAtUtc > now || now - value.ObservedAtUtc > TimeSpan.FromHours(2) || value.ExpiresAtUtc <= now ||
                value.ExpiresAtUtc - value.ObservedAtUtc > TimeSpan.FromHours(4) ||
                (kind == "consumer-column-bootstrap-role-preparation-v1" && (value.MaintenanceRole != scope.Maintenance.Role || value.OrdinaryRole != ordinaryRole)))
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        }
    }
}
