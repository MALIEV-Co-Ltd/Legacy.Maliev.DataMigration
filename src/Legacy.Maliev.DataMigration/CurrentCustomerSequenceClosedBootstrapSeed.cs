using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

// This separate signed mode binds completed component evidence to one genuinely owned
// named disposable Console case. No component report is renamed as closed evidence.
internal sealed record CurrentCustomerSequenceClosedSeed(string Kind, Guid OperationId, string CaseId,
    string SourceCommitSha, string SourceSchemaPlanSha256, string CatalogReportSha256,
    string OwnerHead, string OwnerContextSha256, string OwnerSnapshotSha256, string DefinitionSha256,
    string DefinitionPrecursorSha256, string NativeComponentSha256, string MaintenanceComponentSha256,
    string PrecursorSubjectSha256, string NativeBeforeStateSha256, string CustomerBeforeSha256,
    string RunBindingSha256, string TargetObservationSha256, string TargetGeneration, string FleetBeforeSha256,
    string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);

internal static class CurrentCustomerSequenceClosedBootstrap
{
    internal static IReadOnlyList<string> Cases { get; } = Array.AsReadOnly(["success", "prepared-publication", "lost-commit-ack", "terminal-publication",
        "host-unprobed-sdk", "local-ordinary-trust", "final-fleet", "replay"]);
    internal static byte[] Payload(CurrentCustomerSequenceClosedSeed seed)
    {
        return [.. Encoding.UTF8.GetBytes("Legacy.Maliev.CurrentCustomerSequence.NamedClosedConsoleSeed.v1\0"),
            .. JsonSerializer.SerializeToUtf8Bytes(seed with { Signature = null })];
    }

    internal static void RequireBinding(CurrentCustomerSequenceClosedSeed seed, CurrentCustomerSequenceRepairScope scope)
    {
        RequireNamedTarget(scope.Target);
        if (seed.Kind != "current-customer-sequence-named-closed-console-seed-v1" || !Cases.Contains(seed.CaseId, StringComparer.Ordinal) ||
            scope.ProofAdmission != CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap || scope.BootstrapSubject is not null ||
            scope.ClosedConsoleSeed != seed || scope.OperationId == Guid.Empty || scope.OperationId != seed.OperationId ||
            scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) ||
            DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target) ||
            scope.TargetNamespace != "local-aspire" || scope.TargetCluster != "legacy-postgres-main-local" ||
            scope.SourceCommitSha != seed.SourceCommitSha || scope.SourceSchemaPlanSha256 != seed.SourceSchemaPlanSha256 ||
            scope.CatalogReportSha256 != seed.CatalogReportSha256 || scope.OwnerObservation.Head != seed.OwnerHead ||
            scope.OwnerObservation.ContextSha256 != seed.OwnerContextSha256 || scope.OwnerObservation.SnapshotSha256 != seed.OwnerSnapshotSha256 ||
            seed.OwnerHead != ApprovedCurrentCustomerSequenceDefinition.CustomerOwnerHead ||
            seed.OwnerContextSha256 != ApprovedCurrentCustomerSequenceDefinition.ContextSha256 || seed.OwnerSnapshotSha256 != ApprovedCurrentCustomerSequenceDefinition.OwnerSnapshotSha256 ||
            scope.DefinitionSha256 != seed.DefinitionSha256 || scope.DefinitionProofSha256 != seed.DefinitionPrecursorSha256 ||
            scope.NativeProofSha256 != seed.NativeComponentSha256 || scope.MaintenanceProofSha256 != seed.MaintenanceComponentSha256 ||
            scope.RecoveryReviewSha256 != string.Empty || scope.ExactRoleTransitionReviewSha256 != string.Empty ||
            scope.NativeBeforeStateSha256 != seed.NativeBeforeStateSha256 || scope.RunBindingSha256 != seed.RunBindingSha256 ||
            scope.TargetObservationSha256 != seed.TargetObservationSha256 || scope.TargetGeneration != seed.TargetGeneration ||
            scope.GlobalPreservationSha256 != seed.FleetBeforeSha256 || !scope.BeforeDatabaseSha256.TryGetValue("Customer", out string? customer) || customer != seed.CustomerBeforeSha256 ||
            !scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).Order(StringComparer.Ordinal)) ||
            scope.Maintenance.ExpiresAtUtc > seed.ExpiresAtUtc ||
            new[] { seed.DefinitionPrecursorSha256, seed.NativeComponentSha256, seed.MaintenanceComponentSha256 }.Distinct(StringComparer.Ordinal).Count() != 3 ||
            new[] { seed.SourceSchemaPlanSha256, seed.CatalogReportSha256, seed.DefinitionSha256, seed.DefinitionPrecursorSha256,
                seed.NativeComponentSha256, seed.MaintenanceComponentSha256, seed.PrecursorSubjectSha256, seed.NativeBeforeStateSha256,
                seed.CustomerBeforeSha256, seed.RunBindingSha256, seed.TargetObservationSha256, seed.FleetBeforeSha256,
                seed.TestAssemblySha256, seed.ConsoleAssemblySha256, seed.CoreAssemblySha256 }.Any(x => !CurrentCustomerSequenceRepairPermit.HashShape(x)))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        // OperationSha256 remains the original fixed START definition digest; it does not
        // depend on this seed's digest/signature, so no first-proof hash cycle is introduced.
    }
    internal static void RequireNamedTarget(DeltaTargetAuthority target)
    {
        if (target.Kind != DeltaTargetAuthorityKind.LocalAspire || !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(target) ||
            DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(target)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    internal static void Require(CurrentCustomerSequenceClosedSeed seed, CurrentCustomerSequenceRepairScope scope,
        IReceiptAttestationTrustStore trust, string key, string fingerprint, DateTimeOffset now, bool requireSignature = true)
    {
        RequireBinding(seed, scope);
        if (now.Offset != TimeSpan.Zero || seed.IssuedAtUtc.Offset != TimeSpan.Zero || seed.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            seed.IssuedAtUtc > now || seed.ExpiresAtUtc <= now || seed.ExpiresAtUtc <= seed.IssuedAtUtc ||
            seed.ExpiresAtUtc - seed.IssuedAtUtc > TimeSpan.FromMinutes(8) || seed.KeyId != key ||
            !trust.TryGetPublicKeyFingerprintSha256(key, out string actual) || actual != fingerprint)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        if (!requireSignature)
        { if (seed.Signature is not null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); } return; }
        try
        {
            if (seed.Signature is null || !trust.Verify(key, Payload(seed), Convert.FromBase64String(seed.Signature)))
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        catch (FormatException) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
}
