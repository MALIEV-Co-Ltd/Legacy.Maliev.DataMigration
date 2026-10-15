using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CustomerClosedEightEvidence(string BindingPath, string BindingSha256,
    CustomerClosedEightAcceptance Artifacts, string KeyId, string FingerprintSha256);

internal static class CurrentCustomerClosedEightConsumer
{
    // Header is pure and must run before observer/source/projection construction.
    // This validator creates no permit. All existing live source/native/HBA/full
    // fleet/custody/reservation and continuous budget checks remain mandatory.
    internal static void RequireScope(CustomerClosedEightReport proof, CurrentCustomerSequenceRepairScope scope)
    {
        var s = proof.IntendedSubject;
        if (scope.ProofAdmission != CurrentCustomerSequenceProofAdmission.PersistentWithClosedConsoleProof || scope.ClosedConsoleSeed is not null || scope.BootstrapSubject is not null ||
            scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !scope.Target.AuthorityId.StartsWith("aspire://legacy-postgres-main-local/persistent-", StringComparison.Ordinal) ||
            scope.SourceSchemaPlanSha256 != s.SourceSchemaPlanSha256 || scope.DefinitionSha256 != s.DefinitionSha256 ||
            scope.NativeBeforeStateSha256 != s.IntendedNativeBeforeStateSha256 || scope.TargetObservationSha256 != s.IntendedTargetObservationSha256 ||
            scope.RunBindingSha256 != s.IntendedRunBindingSha256 || scope.DefinitionProofSha256 != proof.CompletedComponents.Completed.Definition.Sha256 ||
            JsonSerializer.Serialize(scope.SourceObservation) != JsonSerializer.Serialize(s.Source) || JsonSerializer.Serialize(scope.OwnerObservation) != JsonSerializer.Serialize(s.Owner))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        // Production is deliberately unavailable here: genuine eighteen-one
        // compatibility and full production fleet proof are separate reviewed
        // requirements, never satisfied by this eighteen-four local fixture.
    }
    internal static async Task RequireAsync(CustomerClosedEightEvidence evidence, CurrentCustomerSequenceRepairScope scope,
        IReceiptAttestationTrustStore trust, CurrentCustomerSequenceRepairSigningPins pins, DateTimeOffset now, CancellationToken ct, bool initialAdmission = true)
    {
        CurrentCustomerSequenceCapacity.Require(admission: initialAdmission);
        if (string.IsNullOrWhiteSpace(evidence.KeyId) || !trust.TryGetPublicKeyFingerprintSha256(evidence.KeyId, out string actualFingerprint) || actualFingerprint != evidence.FingerprintSha256 ||
            evidence.KeyId == pins.ReviewKeyId || evidence.KeyId == pins.AuthorizationKeyId || evidence.KeyId == pins.ReceiptKeyId ||
            evidence.FingerprintSha256 == pins.ReviewFingerprint || evidence.FingerprintSha256 == pins.AuthorizationFingerprint || evidence.FingerprintSha256 == pins.ReceiptFingerprint ||
            evidence.Artifacts.Native.Sha256 != scope.NativeProofSha256 || evidence.Artifacts.Maintenance.Sha256 != scope.MaintenanceProofSha256 ||
            evidence.Artifacts.Recovery.Sha256 != scope.RecoveryReviewSha256 || evidence.Artifacts.RoleTransition.Sha256 != scope.ExactRoleTransitionReviewSha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var binding = CustomerClosedCompletedReadback.ReadProtected<LocalExecutionBinding>(evidence.BindingPath, 65536);
        if (binding.ComputeSha256() != evidence.BindingSha256 || binding.ComputeSha256() == scope.RunBindingSha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        CustomerClosedCompletedReadback.RequireExactBinding(files, evidence.BindingPath, binding);
        string? body = null;
        foreach (var pair in new[]{(evidence.Artifacts.Native,"native"),(evidence.Artifacts.Maintenance,"maintenance"),
            (evidence.Artifacts.Recovery,"recovery"),(evidence.Artifacts.RoleTransition,"role-transition")})
        {
            CurrentCustomerSequenceCapacity.Require(admission: false);
            byte[] bytes = files.Read(pair.Item1.Path, sharedReader: true, maximumBytes: 8_000_000);
            if (CurrentCustomerSequenceRepairPermit.Hash(bytes) != pair.Item1.Sha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            var report = CustomerClosedCompletedReadback.Decode<CustomerClosedEightReport>(bytes);
            CurrentCustomerClosedEightReadback.RequireHeader(report, pair.Item2, trust, evidence.KeyId, evidence.FingerprintSha256, now);
            RequireScope(report, scope);
            string observed = CurrentAppOwnedSnapshotSerialization.Sha256(report with { Purpose = "native", Signature = null });
            if (body is not null && body != observed) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            body = observed;
            await CurrentCustomerClosedEightReadback.RequireBodyAsync(files, report, now, ct).ConfigureAwait(false);
        }
        files.Require();
    }
}
