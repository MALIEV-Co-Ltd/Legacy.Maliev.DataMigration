using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class IsoExternalClosedReader
{
    internal static byte[] Payload(IsoIntendedClosedPhase phase)
    {
        return [.. "Legacy.Maliev.OwnerIso.IntendedClosedPhase.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(phase with { Signature = null })];
    }

    // No authority is obtained here. Real Console/Environment still observe target,
    // source, owners, full fleet, policy and immutable reservation before any effect.
    internal static async Task RequireAllAsync(CurrentAppOwnedRepairCustody runtimeFiles, LocalExecutionBinding runtimeBinding,
        CurrentOwnerIsoRepairScope runtime, CurrentOwnerIsoRepairSigningPins runtimePins, FreshSchemaPlan source,
        IReadOnlyList<CurrentOwnerIsoSourceObservation> owners, CurrentAppOwnedRepairArtifact native,
        CurrentAppOwnedRepairArtifact maintenance, IsoExternalClosedEvidence evidence, CancellationToken ct)
    {
        // Reject production18.1/full53 and every bootstrap BEFORE opening any root,
        // reading credentials or contacting a target.
        if (runtime.ProofAdmission != CurrentOwnerIsoProofAdmission.PersistentWithClosedConsoleProof || runtime.BootstrapSubject is not null || runtime.Target.Kind != DeltaTargetAuthorityKind.LocalAspire || !DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(runtime.Target) || runtime.BeforeDatabaseSha256.Count != 26 ||
            native.Sha256 != runtime.NativeProofSha256 || maintenance.Sha256 != runtime.MaintenanceProofSha256) { throw IsoIntendedRuntimeReader.Invalid(); }
        var intended = await IsoIntendedRuntimeReader.RequireHeldAsync(runtimeFiles, runtimeBinding, evidence.IntendedRuntime, source, owners, runtimePins, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        IsoIntendedRuntimeReader.RequireRuntime(intended, runtime);
        byte[] nativeBytes = runtimeFiles.Read(native.Path, sharedReader: true, maximumBytes: 8_000_000), maintenanceBytes = runtimeFiles.Read(maintenance.Path, sharedReader: true, maximumBytes: 8_000_000);
        if (CurrentAppOwnedRepairPermit.Hash(nativeBytes) != native.Sha256 || CurrentAppOwnedRepairPermit.Hash(maintenanceBytes) != maintenance.Sha256) { throw IsoIntendedRuntimeReader.Invalid(); }
        var binding = ReadBinding(evidence.ProofBindingPath);
        if (binding.ComputeSha256() == runtimeBinding.ComputeSha256() || StringComparer.OrdinalIgnoreCase.Equals(binding.ArtifactRootCanonicalPath, runtimeBinding.ArtifactRootCanonicalPath)) { throw IsoIntendedRuntimeReader.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var proofFiles = new CurrentAppOwnedRepairCustody(authority);
        if (MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(proofFiles.Read(evidence.ProofBindingPath, sharedReader: true, maximumBytes: 65536)) != binding) { throw IsoIntendedRuntimeReader.Invalid(); }
        var pins = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairSigningPins>(proofFiles.Read(evidence.ProofSigningPinsPath, sharedReader: true, maximumBytes: 65536));
        if (new[] { pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.ReceiptFingerprint }.Intersect(new[] { runtimePins.ReviewFingerprint, runtimePins.AuthorizationFingerprint, runtimePins.ReceiptFingerprint }, StringComparer.Ordinal).Any() ||
            new[] { pins.ReviewKeyId, pins.AuthorizationKeyId, pins.ReceiptKeyId }.Intersect(new[] { runtimePins.ReviewKeyId, runtimePins.AuthorizationKeyId, runtimePins.ReceiptKeyId }, StringComparer.Ordinal).Any()) { throw IsoIntendedRuntimeReader.Invalid(); }
        var trust = IsoIntendedRuntimeReader.Trust(proofFiles, evidence.ProofTrustedKeys, pins);
        var runs = new HashSet<Guid>();
        foreach (var pair in new[] { (IsoComponentProofPhase.Native, evidence.OriginalNativePhase, nativeBytes), (IsoComponentProofPhase.Maintenance, evidence.OriginalMaintenancePhase, maintenanceBytes) })
        {
            byte[] original = IsoIntendedRuntimeReader.Read(proofFiles, pair.Item2, 8_000_000);
            if (!original.AsSpan().SequenceEqual(pair.Item3)) { throw IsoIntendedRuntimeReader.Invalid(); }
            var phase = MigrationConsole.DecodeOwnerIso<IsoIntendedClosedPhase>(original);
            RequirePhase(phase, pair.Item1, evidence.IntendedRuntime.Observation.Sha256, intended.DefinitionPrecursorSha256, pins, trust, DateTimeOffset.UtcNow);
            var report = MigrationConsole.DecodeOwnerIso<IsoNamedClosedProof>(IsoIntendedRuntimeReader.Read(proofFiles, phase.CompletedNamedReport, 8_000_000));
            if (report.Phase != pair.Item1 || report.CompletedAtUtc > phase.CompletedAtUtc || phase.ExpiresAtUtc > report.ExpiresAtUtc) { throw IsoIntendedRuntimeReader.Invalid(); }
            await IsoNamedClosedProofReader.RequireAsync(proofFiles, report, intended.DefinitionSubject, trust, pins.ReviewKeyId, pins.ReviewFingerprint, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
            foreach (var item in report.Cases)
            {
                if (!runs.Add(item.OperationId)) { throw IsoIntendedRuntimeReader.Invalid(); }
                var config = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairConfiguration>(IsoIntendedRuntimeReader.Read(proofFiles, item.Configuration, 8_000_000));
                var scopeFile = item.Files.Single(x => x.SourcePath == config.ScopePath);
                var caseScope = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairScope>(IsoIntendedRuntimeReader.Read(proofFiles, scopeFile, 8_000_000));
                if (caseScope.ProofAdmission != CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap || caseScope.BootstrapSubject?.ClosedPrecursorPins?.DefinitionProofSha256 != intended.DefinitionPrecursorSha256 || caseScope.OperationId == runtime.OperationId || caseScope.RunBindingSha256 == runtime.RunBindingSha256) { throw IsoIntendedRuntimeReader.Invalid(); }
            }
        }
        if (runs.Count != 10) { throw IsoIntendedRuntimeReader.Invalid(); }
        proofFiles.Require(); runtimeFiles.Require();
    }
    internal static void RequirePhase(IsoIntendedClosedPhase phase, IsoComponentProofPhase expected, string intendedHash, string definitionHash,
        CurrentOwnerIsoRepairSigningPins pins, IReceiptAttestationTrustStore trust, DateTimeOffset now)
    {
        if (phase.Kind != "current-owner-iso-intended-closed-phase-v1" || phase.Phase != expected || phase.IntendedObservationSha256 != intendedHash || phase.DefinitionPrecursorSha256 != definitionHash || phase.KeyId != pins.ReviewKeyId || phase.CompletedAtUtc > now || phase.CompletedAtUtc.Offset != TimeSpan.Zero || phase.ExpiresAtUtc.Offset != TimeSpan.Zero || phase.ExpiresAtUtc <= now || phase.ExpiresAtUtc - phase.CompletedAtUtc > TimeSpan.FromHours(2) || string.IsNullOrWhiteSpace(phase.Signature)) { throw IsoIntendedRuntimeReader.Invalid(); }
        try { if (!trust.Verify(phase.KeyId, Payload(phase), Convert.FromBase64String(phase.Signature))) { throw IsoIntendedRuntimeReader.Invalid(); } } catch (FormatException) { throw IsoIntendedRuntimeReader.Invalid(); }
    }
    internal static async Task<IsoIntendedClosedPhase> SignCompletedPhaseAsync(CurrentAppOwnedRepairCustody proofFiles,
        IsoIntendedRuntimeObservation observed, string rawObservationSha256, IsoDefinitionArtifact actualNamedReport,
        IsoComponentProofPhase phase, CurrentOwnerIsoRepairSigningPins proofPins, IReceiptAttestationTrustStore proofTrust,
        P256MigrationEvidenceSigner signer, DateTimeOffset expires, CancellationToken ct)
    {
        if (signer.KeyId != proofPins.ReviewKeyId || signer.PublicKeyFingerprintSha256 != proofPins.ReviewFingerprint || !CurrentAppOwnedRepairPermit.HashShape(rawObservationSha256)) { throw IsoIntendedRuntimeReader.Invalid(); }
        var report = MigrationConsole.DecodeOwnerIso<IsoNamedClosedProof>(IsoIntendedRuntimeReader.Read(proofFiles, actualNamedReport, 8_000_000));
        if (report.Phase != phase || expires > report.ExpiresAtUtc || expires > observed.ExpiresAtUtc) { throw IsoIntendedRuntimeReader.Invalid(); }
        await IsoNamedClosedProofReader.RequireAsync(proofFiles, report, observed.DefinitionSubject, proofTrust, proofPins.ReviewKeyId, proofPins.ReviewFingerprint, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        var unsigned = new IsoIntendedClosedPhase("current-owner-iso-intended-closed-phase-v1", phase, rawObservationSha256, observed.DefinitionPrecursorSha256, actualNamedReport, DateTimeOffset.UtcNow, expires, signer.KeyId, null);
        return unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
    }
    private static LocalExecutionBinding ReadBinding(string path)
    { using var held = SecureLocalFile.OpenReadShared(path); if (held.Length is < 1 or > 65536) { throw IsoIntendedRuntimeReader.Invalid(); } byte[] bytes = new byte[(int)held.Length]; held.ReadExactly(bytes); return MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(bytes); }
}
