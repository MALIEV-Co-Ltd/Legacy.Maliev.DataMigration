using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

// Pins are held independently in the operational root. This is a proof consumer,
// not a provider, issuer, bootstrap permission or caller-supplied callback.
internal sealed record CurrentAuthNamedClosedExternalEvidence(string RunBindingPath,
    string SigningPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    CurrentAuthClosedBootstrapEvidence CompletedComponents);

internal static class CurrentAuthNamedClosedExternalReadback
{
    internal static async Task RequireAsync(CurrentAppOwnedRepairCustody operationalFiles,
        CurrentAppOwnedRepairArtifact artifact, string expected, string phase,
        CurrentAuthRepairScope runtime, CurrentAuthRepairSigningPins runtimePins,
        FreshSchemaPlan source, CurrentAuthNamedClosedExternalEvidence evidence, CancellationToken ct)
    {
        operationalFiles.Require();
        if (runtime.ProofAdmission != CurrentAuthProofAdmission.ClosedConsole || runtime.ClosedBootstrapSubject is not null ||
            runtime.ComponentSubject is not null || artifact.Sha256 != expected || phase is not ("helper" or "native" or "recovery" or "maintenance"))
        { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] retained = operationalFiles.Read(artifact.Path, sharedReader: true, maximumBytes: 4 * 1024 * 1024);
        if (CurrentAuthRepairPermit.Hash(retained) != expected) { throw CurrentAuthRepairPermit.Invalid(); }
        if (phase == "helper")
        {
            if (expected != evidence.CompletedComponents.Definition.Sha256 || runtime.AuthHelperProofSha256 != expected)
            { throw CurrentAuthRepairPermit.Invalid(); }
            var precursorBinding = CurrentAuthNamedClosedProofProducer.ReadBinding(evidence.CompletedComponents.PrecursorRunBindingPath);
            if (precursorBinding.ComputeSha256() == runtime.RunBindingSha256) { throw CurrentAuthRepairPermit.Invalid(); }
            await CurrentAuthClosedBootstrapReadback.RequireCompletedForHostAsync(evidence.CompletedComponents, source,
                evidence.CompletedComponents.Seed.TestAssemblySha256,
                CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location),
                CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location), ct).ConfigureAwait(false);
            using var precursorAuthority = WindowsLocalRunAuthority.AcquireResume(precursorBinding.ArtifactRootCanonicalPath, precursorBinding);
            using var precursorFiles = new CurrentAppOwnedRepairCustody(precursorAuthority);
            if (!precursorFiles.Read(evidence.CompletedComponents.Definition.Path, sharedReader: true, maximumBytes: 4 * 1024 * 1024).AsSpan().SequenceEqual(retained))
            { throw CurrentAuthRepairPermit.Invalid(); }
            operationalFiles.Require(); return;
        }
        var report = MigrationConsole.DecodeAuthRepair<CurrentAuthNamedClosedReport>(retained);
        if (report.Phase != phase) { throw CurrentAuthRepairPermit.Invalid(); }
        var binding = CurrentAuthNamedClosedProofProducer.ReadBinding(evidence.RunBindingPath);
        // Runtime lock and proof lock remain independent; neither root is relabelled.
        if (binding.ComputeSha256() == runtime.RunBindingSha256 ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(artifact.Path), binding.ArtifactRootCanonicalPath))
        { throw CurrentAuthRepairPermit.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        if (MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(files.Read(evidence.RunBindingPath, sharedReader: true, maximumBytes: 65536)) != binding ||
            !files.Read(Path.Combine(binding.ArtifactRootCanonicalPath, "auth-named-closed-" + phase + ".json"), sharedReader: true, maximumBytes: 4 * 1024 * 1024).AsSpan().SequenceEqual(retained))
        { throw CurrentAuthRepairPermit.Invalid(); }
        var pins = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairSigningPins>(files.Read(evidence.SigningPinsPath, sharedReader: true, maximumBytes: 65536));
        if (evidence.TrustedKeys.Count != 3 || evidence.TrustedKeys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != 3 ||
            new[] { pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.ReceiptFingerprint }.Distinct(StringComparer.Ordinal).Count() != 3 ||
            new[] { pins.ReviewFingerprint, pins.AuthorizationFingerprint, pins.ReceiptFingerprint }.Intersect(
                new[] { runtimePins.ReviewFingerprint, runtimePins.AuthorizationFingerprint, runtimePins.ReceiptFingerprint }, StringComparer.Ordinal).Any())
        { throw CurrentAuthRepairPermit.Invalid(); }
        var trust = new ReceiptAttestationTrustStore(evidence.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
            files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
        foreach ((string id, string pin) in new[] { (pins.ReviewKeyId, pins.ReviewFingerprint), (pins.AuthorizationKeyId, pins.AuthorizationFingerprint), (pins.ReceiptKeyId, pins.ReceiptFingerprint) })
        { if (!trust.TryGetPublicKeyFingerprintSha256(id, out string observed) || observed != pin) { throw CurrentAuthRepairPermit.Invalid(); } }
        await CurrentAuthNamedClosedProofReadback.RequireAsync(files, binding, report, runtime, source, pins, trust, requireSignature: true, operationalFiles, ct).ConfigureAwait(false);
        files.Require(); operationalFiles.Require();
        // The real Console subsequently repeats target/source/HBA/full-fleet observation
        // before any permit claim or target connection for DDL. This reader grants none.
    }
}
