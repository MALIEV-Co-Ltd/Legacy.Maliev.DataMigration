using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

// Fixed named-disposable fixture configuration. It never signs a repair review or authorization;
// those claims must be produced by the real four public Console routes after custody is released.
internal static class CurrentAuthClosedConfiguration
{
    internal static async Task<string> WriteAsync(CurrentAppOwnedRepairCustody files, LocalExecutionBinding binding,
        CurrentAuthClosedTemplateCapture capture, FreshSchemaPlan source, string caseId,
        CurrentAuthClosedBootstrapEvidence completed, string precursorReviewPrivateKeyPath,
        string testAssemblyPath, CancellationToken ct)
    {
        files.Require(); CurrentAuthRepairCapacity.Require(admission: true);
        if (capture.State.BindingSha256 != binding.ComputeSha256() || capture.State.SourceCommitSha != source.SourceCommitSha ||
            capture.BeforeDatabaseSha256.Count != 26 || !capture.BeforeDatabaseSha256.ContainsKey("Auth") ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(completed.PrecursorRunBindingPath), binding.ArtifactRootCanonicalPath))
        { throw CurrentAuthRepairPermit.Invalid(); }
        string root = binding.ArtifactRootCanonicalPath, suffix = capture.State.OperationId.ToString("N");
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKeys = new[] { reviewKey, authorizationKey, receiptKey };
        string[] ids = ["auth-closed-review-" + suffix, "auth-closed-authorization-" + suffix, "auth-closed-receipt-" + suffix];
        string[] fingerprints = [.. privateKeys.Select(key => Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())))];
        if (fingerprints.Distinct(StringComparer.Ordinal).Count() != 3) { throw CurrentAuthRepairPermit.Invalid(); }
        var pins = new CurrentAuthRepairSigningPins(ids[0], fingerprints[0], ids[1], fingerprints[1], ids[2], fingerprints[2]);
        var trusted = new List<DeltaTrustedKeyReference>();
        for (int i = 0; i < 3; i++)
        {
            string publicPath = Path.Combine(root, ids[i] + ".public.txt"), privatePath = Path.Combine(root, ids[i] + ".private.pem");
            await files.WriteNewAsync(publicPath, Encoding.UTF8.GetBytes(Convert.ToBase64String(privateKeys[i].ExportSubjectPublicKeyInfo())), ct).ConfigureAwait(false);
            await files.WriteNewAsync(privatePath, Encoding.UTF8.GetBytes(privateKeys[i].ExportPkcs8PrivateKeyPem()), ct).ConfigureAwait(false);
            trusted.Add(new(ids[i], publicPath));
        }
        var seed = new CurrentAuthClosedBootstrapSeed("current-auth-genuine-named-closed-bootstrap-seed-v1", capture.State.OperationId, caseId,
            source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(source), ApprovedCurrentAuthSchema.AuthServiceCommit,
            CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256, completed.Definition.Sha256,
            completed.NativeComponent.Sha256, completed.RecoveryComponent.Sha256, completed.MaintenanceComponent.Sha256,
            completed.Seed.PrecursorSubjectSha256, CurrentAuthTypedHostProducer.ImageHash(testAssemblyPath),
            CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location),
            CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location), binding.ComputeSha256(),
            CurrentAppOwnedSnapshotSerialization.Sha256(capture.TargetPins), capture.State.TargetGeneration,
            capture.BeforeDatabaseSha256["Auth"], capture.FleetSha256, DateTimeOffset.UtcNow, capture.State.ExpiresAtUtc,
            completed.Seed.KeyId, null);
        var scope = new CurrentAuthRepairScope(capture.State.OperationId, CurrentAuthRepairOperation.SixteenSameTypeTextCollations,
            source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(source), ApprovedCurrentAuthSchema.AuthServiceCommit,
            CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256, ApprovedCurrentAuthSchema.PhysicalSha256(false),
            ApprovedCurrentAuthSchema.PhysicalSha256(true), CurrentAuthClosedBootstrap.SubjectSha256(seed), completed.Definition.Sha256,
            CurrentAuthRepairPermit.MaintenanceValidator, capture.Target, "local-aspire", "legacy-postgres-main-local",
            capture.State.TargetGeneration, CurrentAppOwnedSnapshotSerialization.Sha256(capture.TargetPins), binding.ComputeSha256(),
            capture.BeforeDatabaseSha256, capture.FleetSha256, completed.NativeComponent.Sha256, completed.RecoveryComponent.Sha256,
            completed.MaintenanceComponent.Sha256, capture.Maintenance, CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap, null, seed);
        var evidence = completed with { Seed = seed };
        // No supplied component summary is sufficient: authenticate all held real artifacts before signing.
        await CurrentAuthClosedBootstrapReadback.RequireUnsignedForProducerAsync(evidence, scope, source, ct).ConfigureAwait(false);
        using (var input = SecureLocalFile.OpenReadShared(completed.PrecursorRunBindingPath))
        {
            if (input.Length is < 1 or > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
            byte[] bytes = new byte[checked((int)input.Length)]; input.ReadExactly(bytes);
            var precursorBinding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bytes);
            using var authority = WindowsLocalRunAuthority.AcquireResume(precursorBinding.ArtifactRootCanonicalPath, precursorBinding);
            using var precursorFiles = new CurrentAppOwnedRepairCustody(authority);
            if (!precursorFiles.Read(completed.PrecursorRunBindingPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes))
            { throw CurrentAuthRepairPermit.Invalid(); }
            using var signer = new P256MigrationEvidenceSigner(seed.KeyId,
                Encoding.UTF8.GetString(precursorFiles.Read(precursorReviewPrivateKeyPath, sharedReader: true, maximumBytes: 65536)));
            var precursorPins = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairSigningPins>(precursorFiles.Read(completed.PrecursorSigningPinsPath,
                sharedReader: true, maximumBytes: 65536));
            if (signer.KeyId != precursorPins.ReviewKeyId || signer.PublicKeyFingerprintSha256 != precursorPins.ReviewFingerprint) { throw CurrentAuthRepairPermit.Invalid(); }
            seed = seed with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthClosedBootstrap.Payload(seed))) };
            string publicPath = Path.Combine(root, "precursor-review.public.txt");
            await files.WriteNewAsync(publicPath, Encoding.UTF8.GetBytes(Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo())), ct).ConfigureAwait(false);
            if (ids.Contains(seed.KeyId, StringComparer.Ordinal) || fingerprints.Contains(signer.PublicKeyFingerprintSha256, StringComparer.Ordinal))
            { throw CurrentAuthRepairPermit.Invalid(); }
            trusted.Add(new(seed.KeyId, publicPath));
        }
        scope = scope with { ClosedBootstrapSubject = seed }; evidence = evidence with { Seed = seed };
        await CurrentAuthClosedBootstrapReadback.RequireAsync(evidence, scope, source, ct).ConfigureAwait(false);
        string sourcePath = Path.Combine(root, "closed-source.json"), scopePath = Path.Combine(root, "closed-scope.json"),
            pinsPath = Path.Combine(root, "closed-signing-pins.json"), bindingPath = Path.Combine(root, "closed-binding.json"),
            targetPath = Path.Combine(root, "closed-target-pins.json"), configPath = Path.Combine(root, "closed-config.json");
        await Write(sourcePath, source).ConfigureAwait(false); await Write(scopePath, scope).ConfigureAwait(false);
        await Write(pinsPath, pins).ConfigureAwait(false); await Write(bindingPath, binding).ConfigureAwait(false); await Write(targetPath, capture.TargetPins).ConfigureAwait(false);
        var config = new CurrentAuthRepairConfiguration(sourcePath, scopePath, Path.Combine(root, "closed-review.json"), Path.Combine(root, "closed-authorization.json"),
            pinsPath, bindingPath, Path.Combine(root, "operator.txt"), Path.Combine(root, "ordinary.txt"), capture.BaselinePath, targetPath,
            trusted, Path.Combine(root, ids[2] + ".private.pem"), new(completed.Definition.Path, completed.Definition.Sha256),
            new(completed.NativeComponent.Path, completed.NativeComponent.Sha256), new(completed.RecoveryComponent.Path, completed.RecoveryComponent.Sha256),
            new(completed.MaintenanceComponent.Path, completed.MaintenanceComponent.Sha256), Path.Combine(root, ids[0] + ".private.pem"),
            Path.Combine(root, "closed-review.json"), seed.ExpiresAtUtc, Path.Combine(root, ids[1] + ".private.pem"),
            Path.Combine(root, "closed-authorization.json"), evidence);
        await Write(configPath, config).ConfigureAwait(false); files.Require(); return configPath;

        async Task Write<T>(string path, T value)
        {
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
            if (bytes.Length > 32 * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
            await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
            if (!files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024).AsSpan().SequenceEqual(bytes)) { throw CurrentAuthRepairPermit.Invalid(); }
        }
    }
}
