using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentCustomerClosedConfiguration
{
    internal static async Task<(string Path, CurrentCustomerSequenceRepairConfiguration Configuration, CurrentCustomerSequenceRepairScope Scope)> WriteAsync(
        CurrentAppOwnedRepairCustody files, LocalExecutionBinding binding, CurrentCustomerClosedTemplateCapture capture,
        FreshSchemaPlan source, CustomerClosedLaneInput input, string caseId, CancellationToken ct)
    {
        CustomerDefinitionSubject intended = CustomerClosedCompletedReadback.Require(input, DateTimeOffset.UtcNow);
        var inputBinding = CustomerClosedCompletedReadback.ReadProtected<LocalExecutionBinding>(input.InputBindingPath, 65536);
        var predecessorBinding = CustomerClosedCompletedReadback.ReadProtected<LocalExecutionBinding>(input.Completed.PrecursorBindingPath, 65536);
        if (inputBinding.ComputeSha256() != input.InputBindingSha256 || inputBinding.ComputeSha256() == binding.ComputeSha256() ||
            inputBinding.ComputeSha256() == predecessorBinding.ComputeSha256() || capture.State.BindingSha256 != binding.ComputeSha256() ||
            source.SourceCommitSha != intended.Source.CommitSha || SchemaPlanCanonicalizer.ComputeSha256(source) != intended.SourceSchemaPlanSha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        using var inputAuthority = WindowsLocalRunAuthority.AcquireResume(inputBinding.ArtifactRootCanonicalPath, inputBinding);
        using var inputFiles = new CurrentAppOwnedRepairCustody(inputAuthority);
        CustomerClosedCompletedReadback.RequireExactBinding(inputFiles, input.InputBindingPath, inputBinding);
        var heldSource = CustomerClosedCompletedReadback.Decode<FreshSchemaPlan>(inputFiles.Read(input.SourceSchemaPath, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
        if (SchemaPlanCanonicalizer.ComputeSha256(heldSource) != SchemaPlanCanonicalizer.ComputeSha256(source)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string root = binding.ArtifactRootCanonicalPath, suffix = capture.State.OperationId.ToString("N");
        string report = await Copy(input.SourceInputs.AcceptedCatalogReportPath, "source-catalog.json", 8_000_000).ConfigureAwait(false);
        if (CurrentCustomerSequenceRepairPermit.Hash(files.Read(report, sharedReader: true, maximumBytes: 8_000_000)) != intended.Source.CatalogReportSha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string sql = await Copy(input.SourceInputs.SourceConnectionPath, "source-connection.txt", 65536).ConfigureAwait(false);
        string token = await Copy(input.SourceInputs.SourceCloudOptions.ServiceAccountTokenFile, "source-token.txt", 65536).ConfigureAwait(false);
        string ca = await Copy(input.SourceInputs.SourceCloudOptions.ServiceAccountCaFile, "source-ca.pem", 65536).ConfigureAwait(false);
        string helper = await Copy(input.MaintenanceValidatorSourcePath, "maintenance-validator.cs", 512 * 1024).ConfigureAwait(false);
        var sourceInputs = new CurrentCustomerSequenceRepairSourceInputs(report, sql,
            input.SourceInputs.SourceCloudOptions with { ServiceAccountTokenFile = token, ServiceAccountCaFile = ca });
        var native = CustomerClosedCompletedReadback.Decode<CurrentCustomerSequenceObservation>(files.Read(capture.NativeBeforePath, sharedReader: true, maximumBytes: 8_000_000));
        ApprovedCurrentCustomerSequenceDefinition.RequireBefore(native, "legacy_local");
        if (native.Snapshot.Sha256 != capture.BeforeDatabaseSha256["Customer"]) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var permissionKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECDsa[] keys = [reviewKey, permissionKey, receiptKey];
        string[] ids = ["customer-closed-review-" + suffix, "customer-closed-authorization-" + suffix, "customer-closed-receipt-" + suffix];
        string[] fingerprints = [.. keys.Select(x => CurrentCustomerSequenceRepairPermit.Hash(x.ExportSubjectPublicKeyInfo()))];
        if (fingerprints.Distinct(StringComparer.Ordinal).Count() != 3) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var pins = new CurrentCustomerSequenceRepairSigningPins(ids[0], fingerprints[0], ids[1], fingerprints[1], ids[2], fingerprints[2]);
        var trusted = new List<DeltaTrustedKeyReference>();
        for (int i = 0; i < 3; i++)
        {
            string path = Path.Combine(root, ids[i] + ".public.txt");
            await files.WriteNewAsync(path, Encoding.UTF8.GetBytes(Convert.ToBase64String(keys[i].ExportSubjectPublicKeyInfo())), ct).ConfigureAwait(false);
            await files.WriteNewAsync(Path.Combine(root, ids[i] + ".private.pem"), Encoding.UTF8.GetBytes(keys[i].ExportPkcs8PrivateKeyPem()), ct).ConfigureAwait(false);
            trusted.Add(new(ids[i], path));
        }
        var trust = new ReceiptAttestationTrustStore(keys.Select((key, i) => new TrustedAttestationKey(ids[i], key.ExportSubjectPublicKeyInfo())).ToArray());
        string nativeHash = ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(native.State);
        var seed = new CurrentCustomerSequenceClosedSeed("current-customer-sequence-named-closed-console-seed-v1", capture.State.OperationId, caseId,
            source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(source), intended.Source.CatalogReportSha256,
            intended.Owner.Head, intended.Owner.ContextSha256, intended.Owner.SnapshotSha256, intended.DefinitionSha256,
            input.Completed.Definition.Sha256, input.Completed.NativeComponent.Sha256, input.Completed.MaintenanceComponent.Sha256,
            CurrentAppOwnedSnapshotSerialization.Sha256(intended), nativeHash, native.Snapshot.Sha256,
            binding.ComputeSha256(), CurrentAppOwnedSnapshotSerialization.Sha256(capture.TargetPins), capture.State.TargetGeneration, capture.FleetSha256,
            input.TestAssemblySha256, input.ConsoleAssemblySha256, input.CoreAssemblySha256, DateTimeOffset.UtcNow, capture.State.ExpiresAtUtc, ids[0], null);
        var definition = ApprovedCurrentCustomerSequenceDefinition.Create(intended.Source, intended.Owner, source.SourceCommitSha, intended.Source.CatalogReportSha256, DateTimeOffset.UtcNow);
        var scope = new CurrentCustomerSequenceRepairScope(capture.State.OperationId, CurrentCustomerSequenceRepairOperation.FixedStartDefinitionOnly,
            source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(source), intended.Source.CatalogReportSha256, intended.Source, intended.Owner,
            intended.DefinitionSha256, nativeHash, CurrentCustomerSequenceRepairPermit.OperationSha256(source, definition, input.Completed.Definition.Sha256, nativeHash),
            input.Completed.Definition.Sha256, CurrentCustomerSequenceRepairPermit.MaintenanceValidator, capture.Target, "local-aspire", "legacy-postgres-main-local",
            capture.State.TargetGeneration, seed.TargetObservationSha256, binding.ComputeSha256(), capture.BeforeDatabaseSha256, capture.FleetSha256,
            input.Completed.NativeComponent.Sha256, string.Empty, string.Empty, capture.Maintenance, input.Completed.MaintenanceComponent.Sha256,
            CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap, null, seed);
        using var signer = new P256MigrationEvidenceSigner(ids[0], reviewKey.ExportPkcs8PrivateKeyPem());
        scope = await CurrentCustomerClosedSeedIssuer.IssueAfterActualCaptureAsync(input.Completed, scope, capture, source, trust, pins, signer, ct).ConfigureAwait(false);
        string sourcePath = Path.Combine(root, "closed-source.json"), scopePath = Path.Combine(root, "closed-scope.json"), pinsPath = Path.Combine(root, "closed-signing-pins.json"),
            bindingPath = Path.Combine(root, "closed-binding.json"), targetPath = Path.Combine(root, "closed-target-pins.json"), configPath = Path.Combine(root, "closed-config.json"),
            reviewPath = Path.Combine(root, "closed-review.json"), authorizationPath = Path.Combine(root, "closed-authorization.json");
        await Write(sourcePath, source).ConfigureAwait(false); await Write(scopePath, scope).ConfigureAwait(false); await Write(pinsPath, pins).ConfigureAwait(false);
        await Write(bindingPath, binding).ConfigureAwait(false); await Write(targetPath, capture.TargetPins).ConfigureAwait(false);
        var config = new CurrentCustomerSequenceRepairConfiguration(sourcePath, sourceInputs, scopePath, reviewPath, authorizationPath, pinsPath, bindingPath,
            Path.Combine(root, "operator.txt"), Path.Combine(root, "ordinary.txt"), capture.BaselinePath, targetPath, trusted,
            Path.Combine(root, ids[2] + ".private.pem"), new(input.Completed.NativeComponent.Path, input.Completed.NativeComponent.Sha256), new("", ""), new("", ""),
            Path.Combine(root, ids[0] + ".private.pem"), reviewPath, scope.ClosedConsoleSeed!.ExpiresAtUtc,
            Path.Combine(root, ids[1] + ".private.pem"), authorizationPath, CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap,
            new(input.Completed.Definition.Path, input.Completed.Definition.Sha256), new(input.Completed.MaintenanceComponent.Path, input.Completed.MaintenanceComponent.Sha256), helper, input.Completed);
        await Write(configPath, config).ConfigureAwait(false); inputFiles.Require(); files.Require(); return (configPath, config, scope);
        async Task Write<T>(string path, T value)
        {
            await files.WriteNewAsync(path, JsonSerializer.SerializeToUtf8Bytes(value), ct).ConfigureAwait(false);
        }

        async Task<string> Copy(string inputPath, string name, int cap)
        {
            byte[] bytes = inputFiles.Read(inputPath, sharedReader: true, maximumBytes: cap); string path = Path.Combine(root, name);
            await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
            return !files.Read(path, sharedReader: true, maximumBytes: cap).AsSpan().SequenceEqual(bytes)
                ? throw CurrentCustomerSequenceRepairPermit.Invalid()
                : path;
        }
    }
}
