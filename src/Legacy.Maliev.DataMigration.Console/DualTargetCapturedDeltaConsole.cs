using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record DualTargetCapturedSigningRole(DeltaTrustedKeyReference Public, string PrivateKeyFile);
internal sealed record DualTargetCapturedEndpointKeys(DualTargetCapturedDeltaEndpoint Endpoint,
    string PlanPrivateKeyFile, string AuthorizationPrivateKeyFile, string EvidencePrivateKeyFile,
    DualTargetCapturedSigningRole? Review);
internal sealed record DualTargetCapturedDeltaConfiguration(string Kind, string BindingPath, string SchemaPath,
    string SourceConnectionFile, string TunnelPath, string CaptureDirectory, string CaptureKeyFile,
    string BundlePath, string OutputPath, string BackupManifestSha256, string BackupKeyFingerprintSha256,
    DualTargetCapturedSigningRole CaptureSigner, IReadOnlyList<DualTargetCapturedEndpointKeys> Targets,
    DateTimeOffset ExpiresAtUtc, DualTargetCapturedDeltaPurpose? Purpose = null, string? ProofPath = null,
    string? ReviewPath = null);

public static partial class MigrationConsole
{
    // Distinct commands only; the old captured-production refusal and old local-only permits are unchanged.
    internal static Task<int> RunDualTargetCapturedDeltaAsync(string command, string path,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        return RunOwnedDualTargetCapturedDeltaAsync(command, path, output, error, null, ct);
    }

    private static async Task<int> RunOwnedDualTargetCapturedDeltaAsync(string command, string path,
        TextWriter output, TextWriter error, DualTargetCapturedOwnedProofPair? ownedProofs, CancellationToken ct)
    {
        CancellationToken publicationToken = ct;
        try
        {
            if (Environment.GetEnvironmentVariable("LEGACY_MIGRATION_CALLER") != "owner" ||
                Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false") { throw DualInvalid(); }
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
            var initial = await ReadProtectedJsonAsync<DualTargetCapturedDeltaConfiguration>(path, "dual_capture_config_unprotected", ct).ConfigureAwait(false);
            LocalExecutionBinding binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(initial.BindingPath, "dual_capture_binding_unprotected", ct).ConfigureAwait(false);
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            var config = DecodeV3<DualTargetCapturedDeltaConfiguration>(files.Read(path, maximumBytes: 1024 * 1024));
            if (JsonSerializer.Serialize(config) != JsonSerializer.Serialize(initial) || config.Kind != "dual-target-captured-delta-config-v1" ||
                config.ExpiresAtUtc.Offset != TimeSpan.Zero || config.ExpiresAtUtc <= DateTimeOffset.UtcNow || config.ExpiresAtUtc - DateTimeOffset.UtcNow > TimeSpan.FromMinutes(15) ||
                config.Targets.Count != 4 || !config.Targets.Select(x => x.Endpoint.Purpose).Order().SequenceEqual(Enum.GetValues<DualTargetCapturedDeltaPurpose>().Order()) ||
                Path.GetDirectoryName(Path.GetFullPath(config.OutputPath)) != binding.ArtifactRootCanonicalPath ||
                new[] { config.OutputPath, config.OutputPath + ".tools.json", config.OutputPath + ".authorization.json" }.Any(x => File.Exists(x) || Directory.Exists(x)))
            { throw DualInvalid(); }
            // This check precedes source/target connections and tool/relay creation.
            DualTargetCapturedOwnedProofPair.RequireCommand(command, config.Purpose, ownedProofs);
            if (command == "plan-dual-target-captured-delta" && Path.GetFullPath(config.OutputPath) != Path.GetFullPath(config.BundlePath)) { throw DualInvalid(); }
            FreshSchemaPlan schema = DecodeV3<FreshSchemaPlan>(files.Read(config.SchemaPath, maximumBytes: 32 * 1024 * 1024));
            RequireDualSchema(schema, accepted);
            ReceiptAttestationTrustStore trust = LoadDualTrust(config, files);
            string sourceConnection = Encoding.UTF8.GetString(files.Read(config.SourceConnectionFile, maximumBytes: 65536)).Trim();
            string liveIdentity = await SqlServerLiveSourceObservation.ObserveSha256Async(sourceConnection, ct).ConfigureAwait(false);
            DualTargetCapturedDeltaObservation observers = await DualTargetCapturedDeltaObservation.OpenAsync(files,
                binding.ArtifactRootCanonicalPath, config.TunnelPath, accepted, config.ExpiresAtUtc, ct).ConfigureAwait(false);
            Exception? operationFailure = null;
            object? result = null;
            try
            {
                ct = observers.OperationToken;
                if (command == "plan-dual-target-captured-delta")
                {
                    if (Path.GetDirectoryName(Path.GetFullPath(config.CaptureDirectory)) != binding.ArtifactRootCanonicalPath ||
                        !Directory.Exists(config.CaptureDirectory) || Directory.EnumerateFileSystemEntries(config.CaptureDirectory).Any()) { throw DualInvalid(); }
                    SecureLocalFile.EnsureOwnerOnlyDirectory(config.CaptureDirectory);
                    byte[] key = RandomNumberGenerator.GetBytes(32);
                    var signers = new List<P256MigrationEvidenceSigner>();
                    try
                    {
                        await files.WriteNewAsync(config.CaptureKeyFile, key, ct).ConfigureAwait(false);
                        var destinations = new List<DualTargetCapturedDeltaDestination>();
                        foreach (DualTargetCapturedEndpointKeys target in config.Targets.OrderBy(x => x.Endpoint.Purpose))
                        {
                            string connection = ReadConnection(files, target.Endpoint.ConnectionFile);
                            DualTargetNativeProofClone.ProofLease? proofLease = target.Endpoint.Purpose is DualTargetCapturedDeltaPurpose.ProductionProof or DualTargetCapturedDeltaPurpose.LocalProof
                                ? ownedProofs!.Get(target.Endpoint.Purpose) : null;
                            DualTargetCapturedTargetObservation observed = await observers.ObserveAsync(target.Endpoint, connection, schema, proofLease, ct).ConfigureAwait(false);
                            P256MigrationEvidenceSigner signer = LoadDualSigner(target.Endpoint.PlanKey, target.PlanPrivateKeyFile, trust, files); signers.Add(signer);
                            _ = trust.TryGetPublicKeyFingerprintSha256(target.Endpoint.AuthorizationKey.KeyId, out string authorizationFingerprint);
                            var request = new Exact23DeltaPlanRequest(schema, DateTimeOffset.UtcNow, config.BackupManifestSha256,
                                HashFile(typeof(MigrationConsole).Assembly.Location), target.Endpoint.Purpose == DualTargetCapturedDeltaPurpose.Production ? "maliev-legacy" : "local-aspire",
                                target.Endpoint.Purpose == DualTargetCapturedDeltaPurpose.Production ? "legacy-postgres-main" : "legacy-postgres-main-local",
                                observed.Generation, observed.Sha256, config.BackupKeyFingerprintSha256, authorizationFingerprint)
                            { TargetAuthority = observed.Authority, SourceMode = DeltaSourceMode.LiveReadOnly, SourceObservationSha256 = liveIdentity };
                            destinations.Add(new(target.Endpoint.Purpose, request, new PostgreSqlDeltaRowSource(new(connection)), signer,
                                ReadPublic(files, target.Endpoint.EvidenceKey), observed));
                        }
                        DateTimeOffset cutoff = DateTimeOffset.UtcNow;
                        destinations = [.. destinations.Select(x => x with { Request = x.Request with { SourceCutoffUtc = cutoff } })];
                        using P256MigrationEvidenceSigner captureSigner = LoadDualSigner(config.CaptureSigner.Public, config.CaptureSigner.PrivateKeyFile, trust, files);
                        await using IMigrationSourceSession source = new SqlServerMigrationSourceFactory().Create(sourceConnection);
                        result = await new DualTargetCapturedDeltaPlanner(source, new SqlServerDeltaReconciliationInspector(source),
                            new DeltaCapturedTableArchive(config.CaptureDirectory), TimeProvider.System).ProduceAsync(destinations, key, captureSigner, ct).ConfigureAwait(false);
                    }
                    finally { CryptographicOperations.ZeroMemory(key); foreach (P256MigrationEvidenceSigner signer in signers) { signer.Dispose(); } }
                }
                else
                {
                    DualTargetCapturedDeltaPurpose purpose = config.Purpose ?? throw DualInvalid();
                    DualTargetCapturedDeltaBundle bundle = DecodeV3<DualTargetCapturedDeltaBundle>(files.Read(config.BundlePath, maximumBytes: 32 * 1024 * 1024));
                    DualTargetCapturedDeltaContract.Verify(bundle, schema, trust, DateTimeOffset.UtcNow);
                    byte[] archiveKey = files.Read(config.CaptureKeyFile, sharedReader: true, maximumBytes: 32);
                    try
                    {
                        SecureLocalFile.EnsureOwnerOnlyDirectory(config.CaptureDirectory);
                        await DualTargetCapturedDeltaPlanner.VerifyFullArchivesAsync(bundle, schema, new(config.CaptureDirectory), archiveKey, ct).ConfigureAwait(false);
                    }
                    finally { CryptographicOperations.ZeroMemory(archiveKey); }
                    if (bundle.SourceObservationSha256 != liveIdentity || bundle.SourceCommitSha != accepted) { throw DualInvalid(); }
                    DualTargetCapturedEndpointKeys target = config.Targets.Single(x => x.Endpoint.Purpose == purpose);
                    string connection = ReadConnection(files, target.Endpoint.ConnectionFile);
                    DualTargetNativeProofClone.ProofLease? proofLease = purpose is DualTargetCapturedDeltaPurpose.ProductionProof or DualTargetCapturedDeltaPurpose.LocalProof
                        ? ownedProofs!.Get(purpose) : null;
                    DualTargetCapturedTargetObservation observed = await observers.ObserveAsync(target.Endpoint, connection, schema, proofLease, ct).ConfigureAwait(false);
                    if (command == "review-dual-target-captured-delta")
                    {
                        Exact23DeltaReconciliationResult proof = ReadDualProof(config, files);
                        DualTargetCapturedSigningRole reviewRole = target.Review ?? throw DualInvalid();
                        using P256MigrationEvidenceSigner signer = LoadDualSigner(reviewRole.Public, reviewRole.PrivateKeyFile, trust, files);
                        result = DualTargetCapturedDeltaAdmission.Issue(bundle, purpose, proof, schema, trust, observed.RuntimeSha256,
                            observed.NativeBeforeSha256, accepted, signer, DateTimeOffset.UtcNow, config.ExpiresAtUtc);
                    }
                    else if (command is "prove-dual-target-captured-delta" or "apply-dual-target-captured-delta")
                    {
                        DualTargetCapturedDeltaNativeGuard guard;
                        if (command == "prove-dual-target-captured-delta")
                        { guard = DualTargetCapturedDeltaNativeGuard.ForDisposable(bundle, purpose, observed, schema, trust, DateTimeOffset.UtcNow); }
                        else
                        {
                            Exact23DeltaReconciliationResult proof = ReadDualProof(config, files);
                            var review = DecodeV3<DualTargetCapturedDeltaReview>(files.Read(config.ReviewPath ?? throw DualInvalid(), maximumBytes: 1024 * 1024));
                            _ = trust.TryGetPublicKeyFingerprintSha256((target.Review ?? throw DualInvalid()).Public.KeyId, out string fingerprint);
                            guard = DualTargetCapturedDeltaNativeGuard.ForPersistent(review, bundle, purpose, proof, observed, schema, trust, fingerprint, accepted, DateTimeOffset.UtcNow);
                        }
                        result = await ExecuteDualTargetAsync(config, target, bundle, schema, sourceConnection, connection,
                            trust, files, observers, guard, proofLease, ct).ConfigureAwait(false);
                    }
                    else { throw DualInvalid(); }
                }
                if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != accepted ||
                    await SqlServerLiveSourceObservation.ObserveSha256Async(sourceConnection, ct).ConfigureAwait(false) != liveIdentity) { throw DualInvalid(); }
            }
            catch (Exception failure) { operationFailure = failure; }
            Exception? cleanupFailure = null;
            try { await observers.DisposeAsync().ConfigureAwait(false); }
            catch (Exception cleanup) { cleanupFailure = cleanup; }
            if (operationFailure is not null && cleanupFailure is not null) { throw new AggregateException(operationFailure, cleanupFailure); }
            if (operationFailure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(operationFailure).Throw(); }
            if (cleanupFailure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(cleanupFailure).Throw(); }
            publicationToken.ThrowIfCancellationRequested();
            if (result is null || DateTimeOffset.UtcNow >= config.ExpiresAtUtc) { throw DualInvalid(); }
            // Resource absence precedes publication; no live-relay artifact is called a completed result.
            await files.WriteNewAsync(config.OutputPath + ".tools.json", JsonSerializer.SerializeToUtf8Bytes(observers.ToolFrames), publicationToken).ConfigureAwait(false);
            await files.WriteNewAsync(config.OutputPath, JsonSerializer.SerializeToUtf8Bytes(result), publicationToken).ConfigureAwait(false);
            await output.WriteLineAsync("dual_target_captured_delta_phase_complete").ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure)
        {
            string code = failure is DeltaExecutionException delta ? delta.Code : failure is MigrationConsoleException console ? console.Code : "dual_target_captured_delta_failed";
            await error.WriteLineAsync(code).ConfigureAwait(false); return 1;
        }
    }

    private static async Task<Exact23DeltaReconciliationResult> ExecuteDualTargetAsync(DualTargetCapturedDeltaConfiguration config,
        DualTargetCapturedEndpointKeys target, DualTargetCapturedDeltaBundle bundle, FreshSchemaPlan schema, string sourceConnection,
        string targetConnection, ReceiptAttestationTrustStore trust, CurrentAppOwnedRepairCustody files,
        DualTargetCapturedDeltaObservation observers, DualTargetCapturedDeltaNativeGuard guard,
        DualTargetNativeProofClone.ProofLease? proofLease, CancellationToken ct)
    {
        await DualTargetNativeProofClone.ProofLease.RequireEndpointAsync(target.Endpoint, targetConnection, schema.SourceCommitSha, proofLease, ct).ConfigureAwait(false);
        DeltaSynchronizationPlan plan = bundle.Plans.Single(x => x.Purpose == target.Endpoint.Purpose).Plan;
        using P256MigrationEvidenceSigner authorizer = LoadDualSigner(target.Endpoint.AuthorizationKey, target.AuthorizationPrivateKeyFile, trust, files);
        DeltaExecutionAuthorization authorization = DeltaExecutionAuthorizationProducer.Produce(plan, DateTimeOffset.UtcNow, config.ExpiresAtUtc, authorizer);
        await files.WriteNewAsync(config.OutputPath + ".authorization.json", JsonSerializer.SerializeToUtf8Bytes(authorization), ct).ConfigureAwait(false);
        SignedDeltaExecutionAuthorizationGate gate = await DeltaExecutionAdmission.AdmitAsync(authorization, trust, TimeProvider.System,
            plan.TargetAuthority!, plan, ct).ConfigureAwait(false);
        byte[] key = files.Read(config.CaptureKeyFile, sharedReader: true, maximumBytes: 32);
        try
        {
            using DeltaCapturedTableRowSource rows = DeltaCapturedTableRowSource.FromSignedPlan(new(config.CaptureDirectory), plan, trust, DateTimeOffset.UtcNow, key);
            await using IMigrationSourceSession source = new SqlServerMigrationSourceFactory().Create(sourceConnection);
            var targetRows = new PostgreSqlDeltaRowSource(new(targetConnection));
            DeltaExecutionCoordinator Executor(string database)
            {
                var settings = new NpgsqlConnectionStringBuilder(targetConnection) { Database = database, Pooling = false };
                return new(new SourceCheckedDualTarget(new PostgreSqlDeltaCanonicalTarget(new(settings.ConnectionString, database, plan.TargetGeneration)
                { SignedSourceSchemaPlan = schema, DualTargetGuard = guard }), observers, plan.SourceCommitSha,
                    target.Endpoint, targetConnection, proofLease), new CapturedDeltaExecutionRowSessionProvider(rows, targetRows),
                    gate, new SignedCapturedSourceReconciliationInspector(plan, schema, trust, TimeProvider.System), trust, TimeProvider.System);
            }
            _ = await new Exact23DeltaExecutionCoordinator(source, Executor, capturedSourceReplay: true).ExecuteAsync(plan, schema, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        guard.RequireCompletedReadback(await observers.ObserveAsync(target.Endpoint, targetConnection, schema, proofLease, ct).ConfigureAwait(false));
        using P256MigrationEvidenceSigner evidence = LoadDualSigner(target.Endpoint.EvidenceKey, target.EvidencePrivateKeyFile, trust, files);
        return await new DefaultGuardedDeltaConsoleRuntime().ReconcileAsync(new(schema, plan, sourceConnection, targetConnection, evidence) { Trust = trust }, ct).ConfigureAwait(false);
    }

    private static void RequireDualSchema(FreshSchemaPlan schema, string accepted)
    {
        if (schema.SourceCommitSha != accepted || schema.Databases.Sum(x => x.Tables.Count) != 100 || !ApprovedConsumerOverlaySelection.IsApproved(schema) ||
            schema.Databases.Single(x => x.Database == "Customer").TargetExtensionProfile != CustomerCompanyStorageManifest.Profile ||
            schema.Databases.Single(x => x.Database == "Country").TargetExtensionProfile != CurrentConsumerSchemaV3SourceOrderIsoManifest.Country)
        { throw DualInvalid(); }
        DatabaseSchemaPlan quotation = schema.Databases.Single(x => x.Database == "Quotation");
        if (quotation.TargetSchemaSha256 != ReviewedQuotationPhysicalSchemaResolver.GetExpected(quotation, ReviewedQuotationPhysicalVariant.MappedFinal)) { throw DualInvalid(); }
    }
    private sealed class SourceCheckedDualTarget(PostgreSqlDeltaCanonicalTarget target, DualTargetCapturedDeltaObservation observers,
        string acceptedMain, DualTargetCapturedDeltaEndpoint endpoint, string connection,
        DualTargetNativeProofClone.ProofLease? proofLease) : IDeltaCanonicalTarget
    {
        public async Task<IDeltaCanonicalTransaction> BeginAsync(DeltaSynchronizationPlan plan, DatabaseSchemaPlan schema,
            string database, CancellationToken ct)
        {
            observers.RequireLive();
            await DualTargetNativeProofClone.ProofLease.RequireEndpointAsync(endpoint, connection, acceptedMain, proofLease, ct).ConfigureAwait(false);
            return await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != acceptedMain
                ? throw DualInvalid()
                : await target.BeginAsync(plan, schema, database, ct).ConfigureAwait(false);
        }
    }
    private static ReceiptAttestationTrustStore LoadDualTrust(DualTargetCapturedDeltaConfiguration config, CurrentAppOwnedRepairCustody files)
    {
        var references = new List<DeltaTrustedKeyReference> { config.CaptureSigner.Public };
        foreach (DualTargetCapturedEndpointKeys target in config.Targets)
        {
            references.Add(target.Endpoint.PlanKey); references.Add(target.Endpoint.AuthorizationKey); references.Add(target.Endpoint.EvidenceKey);
            if (target.Review is not null) { references.Add(target.Review.Public); }
        }
        var trust = new ReceiptAttestationTrustStore(references.Select(x => ReadPublic(files, x)));
        var fingerprints = references.Select(x => { _ = trust.TryGetPublicKeyFingerprintSha256(x.KeyId, out string value); return value; }).ToList();
        fingerprints.Add(config.BackupKeyFingerprintSha256);
        return fingerprints.Distinct(StringComparer.Ordinal).Count() != fingerprints.Count ? throw DualInvalid() : trust;
    }
    private static TrustedAttestationKey ReadPublic(CurrentAppOwnedRepairCustody files, DeltaTrustedKeyReference key)
    {
        return new(key.KeyId, Convert.FromBase64String(Encoding.UTF8.GetString(files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536)).Trim()));
    }

    private static P256MigrationEvidenceSigner LoadDualSigner(DeltaTrustedKeyReference key, string path, ReceiptAttestationTrustStore trust, CurrentAppOwnedRepairCustody files)
    {
        var signer = new P256MigrationEvidenceSigner(key.KeyId, Encoding.UTF8.GetString(files.Read(path, maximumBytes: 65536)));
        if (!trust.TryGetPublicKeyFingerprintSha256(key.KeyId, out string expected) || signer.PublicKeyFingerprintSha256 != expected)
        { signer.Dispose(); throw DualInvalid(); }
        return signer;
    }
    private static Exact23DeltaReconciliationResult ReadDualProof(DualTargetCapturedDeltaConfiguration config, CurrentAppOwnedRepairCustody files)
    {
        return DecodeV3<Exact23DeltaReconciliationResult>(files.Read(config.ProofPath ?? throw DualInvalid(), maximumBytes: 32 * 1024 * 1024));
    }

    private static string ReadConnection(CurrentAppOwnedRepairCustody files, string path)
    {
        return Encoding.UTF8.GetString(files.Read(path, sharedReader: true, maximumBytes: 65536)).Trim();
    }

    private static string HashFile(string path) { using FileStream file = SecureLocalFile.OpenReadShared(path); return Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant(); }
    private static MigrationConsoleException DualInvalid()
    {
        return new("dual_target_captured_delta_configuration_invalid", "The closed common-capture route is not admitted.");
    }
}
