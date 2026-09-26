using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record QuotationTargetBootstrapCommandConfiguration(
    string SchemaPlanPath, string TargetConnectionFile, DeltaTargetAuthority TargetAuthority,
    DeltaTrustedKeyReference AuthorizationKey, string OutputPath, string? AuthorizationPath = null,
    DateTimeOffset? AuthorizationExpiresAtUtc = null, bool AllowAuthorizationSigning = false,
    bool AllowExecution = false, string? DisposableProofPath = null,
    DeltaTrustedKeyReference? DisposableProofKey = null,
    DeltaTrustedKeyReference? EvidenceKey = null);

public static partial class MigrationConsole
{
    private const string QuotationBootstrapSignerEnvironmentVariable =
        "LEGACY_MIGRATION_QUOTATION_BOOTSTRAP_AUTHORIZATION_SIGNING_KEY_FILE";
    private const string QuotationBootstrapEvidenceSignerEnvironmentVariable =
        "LEGACY_MIGRATION_QUOTATION_BOOTSTRAP_EVIDENCE_SIGNING_KEY_FILE";

    internal static Task<int> RunQuotationTargetBootstrapForTestsAsync(IReadOnlyList<string> arguments,
        TextWriter output, TextWriter error, Func<string, string?> environment,
        CancellationToken cancellationToken)
    {
        ConsoleInvocation invocation = ConsoleInvocation.Parse(arguments);
        return RunQuotationTargetBootstrapBoundaryAsync(invocation.Command, invocation.ConfigPath,
            environment, output, error, cancellationToken);
    }

    private static async Task<int> RunQuotationTargetBootstrapBoundaryAsync(string command, string configPath,
        Func<string, string?> environment, TextWriter output, TextWriter error,
        CancellationToken cancellationToken)
    {
        string? reservedOutputPath = null;
        bool ddlAttempted = false;
        try
        {
            if (environment(DeployEnabledEnvironmentVariable) != "false" ||
                environment("LEGACY_MIGRATION_CALLER") != "owner")
            {
                throw new MigrationConsoleException("quotation_target_bootstrap_owner_gate_invalid",
                    "Owner-only local DDL requires deployment disabled.");
            }
            MigrationConsoleConfiguration root = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
                configPath, "quotation_target_bootstrap_config_unprotected", cancellationToken).ConfigureAwait(false);
            QuotationTargetBootstrapCommandConfiguration config = root.QuotationTargetBootstrap ??
                throw new MigrationConsoleException("quotation_target_bootstrap_config_missing",
                    "Quotation target bootstrap configuration is required.");
            if (File.Exists(config.OutputPath) || Directory.Exists(config.OutputPath))
            {
                throw new MigrationConsoleException("quotation_target_bootstrap_output_exists",
                    "The receipt path must be new.");
            }
            OwnerProtectedFilePolicy.ValidatePublicationParent(config.OutputPath);
            await using var reservation = new FileStream(config.OutputPath, FileMode.CreateNew,
                FileAccess.Write, FileShare.Read | FileShare.Delete, 4096, FileOptions.Asynchronous);
            reservedOutputPath = config.OutputPath;
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(config.OutputPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            if (!OwnerProtectedFilePolicy.IsOwnerOnly(config.OutputPath))
            {
                throw new MigrationConsoleException("quotation_target_bootstrap_output_unprotected",
                    "The reserved receipt must be owner-only.");
            }
            byte[] pending = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = "1.0",
                state = "pending",
                command,
                database = "Quotation",
                reservedAtUtc = DateTimeOffset.UtcNow
            }, JsonOptions);
            await reservation.WriteAsync(pending, cancellationToken).ConfigureAwait(false);
            await reservation.FlushAsync(cancellationToken).ConfigureAwait(false);
            reservation.Flush(flushToDisk: true);

            FreshSchemaPlan schema = await ReadProtectedJsonAsync<FreshSchemaPlan>(config.SchemaPlanPath,
                "quotation_target_bootstrap_schema_unprotected", cancellationToken).ConfigureAwait(false);
            if (schema.SchemaVersion != "2.0" || !schema.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
            {
                throw new MigrationConsoleException("quotation_target_bootstrap_inventory_invalid",
                    "An exact-23 protected schema plan is required.");
            }
            DatabaseSchemaPlan database = schema.Databases.Single(item => item.Database == "Quotation");
            QuotationTargetBootstrapAuthorizationProducer.Validate(database, schema.SourceCommitSha,
                config.TargetAuthority);
            bool persistent = config.TargetAuthority.AuthorityId.StartsWith(
                "aspire://legacy-postgres-main-local/persistent-", StringComparison.Ordinal);
            if (persistent)
            {
                ValidatePersistentQuotationSchemaFreshness(schema.CapturedAtUtc, DateTimeOffset.UtcNow);
            }
            string target = await ReadProtectedTextAsync(config.TargetConnectionFile,
                "quotation_target_bootstrap_connection_unprotected", cancellationToken).ConfigureAwait(false);
            await DefaultGuardedDeltaConsoleRuntime.VerifyTargetAuthorityAsync(target, config.TargetAuthority,
                cancellationToken).ConfigureAwait(false);
            byte[] publicKey = Convert.FromBase64String(await ReadProtectedTextAsync(
                config.AuthorizationKey.SubjectPublicKeyInfoPath,
                "quotation_target_bootstrap_trust_unprotected", cancellationToken).ConfigureAwait(false));
            var trust = new ReceiptAttestationTrustStore([new(config.AuthorizationKey.KeyId, publicKey)]);
            string? proofSha256 = persistent
                ? await ReadQuotationBootstrapProofSha256Async(config, database, schema.SourceCommitSha,
                    schema.CapturedAtUtc, publicKey, cancellationToken).ConfigureAwait(false)
                : null;
            if (!persistent && (config.DisposableProofPath is not null || config.DisposableProofKey is not null))
            {
                throw new MigrationConsoleException("quotation_target_bootstrap_proof_unexpected",
                    "Disposable DDL cannot consume a persistent proof input.");
            }
            if (persistent && config.EvidenceKey is not null)
            {
                throw new MigrationConsoleException("quotation_target_bootstrap_evidence_key_invalid",
                    "Persistent DDL cannot sign disposable evidence.");
            }

            object result;
            if (command == "authorize-quotation-target-bootstrap")
            {
                if (!config.AllowAuthorizationSigning || config.AuthorizationExpiresAtUtc is null)
                {
                    throw new MigrationConsoleException("quotation_target_bootstrap_signing_disabled",
                        "DDL authorization signing is disabled.");
                }
                string signerPath = environment(QuotationBootstrapSignerEnvironmentVariable) ??
                    throw new MigrationConsoleException("quotation_target_bootstrap_signer_missing",
                        "The protected DDL signer reference is required.");
                using var signer = new P256MigrationEvidenceSigner(config.AuthorizationKey.KeyId,
                    await ReadProtectedTextAsync(signerPath, "quotation_target_bootstrap_signer_unprotected",
                        cancellationToken).ConfigureAwait(false));
                if (!trust.TryGetPublicKeyFingerprintSha256(config.AuthorizationKey.KeyId, out string fingerprint) ||
                    fingerprint != signer.PublicKeyFingerprintSha256)
                {
                    throw new MigrationConsoleException("quotation_target_bootstrap_signer_mismatch",
                        "The DDL signer is not trusted.");
                }
                result = QuotationTargetBootstrapAuthorizationProducer.Produce(database, schema.SourceCommitSha,
                    config.TargetAuthority, DateTimeOffset.UtcNow, config.AuthorizationExpiresAtUtc.Value, signer,
                    proofSha256);
            }
            else if (command == "apply-quotation-target-bootstrap")
            {
                if (!config.AllowExecution || string.IsNullOrWhiteSpace(config.AuthorizationPath))
                {
                    throw new MigrationConsoleException("quotation_target_bootstrap_execution_disabled",
                        "DDL execution is disabled.");
                }
                QuotationTargetBootstrapAuthorization authorization =
                    await ReadProtectedJsonAsync<QuotationTargetBootstrapAuthorization>(config.AuthorizationPath,
                        "quotation_target_bootstrap_authorization_unprotected", cancellationToken).ConfigureAwait(false);
                if (!QuotationTargetBootstrapAuthorizationVerifier.Verify(authorization, database,
                    schema.SourceCommitSha, config.TargetAuthority, trust, DateTimeOffset.UtcNow, proofSha256))
                {
                    throw new MigrationConsoleException("quotation_target_bootstrap_authorization_invalid",
                        "The DDL authorization is stale or mismatched.");
                }
                using P256MigrationEvidenceSigner? evidenceSigner = persistent ? null :
                    await ReadQuotationBootstrapEvidenceSignerAsync(config, environment, publicKey,
                        cancellationToken)
                        .ConfigureAwait(false);
                var builder = new NpgsqlConnectionStringBuilder(target) { Database = "Quotation", Pooling = false };
                ddlAttempted = true;
                string disposition = await QuotationDispositionTargetBootstrap.ExecuteAsync(database,
                    builder.ConnectionString, "Quotation", config.TargetAuthority.SystemIdentifierSha256,
                    cancellationToken).ConfigureAwait(false);
                string authorizationHash = Convert.ToHexString(SHA256.HashData(
                    JsonSerializer.SerializeToUtf8Bytes(authorization, JsonOptions))).ToLowerInvariant();
                result = !persistent
                    ? QuotationTargetBootstrapProofProducer.Produce(database, schema.SourceCommitSha,
                        config.TargetAuthority, authorizationHash, disposition, DateTimeOffset.UtcNow,
                        evidenceSigner!)
                    : (new
                    {
                        schemaVersion = "1.1",
                        database = "Quotation",
                        disposition,
                        authorizationId = authorization.AuthorizationId,
                        authorizationEnvelopeSha256 = authorizationHash,
                        disposableProofSha256 = proofSha256,
                        sourceCommitSha = schema.SourceCommitSha,
                        reviewedMissingTables = QuotationTargetBootstrapAuthorizationProducer.ReviewedMissingSet,
                        targetAuthority = config.TargetAuthority,
                        transitionSchemaSha256 = authorization.TransitionSchemaSha256,
                        finalTargetSchemaSha256 = database.TargetSchemaSha256,
                        retainedSourceOutboxes = true,
                        rowApplyAuthorized = false,
                        completedAtUtc = DateTimeOffset.UtcNow,
                    });
            }
            else
            {
                throw new MigrationConsoleException("quotation_target_bootstrap_command_invalid",
                    "Unsupported Quotation DDL command.");
            }

            string completePath = config.OutputPath + ".complete-" + Guid.NewGuid().ToString("N");
            await WriteNewJsonAsync(completePath, result, cancellationToken).ConfigureAwait(false);
            File.Replace(completePath, config.OutputPath, destinationBackupFileName: null);
            reservedOutputPath = null;
            await output.WriteLineAsync(command.Replace('-', '_') + "_complete").ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure)
        {
            if (reservedOutputPath is not null && !ddlAttempted)
            {
                try { File.Delete(reservedOutputPath); }
                catch (IOException) { /* A concurrent handle keeps the reservation visible for review. */ }
            }
            await error.WriteLineAsync(ClassifyDeltaFailure(failure)).ConfigureAwait(false);
            return failure is MigrationConsoleException or MigrationExecutionException or ArgumentException or
                FormatException or CryptographicException ? 65 : 70;
        }
    }

    private static async Task<string> ReadQuotationBootstrapProofSha256Async(
        QuotationTargetBootstrapCommandConfiguration config, DatabaseSchemaPlan database,
        string sourceCommitSha, DateTimeOffset schemaCapturedAtUtc,
        byte[] authorizationPublicKey, CancellationToken cancellationToken)
    {
        if (config.DisposableProofPath is null || config.DisposableProofKey is null ||
            config.DisposableProofKey.KeyId == config.AuthorizationKey.KeyId)
        {
            throw new MigrationConsoleException("quotation_target_bootstrap_disposable_proof_required",
                "A distinct signed disposable proof is required for persistent-local DDL.");
        }
        QuotationTargetBootstrapProof proof = await ReadProtectedJsonAsync<QuotationTargetBootstrapProof>(
            config.DisposableProofPath, "quotation_target_bootstrap_proof_unprotected", cancellationToken)
            .ConfigureAwait(false);
        byte[] proofPublicKey = Convert.FromBase64String(await ReadProtectedTextAsync(
            config.DisposableProofKey.SubjectPublicKeyInfoPath,
            "quotation_target_bootstrap_proof_trust_unprotected", cancellationToken).ConfigureAwait(false));
        var trust = new ReceiptAttestationTrustStore([new(config.DisposableProofKey.KeyId, proofPublicKey)]);
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(proofPublicKey),
                SHA256.HashData(authorizationPublicKey)) ||
            proof.CompletedAtUtc < schemaCapturedAtUtc ||
            !QuotationTargetBootstrapProofVerifier.Verify(proof, database, sourceCommitSha,
                config.TargetAuthority, trust, DateTimeOffset.UtcNow)
            ? throw new MigrationConsoleException("quotation_target_bootstrap_disposable_proof_invalid",
                "The disposable proof or independent trust root is invalid.")
            : QuotationTargetBootstrapProofProducer.ComputeSha256(proof);
    }

    internal static void ValidatePersistentQuotationSchemaFreshness(DateTimeOffset capturedAtUtc,
        DateTimeOffset nowUtc)
    {
        if (capturedAtUtc.Offset != TimeSpan.Zero || nowUtc.Offset != TimeSpan.Zero ||
            capturedAtUtc > nowUtc || nowUtc - capturedAtUtc > TimeSpan.FromHours(2))
        {
            throw new MigrationConsoleException("quotation_target_bootstrap_schema_stale",
                "Persistent local DDL requires a fresh UTC exact-23 source schema plan.");
        }
    }

    private static async Task<P256MigrationEvidenceSigner> ReadQuotationBootstrapEvidenceSignerAsync(
        QuotationTargetBootstrapCommandConfiguration config, Func<string, string?> environment,
        byte[] authorizationPublicKey, CancellationToken cancellationToken)
    {
        if (config.EvidenceKey is null || config.EvidenceKey.KeyId == config.AuthorizationKey.KeyId)
        {
            throw new MigrationConsoleException("quotation_target_bootstrap_evidence_key_invalid",
                "A distinct disposable evidence key is required.");
        }
        byte[] publicKey = Convert.FromBase64String(await ReadProtectedTextAsync(
            config.EvidenceKey.SubjectPublicKeyInfoPath,
            "quotation_target_bootstrap_evidence_trust_unprotected", cancellationToken).ConfigureAwait(false));
        if (CryptographicOperations.FixedTimeEquals(SHA256.HashData(publicKey),
            SHA256.HashData(authorizationPublicKey)))
        {
            throw new MigrationConsoleException("quotation_target_bootstrap_evidence_key_invalid",
                "Disposable evidence and DDL authorization must use different keys.");
        }
        var trust = new ReceiptAttestationTrustStore([new(config.EvidenceKey.KeyId, publicKey)]);
        string signerPath = environment(QuotationBootstrapEvidenceSignerEnvironmentVariable) ??
            throw new MigrationConsoleException("quotation_target_bootstrap_evidence_signer_missing",
                "The protected disposable evidence signer is required.");
        var signer = new P256MigrationEvidenceSigner(config.EvidenceKey.KeyId,
            await ReadProtectedTextAsync(signerPath,
                "quotation_target_bootstrap_evidence_signer_unprotected", cancellationToken).ConfigureAwait(false));
        if (!trust.TryGetPublicKeyFingerprintSha256(config.EvidenceKey.KeyId, out string fingerprint) ||
            fingerprint != signer.PublicKeyFingerprintSha256)
        {
            signer.Dispose();
            throw new MigrationConsoleException("quotation_target_bootstrap_evidence_signer_mismatch",
                "The disposable DDL evidence signer is not trusted.");
        }
        return signer;
    }
}
