using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record QuotationTargetBootstrapCommandConfiguration(
    string SchemaPlanPath, string TargetConnectionFile, DeltaTargetAuthority TargetAuthority,
    DeltaTrustedKeyReference AuthorizationKey, string OutputPath, string? AuthorizationPath = null,
    DateTimeOffset? AuthorizationExpiresAtUtc = null, bool AllowAuthorizationSigning = false,
    bool AllowExecution = false);

public static partial class MigrationConsole
{
    private const string QuotationBootstrapSignerEnvironmentVariable =
        "LEGACY_MIGRATION_QUOTATION_BOOTSTRAP_AUTHORIZATION_SIGNING_KEY_FILE";

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
            string target = await ReadProtectedTextAsync(config.TargetConnectionFile,
                "quotation_target_bootstrap_connection_unprotected", cancellationToken).ConfigureAwait(false);
            await DefaultGuardedDeltaConsoleRuntime.VerifyTargetAuthorityAsync(target, config.TargetAuthority,
                cancellationToken).ConfigureAwait(false);
            byte[] publicKey = Convert.FromBase64String(await ReadProtectedTextAsync(
                config.AuthorizationKey.SubjectPublicKeyInfoPath,
                "quotation_target_bootstrap_trust_unprotected", cancellationToken).ConfigureAwait(false));
            var trust = new ReceiptAttestationTrustStore([new(config.AuthorizationKey.KeyId, publicKey)]);

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
                    config.TargetAuthority, DateTimeOffset.UtcNow, config.AuthorizationExpiresAtUtc.Value, signer);
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
                    schema.SourceCommitSha, config.TargetAuthority, trust, DateTimeOffset.UtcNow))
                {
                    throw new MigrationConsoleException("quotation_target_bootstrap_authorization_invalid",
                        "The DDL authorization is stale or mismatched.");
                }
                var builder = new NpgsqlConnectionStringBuilder(target) { Database = "Quotation", Pooling = false };
                ddlAttempted = true;
                string disposition = await QuotationDispositionTargetBootstrap.ExecuteAsync(database,
                    builder.ConnectionString, "Quotation", config.TargetAuthority.SystemIdentifierSha256,
                    cancellationToken).ConfigureAwait(false);
                result = new
                {
                    schemaVersion = "1.0",
                    database = "Quotation",
                    disposition,
                    authorizationId = authorization.AuthorizationId,
                    authorizationEnvelopeSha256 = Convert.ToHexString(SHA256.HashData(
                        JsonSerializer.SerializeToUtf8Bytes(authorization, JsonOptions))).ToLowerInvariant(),
                    sourceCommitSha = schema.SourceCommitSha,
                    reviewedMissingTables = QuotationTargetBootstrapAuthorizationProducer.ReviewedMissingSet,
                    targetAuthority = config.TargetAuthority,
                    reviewedTargetSchemaSha256 = database.TargetSchemaSha256,
                    retainedSourceOutboxes = true,
                    completedAtUtc = DateTimeOffset.UtcNow,
                };
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
}
