using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record TargetExtensionRepairCommandConfiguration(
    string SchemaPlanPath,
    string Database,
    string TargetConnectionFile,
    DeltaTargetAuthority TargetAuthority,
    string ReviewedMissingTables,
    DeltaTrustedKeyReference AuthorizationKey,
    string OutputPath,
    string? AuthorizationPath = null,
    DateTimeOffset? AuthorizationExpiresAtUtc = null,
    bool AllowAuthorizationSigning = false,
    bool AllowExecution = false);

public static partial class MigrationConsole
{
    private const string ExtensionRepairAuthorizationKeyEnvironmentVariable =
        "LEGACY_MIGRATION_EXTENSION_REPAIR_AUTHORIZATION_SIGNING_KEY_FILE";

    internal static Task<int> RunExtensionRepairForTestsAsync(
        IReadOnlyList<string> arguments, TextWriter output, TextWriter error,
        Func<string, string?> environment, CancellationToken cancellationToken)
    {
        ConsoleInvocation invocation = ConsoleInvocation.Parse(arguments);
        return RunExtensionRepairBoundaryAsync(invocation.Command, invocation.ConfigPath, environment,
            output, error, cancellationToken);
    }

    private static async Task<int> RunExtensionRepairBoundaryAsync(
        string command, string configPath, Func<string, string?> environment,
        TextWriter output, TextWriter error, CancellationToken cancellationToken)
    {
        string? reservedOutputPath = null;
        bool ddlAttempted = false;
        bool published = false;
        try
        {
            if (environment(DeployEnabledEnvironmentVariable) != "false")
            {
                throw new MigrationConsoleException("target_extension_repair_deploy_gate_invalid", "Deployment must remain disabled.");
            }
            if (environment("LEGACY_MIGRATION_CALLER") != "owner")
            {
                throw new MigrationConsoleException("target_extension_repair_caller_invalid", "Owner authority is required.");
            }
            MigrationConsoleConfiguration root = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
                configPath, "target_extension_repair_config_unprotected", cancellationToken).ConfigureAwait(false);
            TargetExtensionRepairCommandConfiguration config = root.TargetExtensionRepair ??
                throw new MigrationConsoleException("target_extension_repair_config_missing", "Repair configuration is required.");
            if (File.Exists(config.OutputPath) || Directory.Exists(config.OutputPath))
            {
                throw new MigrationConsoleException("target_extension_repair_output_exists", "The receipt path must be new.");
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
                throw new MigrationConsoleException("target_extension_repair_output_unprotected", "The reserved receipt must be owner-only.");
            }
            byte[] pending = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = "1.0",
                state = "pending",
                command,
                database = config.Database,
                reservedAtUtc = DateTimeOffset.UtcNow
            }, JsonOptions);
            await reservation.WriteAsync(pending, cancellationToken).ConfigureAwait(false);
            await reservation.FlushAsync(cancellationToken).ConfigureAwait(false);
            reservation.Flush(flushToDisk: true);
            if (config.Database is not ("Material" or "QuotationRequest") ||
                !DeltaSynchronizationPlanProducer.ValidAuthority(config.TargetAuthority,
                    "local-aspire", "legacy-postgres-main-local"))
            {
                throw new MigrationConsoleException("target_extension_repair_target_invalid", "Only an exact local Aspire target is supported.");
            }
            FreshSchemaPlan schema = await ReadProtectedJsonAsync<FreshSchemaPlan>(config.SchemaPlanPath,
                "target_extension_repair_schema_unprotected", cancellationToken).ConfigureAwait(false);
            if (schema.SchemaVersion != "2.0" || !schema.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
            {
                throw new MigrationConsoleException("target_extension_repair_schema_inventory_invalid", "An exact-23 schema plan is required.");
            }
            DatabaseSchemaPlan database = schema.Databases.Single(item => item.Database == config.Database);
            if (config.ReviewedMissingTables != TargetExtensionRepairAuthorizationProducer.ExpectedMissingSet(database))
            {
                throw new MigrationConsoleException("target_extension_repair_missing_set_invalid", "The reviewed missing set differs from the approved extension profile.");
            }
            string target = await ReadProtectedTextAsync(config.TargetConnectionFile,
                "target_extension_repair_connection_unprotected", cancellationToken).ConfigureAwait(false);
            await DefaultGuardedDeltaConsoleRuntime.VerifyTargetAuthorityAsync(target, config.TargetAuthority,
                cancellationToken).ConfigureAwait(false);
            byte[] publicKey = Convert.FromBase64String(await ReadProtectedTextAsync(
                config.AuthorizationKey.SubjectPublicKeyInfoPath,
                "target_extension_repair_trust_unprotected", cancellationToken).ConfigureAwait(false));
            var trust = new ReceiptAttestationTrustStore([new(config.AuthorizationKey.KeyId, publicKey)]);

            object result;
            if (command == "authorize-target-extension-repair")
            {
                if (!config.AllowAuthorizationSigning || config.AuthorizationExpiresAtUtc is null)
                {
                    throw new MigrationConsoleException("target_extension_repair_authorization_disabled", "DDL authorization signing is disabled.");
                }
                TargetSchemaGap gap = await TargetSchemaGapInspector.InspectDatabaseAsync(database, target,
                    cancellationToken).ConfigureAwait(false);
                if (gap.MissingTables.Count != 0 || gap.MissingColumns.Count != 0 ||
                    gap.TargetOnlyTables.Count != 0 || gap.TargetOnlyColumns.Count != 0 ||
                    string.Join(';', gap.MissingApprovedTargetExtensions) != config.ReviewedMissingTables)
                {
                    throw new MigrationConsoleException("target_extension_repair_schema_drift", "Target inventory differs from the reviewed missing set.");
                }
                string keyPath = environment(ExtensionRepairAuthorizationKeyEnvironmentVariable) ??
                    throw new MigrationConsoleException("target_extension_repair_signer_missing", "The protected DDL signer reference is required.");
                using var signer = new P256MigrationEvidenceSigner(config.AuthorizationKey.KeyId,
                    await ReadProtectedTextAsync(keyPath, "target_extension_repair_signer_unprotected",
                        cancellationToken).ConfigureAwait(false));
                if (!trust.TryGetPublicKeyFingerprintSha256(config.AuthorizationKey.KeyId, out string fingerprint) ||
                    fingerprint != signer.PublicKeyFingerprintSha256)
                {
                    throw new MigrationConsoleException("target_extension_repair_signer_mismatch", "The DDL signer is not trusted.");
                }
                result = TargetExtensionRepairAuthorizationProducer.Produce(database, schema.SourceCommitSha,
                    config.TargetAuthority, config.ReviewedMissingTables, DateTimeOffset.UtcNow,
                    config.AuthorizationExpiresAtUtc.Value, signer);
            }
            else if (command == "apply-target-extension-repair")
            {
                if (!config.AllowExecution || string.IsNullOrWhiteSpace(config.AuthorizationPath))
                {
                    throw new MigrationConsoleException("target_extension_repair_execution_disabled", "DDL execution is disabled.");
                }
                TargetExtensionRepairAuthorization authorization =
                    await ReadProtectedJsonAsync<TargetExtensionRepairAuthorization>(config.AuthorizationPath,
                        "target_extension_repair_authorization_unprotected", cancellationToken).ConfigureAwait(false);
                if (!TargetExtensionRepairAuthorizationVerifier.Verify(authorization, database,
                    schema.SourceCommitSha, config.TargetAuthority, config.ReviewedMissingTables, trust,
                    DateTimeOffset.UtcNow))
                {
                    throw new MigrationConsoleException("target_extension_repair_authorization_invalid", "The DDL authorization is stale or mismatched.");
                }
                var builder = new NpgsqlConnectionStringBuilder(target) { Database = config.Database, Pooling = false };
                ddlAttempted = true;
                string disposition = await ApprovedTargetExtensionRepair.ExecuteAsync(database,
                    builder.ConnectionString, config.Database, config.TargetAuthority.SystemIdentifierSha256,
                    config.ReviewedMissingTables, cancellationToken).ConfigureAwait(false);
                result = new
                {
                    schemaVersion = "1.0",
                    database = config.Database,
                    disposition,
                    authorizationId = authorization.AuthorizationId,
                    authorizationEnvelopeSha256 = Convert.ToHexString(SHA256.HashData(
                        JsonSerializer.SerializeToUtf8Bytes(authorization, JsonOptions))).ToLowerInvariant(),
                    sourceCommitSha = schema.SourceCommitSha,
                    reviewedMissingTables = config.ReviewedMissingTables,
                    targetAuthority = config.TargetAuthority,
                    targetSchemaSha256 = database.TargetSchemaSha256,
                    completedAtUtc = DateTimeOffset.UtcNow
                };
            }
            else
            {
                throw new MigrationConsoleException("target_extension_repair_command_invalid", "Unsupported DDL command.");
            }

            string completePath = config.OutputPath + ".complete-" + Guid.NewGuid().ToString("N");
            await WriteNewJsonAsync(completePath, result, cancellationToken).ConfigureAwait(false);
            File.Replace(completePath, config.OutputPath, destinationBackupFileName: null);
            published = true;
            await output.WriteLineAsync(command.Replace('-', '_') + "_complete").ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure)
        {
            if (reservedOutputPath is not null && !ddlAttempted && !published)
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
