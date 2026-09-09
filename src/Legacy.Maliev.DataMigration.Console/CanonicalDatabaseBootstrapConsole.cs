using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    private const string BootstrapAuthorizationSigningKeyEnvironmentVariable =
        "LEGACY_MIGRATION_CANONICAL_BOOTSTRAP_AUTHORIZATION_SIGNING_KEY_FILE";
    private const string BootstrapExecutionSigningKeyEnvironmentVariable =
        "LEGACY_MIGRATION_CANONICAL_BOOTSTRAP_EXECUTION_SIGNING_KEY_FILE";

    internal static Task<int> RunBootstrapForTestsAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<string, string?> environment,
        ICanonicalDatabaseBootstrapConsoleRuntime runtime,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ConsoleInvocation invocation = ConsoleInvocation.Parse(arguments);
        return RunBootstrapBoundaryAsync(invocation.Command, invocation.ConfigPath, environment, output, error,
            runtime, timeProvider, cancellationToken);
    }

    private static async Task<int> RunBootstrapBoundaryAsync(
        string command,
        string configPath,
        Func<string, string?> environment,
        TextWriter output,
        TextWriter error,
        ICanonicalDatabaseBootstrapConsoleRuntime runtime,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!string.Equals(environment(DeployEnabledEnvironmentVariable), "false", StringComparison.OrdinalIgnoreCase))
            {
                throw BootstrapInvalid("canonical_database_bootstrap_deploy_gate_invalid");
            }
            if (!string.Equals(environment("LEGACY_MIGRATION_CALLER"), "owner", StringComparison.Ordinal))
            {
                throw BootstrapInvalid("canonical_database_bootstrap_caller_invalid");
            }

            MigrationConsoleConfiguration root = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
                configPath, "canonical_database_bootstrap_config_unprotected", cancellationToken).ConfigureAwait(false);
            CanonicalDatabaseBootstrapCommandConfiguration configuration = root.CanonicalBootstrap ??
                throw BootstrapInvalid("canonical_database_bootstrap_configuration_missing");
            ValidateBootstrapConfiguration(configuration);
            object result = command switch
            {
                "authorize-canonical-bootstrap" => await AuthorizeBootstrapAsync(
                    configuration, environment, timeProvider, cancellationToken).ConfigureAwait(false),
                "bootstrap-canonical-database" => await ExecuteBootstrapAsync(
                    configuration, environment, runtime, timeProvider, cancellationToken).ConfigureAwait(false),
                _ => throw BootstrapInvalid("canonical_database_bootstrap_command_invalid"),
            };
            await WriteNewJsonAsync(configuration.OutputPath, result, cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(command.Replace('-', '_') + "_complete").ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure)
        {
            string code = failure switch
            {
                MigrationConsoleException value => value.Code,
                CanonicalDatabaseBootstrapException value => value.Code,
                IOException or UnauthorizedAccessException => "canonical_database_bootstrap_io_failed",
                OperationCanceledException => "operation_cancelled",
                _ => "canonical_database_bootstrap_failed",
            };
            if (code.Length > 100 || code.Any(value => value is not (>= 'a' and <= 'z') and not '_'))
            {
                code = "canonical_database_bootstrap_failed";
            }
            await error.WriteLineAsync(code).ConfigureAwait(false);
            return failure is OperationCanceledException ? 130 : failure is MigrationConsoleException ? 65 : 70;
        }
    }

    private static async Task<CanonicalDatabaseBootstrapAuthorization> AuthorizeBootstrapAsync(
        CanonicalDatabaseBootstrapCommandConfiguration configuration,
        Func<string, string?> environment,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        if (!configuration.AllowAuthorizationSigning || configuration.AuthorizationExpiresAtUtc is null)
        {
            throw BootstrapInvalid("canonical_database_bootstrap_authorization_owner_review_required");
        }
        DatabaseSchemaPlan schema = await ReadBootstrapSchemaAsync(configuration, cancellationToken).ConfigureAwait(false);
        BootstrapTrustBundle trust = await ReadBootstrapTrustAsync(configuration, cancellationToken).ConfigureAwait(false);
        using P256MigrationEvidenceSigner signer = await ReadBootstrapSignerAsync(
            environment, BootstrapAuthorizationSigningKeyEnvironmentVariable, configuration.AuthorizationKey,
            trust.AuthorizationFingerprint, cancellationToken).ConfigureAwait(false);
        DateTimeOffset issuedAtUtc = timeProvider.GetUtcNow();
        return CanonicalDatabaseBootstrapAuthorizationProducer.Produce(
            schema,
            configuration.DatabaseResourceName,
            configuration.DatabaseResourceUid,
            configuration.DatabaseResourceGeneration,
            configuration.TargetAuthority,
            issuedAtUtc,
            configuration.AuthorizationExpiresAtUtc.Value,
            signer);
    }

    private static async Task<CanonicalDatabaseBootstrapReceipt> ExecuteBootstrapAsync(
        CanonicalDatabaseBootstrapCommandConfiguration configuration,
        Func<string, string?> environment,
        ICanonicalDatabaseBootstrapConsoleRuntime runtime,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        if (!configuration.AllowExecution || string.IsNullOrWhiteSpace(configuration.AuthorizationPath))
        {
            throw BootstrapInvalid("canonical_database_bootstrap_execution_owner_review_required");
        }
        DatabaseSchemaPlan schema = await ReadBootstrapSchemaAsync(configuration, cancellationToken).ConfigureAwait(false);
        BootstrapTrustBundle trust = await ReadBootstrapTrustAsync(configuration, cancellationToken).ConfigureAwait(false);
        CanonicalDatabaseBootstrapAuthorization authorization =
            await ReadProtectedJsonAsync<CanonicalDatabaseBootstrapAuthorization>(
                configuration.AuthorizationPath,
                "canonical_database_bootstrap_authorization_unprotected",
                cancellationToken).ConfigureAwait(false);
        string targetConnection = await ReadProtectedTextAsync(
            configuration.TargetConnectionFile,
            "canonical_database_bootstrap_target_connection_unprotected",
            cancellationToken).ConfigureAwait(false);
        using P256MigrationEvidenceSigner signer = await ReadBootstrapSignerAsync(
            environment, BootstrapExecutionSigningKeyEnvironmentVariable, configuration.ExecutionKey,
            trust.ExecutionFingerprint, cancellationToken).ConfigureAwait(false);
        var request = new CanonicalDatabaseBootstrapRequest(
            schema,
            configuration.DatabaseResourceName,
            configuration.DatabaseResourceUid,
            configuration.DatabaseResourceGeneration,
            configuration.TargetAuthority);
        return await runtime.ExecuteAsync(new(
            request,
            authorization,
            targetConnection,
            configuration.ExpectedOwnerRole,
            trust.TrustStore,
            timeProvider,
            signer), cancellationToken).ConfigureAwait(false);
    }

    private static async Task<DatabaseSchemaPlan> ReadBootstrapSchemaAsync(
        CanonicalDatabaseBootstrapCommandConfiguration configuration,
        CancellationToken cancellationToken)
    {
        FreshSchemaPlan plan = await ReadProtectedJsonAsync<FreshSchemaPlan>(
            configuration.SchemaPlanPath,
            "canonical_database_bootstrap_schema_plan_unprotected",
            cancellationToken).ConfigureAwait(false);
        return plan.Databases.SingleOrDefault(database =>
            string.Equals(database.Database, configuration.Database, StringComparison.Ordinal)) ??
            throw BootstrapInvalid("canonical_database_bootstrap_schema_missing");
    }

    private static async Task<BootstrapTrustBundle> ReadBootstrapTrustAsync(
        CanonicalDatabaseBootstrapCommandConfiguration configuration,
        CancellationToken cancellationToken)
    {
        byte[] authorizationPublicKey = Convert.FromBase64String(await ReadProtectedTextAsync(
            configuration.AuthorizationKey.SubjectPublicKeyInfoPath,
            "canonical_database_bootstrap_trusted_key_unprotected",
            cancellationToken).ConfigureAwait(false));
        byte[] executionPublicKey = Convert.FromBase64String(await ReadProtectedTextAsync(
            configuration.ExecutionKey.SubjectPublicKeyInfoPath,
            "canonical_database_bootstrap_trusted_key_unprotected",
            cancellationToken).ConfigureAwait(false));
        var trust = new ReceiptAttestationTrustStore(
            [
                new(configuration.AuthorizationKey.KeyId, authorizationPublicKey),
                new(configuration.ExecutionKey.KeyId, executionPublicKey),
            ]);
        _ = trust.TryGetPublicKeyFingerprintSha256(
            configuration.AuthorizationKey.KeyId, out string authorizationFingerprint);
        _ = trust.TryGetPublicKeyFingerprintSha256(
            configuration.ExecutionKey.KeyId, out string executionFingerprint);
        return string.Equals(configuration.AuthorizationKey.KeyId, configuration.ExecutionKey.KeyId, StringComparison.Ordinal) ||
            CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(authorizationFingerprint), Convert.FromHexString(executionFingerprint))
            ? throw BootstrapInvalid("canonical_database_bootstrap_signing_role_key_reuse")
            : new(trust, authorizationFingerprint, executionFingerprint);
    }

    private static async Task<P256MigrationEvidenceSigner> ReadBootstrapSignerAsync(
        Func<string, string?> environment,
        string variable,
        BootstrapTrustedKeyReference key,
        string expectedFingerprint,
        CancellationToken cancellationToken)
    {
        string keyPath = Required(environment(variable));
        var signer = new P256MigrationEvidenceSigner(key.KeyId, await ReadProtectedTextAsync(
            keyPath, "canonical_database_bootstrap_signing_key_unprotected", cancellationToken).ConfigureAwait(false));
        if (!string.Equals(signer.PublicKeyFingerprintSha256, expectedFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            signer.Dispose();
            throw BootstrapInvalid("canonical_database_bootstrap_signing_key_mismatch");
        }
        return signer;
    }

    private static void ValidateBootstrapConfiguration(CanonicalDatabaseBootstrapCommandConfiguration configuration)
    {
        if (string.IsNullOrWhiteSpace(configuration.OutputPath) || File.Exists(configuration.OutputPath) ||
            Directory.Exists(configuration.OutputPath) ||
            !DatabaseInventory.ActiveDatabases.Contains(configuration.Database, StringComparer.Ordinal) ||
            !string.Equals(configuration.TargetNamespace, LegacyNamespace, StringComparison.Ordinal) ||
            !string.Equals(configuration.TargetCluster, LegacyPostgreSqlCluster, StringComparison.Ordinal) ||
            !DeltaSynchronizationPlanProducer.ValidAuthority(
                configuration.TargetAuthority, configuration.TargetNamespace, configuration.TargetCluster))
        {
            throw BootstrapInvalid("canonical_database_bootstrap_configuration_invalid");
        }
        OwnerProtectedFilePolicy.ValidatePublicationParent(configuration.OutputPath);
    }

    private static MigrationConsoleException BootstrapInvalid(string code)
    {
        return new(code, "The guarded canonical database bootstrap command is invalid.");
    }

    private sealed record BootstrapTrustBundle(
        ReceiptAttestationTrustStore TrustStore,
        string AuthorizationFingerprint,
        string ExecutionFingerprint);
}

internal sealed record BootstrapTrustedKeyReference(string KeyId, string SubjectPublicKeyInfoPath);

internal sealed record CanonicalDatabaseBootstrapCommandConfiguration(
    string SchemaPlanPath,
    string Database,
    string OutputPath,
    string TargetConnectionFile,
    string ExpectedOwnerRole,
    string DatabaseResourceName,
    string DatabaseResourceUid,
    string DatabaseResourceGeneration,
    string TargetNamespace,
    string TargetCluster,
    DeltaTargetAuthority TargetAuthority,
    BootstrapTrustedKeyReference AuthorizationKey,
    BootstrapTrustedKeyReference ExecutionKey,
    string? AuthorizationPath = null,
    DateTimeOffset? AuthorizationExpiresAtUtc = null,
    bool AllowAuthorizationSigning = false,
    bool AllowExecution = false);

internal sealed record CanonicalDatabaseBootstrapConsoleRuntimeRequest(
    CanonicalDatabaseBootstrapRequest Request,
    CanonicalDatabaseBootstrapAuthorization Authorization,
    string TargetConnectionString,
    string ExpectedOwnerRole,
    IReceiptAttestationTrustStore AuthorizationTrust,
    TimeProvider TimeProvider,
    P256MigrationEvidenceSigner ExecutionSigner);

internal interface ICanonicalDatabaseBootstrapConsoleRuntime
{
    Task<CanonicalDatabaseBootstrapReceipt> ExecuteAsync(
        CanonicalDatabaseBootstrapConsoleRuntimeRequest request,
        CancellationToken cancellationToken);
}

internal sealed class DefaultCanonicalDatabaseBootstrapConsoleRuntime : ICanonicalDatabaseBootstrapConsoleRuntime
{
    public Task<CanonicalDatabaseBootstrapReceipt> ExecuteAsync(
        CanonicalDatabaseBootstrapConsoleRuntimeRequest request,
        CancellationToken cancellationToken)
    {
        var executor = new CanonicalDatabaseBootstrapExecutor(
            request.Authorization,
            request.AuthorizationTrust,
            request.TimeProvider,
            request.ExecutionSigner);
        return executor.ExecuteAsync(
            request.Request,
            request.TargetConnectionString,
            request.ExpectedOwnerRole,
            cancellationToken);
    }
}
