using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    private const string DeltaPlanSigningKeyEnvironmentVariable = "LEGACY_MIGRATION_DELTA_PLAN_SIGNING_KEY_FILE";
    private const string DeltaAuthorizationSigningKeyEnvironmentVariable = "LEGACY_MIGRATION_DELTA_AUTHORIZATION_SIGNING_KEY_FILE";
    private const string DeltaEvidenceSigningKeyEnvironmentVariable = "LEGACY_MIGRATION_DELTA_EVIDENCE_SIGNING_KEY_FILE";

    internal static Task<int> RunDeltaForTestsAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<string, string?> environment,
        IGuardedDeltaConsoleRuntime runtime,
        CancellationToken cancellationToken)
    {
        ConsoleInvocation invocation = ConsoleInvocation.Parse(arguments);
        return RunDeltaBoundaryAsync(invocation.Command, invocation.ConfigPath, environment, output, error, runtime,
            cancellationToken);
    }

    private static async Task<int> RunDeltaBoundaryAsync(
        string command,
        string configPath,
        Func<string, string?> environment,
        TextWriter output,
        TextWriter error,
        IGuardedDeltaConsoleRuntime runtime,
        CancellationToken cancellationToken)
    {
        try
        {
            if (!string.Equals(environment(DeployEnabledEnvironmentVariable), "false", StringComparison.OrdinalIgnoreCase))
            {
                throw DeltaInvalid("delta_deploy_gate_invalid");
            }
            GuardedDeltaCommandPolicy.ValidateCaller(command, environment("LEGACY_MIGRATION_CALLER"));

            MigrationConsoleConfiguration root = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
                configPath, "delta_config_unprotected", cancellationToken).ConfigureAwait(false);
            DeltaCommandConfiguration configuration = root.Delta ?? throw DeltaInvalid("delta_configuration_missing");
            ValidateDeltaConfiguration(command, configuration);
            object result = command switch
            {
                "plan-delta" => await ProduceDeltaPlanAsync(configuration, environment, runtime, cancellationToken).ConfigureAwait(false),
                "authorize-delta" => await ProduceDeltaAuthorizationAsync(configuration, environment, cancellationToken).ConfigureAwait(false),
                "apply-delta-local" => await ApplyDeltaAsync(configuration, DeltaTargetAuthorityKind.LocalAspire, runtime, cancellationToken).ConfigureAwait(false),
                "apply-delta-production" => await ApplyDeltaAsync(configuration, DeltaTargetAuthorityKind.ProductionCloudNativePg, runtime, cancellationToken).ConfigureAwait(false),
                "reconcile-delta" => await ReconcileDeltaAsync(configuration, environment, runtime, cancellationToken).ConfigureAwait(false),
                _ => throw DeltaInvalid("delta_command_invalid"),
            };
            await WriteNewJsonAsync(configuration.OutputPath, result, cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(command.Replace("-", "_", StringComparison.Ordinal) + "_complete").ConfigureAwait(false);
            return 0;
        }
        catch (Exception failure)
        {
            string code = failure switch
            {
                MigrationConsoleException value => value.Code,
                DeltaExecutionException value => value.Code,
                DeltaPlanException value => value.Code,
                MigrationExecutionException value => value.Code,
                JsonException or ArgumentException or FormatException or CryptographicException => "delta_configuration_invalid",
                IOException or UnauthorizedAccessException => "delta_io_failed",
                OperationCanceledException => "operation_cancelled",
                _ => "delta_execution_failed",
            };
            if (code.Length > 100 || code.Any(value => value is not (>= 'a' and <= 'z') and not '_'))
            {
                code = "delta_execution_failed";
            }
            await error.WriteLineAsync(code).ConfigureAwait(false);
            if (failure is MigrationExecutionException { Reconciliation: { } diagnostic })
            {
                await WriteSafeReconciliationDiagnosticAsync(error, diagnostic).ConfigureAwait(false);
            }
            return failure is OperationCanceledException ? 130 : failure is MigrationConsoleException or DeltaPlanException or
                JsonException or ArgumentException or FormatException or CryptographicException ? 65 : 70;
        }
    }

    private static async Task<DeltaSynchronizationPlan> ProduceDeltaPlanAsync(
        DeltaCommandConfiguration configuration,
        Func<string, string?> environment,
        IGuardedDeltaConsoleRuntime runtime,
        CancellationToken cancellationToken)
    {
        if (!configuration.AllowPlanSigning)
        {
            throw DeltaInvalid("delta_plan_owner_review_required");
        }
        FreshSchemaPlan schema = await ReadProtectedJsonAsync<FreshSchemaPlan>(configuration.SchemaPlanPath,
            "delta_schema_plan_unprotected", cancellationToken).ConfigureAwait(false);
        DeltaTrustBundle trust = await ReadDeltaTrustAsync(configuration, cancellationToken).ConfigureAwait(false);
        using P256MigrationEvidenceSigner signer = await ReadDeltaSignerAsync(environment,
            DeltaPlanSigningKeyEnvironmentVariable, configuration.PlanKey.KeyId, trust.PlanFingerprint,
            "delta_plan_signing_key_unprotected", cancellationToken).ConfigureAwait(false);
        string source = await ReadProtectedTextAsync(configuration.SourceConnectionFile,
            "delta_source_connection_unprotected", cancellationToken).ConfigureAwait(false);
        string target = await ReadProtectedTextAsync(configuration.TargetConnectionFile,
            "delta_target_connection_unprotected", cancellationToken).ConfigureAwait(false);
        return await runtime.PlanAsync(new(schema, source, target, configuration,
            trust.AuthorizationFingerprint, signer), cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<DeltaExecutionAuthorization> ProduceDeltaAuthorizationAsync(
        DeltaCommandConfiguration configuration,
        Func<string, string?> environment,
        CancellationToken cancellationToken)
    {
        if (!configuration.AllowAuthorizationSigning || configuration.AuthorizationExpiresAtUtc is null)
        {
            throw DeltaInvalid("delta_authorization_owner_review_required");
        }
        DeltaSynchronizationPlan plan = await ReadProtectedJsonAsync<DeltaSynchronizationPlan>(Required(configuration.PlanPath),
            "delta_plan_unprotected", cancellationToken).ConfigureAwait(false);
        DeltaTrustBundle trust = await ReadDeltaTrustAsync(configuration, cancellationToken).ConfigureAwait(false);
        if (!DeltaSynchronizationPlanVerifier.Verify(plan, trust.TrustStore, DateTimeOffset.UtcNow))
        {
            throw DeltaInvalid("delta_plan_invalid");
        }
        using P256MigrationEvidenceSigner signer = await ReadDeltaSignerAsync(environment,
            DeltaAuthorizationSigningKeyEnvironmentVariable, configuration.AuthorizationKey.KeyId,
            trust.AuthorizationFingerprint, "delta_authorization_signing_key_unprotected", cancellationToken)
            .ConfigureAwait(false);
        DateTimeOffset issuedAtUtc = DateTimeOffset.UtcNow;
        return DeltaExecutionAuthorizationProducer.Produce(plan, issuedAtUtc,
            configuration.AuthorizationExpiresAtUtc.Value, signer);
    }

    private static async Task<Exact23DeltaExecutionResult> ApplyDeltaAsync(
        DeltaCommandConfiguration configuration,
        string requiredAuthorityKind,
        IGuardedDeltaConsoleRuntime runtime,
        CancellationToken cancellationToken)
    {
        if (!configuration.AllowExecution || !string.Equals(configuration.TargetAuthority.Kind, requiredAuthorityKind, StringComparison.Ordinal))
        {
            throw DeltaInvalid("delta_execution_owner_review_required");
        }
        FreshSchemaPlan schema = await ReadProtectedJsonAsync<FreshSchemaPlan>(configuration.SchemaPlanPath,
            "delta_schema_plan_unprotected", cancellationToken).ConfigureAwait(false);
        DeltaSynchronizationPlan plan = await ReadProtectedJsonAsync<DeltaSynchronizationPlan>(Required(configuration.PlanPath),
            "delta_plan_unprotected", cancellationToken).ConfigureAwait(false);
        DeltaExecutionAuthorization authorization = await ReadProtectedJsonAsync<DeltaExecutionAuthorization>(Required(configuration.AuthorizationPath),
            "delta_authorization_unprotected", cancellationToken).ConfigureAwait(false);
        DeltaTrustBundle trust = await ReadDeltaTrustAsync(configuration, cancellationToken).ConfigureAwait(false);
        string source = await ReadProtectedTextAsync(configuration.SourceConnectionFile,
            "delta_source_connection_unprotected", cancellationToken).ConfigureAwait(false);
        string target = await ReadProtectedTextAsync(configuration.TargetConnectionFile,
            "delta_target_connection_unprotected", cancellationToken).ConfigureAwait(false);
        return await runtime.ApplyAsync(new(schema, plan, authorization, source, target, configuration.TargetAuthority,
            trust.TrustStore), cancellationToken).ConfigureAwait(false);
    }

    private static async Task<Exact23DeltaReconciliationResult> ReconcileDeltaAsync(
        DeltaCommandConfiguration configuration,
        Func<string, string?> environment,
        IGuardedDeltaConsoleRuntime runtime,
        CancellationToken cancellationToken)
    {
        FreshSchemaPlan schema = await ReadProtectedJsonAsync<FreshSchemaPlan>(configuration.SchemaPlanPath,
            "delta_schema_plan_unprotected", cancellationToken).ConfigureAwait(false);
        DeltaSynchronizationPlan plan = await ReadProtectedJsonAsync<DeltaSynchronizationPlan>(Required(configuration.PlanPath),
            "delta_plan_unprotected", cancellationToken).ConfigureAwait(false);
        DeltaTrustBundle trust = await ReadDeltaTrustAsync(configuration, cancellationToken).ConfigureAwait(false);
        if (!DeltaSynchronizationPlanVerifier.Verify(plan, trust.TrustStore, DateTimeOffset.UtcNow) ||
            plan.TargetAuthority != configuration.TargetAuthority ||
            !string.Equals(plan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(schema), StringComparison.Ordinal) ||
            !string.Equals(plan.SourceCommitSha, schema.SourceCommitSha, StringComparison.Ordinal))
        {
            throw DeltaInvalid("delta_plan_invalid");
        }
        using P256MigrationEvidenceSigner signer = await ReadDeltaSignerAsync(environment,
            DeltaEvidenceSigningKeyEnvironmentVariable, configuration.EvidenceKey.KeyId, trust.EvidenceFingerprint,
            "delta_evidence_signing_key_unprotected", cancellationToken).ConfigureAwait(false);
        string source = await ReadProtectedTextAsync(configuration.SourceConnectionFile,
            "delta_source_connection_unprotected", cancellationToken).ConfigureAwait(false);
        string target = await ReadProtectedTextAsync(configuration.TargetConnectionFile,
            "delta_target_connection_unprotected", cancellationToken).ConfigureAwait(false);
        return await runtime.ReconcileAsync(new(schema, plan, source, target, signer), cancellationToken)
            .ConfigureAwait(false);
    }

    private static void ValidateDeltaConfiguration(string command, DeltaCommandConfiguration configuration)
    {
        if (string.IsNullOrWhiteSpace(configuration.OutputPath) || File.Exists(configuration.OutputPath) || Directory.Exists(configuration.OutputPath))
        {
            throw DeltaInvalid("delta_output_exists");
        }
        OwnerProtectedFilePolicy.ValidatePublicationParent(configuration.OutputPath);
        if ((command == "apply-delta-local" && configuration.TargetAuthority.Kind != DeltaTargetAuthorityKind.LocalAspire) ||
            (command == "apply-delta-production" && configuration.TargetAuthority.Kind != DeltaTargetAuthorityKind.ProductionCloudNativePg))
        {
            throw DeltaInvalid("delta_command_authority_invalid");
        }
        if (!DeltaSynchronizationPlanProducer.ValidAuthority(configuration.TargetAuthority,
            configuration.TargetNamespace, configuration.TargetCluster))
        {
            throw DeltaInvalid("delta_target_authority_invalid");
        }
    }

    private static async Task<DeltaTrustBundle> ReadDeltaTrustAsync(
        DeltaCommandConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var keys = new List<TrustedAttestationKey>(3);
        foreach (DeltaTrustedKeyReference reference in new[]
            { configuration.PlanKey, configuration.AuthorizationKey, configuration.EvidenceKey })
        {
            byte[] publicKey = Convert.FromBase64String(await ReadProtectedTextAsync(
                reference.SubjectPublicKeyInfoPath, "delta_trusted_key_unprotected", cancellationToken).ConfigureAwait(false));
            keys.Add(new(reference.KeyId, publicKey));
        }
        var trust = new ReceiptAttestationTrustStore(keys);
        _ = trust.TryGetPublicKeyFingerprintSha256(configuration.PlanKey.KeyId, out string planFingerprint);
        _ = trust.TryGetPublicKeyFingerprintSha256(configuration.AuthorizationKey.KeyId, out string authorizationFingerprint);
        _ = trust.TryGetPublicKeyFingerprintSha256(configuration.EvidenceKey.KeyId, out string evidenceFingerprint);
        string[] fingerprints = [planFingerprint, authorizationFingerprint, evidenceFingerprint,
            configuration.BackupKeyFingerprintSha256];
        return fingerprints.All(IsSha256) && fingerprints.Distinct(StringComparer.OrdinalIgnoreCase).Count() == fingerprints.Length
            ? new(trust, planFingerprint, authorizationFingerprint, evidenceFingerprint)
            : throw DeltaInvalid("delta_signing_role_key_reuse");
    }

    private static async Task<P256MigrationEvidenceSigner> ReadDeltaSignerAsync(
        Func<string, string?> environment,
        string variable,
        string keyId,
        string expectedFingerprint,
        string unprotectedCode,
        CancellationToken cancellationToken)
    {
        string keyPath = Required(environment(variable));
        var signer = new P256MigrationEvidenceSigner(keyId,
            await ReadProtectedTextAsync(keyPath, unprotectedCode, cancellationToken).ConfigureAwait(false));
        if (!string.Equals(signer.PublicKeyFingerprintSha256, expectedFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            signer.Dispose();
            throw DeltaInvalid("delta_signing_key_mismatch");
        }
        return signer;
    }

    private static bool IsSha256(string value)
    {
        return value.Length == 64 && value.All(char.IsAsciiHexDigit);
    }

    private static MigrationConsoleException DeltaInvalid(string code)
    {
        return new(code, "The guarded exact-23 delta command configuration is invalid.");
    }

    private sealed record DeltaTrustBundle(
        ReceiptAttestationTrustStore TrustStore,
        string PlanFingerprint,
        string AuthorizationFingerprint,
        string EvidenceFingerprint);
}

internal sealed record DeltaTrustedKeyReference(string KeyId, string SubjectPublicKeyInfoPath);

internal sealed record DeltaCommandConfiguration(
    string SchemaPlanPath,
    string OutputPath,
    string SourceConnectionFile,
    string TargetConnectionFile,
    DeltaTrustedKeyReference PlanKey,
    DeltaTrustedKeyReference AuthorizationKey,
    DeltaTrustedKeyReference EvidenceKey,
    string BackupKeyFingerprintSha256,
    DateTimeOffset SourceCutoffUtc,
    string BackupManifestSha256,
    string RunnerDigestSha256,
    string TargetNamespace,
    string TargetCluster,
    string TargetGeneration,
    string TargetObservationSha256,
    DeltaTargetAuthority TargetAuthority,
    string? PlanPath = null,
    string? AuthorizationPath = null,
    DateTimeOffset? AuthorizationExpiresAtUtc = null,
    bool AllowPlanSigning = false,
    bool AllowAuthorizationSigning = false,
    bool AllowExecution = false);

internal static class GuardedDeltaCommandPolicy
{
    internal static bool IsAppHostCallable(string command)
    {
        return string.Equals(command, "apply-delta-local", StringComparison.Ordinal);
    }

    internal static void ValidateCaller(string command, string? caller)
    {
        bool valid = caller switch
        {
            "owner" => true,
            "operator" => command is "plan-delta" or "apply-delta-local" or "reconcile-delta",
            "apphost" => IsAppHostCallable(command),
            _ => false,
        };
        if (!valid)
        {
            throw new MigrationConsoleException("delta_caller_invalid",
                "The guarded delta command is unavailable to this caller role.");
        }
    }
}

internal sealed record DeltaPlanRuntimeRequest(
    FreshSchemaPlan Schema,
    string SourceConnectionString,
    string TargetConnectionString,
    DeltaCommandConfiguration Configuration,
    string AuthorizationKeyFingerprintSha256,
    P256MigrationEvidenceSigner Signer);

internal sealed record DeltaApplyRuntimeRequest(
    FreshSchemaPlan Schema,
    DeltaSynchronizationPlan Plan,
    DeltaExecutionAuthorization Authorization,
    string SourceConnectionString,
    string TargetConnectionString,
    DeltaTargetAuthority ExpectedAuthority,
    ReceiptAttestationTrustStore Trust);

internal sealed record DeltaReconcileRuntimeRequest(
    FreshSchemaPlan Schema,
    DeltaSynchronizationPlan Plan,
    string SourceConnectionString,
    string TargetConnectionString,
    P256MigrationEvidenceSigner Signer);

internal interface IGuardedDeltaConsoleRuntime
{
    Task<DeltaSynchronizationPlan> PlanAsync(DeltaPlanRuntimeRequest request, CancellationToken cancellationToken);
    Task<Exact23DeltaExecutionResult> ApplyAsync(DeltaApplyRuntimeRequest request, CancellationToken cancellationToken);
    Task<Exact23DeltaReconciliationResult> ReconcileAsync(DeltaReconcileRuntimeRequest request, CancellationToken cancellationToken);
}

internal sealed class DefaultGuardedDeltaConsoleRuntime : IGuardedDeltaConsoleRuntime
{
    public async Task<DeltaSynchronizationPlan> PlanAsync(DeltaPlanRuntimeRequest request, CancellationToken cancellationToken)
    {
        await VerifyTargetAuthorityAsync(request.TargetConnectionString, request.Configuration.TargetAuthority,
            cancellationToken).ConfigureAwait(false);
        var targetSchema = new PostgreSqlDeltaReconciliationInspector(new(request.TargetConnectionString));
        foreach (DatabaseSchemaPlan database in request.Schema.Databases)
        {
            await targetSchema.ValidateSchemaAsync(database, cancellationToken).ConfigureAwait(false);
        }
        await using var source = new SqlServerMigrationSource(new(request.SourceConnectionString));
        var opened = new List<string>(DatabaseInventory.ActiveDatabases.Count);
        try
        {
            foreach (string database in DatabaseInventory.ActiveDatabases)
            {
                await source.BeginDatabaseSnapshotAsync(database, cancellationToken).ConfigureAwait(false);
                opened.Add(database);
            }
            var coordinator = new Exact23DeltaPlanCoordinator(
                new SqlServerSnapshotDeltaRowSource(source),
                new PostgreSqlDeltaRowSource(new(request.TargetConnectionString)),
                request.Signer,
                TimeProvider.System);
            DeltaCommandConfiguration configuration = request.Configuration;
            DeltaSynchronizationPlan result = await coordinator.ProduceAsync(new(
                request.Schema,
                configuration.SourceCutoffUtc,
                configuration.BackupManifestSha256,
                configuration.RunnerDigestSha256,
                configuration.TargetNamespace,
                configuration.TargetCluster,
                configuration.TargetGeneration,
                configuration.TargetObservationSha256,
                configuration.BackupKeyFingerprintSha256,
                request.AuthorizationKeyFingerprintSha256)
            {
                TargetAuthority = configuration.TargetAuthority,
            }, cancellationToken).ConfigureAwait(false);
            foreach (string database in opened)
            {
                await source.CompleteDatabaseSnapshotAsync(database, cancellationToken).ConfigureAwait(false);
            }
            opened.Clear();
            return result;
        }
        catch
        {
            foreach (string database in opened)
            {
                await source.RollbackDatabaseSnapshotAsync(database, CancellationToken.None).ConfigureAwait(false);
            }
            throw;
        }
    }

    public async Task<Exact23DeltaExecutionResult> ApplyAsync(DeltaApplyRuntimeRequest request, CancellationToken cancellationToken)
    {
        if (!DeltaSynchronizationPlanVerifier.Verify(request.Plan, request.Trust, TimeProvider.System.GetUtcNow()) ||
            request.Plan.TargetAuthority != request.ExpectedAuthority)
        {
            throw new DeltaExecutionException("delta_execution_plan_invalid", "The signed delta plan is invalid or targets another authority.");
        }
        await VerifyTargetAuthorityAsync(request.TargetConnectionString, request.ExpectedAuthority, cancellationToken)
            .ConfigureAwait(false);
        var gate = new SignedDeltaExecutionAuthorizationGate(request.Authorization, request.Trust,
            TimeProvider.System, request.ExpectedAuthority);
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            await gate.ValidateAsync(request.Plan, database, cancellationToken).ConfigureAwait(false);
        }
        await new PostgreSqlDeltaMetadataProvisioner(new(request.TargetConnectionString, request.ExpectedAuthority))
            .ProvisionAsync(request.Plan, request.Schema, cancellationToken).ConfigureAwait(false);
        await using var source = new SqlServerMigrationSource(new(request.SourceConnectionString));
        var targetRows = new PostgreSqlDeltaRowSource(new(request.TargetConnectionString));
        DeltaExecutionCoordinator CreateExecutor(string database)
        {
            string connection = new NpgsqlConnectionStringBuilder(request.TargetConnectionString)
            {
                Database = database,
                Pooling = false,
            }.ConnectionString;
            return new(
                new PostgreSqlDeltaCanonicalTarget(new(connection, database, request.Plan.TargetGeneration)),
                new OrderedDeltaExecutionRowSessionProvider(new SqlServerSnapshotDeltaExecutionRowSource(source), targetRows),
                gate,
                new SqlServerDeltaReconciliationInspector(source),
                request.Trust,
                TimeProvider.System);
        }
        return await new Exact23DeltaExecutionCoordinator(source, CreateExecutor)
            .ExecuteAsync(request.Plan, request.Schema, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Exact23DeltaReconciliationResult> ReconcileAsync(DeltaReconcileRuntimeRequest request, CancellationToken cancellationToken)
    {
        await VerifyTargetAuthorityAsync(request.TargetConnectionString,
            request.Plan.TargetAuthority ?? throw new DeltaExecutionException("delta_target_authority_invalid", "The delta plan has no target authority."),
            cancellationToken).ConfigureAwait(false);
        await using var source = new SqlServerMigrationSource(new(request.SourceConnectionString));
        var opened = new List<string>(DatabaseInventory.ActiveDatabases.Count);
        try
        {
            foreach (string database in DatabaseInventory.ActiveDatabases)
            {
                await source.BeginDatabaseSnapshotAsync(database, cancellationToken).ConfigureAwait(false);
                opened.Add(database);
            }
            var coordinator = new Exact23DeltaReconciliationCoordinator(
                new SqlServerDeltaReconciliationInspector(source),
                new PostgreSqlDeltaReconciliationInspector(new(request.TargetConnectionString)),
                new PostgreSqlExact23DeltaCheckpointReader(new(request.TargetConnectionString)),
                TimeProvider.System,
                request.Signer);
            Exact23DeltaReconciliationResult result = await coordinator.ReconcileAsync(
                request.Plan, request.Schema, cancellationToken).ConfigureAwait(false);
            foreach (string database in opened)
            {
                await source.CompleteDatabaseSnapshotAsync(database, cancellationToken).ConfigureAwait(false);
            }
            opened.Clear();
            return result;
        }
        catch
        {
            foreach (string database in opened)
            {
                await source.RollbackDatabaseSnapshotAsync(database, CancellationToken.None).ConfigureAwait(false);
            }
            throw;
        }
    }

    private static async Task VerifyTargetAuthorityAsync(
        string connectionString,
        DeltaTargetAuthority expected,
        CancellationToken cancellationToken)
    {
        var builder = new NpgsqlConnectionStringBuilder(connectionString)
        {
            Pooling = false,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", connection);
        string identifier = Convert.ToString(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
            System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        string fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identifier))).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(fingerprint),
            Encoding.ASCII.GetBytes(expected.SystemIdentifierSha256.ToLowerInvariant())))
        {
            throw new DeltaExecutionException("delta_target_system_identifier_invalid",
                "The opened PostgreSQL cluster does not match the signed target authority.");
        }

        await using var inventoryCommand = new NpgsqlCommand(
            "SELECT datname FROM pg_database WHERE datistemplate = false AND datname <> 'postgres' ORDER BY datname;",
            connection);
        var databases = new List<string>();
        await using NpgsqlDataReader reader = await inventoryCommand.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            databases.Add(reader.GetString(0));
        }
        Exact23TargetDatabaseInventory.Validate(databases);
    }
}
