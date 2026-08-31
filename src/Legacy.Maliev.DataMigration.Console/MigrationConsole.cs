using System.Security.Cryptography;
using System.Runtime.ExceptionServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration.Console;

public static class MigrationConsole
{
    private const string SigningKeyEnvironmentVariable = "LEGACY_MIGRATION_RECEIPT_SIGNING_KEY_FILE";
    private const string SqlServerConnectionEnvironmentVariable = "LEGACY_MIGRATION_SQLSERVER_CONNECTION";
    private const string PostgreSqlConnectionEnvironmentVariable = "LEGACY_MIGRATION_POSTGRES_ADMIN_CONNECTION";
    private const string PostgreSqlControlConnectionEnvironmentVariable = "LEGACY_MIGRATION_POSTGRES_CONTROL_CONNECTION";
    private const string ExecutionSigningKeyEnvironmentVariable = "LEGACY_MIGRATION_EXECUTION_SIGNING_KEY_FILE";
    private const string FinalEvidenceSigningKeyEnvironmentVariable = "LEGACY_MIGRATION_FINAL_EVIDENCE_SIGNING_KEY_FILE";
    private const string SnapshotKeyEnvironmentVariable = "LEGACY_MIGRATION_SNAPSHOT_ENCRYPTION_KEY_FILE";
    private const string BackupSqlUserEnvironmentVariable = "LEGACY_MIGRATION_BACKUP_SQL_USERNAME";
    private const string BackupSqlPasswordEnvironmentVariable = "LEGACY_MIGRATION_BACKUP_SQL_PASSWORD";
    private const string RestoreSqlServerConnectionEnvironmentVariable = "LEGACY_SQLSERVER_ADMIN_CONNECTION";
    private const string ProvenanceSigningKeyEnvironmentVariable = "LEGACY_MIGRATION_PROVENANCE_SIGNING_KEY_FILE";
    private const string DeployEnabledEnvironmentVariable = "LEGACY_DEPLOY_ENABLED";
    private const string AuthorizationSigningKeyEnvironmentVariable = "LEGACY_MIGRATION_AUTHORIZATION_SIGNING_KEY_FILE";
    private const string QuotationSchemaSigningKeyEnvironmentVariable = "LEGACY_QUOTATION_SCHEMA_SIGNING_KEY_FILE";
    private const string QuotationSnapshotSigningKeyEnvironmentVariable = "LEGACY_QUOTATION_SNAPSHOT_SIGNING_KEY_FILE";
    private const string LegacyNamespace = "maliev-legacy";
    private const string LegacyPostgreSqlCluster = "legacy-postgres-main";
    private const string KubernetesApiServer = "https://kubernetes.default.svc";
    private const string KubernetesServiceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    private const string KubernetesServiceAccountCaFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static async Task<int> RunAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        return await RunCoreAsync(
            arguments,
            output,
            error,
            getEnvironmentVariable,
            new DefaultExact25BackupRuntimeFactory(),
            new DefaultAuthorizationRuntimeAttestationFactory(),
            new DefaultQuotationSnapshotRuntimeFactory(),
            cancellationToken).ConfigureAwait(false);
    }

    internal static Task<int> RunForTestsAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<string, string?> getEnvironmentVariable,
        IExact25BackupRuntimeFactory backupRuntimeFactory,
        CancellationToken cancellationToken)
    {
        return RunCoreAsync(arguments, output, error, getEnvironmentVariable, backupRuntimeFactory,
            new DefaultAuthorizationRuntimeAttestationFactory(), new DefaultQuotationSnapshotRuntimeFactory(), cancellationToken);
    }

    internal static Task<int> RunAuthorizationForTestsAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<string, string?> getEnvironmentVariable,
        IAuthorizationRuntimeAttestationFactory runtimeAttestationFactory,
        CancellationToken cancellationToken)
    {
        return RunCoreAsync(arguments, output, error, getEnvironmentVariable, new DefaultExact25BackupRuntimeFactory(),
            runtimeAttestationFactory, new DefaultQuotationSnapshotRuntimeFactory(), cancellationToken);
    }

    internal static Task<int> RunQuotationSnapshotForTestsAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<string, string?> getEnvironmentVariable,
        IQuotationSnapshotRuntimeFactory runtimeFactory,
        CancellationToken cancellationToken)
    {
        return RunCoreAsync(arguments, output, error, getEnvironmentVariable, new DefaultExact25BackupRuntimeFactory(),
            new DefaultAuthorizationRuntimeAttestationFactory(), runtimeFactory, cancellationToken);
    }

    private static async Task<int> RunCoreAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<string, string?> getEnvironmentVariable,
        IExact25BackupRuntimeFactory backupRuntimeFactory,
        IAuthorizationRuntimeAttestationFactory runtimeAttestationFactory,
        IQuotationSnapshotRuntimeFactory quotationSnapshotRuntimeFactory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(getEnvironmentVariable);
        ArgumentNullException.ThrowIfNull(backupRuntimeFactory);
        ArgumentNullException.ThrowIfNull(runtimeAttestationFactory);
        try
        {
            ConsoleInvocation invocation = ConsoleInvocation.Parse(arguments);
            switch (invocation.Command)
            {
                case "plan":
                    await ProducePlanAsync(invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("plan_complete").ConfigureAwait(false);
                    return 0;
                case "plan-digest":
                    string planDigest = await ComputePlanDigestAsync(invocation.ConfigPath, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync($"schema_plan_sha256={planDigest}").ConfigureAwait(false);
                    return 0;
                case "execute-shadow":
                    await ExecuteShadowAsync(invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("execute_shadow_complete").ConfigureAwait(false);
                    return 0;
                case "evidence":
                    await ProduceEvidenceAsync(invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("evidence_complete").ConfigureAwait(false);
                    return 0;
                case "export-local-snapshot":
                    await ExportLocalSnapshotAsync(invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("export_local_snapshot_complete").ConfigureAwait(false);
                    return 0;
                case "backup-full":
                    await ProduceFullBackupAsync(
                        invocation.ConfigPath,
                        getEnvironmentVariable,
                        backupRuntimeFactory,
                        cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("backup_full_complete").ConfigureAwait(false);
                    return 0;
                case "restore-backups":
                    await RestoreBackupsAsync(
                        invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("backup_restore_complete").ConfigureAwait(false);
                    return 0;
                case "cleanup-restore":
                    await CleanupRestoreAsync(invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("restore_cleanup_complete").ConfigureAwait(false);
                    return 0;
                case "authorize-shadow":
                    await AuthorizeShadowAsync(invocation.ConfigPath, getEnvironmentVariable, runtimeAttestationFactory, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("authorize_shadow_complete").ConfigureAwait(false);
                    return 0;
                case "sign-provenance":
                    await SignProvenanceAsync(invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("sign_provenance_complete").ConfigureAwait(false);
                    return 0;
                case "sign-quotation-schema-baseline":
                    await SignQuotationSchemaBaselineAsync(invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("quotation_schema_baseline_complete").ConfigureAwait(false);
                    return 0;
                case "sign-quotation-postgres-snapshot":
                    await SignQuotationPostgreSqlSnapshotAsync(
                        invocation.ConfigPath, getEnvironmentVariable, quotationSnapshotRuntimeFactory, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("quotation_postgres_snapshot_complete").ConfigureAwait(false);
                    return 0;
                default:
                    await error.WriteLineAsync("stage_not_configured").ConfigureAwait(false);
                    return 2;
            }
        }
        catch (CommandLineException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 64;
        }
        catch (MigrationConsoleException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 65;
        }
        catch (Exact25FullBackupException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 65;
        }
        catch (Exact25BackupTransportException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 70;
        }
        catch (Microsoft.Data.SqlClient.SqlException)
        {
            await error.WriteLineAsync("restore_sql_failed").ConfigureAwait(false);
            return 70;
        }
        catch (MigrationExecutionException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 70;
        }
        catch (PostgreSqlMigrationBoundaryException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 70;
        }
        catch (MigrationEvidenceProductionException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 65;
        }
        catch (OperatorAttestationException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 65;
        }
        catch (RuntimeAttestationException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 70;
        }
    }

    private static async Task SignQuotationSchemaBaselineAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(getEnvironmentVariable(DeployEnabledEnvironmentVariable), "false", StringComparison.OrdinalIgnoreCase))
        {
            throw new MigrationExecutionException("quotation_schema_deploy_gate_invalid", "Legacy deployment must remain disabled while schema evidence is signed.");
        }
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "quotation_schema_config_unprotected", cancellationToken).ConfigureAwait(false);
        QuotationSchemaBaselineCommandConfiguration command = configuration.QuotationSchemaBaseline ??
            throw new MigrationExecutionException("quotation_schema_configuration_missing", "Reviewed Quotation schema configuration is required.");
        if (!command.AllowSigning)
        {
            throw new MigrationExecutionException("quotation_schema_owner_review_required", "Explicit owner review is required before schema evidence is signed.");
        }
        FreshSchemaPlan plan = await ReadProtectedJsonAsync<FreshSchemaPlan>(
            command.PlanPath, "quotation_schema_plan_unprotected", cancellationToken).ConfigureAwait(false);
        SigningRoleTrustBundle signingRoles = await ReadSigningRolesAsync(
            configuration.SigningRoles, cancellationToken).ConfigureAwait(false);
        BindConfiguredSigningRoles(configuration, signingRoles);
        if (!string.Equals(plan.SchemaVersion, "2.0", StringComparison.Ordinal) ||
            !string.Equals(SchemaPlanCanonicalizer.ComputeSha256(plan), command.ReviewedSchemaPlanSha256, StringComparison.Ordinal))
        {
            throw new MigrationExecutionException("quotation_schema_plan_mismatch", "The schema plan does not match the reviewed digest.");
        }
        string database = command.Workload switch { "quotation" => "Quotation", "quotation-request" => "QuotationRequest", _ => string.Empty };
        DatabaseSchemaPlan selected = plan.Databases.SingleOrDefault(item => item.Database == database) ??
            throw new MigrationExecutionException("quotation_schema_database_missing", "The selected Quotation database is absent from the reviewed plan.");
        string keyPath = getEnvironmentVariable(QuotationSchemaSigningKeyEnvironmentVariable) ??
            throw new MigrationExecutionException("quotation_schema_signing_key_missing", "The protected Quotation schema signing key is required.");
        using var signer = new P256MigrationEvidenceSigner(command.KeyId,
            await ReadProtectedTextAsync(keyPath, "quotation_schema_signing_key_unprotected", cancellationToken).ConfigureAwait(false));
        EnsureAdditionalSignerSeparated(signer, command.SigningKeyFingerprintSha256,
            command.ForbiddenSigningKeyFingerprintsSha256, signingRoles, "quotation_schema_signing_role_invalid");
        QuotationSchemaBaselineReceipt receipt = QuotationSchemaBaselineReceiptProducer.Produce(
            new(command.Workload, command.SourceSnapshotId, command.CopyPlanId, selected, command.Host, command.Port,
                database, command.ExpiresUtc), signer);
        using JsonDocument envelope = JsonDocument.Parse(receipt.EnvelopeJson);
        await WriteNewJsonAsync(command.OutputPath, new
        {
            Payload = envelope.RootElement.GetProperty("Payload").GetString(),
            Signature = envelope.RootElement.GetProperty("Signature").GetString(),
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task SignQuotationPostgreSqlSnapshotAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        IQuotationSnapshotRuntimeFactory runtimeFactory,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(getEnvironmentVariable(DeployEnabledEnvironmentVariable), "false", StringComparison.OrdinalIgnoreCase))
        {
            throw new MigrationExecutionException("quotation_snapshot_deploy_gate_invalid", "Legacy deployment must remain disabled while snapshot evidence is signed.");
        }
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "quotation_snapshot_config_unprotected", cancellationToken).ConfigureAwait(false);
        QuotationPostgreSqlSnapshotCommandConfiguration command = configuration.QuotationPostgreSqlSnapshot ??
            throw new MigrationExecutionException("quotation_snapshot_configuration_missing", "Reviewed Quotation snapshot configuration is required.");
        if (!command.AllowSigning || command.ClusterNamespace != LegacyNamespace || command.ClusterName != LegacyPostgreSqlCluster)
        {
            throw new MigrationExecutionException("quotation_snapshot_owner_review_required", "Explicit review of the fixed snapshot target is required.");
        }
        FreshSchemaPlan plan = await ReadProtectedJsonAsync<FreshSchemaPlan>(
            command.PlanPath, "quotation_snapshot_plan_unprotected", cancellationToken).ConfigureAwait(false);
        if (SchemaPlanCanonicalizer.ComputeSha256(plan) != command.ReviewedSchemaPlanSha256)
        {
            throw new MigrationExecutionException("quotation_snapshot_plan_mismatch", "The snapshot schema plan does not match the reviewed digest.");
        }
        string database = command.Workload switch { "quotation" => "Quotation", "quotation-request" => "QuotationRequest", _ => string.Empty };
        DatabaseSchemaPlan selected = plan.Databases.SingleOrDefault(item => item.Database == database) ??
            throw new MigrationExecutionException("quotation_snapshot_database_missing", "The selected Quotation database is absent from the reviewed plan.");
        if (selected.TargetSchemaSha256 != command.SchemaHash)
        {
            throw new MigrationExecutionException("quotation_snapshot_schema_mismatch", "The snapshot schema hash is not the reviewed target schema.");
        }
        SigningRoleTrustBundle signingRoles = await ReadSigningRolesAsync(configuration.SigningRoles, cancellationToken).ConfigureAwait(false);
        BindConfiguredSigningRoles(configuration, signingRoles);
        string keyPath = getEnvironmentVariable(QuotationSnapshotSigningKeyEnvironmentVariable) ??
            throw new MigrationExecutionException("quotation_snapshot_signing_key_missing", "The protected snapshot signing key is required.");
        using var signer = new P256MigrationEvidenceSigner(command.KeyId,
            await ReadProtectedTextAsync(keyPath, "quotation_snapshot_signing_key_unprotected", cancellationToken).ConfigureAwait(false));
        EnsureAdditionalSignerSeparated(signer, command.SigningKeyFingerprintSha256,
            command.ForbiddenSigningKeyFingerprintsSha256, signingRoles, "quotation_snapshot_signing_role_invalid");
        IImmutablePostgreSqlSnapshotObserver snapshotObserver = await runtimeFactory.CreateSnapshotObserverAsync(cancellationToken).ConfigureAwait(false);
        ICloudNativePgTargetObserver targetObserver = runtimeFactory.CreateTargetObserver();
        try
        {
            QuotationPostgreSqlSnapshotReceipt receipt = await QuotationPostgreSqlSnapshotReceiptProducer.ProduceAsync(
                new(command.Workload, command.RunId, command.SourceSnapshotId, command.CopyPlanId, command.SchemaHash,
                    command.Host, command.Port, database, command.SnapshotId, command.BackupObjectUri,
                    command.BackupObjectGeneration, command.ClusterNamespace, command.ClusterName, command.ExpiresUtc,
                    command.ForbiddenSigningKeyFingerprintsSha256), signer, snapshotObserver, targetObserver,
                TimeProvider.System, cancellationToken).ConfigureAwait(false);
            using JsonDocument envelope = JsonDocument.Parse(receipt.EnvelopeJson);
            await WriteNewJsonAsync(command.OutputPath, new
            {
                Payload = envelope.RootElement.GetProperty("Payload").GetString(),
                Signature = envelope.RootElement.GetProperty("Signature").GetString(),
            }, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            (snapshotObserver as IDisposable)?.Dispose();
            (targetObserver as IDisposable)?.Dispose();
        }
    }

    private static void EnsureAdditionalSignerSeparated(
        P256MigrationEvidenceSigner signer,
        string configuredFingerprint,
        IReadOnlyList<string> additionalForbiddenFingerprints,
        SigningRoleTrustBundle signingRoles,
        string errorCode)
    {
        string[] established = [signingRoles.Backup.Fingerprint, signingRoles.Authorization.Fingerprint,
            signingRoles.Execution.Fingerprint, signingRoles.Provenance.Fingerprint, signingRoles.FinalEvidence.Fingerprint];
        if (!FixedFingerprintEquals(signer.PublicKeyFingerprintSha256, configuredFingerprint) ||
            established.Any(value => FixedFingerprintEquals(value, signer.PublicKeyFingerprintSha256)) ||
            additionalForbiddenFingerprints.Any(value => FixedFingerprintEquals(value, signer.PublicKeyFingerprintSha256)))
        {
            throw new MigrationExecutionException(errorCode, "The additional signing role must be reviewed and distinct from all established evidence roles.");
        }
    }

    private static bool FixedFingerprintEquals(string left, string right)
    {
        return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
            System.Text.Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static async Task AuthorizeShadowAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        IAuthorizationRuntimeAttestationFactory runtimeAttestationFactory,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(getEnvironmentVariable(DeployEnabledEnvironmentVariable), "false", StringComparison.OrdinalIgnoreCase))
        {
            throw new OperatorAttestationException("authorization_deploy_gate_invalid", "Legacy deployment must remain disabled while authorization is minted.");
        }
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "authorization_config_unprotected", cancellationToken).ConfigureAwait(false);
        AuthorizeShadowCommandConfiguration authorize = configuration.AuthorizeShadow ??
            throw new OperatorAttestationException("authorization_configuration_missing", "Reviewed shadow authorization configuration is required.");
        if (!authorize.AllowShadowAuthorization)
        {
            throw new OperatorAttestationException("authorization_owner_review_required", "Explicit owner review is required before shadow authorization can be signed.");
        }
        SigningRoleTrustBundle signingRoles = await ReadSigningRolesAsync(
            configuration.SigningRoles, cancellationToken).ConfigureAwait(false);
        BindConfiguredSigningRoles(configuration, signingRoles);
        string keyPath = getEnvironmentVariable(AuthorizationSigningKeyEnvironmentVariable) ??
            throw new OperatorAttestationException("authorization_signing_key_missing", "The protected authorization signing key is required.");
        BackupReceipt receipt = await ReadProtectedJsonAsync<BackupReceipt>(
            authorize.ReceiptPath, "authorization_backup_receipt_unprotected", cancellationToken).ConfigureAwait(false);
        FreshSchemaPlan plan = await ReadProtectedJsonAsync<FreshSchemaPlan>(
            authorize.PlanPath, "authorization_plan_unprotected", cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore backupTrust = await ReadTrustStoreAsync(authorize.ReceiptTrustedKeys, cancellationToken)
            .ConfigureAwait(false);
        EnsureTrustMatchesRole(backupTrust, signingRoles.Backup, "authorization_backup_trust_mismatch");
        using var signer = new P256MigrationEvidenceSigner(
            authorize.KeyId,
            await ReadProtectedTextAsync(keyPath, "authorization_signing_key_unprotected", cancellationToken).ConfigureAwait(false));
        EnsureSignerMatchesRole(
            signer,
            signingRoles.Authorization,
            [signingRoles.Backup, signingRoles.Execution, signingRoles.Provenance, signingRoles.FinalEvidence],
            "authorization_signing_key_untrusted", "authorization_key_role_reuse");
        RunnerArtifactManifest runnerManifest = await runtimeAttestationFactory.MeasureRunnerAsync(cancellationToken).ConfigureAwait(false);
        CloudNativePgTargetObservation targetObservation = await runtimeAttestationFactory.ObserveTargetAsync(
            LegacyNamespace, LegacyPostgreSqlCluster, cancellationToken).ConfigureAwait(false);
        ExecutionAuthorizationReceipt signed = ReviewedExecutionAuthorizationProducer.Produce(
            new(
                authorize.ExpectedSourceCommitSha,
                authorize.ReviewedSchemaPlanSha256,
                runnerManifest,
                targetObservation,
                authorize.IssuedAtUtc,
                authorize.ExpiresAtUtc,
                authorize.AllowShadowAuthorization,
                authorize.MaximumReceiptAgeMinutes),
            receipt,
            plan,
            backupTrust,
            signer,
            TimeProvider.System.GetUtcNow());
        try
        {
            await WriteNewJsonAsync(authorize.OutputPath, signed, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new OperatorAttestationException("authorization_publication_failed", "Authorization publication requires a new protected output path.");
        }
    }

    private static async Task SignProvenanceAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(getEnvironmentVariable(DeployEnabledEnvironmentVariable), "false", StringComparison.OrdinalIgnoreCase))
        {
            throw new OperatorAttestationException("provenance_deploy_gate_invalid", "Legacy deployment must remain disabled while provenance is minted.");
        }
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "provenance_config_unprotected", cancellationToken).ConfigureAwait(false);
        SignProvenanceCommandConfiguration sign = configuration.SignProvenance ??
            throw new OperatorAttestationException("provenance_configuration_missing", "Reviewed migration provenance configuration is required.");
        if (!sign.AllowProvenanceSigning)
        {
            throw new OperatorAttestationException("provenance_owner_review_required", "Explicit owner review is required before provenance can be signed.");
        }
        EvidenceCommandConfiguration evidence = configuration.Evidence ??
            throw new OperatorAttestationException("provenance_evidence_configuration_missing", "Final evidence configuration is required for provenance binding.");
        if (!string.Equals(Path.GetFullPath(sign.OutputPath), Path.GetFullPath(evidence.ProvenancePath), StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(evidence.VerifiedRestoreReceiptPath))
        {
            throw new OperatorAttestationException("provenance_output_binding_invalid", "Provenance output and final evidence references must match.");
        }
        string keyPath = getEnvironmentVariable(ProvenanceSigningKeyEnvironmentVariable) ??
            throw new OperatorAttestationException("provenance_signing_key_missing", "The protected provenance signing key is required.");
        MigrationExecutionResult result = await ReadProtectedJsonAsync<MigrationExecutionResult>(
            evidence.ExecutionResultPath, "provenance_execution_unprotected", cancellationToken).ConfigureAwait(false);
        BackupReceipt receipt = await ReadProtectedJsonAsync<BackupReceipt>(
            evidence.ReceiptPath, "provenance_backup_receipt_unprotected", cancellationToken).ConfigureAwait(false);
        FreshSchemaPlan plan = await ReadProtectedJsonAsync<FreshSchemaPlan>(
            evidence.PlanPath, "provenance_plan_unprotected", cancellationToken).ConfigureAwait(false);
        ExecutionAuthorizationReceipt authorization = await ReadProtectedJsonAsync<ExecutionAuthorizationReceipt>(
            evidence.AuthorizationPath, "provenance_authorization_unprotected", cancellationToken).ConfigureAwait(false);
        VerifiedRestoreReceipt verifiedRestore = await ReadProtectedJsonAsync<VerifiedRestoreReceipt>(
            evidence.VerifiedRestoreReceiptPath, "provenance_cleanup_receipt_unprotected", cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore backupTrust = await ReadTrustStoreAsync(evidence.BackupTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore authorizationTrust = await ReadTrustStoreAsync(evidence.AuthorizationTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore executionTrust = await ReadTrustStoreAsync(evidence.ExecutionTrustedKeys, cancellationToken).ConfigureAwait(false);
        using var signer = new P256MigrationEvidenceSigner(
            sign.KeyId,
            await ReadProtectedTextAsync(keyPath, "provenance_signing_key_unprotected", cancellationToken).ConfigureAwait(false));
        MigrationEvidenceProvenanceReceipt provenance = ReviewedMigrationProvenanceProducer.Produce(
            new(
                new(
                    evidence.SourceSnapshotId,
                    evidence.BackupUri,
                    evidence.BackupObjectGeneration,
                    evidence.RestoreId,
                    evidence.EvidenceId,
                    evidence.LeaseId,
                    evidence.LeaseAcquiredAtUtc,
                    evidence.LeaseExpiresAtUtc),
                sign.ReviewedSchemaPlanSha256,
                sign.IssuedAtUtc,
                sign.AllowProvenanceSigning),
            result,
            receipt,
            plan,
            authorization,
            verifiedRestore,
            backupTrust,
            authorizationTrust,
            executionTrust,
            signer,
            TimeProvider.System.GetUtcNow());
        try
        {
            await WriteNewJsonAsync(sign.OutputPath, provenance, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new OperatorAttestationException("provenance_publication_failed", "Provenance publication requires a new protected output path.");
        }
    }

    private static async Task ProduceFullBackupAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        IExact25BackupRuntimeFactory backupRuntimeFactory,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(getEnvironmentVariable(DeployEnabledEnvironmentVariable), "false", StringComparison.OrdinalIgnoreCase))
        {
            throw new MigrationConsoleException("backup_deploy_gate_invalid", "Legacy application deployment must remain disabled during backup production.");
        }

        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
                configPath, "backup_config_unprotected", cancellationToken)
            .ConfigureAwait(false);
        FullBackupCommandConfiguration backup = configuration.FullBackup ??
            throw new MigrationConsoleException("backup_configuration_missing", "Full backup configuration is required.");
        if (!backup.AllowSourceBackup)
        {
            throw new MigrationConsoleException("backup_source_gate_invalid", "The protected configuration does not authorize a source backup.");
        }

        string? sqlUser = getEnvironmentVariable(BackupSqlUserEnvironmentVariable);
        string? sqlPassword = getEnvironmentVariable(BackupSqlPasswordEnvironmentVariable);
        string? keyPath = getEnvironmentVariable(SigningKeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(sqlUser) || string.IsNullOrWhiteSpace(sqlPassword) || string.IsNullOrWhiteSpace(keyPath))
        {
            throw new MigrationConsoleException("backup_runtime_reference_missing", "Protected SQL and signing-key runtime references are required.");
        }

        using ECDsa key = ECDsa.Create();
        try
        {
            key.ImportFromPem(await ReadProtectedTextAsync(
                keyPath, "backup_signing_key_unprotected", cancellationToken).ConfigureAwait(false));
        }
        catch (CryptographicException)
        {
            throw new MigrationConsoleException("backup_signing_key_invalid", "The backup signing key file is invalid.");
        }

        Exact25BackupRuntime runtime = await backupRuntimeFactory.CreateAsync(cancellationToken).ConfigureAwait(false);
        var request = new Exact25FullBackupRequest(
            backup.Namespace,
            backup.ExpectedPodName,
            backup.ExpectedPodUid,
            backup.ContainerName,
            backup.GcsPrefix,
            backup.LocalWorkingDirectory,
            backup.RunId,
            backup.ApprovedRunUtc,
            backup.MaximumTransportAttempts);
        var credential = new SecureSqlBackupCredential(sqlUser, sqlPassword);
        var publisher = new AtomicBackupReceiptPublisher(backup.PublicationDirectory);
        _ = await Exact25FullBackupProducer.ProduceAsync(
            request,
            credential,
            runtime.Process,
            runtime.Storage,
            publisher,
            backup.KeyId,
            key,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task ProduceEvidenceAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "evidence_config_unprotected", cancellationToken).ConfigureAwait(false);
        EvidenceCommandConfiguration evidence = configuration.Evidence ??
            throw new MigrationConsoleException("evidence_configuration_missing", "Evidence configuration is required.");
        string? keyPath = getEnvironmentVariable(FinalEvidenceSigningKeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(keyPath))
        {
            throw new MigrationConsoleException("evidence_runtime_reference_missing", "The protected evidence signing key is required.");
        }

        MigrationExecutionResult result = await ReadProtectedJsonAsync<MigrationExecutionResult>(
            evidence.ExecutionResultPath, "evidence_execution_unprotected", cancellationToken).ConfigureAwait(false);
        MigrationEvidenceProvenanceReceipt provenance = await ReadProtectedJsonAsync<MigrationEvidenceProvenanceReceipt>(
            evidence.ProvenancePath, "evidence_provenance_unprotected", cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(evidence.VerifiedRestoreReceiptPath))
        {
            throw new MigrationConsoleException("verified_restore_receipt_missing", "Completed verified restore evidence is required.");
        }
        VerifiedRestoreReceipt verifiedRestore = await ReadProtectedJsonAsync<VerifiedRestoreReceipt>(
            evidence.VerifiedRestoreReceiptPath, "evidence_cleanup_receipt_unprotected", cancellationToken).ConfigureAwait(false);
        BackupReceipt receipt = await ReadProtectedJsonAsync<BackupReceipt>(
            evidence.ReceiptPath, "evidence_backup_receipt_unprotected", cancellationToken).ConfigureAwait(false);
        FreshSchemaPlan plan = await ReadProtectedJsonAsync<FreshSchemaPlan>(
            evidence.PlanPath, "evidence_plan_unprotected", cancellationToken).ConfigureAwait(false);
        ExecutionAuthorizationReceipt authorization = await ReadProtectedJsonAsync<ExecutionAuthorizationReceipt>(
            evidence.AuthorizationPath, "evidence_authorization_unprotected", cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore backupTrust = await ReadTrustStoreAsync(evidence.BackupTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore authorizationTrust = await ReadTrustStoreAsync(evidence.AuthorizationTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore executionTrust = await ReadTrustStoreAsync(evidence.ExecutionTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore provenanceTrust = await ReadTrustStoreAsync(evidence.ProvenanceTrustedKeys, cancellationToken).ConfigureAwait(false);
        string privateKeyPem = await ReadProtectedTextAsync(
            keyPath, "evidence_signing_key_unprotected", cancellationToken).ConfigureAwait(false);
        using var signer = new P256MigrationEvidenceSigner(evidence.EvidenceKeyId, privateKeyPem);
        var producerConfiguration = new AppHostMigrationEvidenceV2Configuration(
            evidence.SourceSnapshotId,
            evidence.BackupUri,
            evidence.BackupObjectGeneration,
            evidence.RestoreId,
            evidence.EvidenceId,
            evidence.LeaseId,
            evidence.LeaseAcquiredAtUtc,
            evidence.LeaseExpiresAtUtc);
        AppHostMigrationEvidenceV2Document document = AppHostMigrationEvidenceV2Producer.Produce(
            new AppHostMigrationEvidenceV2Request(result, receipt, plan, authorization, producerConfiguration, provenance)
            {
                VerifiedRestoreReceipt = verifiedRestore,
            },
            backupTrust,
            authorizationTrust,
            executionTrust,
            provenanceTrust,
            signer,
            TimeProvider.System);
        try
        {
            await MigrationEvidencePublication.PublishAsync(document, evidence.PublicationDirectory, cancellationToken).ConfigureAwait(false);
        }
        catch (IOException)
        {
            throw new MigrationConsoleException("evidence_publication_failed", "Evidence publication failed before an atomic artifact set was available.");
        }
        catch (UnauthorizedAccessException)
        {
            throw new MigrationConsoleException("evidence_publication_failed", "Evidence publication failed before an atomic artifact set was available.");
        }
    }

    private static async Task ExportLocalSnapshotAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "snapshot_config_unprotected", cancellationToken).ConfigureAwait(false);
        ExportLocalSnapshotCommandConfiguration export = configuration.ExportLocalSnapshot ??
            throw new MigrationConsoleException("snapshot_configuration_missing", "Snapshot export configuration is required.");
        string? targetConnection = getEnvironmentVariable(PostgreSqlConnectionEnvironmentVariable);
        string? keyPath = getEnvironmentVariable(SnapshotKeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(targetConnection) || string.IsNullOrWhiteSpace(keyPath))
        {
            throw new MigrationConsoleException("snapshot_runtime_reference_missing", "Snapshot runtime references are required.");
        }

        MigrationExecutionResult result = await ReadProtectedJsonAsync<MigrationExecutionResult>(
            export.ExecutionResultPath, "snapshot_execution_unprotected", cancellationToken).ConfigureAwait(false);
        if (result.Status is not (MigrationExecutionStatus.Completed or MigrationExecutionStatus.AlreadyCompleted) ||
            result.Receipt.Databases.Count != DatabaseInventory.ActiveDatabases.Count)
        {
            throw new MigrationConsoleException("snapshot_execution_result_invalid", "A completed exact migration result is required.");
        }

        byte[] key;
        try
        {
            await using FileStream keyStream = OwnerProtectedFilePolicy.OpenRead(keyPath, "snapshot_key_unprotected");
            key = SnapshotRootKey.Load(keyStream);
        }
        catch (Exception exception) when (exception is InvalidOperationException or UnauthorizedAccessException or IOException)
        {
            throw new MigrationConsoleException("snapshot_key_invalid", "The snapshot encryption key file is invalid.");
        }
        if (key.Length != 32)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new MigrationConsoleException("snapshot_key_invalid", "The snapshot encryption key file is invalid.");
        }

        try
        {
            var dumpSource = new PgDumpSource(export.PgDumpPath, targetConnection);
            _ = await LocalSnapshotExporter.ExportAsync(
                result.Receipt.Databases,
                export.OutputDirectory,
                result.Receipt.RunId.ToString("D"),
                key,
                dumpSource,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static async Task ExecuteShadowAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(getEnvironmentVariable(DeployEnabledEnvironmentVariable), "false", StringComparison.OrdinalIgnoreCase))
        {
            throw new MigrationConsoleException("shadow_deploy_gate_invalid", "Legacy deployment must remain disabled during shadow execution.");
        }
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "shadow_config_unprotected", cancellationToken).ConfigureAwait(false);
        ExecuteShadowCommandConfiguration execute = configuration.ExecuteShadow ??
            throw new MigrationConsoleException("shadow_configuration_missing", "Shadow execution configuration is required.");
        string? sourceConnection = getEnvironmentVariable(SqlServerConnectionEnvironmentVariable);
        string? targetConnection = getEnvironmentVariable(PostgreSqlConnectionEnvironmentVariable);
        string? controlConnection = getEnvironmentVariable(PostgreSqlControlConnectionEnvironmentVariable);
        string? evidenceKeyPath = getEnvironmentVariable(ExecutionSigningKeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(sourceConnection) || string.IsNullOrWhiteSpace(targetConnection) ||
            string.IsNullOrWhiteSpace(controlConnection) || string.IsNullOrWhiteSpace(evidenceKeyPath))
        {
            throw new MigrationConsoleException("shadow_runtime_reference_missing", "Shadow runtime references are required.");
        }

        _ = await PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
            controlConnection,
            targetConnection,
            execute.ExpectedControlRole,
            execute.ExpectedShadowAdminRole,
            cancellationToken).ConfigureAwait(false);

        SigningRoleTrustBundle signingRoles = await ReadSigningRolesAsync(
            configuration.SigningRoles, cancellationToken).ConfigureAwait(false);
        BindConfiguredSigningRoles(configuration, signingRoles);
        BackupReceipt receipt = await ReadProtectedJsonAsync<BackupReceipt>(
            execute.ReceiptPath, "shadow_backup_receipt_unprotected", cancellationToken).ConfigureAwait(false);
        FreshSchemaPlan plan = await ReadProtectedJsonAsync<FreshSchemaPlan>(
            execute.PlanPath, "shadow_plan_unprotected", cancellationToken).ConfigureAwait(false);
        ExecutionAuthorizationReceipt authorization = await ReadProtectedJsonAsync<ExecutionAuthorizationReceipt>(
            execute.AuthorizationPath, "shadow_authorization_unprotected", cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore receiptTrust = await ReadTrustStoreAsync(execute.ReceiptTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore authorizationTrust = await ReadTrustStoreAsync(execute.AuthorizationTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore executionTrust = await ReadTrustStoreAsync(
            [configuration.SigningRoles!.Execution], cancellationToken).ConfigureAwait(false);
        EnsureTrustMatchesRole(receiptTrust, signingRoles.Backup, "shadow_backup_trust_mismatch");
        EnsureTrustMatchesRole(authorizationTrust, signingRoles.Authorization, "shadow_authorization_trust_mismatch");
        EnsureTrustMatchesRole(executionTrust, signingRoles.Execution, "shadow_execution_trust_mismatch");
        string privateKeyPem = await ReadProtectedTextAsync(
            evidenceKeyPath, "shadow_signing_key_unprotected", cancellationToken).ConfigureAwait(false);
        using var evidenceSigner = new P256MigrationEvidenceSigner(execute.EvidenceKeyId, privateKeyPem);
        EnsureSignerMatchesRole(
            evidenceSigner,
            signingRoles.Execution,
            [signingRoles.Backup, signingRoles.Authorization, signingRoles.Provenance, signingRoles.FinalEvidence],
            "shadow_signing_key_untrusted",
            "signing_role_key_reuse");
        RunnerArtifactManifest runnerManifest = await RunnerArtifactManifestMeasurer.MeasureAsync(
            AppContext.BaseDirectory, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(receipt.AttestationKeyId, signingRoles.Backup.KeyId, StringComparison.Ordinal) ||
            !string.Equals(authorization.AttestationKeyId, signingRoles.Authorization.KeyId, StringComparison.Ordinal))
        {
            throw new OperatorAttestationException("signing_role_binding_invalid", "Signed input artifacts do not match the reviewed signing-role configuration.");
        }
        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(sourceConnection));
        using var provisioner = new CloudNativePgShadowDatabaseProvisioner(new(
            new Uri(KubernetesApiServer, UriKind.Absolute),
            LegacyNamespace,
            LegacyPostgreSqlCluster,
            execute.ExpectedShadowAdminRole,
            KubernetesServiceAccountTokenFile,
            KubernetesServiceAccountCaFile,
            TimeSpan.FromMinutes(5)));
        using var targetObserver = new CloudNativePgTargetObserver(new(
            new Uri(KubernetesApiServer, UriKind.Absolute), KubernetesServiceAccountTokenFile, KubernetesServiceAccountCaFile));
        var runtimeVerifier = new RuntimeAttestationVerifier(
            AppContext.BaseDirectory, targetObserver, LegacyNamespace, LegacyPostgreSqlCluster);
        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(targetConnection, provisioner));
        var journal = new PostgreSqlMigrationRunJournal(new PostgreSqlMigrationRunJournalOptions(
            controlConnection,
            ExpectedControlRole: execute.ExpectedControlRole));
        var runner = new GuardedShadowMigrationRunner(
            new PreflightService(new DisabledExternalCommandExecutor(), receiptTrust),
            authorizationTrust,
            executionTrust,
            source,
            target,
            journal,
            evidenceSigner,
            TimeProvider.System,
            new GuardedRunnerPolicy(plan.SourceCommitSha, runnerManifest.ManifestSha256),
            runtimeVerifier);
        MigrationExecutionResult result = await runner.ExecuteAsync(
            new GuardedMigrationRequest(receipt, plan, authorization),
            cancellationToken).ConfigureAwait(false);
        await WriteNewJsonAsync(execute.OutputPath, result, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<ReceiptAttestationTrustStore> ReadTrustStoreAsync(
        IReadOnlyList<TrustedKeyReference> references,
        CancellationToken cancellationToken)
    {
        var keys = new List<TrustedAttestationKey>(references.Count);
        foreach (TrustedKeyReference reference in references)
        {
            byte[] publicKey = Convert.FromBase64String(await ReadProtectedTextAsync(
                reference.SubjectPublicKeyInfoPath, "trusted_key_unprotected", cancellationToken).ConfigureAwait(false));
            keys.Add(new(reference.KeyId, publicKey));
        }
        return new(keys);
    }

    private static async Task<SigningRoleTrustBundle> ReadSigningRolesAsync(
        SigningRolesCommandConfiguration? configuration,
        CancellationToken cancellationToken)
    {
        if (configuration is null)
        {
            throw new OperatorAttestationException("signing_role_configuration_missing", "All five signing roles must be configured before authorization or execution.");
        }

        SigningRoleTrust backup = await ReadSigningRoleAsync(configuration.Backup, cancellationToken).ConfigureAwait(false);
        SigningRoleTrust authorization = await ReadSigningRoleAsync(configuration.Authorization, cancellationToken).ConfigureAwait(false);
        SigningRoleTrust execution = await ReadSigningRoleAsync(configuration.Execution, cancellationToken).ConfigureAwait(false);
        SigningRoleTrust provenance = await ReadSigningRoleAsync(configuration.Provenance, cancellationToken).ConfigureAwait(false);
        SigningRoleTrust finalEvidence = await ReadSigningRoleAsync(configuration.FinalEvidence, cancellationToken).ConfigureAwait(false);
        SigningRoleTrust[] roles = [backup, authorization, execution, provenance, finalEvidence];
        return roles.Select(role => role.Fingerprint).Distinct(StringComparer.OrdinalIgnoreCase).Count() != roles.Length
            ? throw new OperatorAttestationException("signing_role_key_reuse", "Backup, authorization, execution, provenance, and final-evidence keys must be pairwise distinct.")
            : new(backup, authorization, execution, provenance, finalEvidence);
    }

    private static async Task<SigningRoleTrust> ReadSigningRoleAsync(
        TrustedKeyReference reference,
        CancellationToken cancellationToken)
    {
        ReceiptAttestationTrustStore trust = await ReadTrustStoreAsync([reference], cancellationToken).ConfigureAwait(false);
        return !trust.TryGetPublicKeyFingerprintSha256(reference.KeyId, out string fingerprint)
            ? throw new OperatorAttestationException("signing_role_trust_invalid", "A configured signing-role public key is invalid.")
            : new(reference.KeyId, fingerprint);
    }

    private static void BindConfiguredSigningRoles(
        MigrationConsoleConfiguration configuration,
        SigningRoleTrustBundle roles)
    {
        AuthorizeShadowCommandConfiguration authorize = configuration.AuthorizeShadow ??
            throw new OperatorAttestationException("authorization_configuration_missing", "Reviewed shadow authorization configuration is required.");
        ExecuteShadowCommandConfiguration execute = configuration.ExecuteShadow ??
            throw new OperatorAttestationException("signing_role_binding_missing", "Shadow execution key binding is required.");
        SignProvenanceCommandConfiguration provenance = configuration.SignProvenance ??
            throw new OperatorAttestationException("signing_role_binding_missing", "Provenance key binding is required.");
        EvidenceCommandConfiguration evidence = configuration.Evidence ??
            throw new OperatorAttestationException("signing_role_binding_missing", "Final-evidence key binding is required.");
        if (!string.Equals(authorize.KeyId, roles.Authorization.KeyId, StringComparison.Ordinal) ||
            !string.Equals(execute.EvidenceKeyId, roles.Execution.KeyId, StringComparison.Ordinal) ||
            !string.Equals(provenance.KeyId, roles.Provenance.KeyId, StringComparison.Ordinal) ||
            !string.Equals(evidence.EvidenceKeyId, roles.FinalEvidence.KeyId, StringComparison.Ordinal))
        {
            throw new OperatorAttestationException("signing_role_binding_invalid", "A command signing key identity does not match the reviewed five-role configuration.");
        }
    }

    private static void EnsureSignerMatchesRole(
        P256MigrationEvidenceSigner signer,
        SigningRoleTrust expected,
        IReadOnlyList<SigningRoleTrust> forbidden,
        string mismatchCode,
        string reuseCode)
    {
        if (forbidden.Any(role => string.Equals(
            signer.PublicKeyFingerprintSha256, role.Fingerprint, StringComparison.OrdinalIgnoreCase)))
        {
            throw new OperatorAttestationException(reuseCode, "A signing private key reuses another configured role.");
        }
        if (!string.Equals(signer.KeyId, expected.KeyId, StringComparison.Ordinal) ||
            !string.Equals(signer.PublicKeyFingerprintSha256, expected.Fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new OperatorAttestationException(mismatchCode, "The signing private key does not match its configured trusted public key.");
        }
    }

    private static void EnsureTrustMatchesRole(
        ReceiptAttestationTrustStore trust,
        SigningRoleTrust expected,
        string mismatchCode)
    {
        if (!trust.TryGetPublicKeyFingerprintSha256(expected.KeyId, out string fingerprint) ||
            !string.Equals(fingerprint, expected.Fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new OperatorAttestationException(mismatchCode, "A command trust reference does not match the reviewed signing-role public key.");
        }
    }

    private static async Task ProducePlanAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "plan_config_unprotected", cancellationToken).ConfigureAwait(false);
        PlanCommandConfiguration plan = configuration.Plan ??
            throw new MigrationConsoleException("plan_configuration_missing", "Plan configuration is required.");
        string sourceConnection = getEnvironmentVariable(SqlServerConnectionEnvironmentVariable) ??
            throw new MigrationConsoleException("plan_source_reference_missing", "The source connection reference is required.");
        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(sourceConnection));
        FreshSchemaPlan schemaPlan = await FreshSchemaPlanProducer.ProduceAsync(
            source,
            plan.SourceCommitSha,
            DateTimeOffset.UtcNow,
            cancellationToken).ConfigureAwait(false);
        await WriteNewJsonAsync(plan.OutputPath, schemaPlan, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ComputePlanDigestAsync(
        string configPath,
        CancellationToken cancellationToken)
    {
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "plan_digest_config_unprotected", cancellationToken).ConfigureAwait(false);
        PlanCommandConfiguration command = configuration.Plan ??
            throw new MigrationConsoleException("plan_configuration_missing", "Plan configuration is required.");
        FreshSchemaPlan plan = await ReadProtectedJsonAsync<FreshSchemaPlan>(
            command.OutputPath, "plan_digest_input_unprotected", cancellationToken).ConfigureAwait(false);
        return string.Equals(plan.SourceCommitSha, command.SourceCommitSha, StringComparison.Ordinal)
            ? SchemaPlanCanonicalizer.ComputeSha256(plan)
            : throw new MigrationConsoleException(
                "plan_source_commit_mismatch",
                "The generated schema plan is not bound to the configured source commit.");
    }

    private static async Task RestoreBackupsAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "backup_config_unprotected", cancellationToken).ConfigureAwait(false);
        RestoreBackupsCommandConfiguration restore = configuration.RestoreBackups ??
            throw new MigrationConsoleException("restore_configuration_missing", "Restore configuration is required.");
        string connectionString = getEnvironmentVariable(RestoreSqlServerConnectionEnvironmentVariable) ??
            throw new MigrationConsoleException("restore_connection_missing", "The disposable SQL Server admin connection is required.");
        string provenanceKeyPath = getEnvironmentVariable(ProvenanceSigningKeyEnvironmentVariable) ??
            throw new MigrationConsoleException("restore_signing_key_missing", "The protected restore provenance signing key is required.");
        if (string.IsNullOrWhiteSpace(restore.VerifiedRestoreReceiptPath) ||
            string.IsNullOrWhiteSpace(restore.FinalVerifiedRestoreReceiptPath) ||
            string.IsNullOrWhiteSpace(restore.ProvenanceKeyId))
        {
            throw new MigrationConsoleException("restore_receipt_configuration_missing", "Verified restore receipt publication is required.");
        }
        using ECDsa provenanceKey = ECDsa.Create();
        provenanceKey.ImportFromPem(await ReadProtectedTextAsync(
            provenanceKeyPath, "restore_signing_key_unprotected", cancellationToken).ConfigureAwait(false));
        if (restore.ProvenanceTrustedKeys is null)
        {
            throw new MigrationConsoleException("restore_provenance_trust_missing", "Restore provenance trust is required.");
        }
        ReceiptAttestationTrustStore provenanceTrust = await ReadTrustStoreAsync(
            restore.ProvenanceTrustedKeys, cancellationToken).ConfigureAwait(false);
        if (!VerifiedRestoreReceiptAttestation.SigningKeyMatchesTrust(restore.ProvenanceKeyId, provenanceKey, provenanceTrust))
        {
            throw new MigrationConsoleException("restore_signing_key_untrusted", "The restore provenance signing key does not match its trusted key identity.");
        }
        BackupReceipt receipt = await ReadProtectedJsonAsync<BackupReceipt>(
            restore.ReceiptPath, "backup_receipt_unprotected", cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore trust = await ReadTrustStoreAsync(restore.ReceiptTrustedKeys, cancellationToken).ConfigureAwait(false);
        DateTimeOffset nowUtc = TimeProvider.System.GetUtcNow();
        TimeSpan maximumReceiptAge = TimeSpan.FromMinutes(restore.MaximumReceiptAgeMinutes);
        VerifiedBackupRestorer.ValidateReceipt(receipt, trust, nowUtc, maximumReceiptAge);
        DockerRestoreResources resources = await DockerDisposableSqlServerProvisioner.ProvisionAsync(
            connectionString,
            restore.StagingVolumeName,
            restore.SqlServerContainerName,
            restore.SqlServerVisibleRecoveryDirectory,
            restore.SqlServerImage,
            restore.SqlServerImageId,
            restore.StagingImage,
            restore.RunBinding,
            cancellationToken).ConfigureAwait(false);
        try
        {
            IReadOnlyList<VerifiedRestoreArtifactEvidence> restored = await VerifiedBackupRestorer.RestoreWithEvidenceAsync(
                receipt,
                trust,
                restore.RecoveryDirectory,
                new SqlServerBackupRestoreTarget(
                    connectionString,
                    restore.SqlServerDataDirectory,
                    new DockerVolumeBackupStager(
                        resources.VolumeName,
                        restore.SqlServerVisibleRecoveryDirectory,
                        restore.StagingImage,
                        restore.SqlServerContainerName,
                        restore.SqlServerImageId)),
                nowUtc,
                maximumReceiptAge,
                cancellationToken).ConfigureAwait(false);
            DateTimeOffset restoredAtUtc = TimeProvider.System.GetUtcNow().ToUniversalTime();
            var resourceEvidence = new VerifiedRestoreResourceEvidence(
                resources.SqlServerImage,
                resources.SqlServerImageId,
                resources.ContainerId,
                resources.ContainerName,
                resources.RunBinding,
                resources.VolumeName,
                resources.VolumeId,
                resources.VolumeBinding,
                resources.VolumeFingerprint,
                resources.MountPath,
                resources.MountReadOnly,
                resources.StagingImage,
                resources.SqlServerProductMajorVersion);
            VerifiedRestoreReceipt pending = VerifiedRestoreReceiptAttestation.Sign(new(
                "1.0",
                restoredAtUtc,
                DatabaseInventory.InventorySha256,
                receipt.ManifestSha256!,
                resourceEvidence,
                restored,
                RestoreCleanupDisposition.Pending,
                null,
                restore.ProvenanceKeyId,
                null), provenanceKey);
            await WriteNewJsonAsync(restore.VerifiedRestoreReceiptPath, pending, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception restoreException)
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                await DockerDisposableSqlServerProvisioner.CleanupAsync(resources, cleanup.Token).ConfigureAwait(false);
            }
            catch (Exception cleanupException)
            {
                throw new AggregateException(
                    "The verified SQL Server restore failed and its run-owned Docker resources could not be fully removed.",
                    restoreException,
                    cleanupException);
            }

            throw;
        }
    }

    private static async Task CleanupRestoreAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        MigrationConsoleConfiguration configuration = await ReadProtectedJsonAsync<MigrationConsoleConfiguration>(
            configPath, "backup_config_unprotected", cancellationToken).ConfigureAwait(false);
        RestoreBackupsCommandConfiguration restore = configuration.RestoreBackups ??
            throw new MigrationConsoleException("restore_configuration_missing", "Restore configuration is required.");
        string provenanceKeyPath = getEnvironmentVariable(ProvenanceSigningKeyEnvironmentVariable) ??
            throw new MigrationConsoleException("restore_signing_key_missing", "The protected restore provenance signing key is required.");
        if (string.IsNullOrWhiteSpace(restore.VerifiedRestoreReceiptPath) ||
            string.IsNullOrWhiteSpace(restore.FinalVerifiedRestoreReceiptPath) ||
            string.IsNullOrWhiteSpace(restore.ProvenanceKeyId))
        {
            throw new MigrationConsoleException("restore_receipt_configuration_missing", "Verified restore receipt publication is required.");
        }
        VerifiedRestoreReceipt pending = await ReadProtectedJsonAsync<VerifiedRestoreReceipt>(
            restore.VerifiedRestoreReceiptPath, "restore_pending_receipt_unprotected", cancellationToken).ConfigureAwait(false);
        if (restore.ProvenanceTrustedKeys is null)
        {
            throw new MigrationConsoleException("restore_provenance_trust_missing", "Restore provenance trust is required.");
        }
        ReceiptAttestationTrustStore trust = await ReadTrustStoreAsync(restore.ProvenanceTrustedKeys, cancellationToken).ConfigureAwait(false);
        using ECDsa provenanceKey = ECDsa.Create();
        provenanceKey.ImportFromPem(await ReadProtectedTextAsync(
            provenanceKeyPath, "restore_signing_key_unprotected", cancellationToken).ConfigureAwait(false));
        if (!VerifiedRestoreReceiptAttestation.SigningKeyMatchesTrust(restore.ProvenanceKeyId, provenanceKey, trust))
        {
            throw new MigrationConsoleException("restore_signing_key_untrusted", "The restore provenance signing key does not match its trusted key identity.");
        }
        if (pending.CleanupDisposition != RestoreCleanupDisposition.Pending ||
            !VerifiedRestoreReceiptAttestation.Verify(pending, trust) ||
            !string.Equals(pending.AttestationKeyId, restore.ProvenanceKeyId, StringComparison.Ordinal) ||
            !string.Equals(pending.Resources.ContainerName, restore.SqlServerContainerName, StringComparison.Ordinal) ||
            !string.Equals(pending.Resources.VolumeBinding, restore.StagingVolumeName, StringComparison.Ordinal) ||
            !string.Equals(pending.Resources.RunBinding, restore.RunBinding, StringComparison.Ordinal))
        {
            throw new MigrationConsoleException("verified_restore_receipt_invalid", "The pending verified restore receipt is invalid or belongs to another run.");
        }
        var resources = new DockerRestoreResources(
            pending.Resources.ContainerId,
            pending.Resources.ContainerName,
            pending.Resources.VolumeId,
            pending.Resources.VolumeName,
            pending.Resources.VolumeBinding,
            pending.Resources.VolumeFingerprint,
            pending.Resources.RunBinding,
            pending.Resources.SqlServerImage,
            pending.Resources.SqlServerImageId,
            pending.Resources.StagingImage,
            pending.Resources.MountPath,
            pending.Resources.MountReadOnly,
            pending.Resources.SqlServerProductMajorVersion);
        using var cleanupTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cleanupTimeout.CancelAfter(TimeSpan.FromSeconds(30));
        await DockerDisposableSqlServerProvisioner.CleanupAsync(resources, cleanupTimeout.Token).ConfigureAwait(false);

        VerifiedRestoreReceipt completed = VerifiedRestoreReceiptAttestation.Sign(pending with
        {
            CleanupDisposition = RestoreCleanupDisposition.Removed,
            CleanedAtUtc = TimeProvider.System.GetUtcNow().ToUniversalTime(),
            AttestationSignature = null,
        }, provenanceKey);
        await WriteNewJsonAsync(restore.FinalVerifiedRestoreReceiptPath, completed, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<T> ReadProtectedJsonAsync<T>(
        string path,
        string unprotectedCode,
        CancellationToken cancellationToken)
    {
        await using FileStream stream = OwnerProtectedFilePolicy.OpenRead(path, unprotectedCode);
        try
        {
            return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken).ConfigureAwait(false) ??
                throw new MigrationConsoleException("configuration_invalid", "A protected JSON document is empty.");
        }
        catch (JsonException)
        {
            throw new MigrationConsoleException("configuration_invalid", "A protected JSON document is invalid.");
        }
    }

    private static async Task<string> ReadProtectedTextAsync(
        string path,
        string unprotectedCode,
        CancellationToken cancellationToken)
    {
        await using FileStream stream = OwnerProtectedFilePolicy.OpenRead(path, unprotectedCode);
        using var reader = new StreamReader(stream, leaveOpen: true);
        return await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteNewJsonAsync<T>(string path, T value, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)!;
        _ = Directory.CreateDirectory(directory);
        string temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        Exception? publicationFailure = null;
        try
        {
            await using (FileStream stream = new(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, value, JsonOptions, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporaryPath, fullPath, overwrite: false);
        }
        catch (Exception exception)
        {
            publicationFailure = exception;
        }
        Exception? cleanupFailure = null;
        try
        {
            File.Delete(temporaryPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            cleanupFailure = exception;
        }
        if (publicationFailure is not null && cleanupFailure is not null)
        {
            throw new AggregateException(
                "Create-only JSON publication failed and its temporary file could not be removed.",
                publicationFailure,
                cleanupFailure);
        }
        if (cleanupFailure is not null)
        {
            ExceptionDispatchInfo.Capture(cleanupFailure).Throw();
        }
        if (publicationFailure is not null)
        {
            ExceptionDispatchInfo.Capture(publicationFailure).Throw();
        }
    }

    internal static Task WriteNewJsonForTestsAsync<T>(string path, T value, CancellationToken cancellationToken)
    {
        return WriteNewJsonAsync(path, value, cancellationToken);
    }

    private sealed record MigrationConsoleConfiguration(
        PlanCommandConfiguration? Plan = null,
        ExecuteShadowCommandConfiguration? ExecuteShadow = null,
        EvidenceCommandConfiguration? Evidence = null,
        ExportLocalSnapshotCommandConfiguration? ExportLocalSnapshot = null,
        FullBackupCommandConfiguration? FullBackup = null,
        RestoreBackupsCommandConfiguration? RestoreBackups = null,
        AuthorizeShadowCommandConfiguration? AuthorizeShadow = null,
        SignProvenanceCommandConfiguration? SignProvenance = null,
        QuotationSchemaBaselineCommandConfiguration? QuotationSchemaBaseline = null,
        QuotationPostgreSqlSnapshotCommandConfiguration? QuotationPostgreSqlSnapshot = null,
        SigningRolesCommandConfiguration? SigningRoles = null);

    private sealed record QuotationSchemaBaselineCommandConfiguration(
        string PlanPath,
        string OutputPath,
        string ReviewedSchemaPlanSha256,
        string Workload,
        string SourceSnapshotId,
        string CopyPlanId,
        string Host,
        int Port,
        DateTimeOffset ExpiresUtc,
        string KeyId,
        string SigningKeyFingerprintSha256,
        IReadOnlyList<string> ForbiddenSigningKeyFingerprintsSha256,
        bool AllowSigning);

    private sealed record QuotationPostgreSqlSnapshotCommandConfiguration(
        string PlanPath,
        string OutputPath,
        string ReviewedSchemaPlanSha256,
        string Workload,
        Guid RunId,
        string SourceSnapshotId,
        string CopyPlanId,
        string SchemaHash,
        string Host,
        int Port,
        string SnapshotId,
        string BackupObjectUri,
        long BackupObjectGeneration,
        string ClusterNamespace,
        string ClusterName,
        DateTimeOffset ExpiresUtc,
        string KeyId,
        string SigningKeyFingerprintSha256,
        IReadOnlyList<string> ForbiddenSigningKeyFingerprintsSha256,
        bool AllowSigning);

    private sealed record SigningRolesCommandConfiguration(
        TrustedKeyReference Backup,
        TrustedKeyReference Authorization,
        TrustedKeyReference Execution,
        TrustedKeyReference Provenance,
        TrustedKeyReference FinalEvidence);

    private sealed record SigningRoleTrust(string KeyId, string Fingerprint);

    private sealed record SigningRoleTrustBundle(
        SigningRoleTrust Backup,
        SigningRoleTrust Authorization,
        SigningRoleTrust Execution,
        SigningRoleTrust Provenance,
        SigningRoleTrust FinalEvidence);

    private sealed record FullBackupCommandConfiguration(
        string Namespace,
        string ExpectedPodName,
        string ExpectedPodUid,
        string ContainerName,
        string GcsPrefix,
        string LocalWorkingDirectory,
        string RunId,
        DateTimeOffset ApprovedRunUtc,
        int MaximumTransportAttempts,
        string PublicationDirectory,
        string KeyId,
        bool AllowSourceBackup);

    private sealed record PlanCommandConfiguration(string OutputPath, string SourceCommitSha);

    private sealed record AuthorizeShadowCommandConfiguration(
        string ReceiptPath,
        string PlanPath,
        string OutputPath,
        string ExpectedSourceCommitSha,
        string ReviewedSchemaPlanSha256,
        DateTimeOffset IssuedAtUtc,
        DateTimeOffset ExpiresAtUtc,
        string KeyId,
        IReadOnlyList<TrustedKeyReference> ReceiptTrustedKeys,
        double MaximumReceiptAgeMinutes,
        bool AllowShadowAuthorization);

    private sealed record SignProvenanceCommandConfiguration(
        string OutputPath,
        string ReviewedSchemaPlanSha256,
        DateTimeOffset IssuedAtUtc,
        string KeyId,
        bool AllowProvenanceSigning);

    private sealed record RestoreBackupsCommandConfiguration(
        string ReceiptPath,
        string RecoveryDirectory,
        string SqlServerDataDirectory,
        string SqlServerVisibleRecoveryDirectory,
        string StagingVolumeName,
        string StagingImage,
        string SqlServerContainerName,
        string SqlServerImageId,
        string SqlServerImage,
        string RunBinding,
        double MaximumReceiptAgeMinutes,
        IReadOnlyList<TrustedKeyReference> ReceiptTrustedKeys,
        string? VerifiedRestoreReceiptPath = null,
        string? FinalVerifiedRestoreReceiptPath = null,
        string? ProvenanceKeyId = null,
        IReadOnlyList<TrustedKeyReference>? ProvenanceTrustedKeys = null);

    private sealed record ExecuteShadowCommandConfiguration(
        string ReceiptPath,
        string PlanPath,
        string AuthorizationPath,
        string OutputPath,
        IReadOnlyList<TrustedKeyReference> ReceiptTrustedKeys,
        IReadOnlyList<TrustedKeyReference> AuthorizationTrustedKeys,
        string EvidenceKeyId,
        string ExpectedControlRole,
        string ExpectedShadowAdminRole);

    private sealed record TrustedKeyReference(string KeyId, string SubjectPublicKeyInfoPath);

    private sealed record EvidenceCommandConfiguration(
        string ExecutionResultPath,
        string ProvenancePath,
        string ReceiptPath,
        string PlanPath,
        string AuthorizationPath,
        string PublicationDirectory,
        string SourceSnapshotId,
        string BackupUri,
        string BackupObjectGeneration,
        string RestoreId,
        Guid EvidenceId,
        Guid LeaseId,
        DateTimeOffset LeaseAcquiredAtUtc,
        DateTimeOffset LeaseExpiresAtUtc,
        IReadOnlyList<TrustedKeyReference> BackupTrustedKeys,
        IReadOnlyList<TrustedKeyReference> AuthorizationTrustedKeys,
        IReadOnlyList<TrustedKeyReference> ExecutionTrustedKeys,
        IReadOnlyList<TrustedKeyReference> ProvenanceTrustedKeys,
        string EvidenceKeyId,
        string? VerifiedRestoreReceiptPath = null);

    private sealed record ExportLocalSnapshotCommandConfiguration(
        string ExecutionResultPath,
        string OutputDirectory,
        string PgDumpPath);

    private sealed class DisabledExternalCommandExecutor : IExternalCommandExecutor
    {
        public Task<int> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("External commands are disabled in the guarded shadow runner.");
        }
    }
}

internal sealed record Exact25BackupRuntime(
    IExact25FullBackupProcess Process,
    IImmutableBackupObjectStorage Storage);

internal interface IExact25BackupRuntimeFactory
{
    Task<Exact25BackupRuntime> CreateAsync(CancellationToken cancellationToken);
}

internal interface IAuthorizationRuntimeAttestationFactory
{
    Task<RunnerArtifactManifest> MeasureRunnerAsync(CancellationToken cancellationToken);

    Task<CloudNativePgTargetObservation> ObserveTargetAsync(
        string namespaceName,
        string cluster,
        CancellationToken cancellationToken);
}

internal interface IQuotationSnapshotRuntimeFactory
{
    Task<IImmutablePostgreSqlSnapshotObserver> CreateSnapshotObserverAsync(CancellationToken cancellationToken);
    ICloudNativePgTargetObserver CreateTargetObserver();
}

internal sealed class DefaultQuotationSnapshotRuntimeFactory : IQuotationSnapshotRuntimeFactory
{
    public async Task<IImmutablePostgreSqlSnapshotObserver> CreateSnapshotObserverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await GoogleCloudImmutablePostgreSqlSnapshotObserver.CreateWithApplicationDefaultCredentialsAsync()
            .ConfigureAwait(false);
    }

    public ICloudNativePgTargetObserver CreateTargetObserver()
    {
        return new CloudNativePgTargetObserver(new(
            new Uri("https://kubernetes.default.svc", UriKind.Absolute),
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"));
    }
}

internal sealed class DefaultAuthorizationRuntimeAttestationFactory : IAuthorizationRuntimeAttestationFactory
{
    public Task<RunnerArtifactManifest> MeasureRunnerAsync(CancellationToken cancellationToken)
    {
        return RunnerArtifactManifestMeasurer.MeasureAsync(AppContext.BaseDirectory, cancellationToken);
    }

    public async Task<CloudNativePgTargetObservation> ObserveTargetAsync(
        string namespaceName,
        string cluster,
        CancellationToken cancellationToken)
    {
        using var observer = new CloudNativePgTargetObserver(new(
            new Uri("https://kubernetes.default.svc", UriKind.Absolute),
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"));
        return await observer.ObserveAsync(namespaceName, cluster, cancellationToken).ConfigureAwait(false);
    }
}

internal sealed class DefaultExact25BackupRuntimeFactory : IExact25BackupRuntimeFactory
{
    public async Task<Exact25BackupRuntime> CreateAsync(CancellationToken cancellationToken)
    {
        var process = new KubernetesSqlServerFullBackupProcess(new SystemBackupProcessRunner());
        GoogleCloudImmutableBackupObjectStorage storage = await GoogleCloudImmutableBackupObjectStorage
            .CreateWithApplicationDefaultCredentialsAsync(cancellationToken).ConfigureAwait(false);
        return new(process, storage);
    }
}

internal static class OwnerProtectedFilePolicy
{
    public static FileStream OpenRead(string path, string errorCode)
    {
        string fullPath = Path.GetFullPath(path);
        if (!HasNoLinkAncestors(fullPath) || !IsOwnerOnly(fullPath))
        {
            throw new MigrationConsoleException(errorCode, "The protected file must be owner-only and must not be a symbolic link.");
        }

        try
        {
            var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.None,
                64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (!HasNoLinkAncestors(fullPath) || !IsOwnerOnly(fullPath) ||
                !HandleResolvesTo(stream.SafeFileHandle, fullPath) ||
                (!OperatingSystem.IsWindows() && !UnixHandleIsOwnedByEffectiveUser(stream.SafeFileHandle)))
            {
                stream.Dispose();
                throw new MigrationConsoleException(errorCode, "The protected file changed while it was being opened.");
            }
            return stream;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new MigrationConsoleException(errorCode, "The protected file could not be opened safely.");
        }
    }

    public static bool IsOwnerOnly(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var file = new FileInfo(Path.GetFullPath(path));
        if (!file.Exists || file.LinkTarget is not null || (file.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            return false;
        }

        if (OperatingSystem.IsWindows())
        {
            return IsOwnerOnlyWindows(file.FullName);
        }

        UnixFileMode mode = File.GetUnixFileMode(file.FullName);
        const UnixFileMode forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        return (mode & forbidden) == 0 && (mode & UnixFileMode.UserRead) != 0 &&
            UnixPathIsOwnedByEffectiveUser(file.FullName);
    }

    private static bool HasNoLinkAncestors(string path)
    {
        for (DirectoryInfo? current = new(Path.GetDirectoryName(Path.GetFullPath(path))!); current is not null; current = current.Parent)
        {
            current.Refresh();
            if (current.Exists && (current.LinkTarget is not null || (current.Attributes & FileAttributes.ReparsePoint) != 0))
            {
                return false;
            }
        }
        return true;
    }

    private static bool HandleResolvesTo(SafeFileHandle handle, string expectedPath)
    {
        string? observed = OperatingSystem.IsWindows()
            ? FinalWindowsPath(handle)
            : OperatingSystem.IsLinux() ? FinalLinuxPath(handle) : expectedPath;
        return observed is not null && string.Equals(
            Path.GetFullPath(observed).TrimEnd(Path.DirectorySeparatorChar),
            Path.GetFullPath(expectedPath).TrimEnd(Path.DirectorySeparatorChar),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }

    [SupportedOSPlatform("windows")]
    private static string? FinalWindowsPath(SafeFileHandle handle)
    {
        var buffer = new char[4096];
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0 || length >= buffer.Length)
        {
            return null;
        }
        string value = new(buffer, 0, checked((int)length));
        return NormalizeWindowsFinalPath(value);
    }

    internal static string NormalizeWindowsFinalPath(string value)
    {
        const string uncPrefix = @"\\?\UNC\";
        const string devicePrefix = @"\\?\";
        return value.StartsWith(uncPrefix, StringComparison.OrdinalIgnoreCase)
            ? @"\\" + value[uncPrefix.Length..]
            : value.StartsWith(devicePrefix, StringComparison.Ordinal) ? value[devicePrefix.Length..] : value;
    }

    internal static bool IsEffectiveUnixUserId(uint uid)
    {
        return OperatingSystem.IsLinux() && uid == GetEffectiveUserId();
    }

    [SupportedOSPlatform("linux")]
    internal static uint GetEffectiveUserId()
    {
        return GetEffectiveUserIdNative();
    }

    private static bool UnixPathIsOwnedByEffectiveUser(string path)
    {
        return OperatingSystem.IsLinux() &&
            Statx(AtCurrentWorkingDirectory, path, AtSymlinkNoFollow, StatxBasicStats, out LinuxStatx stat) == 0 &&
            IsEffectiveUnixUserId(stat.Uid);
    }

    private static bool UnixHandleIsOwnedByEffectiveUser(SafeFileHandle handle)
    {
        if (!OperatingSystem.IsLinux())
        {
            return false;
        }

        int fd = checked((int)handle.DangerousGetHandle());
        return Statx(fd, string.Empty, AtEmptyPath, StatxBasicStats, out LinuxStatx stat) == 0 &&
            IsEffectiveUnixUserId(stat.Uid);
    }

    [SupportedOSPlatform("linux")]
    private static string? FinalLinuxPath(SafeFileHandle handle)
    {
        string fdPath = $"/proc/self/fd/{handle.DangerousGetHandle()}";
        return File.ResolveLinkTarget(fdPath, returnFinalTarget: true)?.FullName;
    }

#pragma warning disable SYSLIB1054 // SafeFileHandle plus a fixed caller-owned character buffer has no source-generated safe alternative without enabling unsafe code.
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle handle,
        [Out] char[] path,
        uint capacity,
        uint flags);
#pragma warning restore SYSLIB1054

    private const int AtCurrentWorkingDirectory = -100;
    private const int AtSymlinkNoFollow = 0x100;
    private const int AtEmptyPath = 0x1000;
    private const uint StatxBasicStats = 0x7ff;

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStatx
    {
        [FieldOffset(20)] public uint Uid;
    }

#pragma warning disable SYSLIB1054, CA2101 // Fixed Linux ABI; UTF-8 path is explicit and no unsafe source-generated marshaller is enabled.
    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint GetEffectiveUserIdNative();

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(int directoryFileDescriptor, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out LinuxStatx stat);
#pragma warning restore SYSLIB1054, CA2101

    [SupportedOSPlatform("windows")]
    private static bool IsOwnerOnlyWindows(string path)
    {
        SecurityIdentifier current = WindowsIdentity.GetCurrent().User ?? throw new UnauthorizedAccessException();
        FileSecurity security = new FileInfo(path).GetAccessControl();
        return security.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && owner.Equals(current) &&
            security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .All(rule => rule.IdentityReference.Equals(current));
    }
}

public sealed class MigrationConsoleException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
