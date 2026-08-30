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
    private const string CloudNativePgApiServerEnvironmentVariable = "LEGACY_MIGRATION_CNPG_API_SERVER";
    private const string CloudNativePgTokenFileEnvironmentVariable = "LEGACY_MIGRATION_CNPG_TOKEN_FILE";
    private const string CloudNativePgCaFileEnvironmentVariable = "LEGACY_MIGRATION_CNPG_CA_FILE";
    private const string EvidenceKeyEnvironmentVariable = "LEGACY_MIGRATION_EVIDENCE_SIGNING_KEY_FILE";
    private const string SnapshotKeyEnvironmentVariable = "LEGACY_MIGRATION_SNAPSHOT_ENCRYPTION_KEY_FILE";
    private const string BackupSqlUserEnvironmentVariable = "LEGACY_MIGRATION_BACKUP_SQL_USERNAME";
    private const string BackupSqlPasswordEnvironmentVariable = "LEGACY_MIGRATION_BACKUP_SQL_PASSWORD";
    private const string RestoreSqlServerConnectionEnvironmentVariable = "LEGACY_SQLSERVER_ADMIN_CONNECTION";
    private const string ProvenanceSigningKeyEnvironmentVariable = "LEGACY_MIGRATION_PROVENANCE_SIGNING_KEY_FILE";
    private const string DeployEnabledEnvironmentVariable = "LEGACY_DEPLOY_ENABLED";
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
        return RunCoreAsync(arguments, output, error, getEnvironmentVariable, backupRuntimeFactory, cancellationToken);
    }

    private static async Task<int> RunCoreAsync(
        IReadOnlyList<string> arguments,
        TextWriter output,
        TextWriter error,
        Func<string, string?> getEnvironmentVariable,
        IExact25BackupRuntimeFactory backupRuntimeFactory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(getEnvironmentVariable);
        ArgumentNullException.ThrowIfNull(backupRuntimeFactory);
        try
        {
            ConsoleInvocation invocation = ConsoleInvocation.Parse(arguments);
            switch (invocation.Command)
            {
                case "plan":
                    await ProducePlanAsync(invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("plan_complete").ConfigureAwait(false);
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
        MigrationConsoleConfiguration configuration = await ReadJsonAsync<MigrationConsoleConfiguration>(configPath, cancellationToken)
            .ConfigureAwait(false);
        EvidenceCommandConfiguration evidence = configuration.Evidence ??
            throw new MigrationConsoleException("evidence_configuration_missing", "Evidence configuration is required.");
        string? keyPath = getEnvironmentVariable(EvidenceKeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(keyPath))
        {
            throw new MigrationConsoleException("evidence_runtime_reference_missing", "The protected evidence signing key is required.");
        }

        MigrationExecutionResult result = await ReadJsonAsync<MigrationExecutionResult>(evidence.ExecutionResultPath, cancellationToken)
            .ConfigureAwait(false);
        MigrationEvidenceProvenanceReceipt provenance = await ReadJsonAsync<MigrationEvidenceProvenanceReceipt>(evidence.ProvenancePath, cancellationToken)
            .ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(evidence.VerifiedRestoreReceiptPath))
        {
            throw new MigrationConsoleException("verified_restore_receipt_missing", "Completed verified restore evidence is required.");
        }
        VerifiedRestoreReceipt verifiedRestore = await ReadJsonAsync<VerifiedRestoreReceipt>(
            evidence.VerifiedRestoreReceiptPath, cancellationToken).ConfigureAwait(false);
        BackupReceipt receipt = await ReadJsonAsync<BackupReceipt>(evidence.ReceiptPath, cancellationToken).ConfigureAwait(false);
        FreshSchemaPlan plan = await ReadJsonAsync<FreshSchemaPlan>(evidence.PlanPath, cancellationToken).ConfigureAwait(false);
        ExecutionAuthorizationReceipt authorization = await ReadJsonAsync<ExecutionAuthorizationReceipt>(evidence.AuthorizationPath, cancellationToken)
            .ConfigureAwait(false);
        ReceiptAttestationTrustStore backupTrust = await ReadTrustStoreAsync(evidence.BackupTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore authorizationTrust = await ReadTrustStoreAsync(evidence.AuthorizationTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore executionTrust = await ReadTrustStoreAsync(evidence.ExecutionTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore provenanceTrust = await ReadTrustStoreAsync(evidence.ProvenanceTrustedKeys, cancellationToken).ConfigureAwait(false);
        string privateKeyPem = await File.ReadAllTextAsync(keyPath, cancellationToken).ConfigureAwait(false);
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
        MigrationConsoleConfiguration configuration = await ReadJsonAsync<MigrationConsoleConfiguration>(configPath, cancellationToken)
            .ConfigureAwait(false);
        ExportLocalSnapshotCommandConfiguration export = configuration.ExportLocalSnapshot ??
            throw new MigrationConsoleException("snapshot_configuration_missing", "Snapshot export configuration is required.");
        string? targetConnection = getEnvironmentVariable(PostgreSqlConnectionEnvironmentVariable);
        string? keyPath = getEnvironmentVariable(SnapshotKeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(targetConnection) || string.IsNullOrWhiteSpace(keyPath))
        {
            throw new MigrationConsoleException("snapshot_runtime_reference_missing", "Snapshot runtime references are required.");
        }

        MigrationExecutionResult result = await ReadJsonAsync<MigrationExecutionResult>(export.ExecutionResultPath, cancellationToken)
            .ConfigureAwait(false);
        if (result.Status is not (MigrationExecutionStatus.Completed or MigrationExecutionStatus.AlreadyCompleted) ||
            result.Receipt.Databases.Count != DatabaseInventory.ActiveDatabases.Count)
        {
            throw new MigrationConsoleException("snapshot_execution_result_invalid", "A completed exact migration result is required.");
        }

        byte[] key;
        try
        {
            key = SnapshotRootKey.Load(keyPath);
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
        MigrationConsoleConfiguration configuration = await ReadJsonAsync<MigrationConsoleConfiguration>(configPath, cancellationToken)
            .ConfigureAwait(false);
        ExecuteShadowCommandConfiguration execute = configuration.ExecuteShadow ??
            throw new MigrationConsoleException("shadow_configuration_missing", "Shadow execution configuration is required.");
        string? sourceConnection = getEnvironmentVariable(SqlServerConnectionEnvironmentVariable);
        string? targetConnection = getEnvironmentVariable(PostgreSqlConnectionEnvironmentVariable);
        string? controlConnection = getEnvironmentVariable(PostgreSqlControlConnectionEnvironmentVariable);
        string? cloudNativePgApiServer = getEnvironmentVariable(CloudNativePgApiServerEnvironmentVariable);
        string? cloudNativePgTokenFile = getEnvironmentVariable(CloudNativePgTokenFileEnvironmentVariable);
        string? cloudNativePgCaFile = getEnvironmentVariable(CloudNativePgCaFileEnvironmentVariable);
        string? evidenceKeyPath = getEnvironmentVariable(EvidenceKeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(sourceConnection) || string.IsNullOrWhiteSpace(targetConnection) ||
            string.IsNullOrWhiteSpace(controlConnection) || string.IsNullOrWhiteSpace(evidenceKeyPath) ||
            string.IsNullOrWhiteSpace(cloudNativePgApiServer) || string.IsNullOrWhiteSpace(cloudNativePgTokenFile) ||
            string.IsNullOrWhiteSpace(cloudNativePgCaFile))
        {
            throw new MigrationConsoleException("shadow_runtime_reference_missing", "Shadow runtime references are required.");
        }

        _ = await PostgreSqlMigrationRuntimeBoundaryValidator.ValidateAsync(
            controlConnection,
            targetConnection,
            execute.ExpectedControlRole,
            execute.ExpectedShadowAdminRole,
            cancellationToken).ConfigureAwait(false);

        BackupReceipt receipt = await ReadJsonAsync<BackupReceipt>(execute.ReceiptPath, cancellationToken).ConfigureAwait(false);
        FreshSchemaPlan plan = await ReadJsonAsync<FreshSchemaPlan>(execute.PlanPath, cancellationToken).ConfigureAwait(false);
        ExecutionAuthorizationReceipt authorization = await ReadJsonAsync<ExecutionAuthorizationReceipt>(execute.AuthorizationPath, cancellationToken)
            .ConfigureAwait(false);
        ReceiptAttestationTrustStore receiptTrust = await ReadTrustStoreAsync(execute.ReceiptTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore authorizationTrust = await ReadTrustStoreAsync(execute.AuthorizationTrustedKeys, cancellationToken).ConfigureAwait(false);
        string privateKeyPem = await File.ReadAllTextAsync(evidenceKeyPath, cancellationToken).ConfigureAwait(false);
        using var evidenceSigner = new P256MigrationEvidenceSigner(execute.EvidenceKeyId, privateKeyPem);
        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(sourceConnection));
        using var provisioner = new CloudNativePgShadowDatabaseProvisioner(new(
            new Uri(cloudNativePgApiServer, UriKind.Absolute),
            execute.CloudNativePgNamespace,
            execute.CloudNativePgCluster,
            execute.ExpectedShadowAdminRole,
            cloudNativePgTokenFile,
            cloudNativePgCaFile,
            TimeSpan.FromMinutes(5)));
        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(targetConnection, provisioner));
        var journal = new PostgreSqlMigrationRunJournal(new PostgreSqlMigrationRunJournalOptions(
            controlConnection,
            ExpectedControlRole: execute.ExpectedControlRole));
        var runner = new GuardedShadowMigrationRunner(
            new PreflightService(new DisabledExternalCommandExecutor(), receiptTrust),
            authorizationTrust,
            source,
            target,
            journal,
            evidenceSigner,
            TimeProvider.System,
            new GuardedRunnerPolicy(plan.SourceCommitSha, execute.RunnerDigestSha256));
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

    private static async Task ProducePlanAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        MigrationConsoleConfiguration configuration = await ReadJsonAsync<MigrationConsoleConfiguration>(configPath, cancellationToken)
            .ConfigureAwait(false);
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

    private static async Task<T> ReadJsonAsync<T>(string path, CancellationToken cancellationToken)
    {
        try
        {
            await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken).ConfigureAwait(false) ??
                throw new MigrationConsoleException("configuration_invalid", "A referenced JSON document is empty.");
        }
        catch (JsonException)
        {
            throw new MigrationConsoleException("configuration_invalid", "A referenced JSON document is invalid.");
        }
        catch (IOException)
        {
            throw new MigrationConsoleException("configuration_unavailable", "A referenced JSON document is unavailable.");
        }
        catch (UnauthorizedAccessException)
        {
            throw new MigrationConsoleException("configuration_unavailable", "A referenced JSON document is unavailable.");
        }
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
        VerifiedRestoreReceipt pending = await ReadJsonAsync<VerifiedRestoreReceipt>(
            restore.VerifiedRestoreReceiptPath, cancellationToken).ConfigureAwait(false);
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
        RestoreBackupsCommandConfiguration? RestoreBackups = null);

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
        string RunnerDigestSha256,
        IReadOnlyList<TrustedKeyReference> ReceiptTrustedKeys,
        IReadOnlyList<TrustedKeyReference> AuthorizationTrustedKeys,
        string EvidenceKeyId,
        string ExpectedControlRole,
        string ExpectedShadowAdminRole,
        string CloudNativePgNamespace = "maliev-legacy",
        string CloudNativePgCluster = "legacy-postgres-main");

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
