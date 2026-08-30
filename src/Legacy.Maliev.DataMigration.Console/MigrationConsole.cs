using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration.Console;

public static class MigrationConsole
{
    private const string SigningKeyEnvironmentVariable = "LEGACY_MIGRATION_RECEIPT_SIGNING_KEY_FILE";
    private const string SqlServerConnectionEnvironmentVariable = "LEGACY_MIGRATION_SQLSERVER_CONNECTION";
    private const string PostgreSqlConnectionEnvironmentVariable = "LEGACY_MIGRATION_POSTGRES_ADMIN_CONNECTION";
    private const string EvidenceKeyEnvironmentVariable = "LEGACY_MIGRATION_EVIDENCE_SIGNING_KEY_FILE";
    private const string SnapshotKeyEnvironmentVariable = "LEGACY_MIGRATION_SNAPSHOT_ENCRYPTION_KEY_FILE";
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
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(getEnvironmentVariable);
        try
        {
            ConsoleInvocation invocation = ConsoleInvocation.Parse(arguments);
            switch (invocation.Command)
            {
                case "receipt":
                    await ProduceReceiptAsync(invocation.ConfigPath, getEnvironmentVariable, cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("receipt_complete").ConfigureAwait(false);
                    return 0;
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
        catch (BackupReceiptProductionException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 65;
        }
        catch (MigrationExecutionException exception)
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
            new(result, receipt, plan, authorization, producerConfiguration, provenance),
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
            key = Convert.FromBase64String((await File.ReadAllTextAsync(keyPath, cancellationToken).ConfigureAwait(false)).Trim());
        }
        catch (FormatException)
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
        string? evidenceKeyPath = getEnvironmentVariable(EvidenceKeyEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(sourceConnection) || string.IsNullOrWhiteSpace(targetConnection) || string.IsNullOrWhiteSpace(evidenceKeyPath))
        {
            throw new MigrationConsoleException("shadow_runtime_reference_missing", "Shadow runtime references are required.");
        }

        BackupReceipt receipt = await ReadJsonAsync<BackupReceipt>(execute.ReceiptPath, cancellationToken).ConfigureAwait(false);
        FreshSchemaPlan plan = await ReadJsonAsync<FreshSchemaPlan>(execute.PlanPath, cancellationToken).ConfigureAwait(false);
        ExecutionAuthorizationReceipt authorization = await ReadJsonAsync<ExecutionAuthorizationReceipt>(execute.AuthorizationPath, cancellationToken)
            .ConfigureAwait(false);
        ReceiptAttestationTrustStore receiptTrust = await ReadTrustStoreAsync(execute.ReceiptTrustedKeys, cancellationToken).ConfigureAwait(false);
        ReceiptAttestationTrustStore authorizationTrust = await ReadTrustStoreAsync(execute.AuthorizationTrustedKeys, cancellationToken).ConfigureAwait(false);
        string privateKeyPem = await File.ReadAllTextAsync(evidenceKeyPath, cancellationToken).ConfigureAwait(false);
        using var evidenceSigner = new P256MigrationEvidenceSigner(execute.EvidenceKeyId, privateKeyPem);
        await using var source = new SqlServerMigrationSource(new SqlServerMigrationSourceOptions(sourceConnection));
        var target = new PostgreSqlShadowTarget(new PostgreSqlShadowTargetOptions(targetConnection));
        var journal = new PostgreSqlMigrationRunJournal(new PostgreSqlMigrationRunJournalOptions(targetConnection));
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
            byte[] publicKey = Convert.FromBase64String(await File.ReadAllTextAsync(reference.SubjectPublicKeyInfoPath, cancellationToken)
                .ConfigureAwait(false));
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

    private static async Task ProduceReceiptAsync(
        string configPath,
        Func<string, string?> getEnvironmentVariable,
        CancellationToken cancellationToken)
    {
        MigrationConsoleConfiguration configuration = await ReadJsonAsync<MigrationConsoleConfiguration>(configPath, cancellationToken)
            .ConfigureAwait(false);
        ReceiptCommandConfiguration receipt = configuration.Receipt ??
            throw new MigrationConsoleException("receipt_configuration_missing", "Receipt configuration is required.");
        string keyPath = getEnvironmentVariable(SigningKeyEnvironmentVariable) ??
            throw new MigrationConsoleException("receipt_signing_key_reference_missing", "The signing key file reference is required.");
        BackupStateDocument state = await ReadJsonAsync<BackupStateDocument>(receipt.BackupStatePath, cancellationToken)
            .ConfigureAwait(false);

        using ECDsa key = ECDsa.Create();
        try
        {
            key.ImportFromPem(await File.ReadAllTextAsync(keyPath, cancellationToken).ConfigureAwait(false));
        }
        catch (CryptographicException)
        {
            throw new MigrationConsoleException("receipt_signing_key_invalid", "The signing key file is invalid.");
        }

        BackupReceipt backupReceipt = await BackupReceiptProducer.ProduceAsync(
            state.Artifacts,
            receipt.KeyId,
            key,
            DateTimeOffset.UtcNow,
            cancellationToken).ConfigureAwait(false);
        await WriteNewJsonAsync(receipt.OutputPath, backupReceipt, cancellationToken).ConfigureAwait(false);
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

    private static async Task WriteNewJsonAsync<T>(string path, T value, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(path);
        _ = Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        await using FileStream stream = new(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await JsonSerializer.SerializeAsync(stream, value, JsonOptions, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private sealed record MigrationConsoleConfiguration(
        ReceiptCommandConfiguration? Receipt = null,
        PlanCommandConfiguration? Plan = null,
        ExecuteShadowCommandConfiguration? ExecuteShadow = null,
        EvidenceCommandConfiguration? Evidence = null,
        ExportLocalSnapshotCommandConfiguration? ExportLocalSnapshot = null);

    private sealed record ReceiptCommandConfiguration(string BackupStatePath, string OutputPath, string KeyId);

    private sealed record PlanCommandConfiguration(string OutputPath, string SourceCommitSha);

    private sealed record ExecuteShadowCommandConfiguration(
        string ReceiptPath,
        string PlanPath,
        string AuthorizationPath,
        string OutputPath,
        string RunnerDigestSha256,
        IReadOnlyList<TrustedKeyReference> ReceiptTrustedKeys,
        IReadOnlyList<TrustedKeyReference> AuthorizationTrustedKeys,
        string EvidenceKeyId);

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
        string EvidenceKeyId);

    private sealed record ExportLocalSnapshotCommandConfiguration(
        string ExecutionResultPath,
        string OutputDirectory,
        string PgDumpPath);

    private sealed record BackupStateDocument(IReadOnlyList<VerifiedBackupStateArtifact> Artifacts);

    private sealed class DisabledExternalCommandExecutor : IExternalCommandExecutor
    {
        public Task<int> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("External commands are disabled in the guarded shadow runner.");
        }
    }
}

public sealed class MigrationConsoleException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
