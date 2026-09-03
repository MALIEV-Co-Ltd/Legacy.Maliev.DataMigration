namespace Legacy.Maliev.DataMigration.Tests;

public sealed class MigrationScriptContractTests
{
    [Theory]
    [InlineData("execute-shadow")]
    [InlineData("plan-incremental")]
    [InlineData("plan-resume")]
    [InlineData("authorize-resume")]
    [InlineData("resume-shadow")]
    [InlineData("finalize-local")]
    public async Task IncrementalStages_RejectUnprotectedOperatorConfigurationBeforeRuntime(string command)
    {
        string path = Path.Combine(Path.GetTempPath(), "unsafe-console-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            await File.WriteAllTextAsync(path, "private data must not be printed");
            if (!OperatingSystem.IsWindows()) { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead); }
            using var error = new StringWriter();
            int exit = await Console.MigrationConsole.RunAsync([command, "--config", path], TextWriter.Null, error,
                name => name == "LEGACY_DEPLOY_ENABLED" ? "false" : throw new InvalidOperationException("Runtime must not be reached"), CancellationToken.None);
            Assert.Equal(65, exit);
            Assert.Equal("incremental_config_unprotected" + Environment.NewLine, error.ToString());
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void RestoreScript_VerifiesAndRestoresExactInventoryReadOnly()
    {
        string script = File.ReadAllText(SourcePath("restore-verified-sqlserver-backups.ps1"));

        Assert.Contains("restore-backups", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Invoke-Sqlcmd", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Get-FileHash", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Get-Content", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("backup-state.json", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("restoreManifest", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-Password", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DotNetRestoreTarget_ProvesSqlServerReadsTheVerifiedBytesBeforeRestore()
    {
        string source = File.ReadAllText(SourceCodePath("VerifiedBackupRestorer.cs"));
        string staging = File.ReadAllText(SourceCodePath("DockerVolumeBackupStager.cs"));
        string provisioning = File.ReadAllText(SourceCodePath("DockerDisposableSqlServerProvisioner.cs"));
        string console = File.ReadAllText(ConsoleSourceCodePath("MigrationConsole.cs"));
        Assert.Contains("RESTORE VERIFYONLY", source, StringComparison.Ordinal);
        Assert.Contains("WITH CHECKSUM", source, StringComparison.Ordinal);
        Assert.Contains("CommandTimeout = 0", source, StringComparison.Ordinal);
        Assert.Contains("DockerVolumeBackupStager", staging, StringComparison.Ordinal);
        Assert.Contains("type=volume", staging, StringComparison.Ordinal);
        Assert.Contains("!mount.RW", staging, StringComparison.Ordinal);
        Assert.Contains("sha256sum", staging, StringComparison.Ordinal);
        Assert.Contains("artifact.ByteLength", staging, StringComparison.Ordinal);
        Assert.Contains("volume", provisioning, StringComparison.Ordinal);
        Assert.Contains("readonly", provisioning, StringComparison.Ordinal);
        Assert.Contains("MSSQL_SA_PASSWORD", provisioning, StringComparison.Ordinal);
        Assert.Contains("startInfo.Environment", provisioning, StringComparison.Ordinal);
        Assert.DoesNotContain("connection.Password]", provisioning, StringComparison.Ordinal);
        Assert.DoesNotContain("SINGLE_BLOB", source, StringComparison.Ordinal);
        Assert.DoesNotContain("HASHBYTES", source, StringComparison.Ordinal);
        Assert.Contains("SET ALLOW_SNAPSHOT_ISOLATION ON", source, StringComparison.Ordinal);
        Assert.Contains("snapshot_isolation_state", source, StringComparison.Ordinal);
        Assert.Contains("SET READ_ONLY", source, StringComparison.Ordinal);
        Assert.Contains("restore_container_cleanup_failed", provisioning, StringComparison.Ordinal);
        Assert.Contains("restore_volume_cleanup_failed", provisioning, StringComparison.Ordinal);
        int volumeCreateStart = provisioning.IndexOf("DockerResult volumeCreate", StringComparison.Ordinal);
        int volumeCreateEnd = provisioning.IndexOf("EnsureSuccess(volumeCreate", StringComparison.Ordinal);
        string volumeCreateSection = provisioning[volumeCreateStart..volumeCreateEnd];
        Assert.Contains("restore-volume-fingerprint", volumeCreateSection, StringComparison.Ordinal);
        Assert.DoesNotContain("volumeName", volumeCreateSection, StringComparison.Ordinal);
        Assert.Contains("SERVERPROPERTY('ProductMajorVersion')", provisioning, StringComparison.Ordinal);
        Assert.Contains("IsSqlServer2022", provisioning, StringComparison.Ordinal);
        Assert.Contains("restoreException", console, StringComparison.Ordinal);
        Assert.Contains("cleanupException", console, StringComparison.Ordinal);
        int restoreStart = console.IndexOf("private static async Task RestoreBackupsAsync", StringComparison.Ordinal);
        int cleanupStart = console.IndexOf("private static async Task CleanupRestoreAsync", StringComparison.Ordinal);
        string restoreSection = console[restoreStart..cleanupStart];
        string cleanupSection = console[cleanupStart..];
        Assert.Contains("ReadTrustStoreAsync(restore.ReceiptTrustedKeys", restoreSection, StringComparison.Ordinal);
        Assert.DoesNotContain("ReadTrustStoreAsync(restore.ProvenanceTrustedKeys", restoreSection, StringComparison.Ordinal);
        Assert.Contains("ReadTrustStoreAsync(restore.ProvenanceTrustedKeys", cleanupSection, StringComparison.Ordinal);
        Assert.Contains("SigningKeyMatchesTrust", restoreSection, StringComparison.Ordinal);
        Assert.Contains("SigningKeyMatchesTrust", cleanupSection, StringComparison.Ordinal);
        Assert.True(restoreSection.IndexOf("SigningKeyMatchesTrust", StringComparison.Ordinal) <
            restoreSection.IndexOf("ProvisionAsync", StringComparison.Ordinal));
        Assert.True(cleanupSection.IndexOf("SigningKeyMatchesTrust", StringComparison.Ordinal) <
            cleanupSection.IndexOf("CleanupAsync", StringComparison.Ordinal));
    }

    [Fact]
    public void OperatorScripts_SeparatePreparationApprovalExecutionAndFinalEvidence()
    {
        string prepare = File.ReadAllText(SourcePath("prepare-shadow-migration.ps1"));
        string execute = File.ReadAllText(SourcePath("execute-approved-shadow-migration.ps1"));
        string finalize = File.ReadAllText(SourcePath("finalize-shadow-migration.ps1"));
        Assert.False(File.Exists(SourcePath("invoke-shadow-migration.ps1")));

        Assert.Contains("backup-full", prepare, StringComparison.Ordinal);
        Assert.Contains("restore-verified-sqlserver-backups.ps1", prepare, StringComparison.Ordinal);
        Assert.Contains("plan", prepare, StringComparison.Ordinal);
        Assert.Contains("plan-digest", prepare, StringComparison.Ordinal);
        Assert.DoesNotContain("authorize-shadow", prepare, StringComparison.Ordinal);
        Assert.DoesNotContain("execute-shadow", prepare, StringComparison.Ordinal);

        Assert.Contains("authorize-shadow", execute, StringComparison.Ordinal);
        Assert.Contains("execute-shadow", execute, StringComparison.Ordinal);
        Assert.DoesNotContain("plan", execute, StringComparison.Ordinal);
        Assert.DoesNotContain("evidence", execute, StringComparison.Ordinal);

        int snapshot = finalize.IndexOf("export-local-snapshot", StringComparison.Ordinal);
        int cleanupAuthorization = finalize.IndexOf("authorize-cleanup", StringComparison.Ordinal);
        int shadowCleanup = finalize.IndexOf("cleanup-shadows", StringComparison.Ordinal);
        int cleanup = finalize.IndexOf("cleanup-restore", StringComparison.Ordinal);
        int provenance = finalize.IndexOf("sign-provenance", StringComparison.Ordinal);
        int evidence = finalize.IndexOf(" evidence ", StringComparison.Ordinal);
        Assert.True(snapshot >= 0 && snapshot < cleanupAuthorization);
        Assert.True(cleanupAuthorization < shadowCleanup);
        Assert.True(shadowCleanup < cleanup);
        Assert.True(cleanup < provenance);
        Assert.True(provenance < evidence);
        Assert.Contains("finally", finalize, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("AggregateException", finalize, StringComparison.Ordinal);
        Assert.Contains("if ($null -ne $snapshotFailure)", finalize, StringComparison.Ordinal);
        Assert.Contains("if ($null -ne $cleanupFailure)", finalize, StringComparison.Ordinal);
        Assert.DoesNotContain("execute-shadow", finalize, StringComparison.Ordinal);

        string all = string.Join('\n', prepare, execute, finalize);
        Assert.Contains("--config", all, StringComparison.Ordinal);
        Assert.Contains("LEGACY_DEPLOY_ENABLED", all, StringComparison.Ordinal);
        Assert.DoesNotContain("kubectl", all, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("gcloud", all, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("invoke-shadow-migration.ps1", all, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CleanupPublication_ReservesCanonicalOutputForCompleteReceiptAndUsesUniqueFailureEvidence()
    {
        string source = File.ReadAllText(ConsoleSourceCodePath("MigrationConsole.cs"));
        int incomplete = source.IndexOf("if (!result.IsComplete)", StringComparison.Ordinal);
        int failureDirectory = source.IndexOf("cleanup.FailurePublicationDirectory", incomplete, StringComparison.Ordinal);
        int failureSuffix = source.IndexOf(".cleanup-failure.json", incomplete, StringComparison.Ordinal);
        int canonical = source.IndexOf("WriteNewJsonAsync(cleanup.OutputPath", incomplete, StringComparison.Ordinal);

        Assert.True(incomplete >= 0 && failureDirectory > incomplete);
        Assert.True(failureSuffix > failureDirectory && canonical > failureSuffix);
        Assert.Contains("Guid.NewGuid():N", source[incomplete..canonical], StringComparison.Ordinal);
    }

    private static string SourcePath(string file)
    {
        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../scripts", file));
    }

    private static string SourceCodePath(string file)
    {
        return Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "../../../../../src/Legacy.Maliev.DataMigration", file));
    }

    private static string ConsoleSourceCodePath(string file)
    {
        return Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "../../../../../src/Legacy.Maliev.DataMigration.Console", file));
    }
}
