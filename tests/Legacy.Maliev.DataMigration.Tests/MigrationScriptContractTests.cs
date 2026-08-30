namespace Legacy.Maliev.DataMigration.Tests;

public sealed class MigrationScriptContractTests
{
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
        Assert.Contains("restoreException", console, StringComparison.Ordinal);
        Assert.Contains("cleanupException", console, StringComparison.Ordinal);
    }

    [Fact]
    public void OrchestrationScript_UsesProtectedConfigAndExplicitShadowStages()
    {
        string script = File.ReadAllText(SourcePath("invoke-shadow-migration.ps1"));

        Assert.Contains("--config", script, StringComparison.Ordinal);
        Assert.DoesNotContain("'receipt'", script, StringComparison.Ordinal);
        Assert.Contains("restore-verified-sqlserver-backups.ps1", script, StringComparison.Ordinal);
        Assert.Contains("plan", script, StringComparison.Ordinal);
        Assert.Contains("execute-shadow", script, StringComparison.Ordinal);
        Assert.Contains("evidence", script, StringComparison.Ordinal);
        Assert.Contains("export-local-snapshot", script, StringComparison.Ordinal);
        Assert.Contains("LEGACY_DEPLOY_ENABLED", script, StringComparison.Ordinal);
        Assert.DoesNotContain("kubectl", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("gcloud", script, StringComparison.OrdinalIgnoreCase);
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
