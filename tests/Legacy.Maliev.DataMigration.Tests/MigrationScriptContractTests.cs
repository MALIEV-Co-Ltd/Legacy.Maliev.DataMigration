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
        int hashProbe = source.IndexOf("OPENROWSET(BULK", StringComparison.Ordinal);
        int verifyOnly = source.IndexOf("RESTORE VERIFYONLY", StringComparison.Ordinal);

        Assert.True(hashProbe >= 0 && verifyOnly > hashProbe);
        Assert.Contains("HASHBYTES('SHA2_256'", source, StringComparison.Ordinal);
        Assert.Contains("FixedTimeEquals", source, StringComparison.Ordinal);
        Assert.Contains("SET ALLOW_SNAPSHOT_ISOLATION ON", source, StringComparison.Ordinal);
        Assert.Contains("snapshot_isolation_state", source, StringComparison.Ordinal);
        Assert.Contains("SET READ_ONLY", source, StringComparison.Ordinal);
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
}
