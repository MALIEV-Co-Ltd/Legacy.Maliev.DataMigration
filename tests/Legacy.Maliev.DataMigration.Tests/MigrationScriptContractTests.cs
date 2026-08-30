namespace Legacy.Maliev.DataMigration.Tests;

public sealed class MigrationScriptContractTests
{
    [Fact]
    public void RestoreScript_VerifiesAndRestoresExactInventoryReadOnly()
    {
        string script = File.ReadAllText(SourcePath("restore-verified-sqlserver-backups.ps1"));

        Assert.Contains("RESTORE VERIFYONLY", script, StringComparison.Ordinal);
        Assert.Contains("RESTORE FILELISTONLY", script, StringComparison.Ordinal);
        Assert.Contains("WITH MOVE", script, StringComparison.Ordinal);
        Assert.Contains("SET READ_ONLY", script, StringComparison.Ordinal);
        Assert.Contains("database-disposition.json", script, StringComparison.Ordinal);
        Assert.Contains("verify-backup", script, StringComparison.Ordinal);
        Assert.Contains("Get-FileHash", script, StringComparison.Ordinal);
        Assert.Contains("SET ALLOW_SNAPSHOT_ISOLATION ON", script, StringComparison.Ordinal);
        Assert.Contains("snapshot_isolation_state", script, StringComparison.Ordinal);
        Assert.Contains("SET READ_ONLY", script, StringComparison.Ordinal);
        Assert.DoesNotContain("backup-state.json", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-Password", script, StringComparison.OrdinalIgnoreCase);
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
}
