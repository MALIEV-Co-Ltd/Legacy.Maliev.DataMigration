namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PgDumpSourceContractTests
{
    [Fact]
    public void BuildStartInfo_UsesRestorableCustomDumpAndKeepsCredentialsOutOfArguments()
    {
        System.Diagnostics.ProcessStartInfo start = PgDumpSource.BuildStartInfo(
            "C:/tools/pg_dump.exe",
            "Host=localhost;Port=5432;Database=postgres;Username=legacy;Password=super-secret;SSL Mode=Disable",
            "legacy_shadow_order_0123456789abcdef0123456789abcdef");

        Assert.Contains("--format=custom", start.ArgumentList);
        Assert.DoesNotContain("--format=plain", start.ArgumentList);
        Assert.DoesNotContain("--restrict-key", start.ArgumentList);
        Assert.Contains("legacy_shadow_order_0123456789abcdef0123456789abcdef", start.ArgumentList);
        Assert.DoesNotContain(start.ArgumentList, argument => argument.Contains("super-secret", StringComparison.Ordinal));
        Assert.Equal("super-secret", start.Environment["PGPASSWORD"]);
        Assert.True(start.RedirectStandardOutput);
        Assert.True(start.RedirectStandardError);
    }
}
