namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PgDumpSourceContractTests
{
    [Theory]
    [InlineData("Search Path=untrusted")]
    [InlineData("Options=-c statement_timeout=0")]
    [InlineData("SSL Certificate=other.pem")]
    [InlineData("GSS Encryption Mode=Require")]
    public void BuildStartInfo_UnsupportedSettingsFailRatherThanBeingDropped(string extra)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => PgDumpSource.BuildStartInfo("C:/tools/pg_dump.exe",
            "Host=localhost;Database=postgres;Username=fixture;Password=secret;" + extra,
            "legacy_shadow_order_0123456789abcdef0123456789abcdef"));
    }
    [Theory]
    [InlineData("VerifyFull", "verify-full")]
    [InlineData("VerifyCA", "verify-ca")]
    public void BuildStartInfo_PreservesExplicitTlsTrust(string mode, string expected)
    {
        System.Diagnostics.ProcessStartInfo start = PgDumpSource.BuildStartInfo(
            "C:/tools/pg_dump.exe",
            $"Host=postgres.example;Database=postgres;Username=legacy;Password=secret;SSL Mode={mode};Root Certificate=C:/protected/ca.pem",
            "legacy_shadow_order_0123456789abcdef0123456789abcdef");
        Assert.Equal(expected, start.Environment["PGSSLMODE"]);
        Assert.Equal("C:/protected/ca.pem", start.Environment["PGSSLROOTCERT"]);
    }

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
