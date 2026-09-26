using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class QuotationTargetBootstrapConsoleTests
{
    [Fact]
    public void Persistent_schema_plan_accepts_exact_two_hour_utc_boundary()
    {
        DateTimeOffset now = new(2026, 9, 26, 16, 0, 0, TimeSpan.Zero);

        MigrationConsole.ValidatePersistentQuotationSchemaFreshness(now.AddHours(-2), now);
    }

    [Theory]
    [InlineData(-120.001)]
    [InlineData(0.001)]
    public void Persistent_schema_plan_rejects_stale_or_future_capture(double minutesFromNow)
    {
        DateTimeOffset now = new(2026, 9, 26, 16, 0, 0, TimeSpan.Zero);

        MigrationConsoleException failure = Assert.Throws<MigrationConsoleException>(() =>
            MigrationConsole.ValidatePersistentQuotationSchemaFreshness(
                now.AddMinutes(minutesFromNow), now));
        Assert.Equal("quotation_target_bootstrap_schema_stale", failure.Code);
    }

    [Fact]
    public void Persistent_schema_plan_rejects_non_utc_offset()
    {
        DateTimeOffset now = new(2026, 9, 26, 16, 0, 0, TimeSpan.Zero);

        MigrationConsoleException failure = Assert.Throws<MigrationConsoleException>(() =>
            MigrationConsole.ValidatePersistentQuotationSchemaFreshness(
                now.ToOffset(TimeSpan.FromHours(7)), now));
        Assert.Equal("quotation_target_bootstrap_schema_stale", failure.Code);
    }

    [Theory]
    [InlineData("true", "owner")]
    [InlineData("false", "operator")]
    public async Task CommandsRejectUnsafeCallerBeforeReadingConfiguration(string deployEnabled, string caller)
    {
        using var error = new StringWriter();
        int exit = await MigrationConsole.RunQuotationTargetBootstrapForTestsAsync(
            ["apply-quotation-target-bootstrap", "--config", "missing-protected-config.json"],
            TextWriter.Null, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => deployEnabled,
                "LEGACY_MIGRATION_CALLER" => caller,
                _ => null,
            }, CancellationToken.None);
        Assert.Equal(65, exit);
        Assert.Equal("quotation_target_bootstrap_owner_gate_invalid" + Environment.NewLine, error.ToString());
    }
}
