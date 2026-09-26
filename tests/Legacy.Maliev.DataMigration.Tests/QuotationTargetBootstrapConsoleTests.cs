using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class QuotationTargetBootstrapConsoleTests
{
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
