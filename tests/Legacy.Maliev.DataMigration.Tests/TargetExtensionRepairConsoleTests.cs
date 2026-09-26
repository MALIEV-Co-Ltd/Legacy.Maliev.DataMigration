using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class TargetExtensionRepairConsoleTests
{
    [Theory]
    [InlineData("true", "owner", "target_extension_repair_deploy_gate_invalid")]
    [InlineData("false", "operator", "target_extension_repair_caller_invalid")]
    public async Task CommandsRejectUnsafeCallerBeforeReadingConfiguration(
        string deployEnabled, string caller, string expected)
    {
        using var error = new StringWriter();
        int exit = await MigrationConsole.RunExtensionRepairForTestsAsync(
            ["apply-target-extension-repair", "--config", "missing-protected-config.json"],
            TextWriter.Null, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => deployEnabled,
                "LEGACY_MIGRATION_CALLER" => caller,
                _ => null,
            }, CancellationToken.None);
        Assert.Equal(65, exit);
        Assert.Equal(expected + Environment.NewLine, error.ToString());
    }
}
