using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ConsoleCommandContractTests
{
    public static TheoryData<string> SupportedCommands =>
    [
        "plan",
        "execute-shadow",
        "evidence",
        "export-local-snapshot",
        "backup-full",
        "authorize-shadow",
        "sign-provenance",
    ];

    [Theory]
    [MemberData(nameof(SupportedCommands))]
    public void Parse_AcceptsOnlyExplicitSubcommands(string command)
    {
        ConsoleInvocation invocation = ConsoleInvocation.Parse([command, "--config", "protected.json"]);

        Assert.Equal(command, invocation.Command);
        Assert.Equal("protected.json", invocation.ConfigPath);
    }

    [Fact]
    public void Parse_RejectsSecretBearingArguments()
    {
        CommandLineException exception = Assert.Throws<CommandLineException>(() =>
            ConsoleInvocation.Parse(["plan", "--connection-string", "Server=secret"]));

        Assert.Equal("secret_cli_argument_forbidden", exception.Code);
        Assert.DoesNotContain("Server=secret", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("authorize-shadow")]
    [InlineData("sign-provenance")]
    public void Parse_SigningCommandsRejectInlinePrivateKeys(string command)
    {
        CommandLineException exception = Assert.Throws<CommandLineException>(() =>
            ConsoleInvocation.Parse([command, "--private-key", "-----BEGIN PRIVATE KEY-----"]));

        Assert.Equal("secret_cli_argument_forbidden", exception.Code);
        Assert.DoesNotContain("PRIVATE KEY", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RejectsUnknownOptionsWithoutEchoingTheirValues()
    {
        CommandLineException exception = Assert.Throws<CommandLineException>(() =>
            ConsoleInvocation.Parse(["plan", "--unknown", "sensitive-value"]));

        Assert.Equal("unknown_cli_argument", exception.Code);
        Assert.DoesNotContain("sensitive-value", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RequiresProtectedConfigurationReference()
    {
        CommandLineException exception = Assert.Throws<CommandLineException>(() =>
            ConsoleInvocation.Parse(["plan"]));

        Assert.Equal("config_reference_required", exception.Code);
    }
}
