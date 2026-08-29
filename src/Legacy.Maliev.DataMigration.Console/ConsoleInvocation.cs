namespace Legacy.Maliev.DataMigration.Console;

public sealed record ConsoleInvocation(string Command, string ConfigPath)
{
    private static readonly HashSet<string> Commands =
    [
        "receipt",
        "plan",
        "execute-shadow",
        "evidence",
        "export-local-snapshot",
    ];

    private static readonly string[] SecretOptionFragments =
    [
        "secret", "password", "connection", "token", "private-key", "credential",
    ];

    public static ConsoleInvocation Parse(IReadOnlyList<string> arguments)
    {
        if (arguments.Count == 0 || !Commands.Contains(arguments[0]))
        {
            throw new CommandLineException("subcommand_invalid", "An approved subcommand is required.");
        }

        string? configPath = null;
        for (var index = 1; index < arguments.Count; index++)
        {
            string option = arguments[index];
            if (SecretOptionFragments.Any(fragment => option.Contains(fragment, StringComparison.OrdinalIgnoreCase)))
            {
                throw new CommandLineException("secret_cli_argument_forbidden", "Secrets are accepted only through protected configuration references.");
            }

            if (!string.Equals(option, "--config", StringComparison.Ordinal) || index + 1 >= arguments.Count)
            {
                throw new CommandLineException("unknown_cli_argument", "An unsupported command-line option was supplied.");
            }

            configPath = arguments[++index];
        }

        return string.IsNullOrWhiteSpace(configPath)
            ? throw new CommandLineException("config_reference_required", "A protected configuration file reference is required.")
            : new(arguments[0], configPath);
    }
}

public sealed class CommandLineException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
