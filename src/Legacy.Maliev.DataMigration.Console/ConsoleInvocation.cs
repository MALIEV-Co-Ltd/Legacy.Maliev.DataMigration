namespace Legacy.Maliev.DataMigration.Console;

public sealed record ConsoleInvocation(string Command, string ConfigPath)
{
    private static readonly HashSet<string> Commands =
    [
        "verify-current-company-storage",
        "apply-current-company-storage",
        "observe-current-company-storage",
        "characterize-current-company-storage-native-faults",
        "characterize-consumer-column-bootstrap-native-faults",
        "rehearse-consumer-column-bootstrap",
        "run-consumer-column-bootstrap-reviewed",
        "owner-iso-bootstrap-host-child",
        "owner-iso-named-closed-host-child",
        "plan",
        "plan-digest",
        "execute-shadow",
        "plan-incremental",
        "plan-resume",
        "authorize-resume",
        "authorize-compatible-resume",
        "resume-shadow",
        "finalize-local",
        "evidence",
        "export-local-snapshot",
        "cleanup-shadows",
        "backup-full",
        "restore-backups",
        "cleanup-restore",
        "authorize-shadow",
        "authorize-cleanup",
        "sign-provenance",
        "sign-quotation-schema-baseline",
        "sign-quotation-postgres-snapshot",
        "plan-dual-target-captured-delta",
        "prove-dual-target-captured-delta",
        "review-dual-target-captured-delta",
        "apply-dual-target-captured-delta",
        "run-dual-target-captured-relay",
        "prepare-dual-target-native-proof",
        "observe-current-order-subtotal",
        "verify-current-order-subtotal",
        "apply-current-order-subtotal",
        "characterize-current-order-subtotal-faults",
        "observe-current-source-order-owner-iso",
        "verify-current-source-order-owner-iso",
        "apply-current-source-order-owner-iso",
        "characterize-current-source-order-owner-iso-native-faults",
        "plan-delta",
        "plan-paired-delta",
        "project-paired-local-template",
        "review-historical-local-target",
        "issue-historical-local-continuity",
        "stage-source-backed-local-repair",
        "prepare-source-backed-local-repair-authority",
        "authorize-source-backed-local-repair",
        "admit-source-backed-local-repair",
        "apply-source-backed-local-repair-next",
        "reconcile-source-backed-local-repair",
        "renew-source-backed-local-repair",
        "authorize-current-app-owned-eight-repair",
        "verify-current-app-owned-eight-repair",
        "apply-current-app-owned-eight-repair",
        "review-current-app-owned-retained31-repair",
        "authorize-current-app-owned-retained31-repair",
        "verify-current-app-owned-retained31-repair",
        "apply-current-app-owned-retained31-repair",
        "review-current-app-owned-v3-repair",
        "authorize-current-app-owned-v3-repair",
        "verify-current-app-owned-v3-repair",
        "apply-current-app-owned-v3-repair",
        "observe-current-owner-iso-intended-runtime",
        "review-current-owner-iso-repair",
        "authorize-current-owner-iso-repair",
        "verify-current-owner-iso-repair",
        "apply-current-owner-iso-repair",
        "review-current-customer-sequence-repair",
        "authorize-current-customer-sequence-repair",
        "verify-current-customer-sequence-repair",
        "apply-current-customer-sequence-repair",
        "customer-sequence-bootstrap-host-child",
        "customer-sequence-named-closed-host-child",
        "assemble-current-auth-typed-proof",
        "prepare-current-auth-named-closed-proof",
        "observe-current-auth-closed-intent",
        "assemble-current-auth-named-closed-proof",
        "produce-current-auth-typed-host",
        "run-current-auth-typed-testhost",
        "observe-current-auth-archive-initial-pair",
        "provider-current-auth-archive-proof",
        "run-current-auth-archive-genuine-testhost",
        "produce-current-auth-archive-helper-host",
        "produce-current-auth-archive-proof-v2",
        "run-current-auth-archive-helper-sdk",
        "execute-current-auth-archive-helper-provider",
        "produce-current-auth-archive-recovery-host",
        "run-current-auth-archive-recovery-sdk",
        "execute-current-auth-archive-recovery-provider",
        "produce-current-auth-archive-execution-host",
        "run-current-auth-archive-execution-sdk",
        "execute-current-auth-archive-execution-provider",
        "produce-current-auth-archive-preflight-host",
        "run-current-auth-archive-preflight-sdk",
        "execute-current-auth-archive-preflight-provider",
        "review-current-auth-repair",
        "review-current-auth-local-session-archive",
        "authorize-current-auth-local-session-archive",
        "verify-current-auth-local-session-archive",
        "apply-current-auth-local-session-archive",
        "authorize-current-auth-repair",
        "verify-current-auth-repair",
        "apply-current-auth-repair",
        "inspect-target-schema-gaps",
        "inspect-production-schema-catalog",
        "inspect-local-schema-catalog",
        "authorize-target-extension-repair",
        "apply-target-extension-repair",
        "authorize-quotation-target-bootstrap",
        "apply-quotation-target-bootstrap",
        "verify-disposable-delta-proof",
        "authorize-paired-local-transition",
        "preflight-paired-local-transition",
        "apply-paired-local-transition",
        "authorize-delta",
        "apply-delta-local",
        "apply-delta-production",
        "reconcile-delta",
        "authorize-canonical-bootstrap",
        "bootstrap-canonical-database",
        "cnpg-exec-tunnel",
        "inspect-sql-source-endpoint",
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

        if (arguments[0] is "owner-iso-bootstrap-host-child" or "owner-iso-named-closed-host-child")
        {
            return arguments.Count == 2 && Path.IsPathFullyQualified(arguments[1])
                ? new(arguments[0], arguments[1])
                : throw new CommandLineException("config_reference_required", "An absolute protected child configuration reference is required.");
        }
        string? configPath = null;
        if (arguments[0] is "customer-sequence-bootstrap-host-child" or "customer-sequence-named-closed-host-child")
        {
            return arguments.Count == 2 && Path.IsPathFullyQualified(arguments[1])
                ? new(arguments[0], arguments[1])
                : throw new CommandLineException("config_reference_required", "An absolute protected child configuration reference is required.");
        }
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

        return arguments[0] == "inspect-sql-source-endpoint" &&
            (string.IsNullOrWhiteSpace(configPath) || !Path.IsPathFullyQualified(configPath))
            ? throw new CommandLineException("config_reference_required", "An absolute protected configuration reference is required.")
            : string.IsNullOrWhiteSpace(configPath)
                ? throw new CommandLineException("config_reference_required", "A protected configuration file reference is required.")
                : new(arguments[0], configPath);
    }
}

public sealed class CommandLineException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
