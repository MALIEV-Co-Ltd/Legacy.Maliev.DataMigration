using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentCustomerClosedConsoleProducerTests
{
    [Theory]
    [InlineData("success")]
    [InlineData("prepared-publication")]
    [InlineData("lost-commit-ack")]
    [InlineData("terminal-publication")]
    [InlineData("host-unprobed-sdk")]
    [InlineData("local-ordinary-trust")]
    [InlineData("final-fleet")]
    [InlineData("replay")]
    public void Phase_contract_keeps_early_absent_claims_distinct_from_actual_apply(string scenario)
    { CurrentCustomerClosedConsoleCase.RequirePhases(Facts(scenario)); }

    [Theory]
    [InlineData("fabricated-review")]
    [InlineData("fabricated-authorization")]
    [InlineData("early-receipt")]
    [InlineData("continued-after-review-failure")]
    [InlineData("unknown-case")]
    [InlineData("late-command")]
    [InlineData("uncertain-success")]
    [InlineData("replay-success")]
    public void Phase_contract_rejects_fabricated_or_out_of_phase_raw_facts(string fault)
    {
        var value = Facts("host-unprobed-sdk");
        value = fault switch
        {
            "fabricated-review" => value with { Review = Artifact("fake-review") },
            "fabricated-authorization" => value with { Authorization = Artifact("fake-authorization") },
            "early-receipt" => value with { RetainedReceipts = [Artifact("fake-receipt")] },
            "continued-after-review-failure" => value with { Commands = [.. value.Commands, new("authorize-current-customer-sequence-repair", value.CompletedAtUtc, value.CompletedAtUtc, 1)] },
            "unknown-case" => value with { CaseId = "native-component" },
            "late-command" => value with { Commands = [value.Commands[0] with { CompletedAtUtc = value.CompletedAtUtc.AddTicks(1) }] },
            "uncertain-success" => Facts("lost-commit-ack") with { Commands = Facts("success").Commands },
            "replay-success" => Facts("replay") with { Commands = [.. Facts("replay").Commands.Take(4), Facts("replay").Commands[^1] with { ExitCode = 0 }] },
            _ => throw new InvalidOperationException()
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerClosedConsoleCase.RequirePhases(value));
    }
    [Theory]
    [InlineData("aspire://legacy-postgres-main-local/persistent", DeltaTargetAuthorityKind.LocalAspire)]
    [InlineData("cnpg://maliev-legacy/legacy-postgres-main", DeltaTargetAuthorityKind.ProductionCloudNativePg)]
    public void Named_seed_target_cannot_be_persistent_or_production(string id, string kind)
    { _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedBootstrap.RequireNamedTarget(new(kind, id, new('a', 64)))); }

    private static CustomerDefinitionArtifact Artifact(string name)
    {
        return new(name, new('a', 64));
    }

    private static CustomerClosedCase Facts(string scenario)
    {
        // These are phase-parser unit inputs, never authenticated artifacts or runtime proof.
        DateTimeOffset now = new(2026, 10, 13, 0, 0, 0, TimeSpan.Zero);
        bool early = scenario is "host-unprobed-sdk" or "local-ordinary-trust";
        string[] all = ["review-current-customer-sequence-repair", "authorize-current-customer-sequence-repair", "verify-current-customer-sequence-repair", "apply-current-customer-sequence-repair"];
        var commands = all.Take(early ? 1 : 4).Select((name, i) => new CustomerClosedCommand(name, now.AddSeconds(i), now.AddSeconds(i + 1),
            early || (i == 3 && scenario is not ("success" or "replay")) ? 1 : 0)).ToList();
        if (scenario == "replay") { commands.Add(new(all[^1], now.AddSeconds(4), now.AddSeconds(5), 1)); }
        return new("current-customer-sequence-public-console-case-v1", Guid.NewGuid(), scenario, new('a', 64), now,
            now.AddSeconds(6), commands, early ? null : Artifact("review"), early ? null : Artifact("authorization"),
            Artifact("before-native"), Artifact("after-native"), Artifact("before-fleet"), Artifact("after-fleet"), []);
    }
}
