using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveFinal6DefinitionConsoleTests
{
    [Fact]
    public void New_definition_entrypoint_has_no_case_SQL_or_repair_selector()
    {
        const string command = "produce-current-auth-archive-final6-definition";
        Assert.Equal(command, ConsoleInvocation.Parse([command, "--config", "protected.json"]).Command);
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "--config", "protected.json", "--case", "success"]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "--config", "protected.json", "--sql", "SELECT 1"]));
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireArchiveCommand(command));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("old-kind")]
    [InlineData("outside-result")]
    [InlineData("same-config-result")]
    [InlineData("nested-qualified")]
    [InlineData("foreign-credential")]
    [InlineData("wrong-tests")]
    [InlineData("parent-lock-collision")]
    [InlineData("qualified-lock-collision")]
    public void Definition_configuration_keeps_each_input_under_its_own_bounded_custody_before_any_target_creation(string fault)
    {
        string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "structural-final6-producer"));
        string qualified = Path.Combine(root, "qualified"), local = root + "-local", comparison = root + "-comparison";
        var binding = new LocalExecutionBinding(1, "structural-only", "structural-only", root, "structural-only", "lock", "structural-only", 1);
        CurrentAuthArchiveProofArtifact File(string name)
        {
            return new(Path.Combine(qualified, name), new('a', 64));
        }

        CurrentAuthArchiveProofArtifact Held(string directory, string name)
        {
            return new(Path.Combine(directory, name), new('a', 64));
        }

        var pins = new CurrentAuthRepairSigningPins("review", new('1', 64), "authorization", new('2', 64), "receipt", new('3', 64));
        var signing = new CurrentAuthArchiveDefinitionSigningInputs(pins, [new("review", Path.Combine(qualified, "review.spki")),
            new("authorization", Path.Combine(qualified, "authorization.spki")), new("receipt", Path.Combine(qualified, "receipt.spki"))], File("review.private.pem"), File("receipt.private.pem"));
        var intended = new CurrentAuthArchiveFinal6IntendedObservationInput(Held(local, "binding.json"), Held(comparison, "binding.json"),
            Held(local, "descriptor.json"), Held(local, "target.json"), Held(comparison, "target.json"), Held(local, "operator.txt"),
            Held(comparison, "operator.txt"), Held(local, "ordinary.txt"), Held(comparison, "ordinary.txt"));
        string path = Path.Combine(root, "config.json");
        var config = new CurrentAuthArchiveFinal6DefinitionConfiguration("current-auth-archive-final6-definition-config-v1", Path.Combine(root, "binding.json"),
            File("binding.json"), File("source.txt"), File("audience.json"), intended, File("Legacy.Maliev.DataMigration.Tests.dll"), signing, Path.Combine(root, "result.json"));
        config = fault switch
        {
            "old-kind" => config with { Kind = "current-auth-archive-full-eighteen-producer-config-v2" },
            "outside-result" => config with { ResultPath = Path.Combine(qualified, "result.json") },
            "same-config-result" => config with { ResultPath = path },
            "nested-qualified" => config with { QualifiedBinding = File(Path.Combine("nested", "binding.json")) },
            "foreign-credential" => config with { SourceCredential = Held(local, "source.txt") },
            "wrong-tests" => config with { QualifiedTests = File("Untrusted.dll") },
            "parent-lock-collision" => config with { Intended = intended with { LocalBinding = Held(root, "binding.json") } },
            "qualified-lock-collision" => config with { Intended = intended with { ComparisonBinding = File("binding.json") } },
            _ => config,
        };
        if (fault == "none") { MigrationConsole.RequireFinal6DefinitionPaths(config, path, binding); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireFinal6DefinitionPaths(config, path, binding)); }
    }
}
