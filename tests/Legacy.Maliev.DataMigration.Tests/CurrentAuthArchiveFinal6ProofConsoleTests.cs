using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveFinal6ProofConsoleTests
{
    [Fact]
    public void Proof_command_accepts_only_a_protected_configuration_path()
    {
        const string command = "produce-current-auth-archive-final6-proof";
        Assert.Equal(command, ConsoleInvocation.Parse([command, "--config", "protected.json"]).Command);
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "--config", "protected.json", "--case", "1"]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "--config", "protected.json", "--sql", "SELECT 1"]));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("old-kind")]
    [InlineData("result-collision")]
    [InlineData("qualified-root")]
    [InlineData("intended-root")]
    public void Proof_roots_cannot_reenter_parent_or_qualified_custody(string fault)
    {
        string root = Path.Combine(Path.GetTempPath(), "final6-proof-shape-" + Guid.NewGuid().ToString("N"));
        static CurrentAuthArchiveProofArtifact File(string directory, string name)
        {
            return new(Path.Combine(directory, name), new('a', 64));
        }

        string qualified = Path.Combine(root, "qualified"); string local = root + "-local"; string comparison = root + "-comparison";
        var intended = new CurrentAuthArchiveFinal6IntendedObservationInput(File(local, "binding.json"), File(comparison, "binding.json"),
            File(local, "descriptor.json"), File(local, "target.json"), File(comparison, "target.json"),
            File(local, "operator"), File(comparison, "operator"), File(local, "ordinary"), File(comparison, "ordinary"));
        var input = new CurrentAuthArchiveFinal6GeneratorInput(File(qualified, "audience"), File(qualified, "credential"), intended,
            File(qualified, "binding.json"), File(qualified, "Legacy.Maliev.DataMigration.Tests.dll"), null!, File(qualified, "authorization"), local, comparison);
        string path = Path.Combine(root, "config.json");
        var config = new CurrentAuthArchiveFinal6ProofConfiguration("current-auth-archive-final6-proof-config-v1", File(root, "binding.json"), input, Path.Combine(root, "result.json"));
        config = fault switch
        {
            "old-kind" => config with { Kind = "current-auth-archive-proof-config-v2" },
            "result-collision" => config with { ResultPath = path },
            "qualified-root" => config with { Inputs = input with { QualifiedInputBinding = File(root, "binding.json") } },
            "intended-root" => config with { Inputs = input with { Intended = intended with { LocalBinding = File(qualified, "binding.json") } } },
            _ => config,
        };
        if (fault == "none") { MigrationConsole.RequireFinal6ProofConfiguration(config, path); } // Path shape only; keys/source/targets are independently authenticated at execution.
        else { _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireFinal6ProofConfiguration(config, path)); }
        Assert.False(Directory.Exists(root));
    }
}
