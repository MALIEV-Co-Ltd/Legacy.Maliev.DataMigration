using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveProofV2ConsoleTests
{
    [Fact]
    public void Full_eighteen_producer_accepts_only_a_protected_config_reference_and_has_no_case_selection_option()
    {
        var invocation = ConsoleInvocation.Parse(["produce-current-auth-archive-proof-v2", "--config", "protected.json"]);
        Assert.Equal("produce-current-auth-archive-proof-v2", invocation.Command);
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse(["produce-current-auth-archive-proof-v2", "--case", "complete", "--config", "protected.json"]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse(["produce-current-auth-archive-proof-v2", "--config", "protected.json", "--sql", "SELECT 1"]));
    }

    [Theory]
    [InlineData("kind")]
    [InlineData("result-outside")]
    [InlineData("result-config")]
    [InlineData("nested-input")]
    public void Configuration_cannot_select_old_wire_kinds_foreign_outputs_or_arbitrary_descendant_roots(string change)
    {
        string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "structural-archive-v2"));
        var binding = new LocalExecutionBinding(1, "structural-only", "structural-only", root, "structural-only", "lock", "structural-only", 1);
        var reference = new CurrentAuthArchiveProofArtifact(Path.Combine(root, "qualified", "fixture-binding.json"), new string('a', 64));
        var input = new CurrentAuthArchiveGeneratedCaseInputV2(reference, reference, null!, reference, reference, null!, reference, "first", "second");
        string path = Path.Combine(root, "producer.json");
        var config = new CurrentAuthArchiveProofV2Configuration("current-auth-archive-full-eighteen-producer-config-v2", Path.Combine(root, "fixture-binding.json"), input, Path.Combine(root, "result.json"));
        MigrationConsole.RequireArchiveProofV2Paths(config, path, binding);
        var invalid = change switch
        {
            "kind" => config with { Kind = "current-auth-archive-full-eighteen-producer-config-v1" },
            "result-outside" => config with { ResultPath = Path.Combine(root, "foreign", "result.json") },
            "result-config" => config with { ResultPath = path },
            _ => config with { Inputs = input with { QualifiedInputBinding = reference with { Path = Path.Combine(root, "qualified", "nested", "fixture-binding.json") } } },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireArchiveProofV2Paths(invalid, path, binding));
    }
}
