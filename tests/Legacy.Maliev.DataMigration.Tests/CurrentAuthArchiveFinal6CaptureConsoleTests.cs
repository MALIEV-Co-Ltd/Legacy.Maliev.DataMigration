using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveFinal6CaptureConsoleTests
{
    [Fact]
    public void Fixed_capture_command_cannot_select_a_profile_case_SQL_or_an_apply_operation()
    {
        const string command = "capture-current-auth-archive-final6-source";
        Assert.Equal(command, ConsoleInvocation.Parse([command, "--config", "protected.json"]).Command);
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "--config", "protected.json", "--profile", "3"]));
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "--config", "protected.json", "--sql", "SELECT 1"]));
        _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireArchiveCommand(command));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("old-kind")]
    [InlineData("outside")]
    [InlineData("nested")]
    [InlineData("overwrite-config")]
    [InlineData("duplicate-key")]
    [InlineData("missing-key")]
    [InlineData("credential-hash")]
    public void Protected_capture_paths_are_distinct_direct_children_of_one_actual_bound_root(string change)
    {
        string root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "structural-final6-capture"));
        var binding = new LocalExecutionBinding(1, "structural-only", "structural-only", root, "structural-only", "lock", "structural-only", 1);
        CurrentAuthArchiveProofArtifact Artifact(string name)
        {
            return new(Path.Combine(root, name), new('a', 64));
        }

        var keys = new DeltaTrustedKeyReference[] { new("review", Path.Combine(root, "review.spki")),
            new("authorization", Path.Combine(root, "authorization.spki")), new("evidence", Path.Combine(root, "evidence.spki")) };
        string path = Path.Combine(root, "config.json");
        var config = new CurrentAuthArchiveFinal6CaptureConfiguration("current-auth-archive-final6-source-capture-config-v1",
            Path.Combine(root, "binding.json"), Artifact("source.txt"), Artifact("audience.json"), Artifact("pins.json"), keys, Path.Combine(root, "result.json"));
        config = change switch
        {
            "old-kind" => config with { Kind = "current-auth-archive-full-eighteen-producer-config-v2" },
            "outside" => config with { ResultPath = Path.Combine(Path.GetDirectoryName(root)!, "foreign.json") },
            "nested" => config with { SourceCredential = Artifact(Path.Combine("nested", "source.txt")) },
            "overwrite-config" => config with { ResultPath = path },
            "duplicate-key" => config with { TrustedKeys = [keys[0], keys[0], keys[2]] },
            "missing-key" => config with { TrustedKeys = keys.Skip(1).ToArray() },
            "credential-hash" => config with { SourceCredential = config.SourceCredential with { Sha256 = "" } },
            _ => config,
        };
        if (change == "none") { MigrationConsole.RequireFinal6CapturePaths(config, path, binding); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.RequireFinal6CapturePaths(config, path, binding)); }
    }
}
