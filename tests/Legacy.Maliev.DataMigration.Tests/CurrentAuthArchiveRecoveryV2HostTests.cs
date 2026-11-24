using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveRecoveryV2HostTests
{
    [Theory]
    [InlineData(1, "first-only-decrypt-insert-readback")]
    [InlineData(2, "second-only-decrypt-insert-readback")]
    public void Recovery_host_selects_only_the_two_implemented_fixed_methods(int value, string name)
    {
        var selected = (CurrentAuthArchiveRecoveryV2Case)value;
        Assert.Equal("FullyQualifiedName=Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGuardedExecutionTests.Archive_recovery_" + name.Replace('-', '_'), CurrentAuthArchiveRecoveryV2Host.Filter(selected));
        Assert.Equal(0, CurrentAuthArchiveRecoveryV2Host.ExpectedMethodCode(selected));
        Assert.StartsWith("MALIEV_AUTH_ARCHIVE_GENUINE_", CurrentAuthArchiveRecoveryV2Host.InputVariable(selected), StringComparison.Ordinal);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveExecutionHost.InputVariable(CurrentAuthArchiveRecoveryV2.SetupCase(selected)));
    }
    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(12)]
    [InlineData(13)]
    public void Another_enum_value_cannot_select_an_executable_case(int value)
    {
        var selected = (CurrentAuthArchiveRecoveryV2Case)value;
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2Host.Filter(selected));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2Host.ExpectedMethodCode(selected));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2Host.InputVariable(selected));
    }
    [Theory]
    [InlineData("none")]
    [InlineData("kind")]
    [InlineData("roots")]
    [InlineData("case")]
    public void Host_control_and_qualified_input_roots_are_distinct_before_resource_use(string fault)
    {
        string root = Path.Combine(Path.GetTempPath(), "archive-recovery-v2-shape-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "host", "config.json");
        var config = new CurrentAuthArchiveRecoveryV2HostConfiguration("current-auth-archive-recovery-host-v2",
            new(Path.Combine(root, "host", "binding.json"), new('a', 64)), new(Path.Combine(root, "input", "case.json"), new('b', 64)), CurrentAuthArchiveRecoveryV2Case.FirstOnly);
        config = fault switch
        {
            "none" => config,
            "kind" => config with { Kind = "current-auth-archive-execution-host-v1" },
            "roots" => config with { CaseInput = config.CaseInput with { Path = Path.Combine(root, "host", "case.json") } },
            "case" => config with { ExpectedCase = (CurrentAuthArchiveRecoveryV2Case)3 },
            _ => throw new InvalidOperationException(),
        };
        if (fault == "none") { CurrentAuthArchiveRecoveryV2Host.RequireConfiguration(config, path); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2Host.RequireConfiguration(config, path)); }
        Assert.False(Directory.Exists(root));
    }
}
