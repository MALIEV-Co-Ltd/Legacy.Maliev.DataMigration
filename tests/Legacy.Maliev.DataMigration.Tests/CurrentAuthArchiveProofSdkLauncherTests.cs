using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveProofSdkLauncherTests
{
    private static readonly string[] FixedTools = ["dotnet", "git", "gh", "docker"];

    [Theory]
    [InlineData("none")]
    [InlineData("purpose")]
    [InlineData("operation")]
    [InlineData("binding")]
    [InlineData("extra")]
    public void Cleanup_label_guard_rejects_any_other_resource_owner(string fault)
    {
        Guid operation = Guid.NewGuid(); string hash = new('a', 64);
        var labels = new Dictionary<string, string>
        {
            ["codex.repair.purpose"] = fault == "purpose" ? "persistent" : "current-auth-local-session-archive-proof",
            ["codex.repair.operation"] = (fault == "operation" ? Guid.NewGuid() : operation).ToString("D"),
            ["codex.repair.run-binding"] = fault == "binding" ? new string('b', 64) : hash,
        };
        if (fault == "extra") { labels.Add("unreviewed", "value"); }
        JsonElement actual = JsonSerializer.SerializeToElement(labels);
        if (fault == "none") { CurrentAuthArchiveHelperResources.RequireResourceLabels(actual, operation, hash); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveHelperResources.RequireResourceLabels(actual, operation, hash)); }
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(6)]
    public void Only_five_fixed_helper_cases_can_select_a_host(int value)
    {
        string root = Path.Combine(Path.GetTempPath(), "archive-helper-shape");
        var config = new CurrentAuthArchiveHelperHostConfiguration("current-auth-archive-helper-host-v1",
            new(Path.Combine(root, "control", "binding.json"), new('0', 64)),
            new(Path.Combine(root, "input", "case.json"), new('0', 64)), (CurrentAuthArchiveGenuineRecoveryHelperCase)value);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveHelperHost.RequireConfiguration(config, Path.Combine(root, "control", "host.json")));
    }

    [Fact]
    public void Input_root_cannot_be_the_parent_control_root()
    {
        string root = Path.Combine(Path.GetTempPath(), "archive-helper-shape");
        var config = new CurrentAuthArchiveHelperHostConfiguration("current-auth-archive-helper-host-v1",
            new(Path.Combine(root, "binding.json"), new('0', 64)), new(Path.Combine(root, "case.json"), new('0', 64)),
            CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveHelperHost.RequireConfiguration(config, Path.Combine(root, "host.json")));
    }

    [WindowsLocalRunFact]
    public void Archive_environment_uses_only_fixed_tools_and_no_inherited_tokens()
    {
        var start = CurrentAuthArchiveHelperHost.Start(Path.Combine(Path.GetTempPath(), "archive-helper-shape"));
        Assert.Equal(CurrentAuthArchiveHelperHost.Tool("dotnet"), start.FileName);
        Assert.Equal(string.Join(';', FixedTools.Select(x => Path.GetDirectoryName(CurrentAuthArchiveHelperHost.Tool(x))).Append(Environment.SystemDirectory)), start.Environment["PATH"]);
        Assert.DoesNotContain(start.Environment.Keys, x => x is "GH_TOKEN" or "GITHUB_TOKEN" or "GH_HOST" or "GH_CONFIG_DIR" or "DOCKER_HOST");
        Assert.Equal(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), start.Environment["USERPROFILE"]);
    }

    [Theory]
    [InlineData("Passed", "1", "Archive_helper_dual_durable_readback", true)]
    [InlineData("NotExecuted", "0", "Archive_helper_dual_durable_readback", false)]
    [InlineData("Failed", "0", "Archive_helper_dual_durable_readback", false)]
    [InlineData("Passed", "1", "Different_case", false)]
    public void Trx_requires_an_actual_selected_passed_test(string outcome, string passed, string name, bool valid)
    {
        byte[] xml = Encoding.UTF8.GetBytes($$"""
            <TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
              <Results><UnitTestResult testId="11111111-1111-1111-1111-111111111111" executionId="22222222-2222-2222-2222-222222222222" testName="{{name}}" outcome="{{outcome}}" /></Results>
              <TestDefinitions><UnitTest id="11111111-1111-1111-1111-111111111111"><TestMethod className="Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGuardedExecutionTests" name="{{name}}" /></UnitTest></TestDefinitions>
              <ResultSummary><Counters total="1" passed="{{passed}}" executed="1" /></ResultSummary>
            </TestRun>
            """);
        if (valid) { CurrentAuthArchiveHelperHost.RequireTrx(xml, "Archive_helper_dual_durable_readback"); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveHelperHost.RequireTrx(xml, "Archive_helper_dual_durable_readback")); }
    }
}
