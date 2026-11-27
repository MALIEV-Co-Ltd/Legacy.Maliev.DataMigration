using System.Text;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveFinal6HostTests
{
    [Fact]
    public void Final6_filters_select_exactly_the_real_separate_eighteen_methods()
    {
        var methods = typeof(CurrentAuthArchiveFinal6GuardedExecutionTests).GetMethods()
            .Where(method => method.GetCustomAttributes(typeof(CurrentAuthArchiveFinal6FactAttribute), false).Length == 1)
            .Select(method => method.Name).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(18, methods.Length);
        Assert.Equal(Enum.GetValues<CurrentAuthArchiveProofCaseV2>().Select(CurrentAuthArchiveGeneratedCasesV2.Identity)
            .Select(value => value.MethodName).Order(StringComparer.Ordinal), methods);
        foreach (var selected in Enum.GetValues<CurrentAuthArchiveProofCaseV2>())
        {
            var identity = CurrentAuthArchiveGeneratedCasesV2.Identity(selected);
            Assert.Equal("FullyQualifiedName=" + typeof(CurrentAuthArchiveFinal6GuardedExecutionTests).FullName + "." + identity.MethodName,
                CurrentAuthArchiveFinal6Host.Filter(selected));
            Assert.Equal(identity.ExpectedProviderExitCode, CurrentAuthArchiveFinal6Host.ExpectedMethodCode(selected));
            Assert.StartsWith("MALIEV_AUTH_ARCHIVE_FINAL6_", CurrentAuthArchiveFinal6Host.InputVariable(selected), StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(19)]
    public async Task Unknown_case_fails_before_input_or_resources(int value)
    {
        var selected = (CurrentAuthArchiveProofCaseV2)value;
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6Host.Filter(selected));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6Host.ExpectedMethodCode(selected));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6Host.InputVariable(selected));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthArchiveFinal6CaseRunner.ExecuteAsync("unused", selected, CancellationToken.None));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("old-family")]
    [InlineData("same-root")]
    [InlineData("unknown")]
    public void Final6_host_configuration_is_closed_before_file_access(string fault)
    {
        string root = Path.Combine(Path.GetTempPath(), "final6-host-shape-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "control", "config.json");
        var config = new CurrentAuthArchiveFinal6HostConfiguration("current-auth-archive-final6-host-v1",
            new(Path.Combine(root, "control", "binding.json"), new('a', 64)),
            new(Path.Combine(root, "qualified", "input.json"), new('b', 64)), CurrentAuthArchiveProofCaseV2.Dual);
        config = fault switch
        {
            "old-family" => config with { Kind = "current-auth-archive-helper-host-v1" },
            "same-root" => config with { CaseInput = config.CaseInput with { Path = Path.Combine(root, "control", "input.json") } },
            "unknown" => config with { ExpectedCase = (CurrentAuthArchiveProofCaseV2)19 },
            _ => config,
        };
        if (fault == "none") { CurrentAuthArchiveFinal6Host.RequireConfiguration(config, path); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6Host.RequireConfiguration(config, path)); }
        Assert.False(Directory.Exists(root));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("old-class")]
    [InlineData("skipped")]
    [InlineData("foreign-assembly")]
    public void Real_trx_requires_the_exact_Final6_class_method_and_qualified_assembly(string fault)
    {
        string image = Path.Combine(Path.GetTempPath(), "qualified-final6", "Legacy.Maliev.DataMigration.Tests.dll");
        string method = CurrentAuthArchiveGeneratedCasesV2.Identity(CurrentAuthArchiveProofCaseV2.Dual).MethodName;
        string className = typeof(CurrentAuthArchiveFinal6GuardedExecutionTests).FullName!;
        string outcome = "Passed";
        string codeBase = image;
        if (fault == "old-class") { className = typeof(CurrentAuthArchiveGuardedExecutionTests).FullName!; }
        if (fault == "skipped") { outcome = "NotExecuted"; }
        if (fault == "foreign-assembly") { codeBase = Path.Combine(Path.GetTempPath(), "foreign", "Legacy.Maliev.DataMigration.Tests.dll"); }
        string xml = $"""
            <TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">
              <Results><UnitTestResult testId="test" executionId="{Guid.NewGuid()}" testName="{method}" outcome="{outcome}" /></Results>
              <TestDefinitions><UnitTest id="test" storage="{image}"><TestMethod name="{method}" className="{className}" codeBase="{codeBase}" /></UnitTest></TestDefinitions>
              <ResultSummary><Counters total="1" passed="1" executed="1" /></ResultSummary>
            </TestRun>
            """;
        if (fault == "none") { CurrentAuthArchiveFinal6Trx.Require(Encoding.UTF8.GetBytes(xml), method, image); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFinal6Trx.Require(Encoding.UTF8.GetBytes(xml), method, image)); }
    }
}
