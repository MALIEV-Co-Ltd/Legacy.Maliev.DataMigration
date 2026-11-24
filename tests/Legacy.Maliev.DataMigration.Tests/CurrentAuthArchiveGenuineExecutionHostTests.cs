using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineExecutionHostTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(14)]
    public void Missing_execution_body_cannot_select_a_host_or_input_variable(int value)
    {
        var config = Configuration((CurrentAuthArchiveGenuineExecutionCase)value);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveExecutionHost.RequireConfiguration(config, ControlPath));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveExecutionHost.InputVariable(config.ExpectedCase));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveExecutionHost.ExpectedMethodCode(config.ExpectedCase));
    }

    [Theory]
    [InlineData(1, "MALIEV_AUTH_ARCHIVE_GENUINE_NATIVE_COMPLETE_INPUT", "native", "complete", 0)]
    [InlineData(7, "MALIEV_AUTH_ARCHIVE_GENUINE_EXACT_DELETE_INPUT", "delete", "exact-reviewed-delete", 0)]
    [InlineData(2, "MALIEV_AUTH_ARCHIVE_GENUINE_PREPARED_PUBLICATION_INPUT", "native", "prepared-publication", 1)]
    [InlineData(4, "MALIEV_AUTH_ARCHIVE_GENUINE_TERMINAL_PUBLICATION_INPUT", "native", "terminal-publication", 1)]
    [InlineData(3, "MALIEV_AUTH_ARCHIVE_GENUINE_COMMIT_ACK_INPUT", "native", "commit-ack-lost", 1)]
    [InlineData(8, "MALIEV_AUTH_ARCHIVE_GENUINE_CAS_DRIFT_INPUT", "delete", "CAS-field-drift", 1)]
    [InlineData(9, "MALIEV_AUTH_ARCHIVE_GENUINE_PRIVATE_JOURNAL_DRIFT_INPUT", "delete", "private-journal-drift", 1)]
    [InlineData(10, "MALIEV_AUTH_ARCHIVE_GENUINE_SEQUENCE_DRIFT_INPUT", "delete", "sequence-drift", 1)]
    [InlineData(11, "MALIEV_AUTH_ARCHIVE_GENUINE_COMPARISON_DRIFT_INPUT", "delete", "production-drift", 1)]
    public void Only_implemented_execution_cases_select_their_exact_gated_test(int value, string variable, string phase, string id, int expectedCode)
    {
        var config = Configuration((CurrentAuthArchiveGenuineExecutionCase)value);
        CurrentAuthArchiveExecutionHost.RequireConfiguration(config, ControlPath);
        Assert.Equal(variable, CurrentAuthArchiveExecutionHost.InputVariable(config.ExpectedCase));
        Assert.Equal(expectedCode, CurrentAuthArchiveExecutionHost.ExpectedMethodCode(config.ExpectedCase));
        Assert.Equal("FullyQualifiedName=Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGuardedExecutionTests." +
            CurrentAuthArchiveGenuineCases.Require(phase, id).MethodName, CurrentAuthTypedHostProducer.ArchiveFilter(phase, id));
    }

    [Theory]
    [InlineData("current-auth-archive-helper-host-v1")]
    [InlineData("current-auth-archive-genuine-execution13-input-v1")]
    public void Helper_or_packet_kind_cannot_be_reinterpreted_as_execution_host(string kind)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveExecutionHost.RequireConfiguration(
            Configuration(CurrentAuthArchiveGenuineExecutionCase.NativeComplete) with { Kind = kind }, ControlPath));
    }

    [Fact]
    public void Input_root_cannot_be_exclusively_held_as_execution_host_control()
    {
        var config = Configuration(CurrentAuthArchiveGenuineExecutionCase.NativeComplete);
        config = config with { CaseInput = config.CaseInput with { Path = Path.Combine(Path.GetDirectoryName(ControlPath)!, "case.json") } };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveExecutionHost.RequireConfiguration(config, ControlPath));
    }

    [Fact]
    public async Task Canceled_execution_harness_precedes_environment_file_or_process_access()
    {
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAuthArchiveGenuineExecutionSdkHarness.RunAsync(
            "not-a-path", CurrentAuthArchiveGenuineExecutionCase.NativeComplete, canceled.Token));
    }

    private static string ControlPath => Path.Combine(Path.GetTempPath(), "execution-host-unit", "control", "host.json");
    private static CurrentAuthArchiveExecutionHostConfiguration Configuration(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return new(
        "current-auth-archive-execution-host-v1", new(Path.Combine(Path.GetDirectoryName(ControlPath)!, "binding.json"), new('a', 64)),
        new(Path.Combine(Path.GetTempPath(), "execution-host-unit", "input", "case.json"), new('b', 64)), value);
    }
}
