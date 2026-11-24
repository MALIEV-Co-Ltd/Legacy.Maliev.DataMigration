using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuinePreflightHostTests
{
    [Theory]
    [InlineData(1, "MALIEV_AUTH_ARCHIVE_GENUINE_HOST_UNPROBED_INPUT", "host-unprobed-sdk", "Archive_native_host_unprobed_sdk")]
    [InlineData(2, "MALIEV_AUTH_ARCHIVE_GENUINE_LOCAL_TRUST_INPUT", "local-trust", "Archive_native_local_trust")]
    public void Only_fixed_preflight_cases_select_their_actual_native_method(int number, string variable, string caseId, string method)
    {
        var expected = (CurrentAuthArchiveGenuinePreflightCase)number;
        CurrentAuthArchivePreflightHost.RequireConfiguration(Configuration(expected), ControlPath);
        Assert.Equal(variable, CurrentAuthArchivePreflightHost.InputVariable(expected));
        Assert.Equal(1, CurrentAuthArchivePreflightHost.ExpectedMethodCode(expected));
        Assert.Equal(("native", caseId), CurrentAuthArchivePreflightHost.Identity(expected));
        Assert.Equal("FullyQualifiedName=Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGuardedExecutionTests." + method,
            CurrentAuthTypedHostProducer.ArchiveFilter("native", caseId));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(6)]
    public void Another_numeric_family_cannot_select_preflight(int number)
    {
        var expected = (CurrentAuthArchiveGenuinePreflightCase)number;
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchivePreflightHost.RequireConfiguration(Configuration(expected), ControlPath));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchivePreflightHost.InputVariable(expected));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchivePreflightHost.ExpectedMethodCode(expected));
    }

    [Theory]
    [InlineData("current-auth-archive-execution-host-v1")]
    [InlineData("current-auth-archive-helper-host-v1")]
    [InlineData(CurrentAuthArchiveGenuinePreflightInputContract.Kind)]
    public void Another_packet_family_cannot_select_the_preflight_host(string kind)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchivePreflightHost.RequireConfiguration(
            Configuration(CurrentAuthArchiveGenuinePreflightCase.LocalTrust) with { Kind = kind }, ControlPath));
    }

    [Theory]
    [InlineData(5)]
    [InlineData(6)]
    public void Preflight_does_not_enable_the_execution_permit_family(int number)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineExecutionCases.RequireImplemented((CurrentAuthArchiveGenuineExecutionCase)number));
    }

    [Fact]
    public async Task Cancellation_precedes_preflight_host_inputs_or_processes()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAuthArchiveGenuinePreflightSdkHarness.RunAsync(
            "not-a-path", CurrentAuthArchiveGenuinePreflightCase.LocalTrust, cancelled.Token));
    }

    [Theory]
    [InlineData(CurrentAuthArchivePreflightHost.ParentCommand)]
    [InlineData(CurrentAuthArchivePreflightHost.ChildCommand)]
    [InlineData(CurrentAuthArchivePreflightHost.ProviderCommand)]
    public void Preflight_commands_accept_only_the_protected_configuration_reference(string command)
    {
        Assert.Equal(command, ConsoleInvocation.Parse([command, "--config", ControlPath]).Command);
        _ = Assert.Throws<CommandLineException>(() => ConsoleInvocation.Parse([command, "--password", "forbidden"]));
    }

    private static string ControlPath => Path.Combine(Path.GetTempPath(), "preflight-host-unit", "control", "host.json");
    private static CurrentAuthArchivePreflightHostConfiguration Configuration(CurrentAuthArchiveGenuinePreflightCase expected)
    {
        return new("current-auth-archive-preflight-host-v1", new(Path.Combine(Path.GetDirectoryName(ControlPath)!, "binding.json"), new('a', 64)),
            new(Path.Combine(Path.GetTempPath(), "preflight-host-unit", "input", "case.json"), new('b', 64)), expected);
    }
}
