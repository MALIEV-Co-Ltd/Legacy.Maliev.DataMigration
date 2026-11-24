using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuinePreflightFactAttribute : FactAttribute
{
    public CurrentAuthArchiveGenuinePreflightFactAttribute(string caseId)
    {
        var selected = caseId switch
        {
            "host-unprobed-sdk" => CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk,
            "local-trust" => CurrentAuthArchiveGenuinePreflightCase.LocalTrust,
            _ => throw CurrentAuthArchiveGenuinePreflight.Invalid(),
        };
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(CurrentAuthArchivePreflightHost.InputVariable(selected))))
        { Skip = "Requires fresh signed preflight input and the actual accepted Console preflight host; a skip produces no preflight proof."; }
    }
}

public sealed partial class CurrentAuthArchiveGuardedExecutionTests
{
    [CurrentAuthArchiveGenuinePreflightFact("host-unprobed-sdk")]
    public Task Archive_native_host_unprobed_sdk()
    {
        return RunGenuinePreflightAsync(CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk);
    }

    [CurrentAuthArchiveGenuinePreflightFact("local-trust")]
    public Task Archive_native_local_trust()
    {
        return RunGenuinePreflightAsync(CurrentAuthArchiveGenuinePreflightCase.LocalTrust);
    }

    private static async Task RunGenuinePreflightAsync(CurrentAuthArchiveGenuinePreflightCase expected)
    {
        string input = Environment.GetEnvironmentVariable(CurrentAuthArchivePreflightHost.InputVariable(expected)) ??
            throw new InvalidOperationException("archive_preflight_protected_input_required");
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        var result = await CurrentAuthArchiveGenuinePreflightSdkHarness.RunAsync(input, expected, deadline.Token);
        Assert.Equal(1, result.Method.ReturnCode);
    }
}
