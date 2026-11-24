using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineDualHelperFactAttribute : FactAttribute
{
    public CurrentAuthArchiveGenuineDualHelperFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(CurrentAuthArchiveGenuineDualInputContract.InputVariable)))
        { Skip = "Requires fresh protected dual-helper inputs, three pinned role keys and the actual qualified test bundle."; }
    }
}

[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed partial class CurrentAuthArchiveGuardedExecutionTests
{
    [CurrentAuthArchiveGenuineDualHelperFact]
    public async Task Archive_helper_dual_durable_readback()
    {
        string path = Environment.GetEnvironmentVariable(CurrentAuthArchiveGenuineDualInputContract.InputVariable) ??
            throw new InvalidOperationException("archive_dual_helper_protected_input_required");
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        var result = await CurrentAuthArchiveGenuineHelperSdkHarness.RunAsync(path,
            CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback, timeout.Token);
        Assert.Equal(0, result.Method.ReturnCode);
    }
}
