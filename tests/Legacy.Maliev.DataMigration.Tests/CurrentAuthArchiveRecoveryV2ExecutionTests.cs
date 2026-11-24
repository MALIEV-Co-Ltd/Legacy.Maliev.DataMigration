using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveRecoveryV2FactAttribute : FactAttribute
{
    public CurrentAuthArchiveRecoveryV2FactAttribute(string caseId)
    {
        var selected = caseId switch
        {
            "first-only-decrypt-insert-readback" => CurrentAuthArchiveRecoveryV2Case.FirstOnly,
            "second-only-decrypt-insert-readback" => CurrentAuthArchiveRecoveryV2Case.SecondOnly,
            _ => throw CurrentAuthArchiveRecoveryV2.Invalid(),
        };
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(CurrentAuthArchiveRecoveryV2Host.InputVariable(selected))))
        { Skip = "Requires fresh protected input and the accepted Console recovery provider host. A skip is no recovery proof."; }
    }
}
public sealed partial class CurrentAuthArchiveGuardedExecutionTests
{
    [CurrentAuthArchiveRecoveryV2Fact("first-only-decrypt-insert-readback")]
    public Task Archive_recovery_first_only_decrypt_insert_readback()
    {
        return RunRecoveryV2Async(CurrentAuthArchiveRecoveryV2Case.FirstOnly);
    }

    [CurrentAuthArchiveRecoveryV2Fact("second-only-decrypt-insert-readback")]
    public Task Archive_recovery_second_only_decrypt_insert_readback()
    {
        return RunRecoveryV2Async(CurrentAuthArchiveRecoveryV2Case.SecondOnly);
    }

    private static async Task RunRecoveryV2Async(CurrentAuthArchiveRecoveryV2Case selected)
    {
        string path = Environment.GetEnvironmentVariable(CurrentAuthArchiveRecoveryV2Host.InputVariable(selected)) ?? throw new InvalidOperationException("archive_recovery_v2_protected_input_required");
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        var result = await CurrentAuthArchiveRecoveryV2SdkHarness.RunAsync(path, selected, timeout.Token); Assert.Equal(0, result.Method.ReturnCode);
    }
}
