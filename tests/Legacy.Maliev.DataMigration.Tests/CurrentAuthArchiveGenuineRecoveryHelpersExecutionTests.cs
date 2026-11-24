using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineRecoveryHelperFactAttribute : FactAttribute
{
    public CurrentAuthArchiveGenuineRecoveryHelperFactAttribute(string caseId)
    {
        var helperCase = CurrentAuthArchiveGenuineRecoveryHelpers.Parse(caseId);
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(CurrentAuthArchiveGenuineRecoveryHelpersInputContract.InputVariable(helperCase))))
        { Skip = "Requires this case's fresh signed inputs, role keys and the real accepted Console provider host."; }
    }
}

public sealed partial class CurrentAuthArchiveGuardedExecutionTests
{
    [CurrentAuthArchiveGenuineRecoveryHelperFact("first-only-recovery")]
    public Task Archive_helper_first_only_recovery()
    {
        return RunRecoveryHelperAsync(CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery);
    }

    [CurrentAuthArchiveGenuineRecoveryHelperFact("second-only-recovery")]
    public Task Archive_helper_second_only_recovery()
    {
        return RunRecoveryHelperAsync(CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery);
    }

    [CurrentAuthArchiveGenuineRecoveryHelperFact("key-corruption")]
    public Task Archive_helper_key_corruption()
    {
        return RunRecoveryHelperAsync(CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption);
    }

    [CurrentAuthArchiveGenuineRecoveryHelperFact("cipher-corruption")]
    public Task Archive_helper_cipher_corruption()
    {
        return RunRecoveryHelperAsync(CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption);
    }

    private static async Task RunRecoveryHelperAsync(CurrentAuthArchiveGenuineRecoveryHelperCase helperCase)
    {
        string path = Environment.GetEnvironmentVariable(CurrentAuthArchiveGenuineRecoveryHelpersInputContract.InputVariable(helperCase)) ??
            throw new InvalidOperationException("archive_recovery_helper_protected_input_required");
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        var result = await CurrentAuthArchiveGenuineHelperSdkHarness.RunAsync(path, helperCase, timeout.Token);
        int expected = helperCase is CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption or CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption ? 1 : 0;
        Assert.Equal(expected, result.Method.ReturnCode);
    }
}
