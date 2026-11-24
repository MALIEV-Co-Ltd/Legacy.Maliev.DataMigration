using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineExecutionFactAttribute : FactAttribute
{
    public CurrentAuthArchiveGenuineExecutionFactAttribute(string caseId)
    {
        var executionCase = caseId switch
        {
            "complete" => CurrentAuthArchiveGenuineExecutionCase.NativeComplete,
            "exact-reviewed-delete" => CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete,
            "prepared-publication" => CurrentAuthArchiveGenuineExecutionCase.PreparedPublication,
            "terminal-publication" => CurrentAuthArchiveGenuineExecutionCase.TerminalPublication,
            _ => throw CurrentAuthArchiveGenuineExecutionCases.Invalid(),
        };
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(CurrentAuthArchiveExecutionHost.InputVariable(executionCase))))
        { Skip = "Requires fresh signed execution input and the actual accepted Console execution provider host; a skip produces no execution proof."; }
    }
}

public sealed partial class CurrentAuthArchiveGuardedExecutionTests
{
    [CurrentAuthArchiveGenuineExecutionFact("complete")]
    public Task Archive_native_complete()
    {
        return RunGenuineExecutionAsync(CurrentAuthArchiveGenuineExecutionCase.NativeComplete);
    }

    [CurrentAuthArchiveGenuineExecutionFact("exact-reviewed-delete")]
    public Task Archive_delete_exact_reviewed_delete()
    {
        return RunGenuineExecutionAsync(CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete);
    }

    [CurrentAuthArchiveGenuineExecutionFact("prepared-publication")]
    public Task Archive_native_prepared_publication()
    {
        return RunGenuineExecutionAsync(CurrentAuthArchiveGenuineExecutionCase.PreparedPublication);
    }

    [CurrentAuthArchiveGenuineExecutionFact("terminal-publication")]
    public Task Archive_native_terminal_publication()
    {
        return RunGenuineExecutionAsync(CurrentAuthArchiveGenuineExecutionCase.TerminalPublication);
    }

    private static async Task RunGenuineExecutionAsync(CurrentAuthArchiveGenuineExecutionCase executionCase)
    {
        string path = Environment.GetEnvironmentVariable(CurrentAuthArchiveExecutionHost.InputVariable(executionCase)) ??
            throw new InvalidOperationException("archive_execution_protected_input_required");
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        var result = await CurrentAuthArchiveGenuineExecutionSdkHarness.RunAsync(path, executionCase, timeout.Token);
        Assert.Equal(CurrentAuthArchiveExecutionHost.ExpectedMethodCode(executionCase), result.Method.ReturnCode);
    }
}
