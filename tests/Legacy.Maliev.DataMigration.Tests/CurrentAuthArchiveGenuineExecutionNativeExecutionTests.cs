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
            "CAS-field-drift" => CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift,
            "private-journal-drift" => CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift,
            "sequence-drift" => CurrentAuthArchiveGenuineExecutionCase.SequenceDrift,
            "production-drift" => CurrentAuthArchiveGenuineExecutionCase.ProductionDrift,
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

    [CurrentAuthArchiveGenuineExecutionFact("CAS-field-drift")]
    public Task Archive_delete_CAS_field_drift() => RunGenuineExecutionAsync(CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift);

    [CurrentAuthArchiveGenuineExecutionFact("private-journal-drift")]
    public Task Archive_delete_private_journal_drift() => RunGenuineExecutionAsync(CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift);

    [CurrentAuthArchiveGenuineExecutionFact("sequence-drift")]
    public Task Archive_delete_sequence_drift() => RunGenuineExecutionAsync(CurrentAuthArchiveGenuineExecutionCase.SequenceDrift);

    [CurrentAuthArchiveGenuineExecutionFact("production-drift")]
    public Task Archive_delete_production_drift() => RunGenuineExecutionAsync(CurrentAuthArchiveGenuineExecutionCase.ProductionDrift);

    private static async Task RunGenuineExecutionAsync(CurrentAuthArchiveGenuineExecutionCase executionCase)
    {
        string path = Environment.GetEnvironmentVariable(CurrentAuthArchiveExecutionHost.InputVariable(executionCase)) ??
            throw new InvalidOperationException("archive_execution_protected_input_required");
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        var result = await CurrentAuthArchiveGenuineExecutionSdkHarness.RunAsync(path, executionCase, timeout.Token);
        Assert.Equal(CurrentAuthArchiveExecutionHost.ExpectedMethodCode(executionCase), result.Method.ReturnCode);
    }
}
