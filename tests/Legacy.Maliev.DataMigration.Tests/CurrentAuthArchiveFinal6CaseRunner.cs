using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal static class CurrentAuthArchiveFinal6CaseRunner
{
    // The accepted Console loads this exact entry from its held qualified Tests bundle.
    internal static Task<CurrentAuthArchiveFinal6CaseResult> ExecuteAsync(string inputPath, CurrentAuthArchiveProofCaseV2 selected, CancellationToken ct)
    {
        _ = CurrentAuthArchiveGeneratedCasesV2.Identity(selected);
        return selected switch
        {
            CurrentAuthArchiveProofCaseV2.Dual or CurrentAuthArchiveProofCaseV2.FirstHelper or CurrentAuthArchiveProofCaseV2.SecondHelper or
                CurrentAuthArchiveProofCaseV2.KeyCorruption or CurrentAuthArchiveProofCaseV2.CipherCorruption =>
                CurrentAuthArchiveFinal6HelpersRunner.ExecuteAsync(inputPath, CurrentAuthArchiveGeneratedCasesV2.Helper(selected), ct),
            CurrentAuthArchiveProofCaseV2.HostUnprobed or CurrentAuthArchiveProofCaseV2.LocalTrust =>
                CurrentAuthArchiveFinal6PreflightRunner.ExecuteAsync(inputPath, CurrentAuthArchiveGeneratedCasesV2.Preflight(selected), ct),
            CurrentAuthArchiveProofCaseV2.FirstRestore or CurrentAuthArchiveProofCaseV2.SecondRestore =>
                CurrentAuthArchiveFinal6RecoveryRunner.ExecuteAsync(inputPath, CurrentAuthArchiveGeneratedCasesV2.Recovery(selected), ct),
            CurrentAuthArchiveProofCaseV2.Complete or CurrentAuthArchiveProofCaseV2.PreparedPublication or CurrentAuthArchiveProofCaseV2.CommitAckLost or
                CurrentAuthArchiveProofCaseV2.TerminalPublication or CurrentAuthArchiveProofCaseV2.ExactDelete or CurrentAuthArchiveProofCaseV2.CasDrift or
                CurrentAuthArchiveProofCaseV2.JournalDrift or CurrentAuthArchiveProofCaseV2.SequenceDrift or CurrentAuthArchiveProofCaseV2.ComparisonDrift =>
                CurrentAuthArchiveFinal6ExecutionRunner.ExecuteAsync(inputPath, CurrentAuthArchiveGeneratedCasesV2.Execution(selected), ct),
            _ => throw CurrentAuthArchiveFinal6Source.Invalid(),
        };
    }
}
