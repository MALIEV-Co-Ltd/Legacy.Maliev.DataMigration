namespace Legacy.Maliev.DataMigration;

// A separate closed family. An enum member is not an implemented case or admission.
internal enum CurrentAuthArchiveGenuineExecutionCase
{
    NativeComplete = 1, PreparedPublication = 2, CommitAcknowledgmentLost = 3, TerminalPublication = 4,
    HostUnprobedSdk = 5, LocalTrust = 6, ExactReviewedDelete = 7, CasFieldDrift = 8,
    PrivateJournalDrift = 9, SequenceDrift = 10, ProductionDrift = 11,
    FirstOnlyDecryptInsertReadback = 12, SecondOnlyDecryptInsertReadback = 13,
}

internal static class CurrentAuthArchiveGenuineExecutionCases
{
    internal static (string Phase, string CaseId) Identity(CurrentAuthArchiveGenuineExecutionCase value)
    {
        return value switch
        {
            CurrentAuthArchiveGenuineExecutionCase.NativeComplete => ("native", "complete"),
            CurrentAuthArchiveGenuineExecutionCase.PreparedPublication => ("native", "prepared-publication"),
            CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost => ("native", "commit-ack-lost"),
            CurrentAuthArchiveGenuineExecutionCase.TerminalPublication => ("native", "terminal-publication"),
            CurrentAuthArchiveGenuineExecutionCase.HostUnprobedSdk => ("native", "host-unprobed-sdk"),
            CurrentAuthArchiveGenuineExecutionCase.LocalTrust => ("native", "local-trust"),
            CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete => ("delete", "exact-reviewed-delete"),
            CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift => ("delete", "CAS-field-drift"),
            CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift => ("delete", "private-journal-drift"),
            CurrentAuthArchiveGenuineExecutionCase.SequenceDrift => ("delete", "sequence-drift"),
            CurrentAuthArchiveGenuineExecutionCase.ProductionDrift => ("delete", "production-drift"),
            CurrentAuthArchiveGenuineExecutionCase.FirstOnlyDecryptInsertReadback => ("recovery", "first-only-decrypt-insert-readback"),
            CurrentAuthArchiveGenuineExecutionCase.SecondOnlyDecryptInsertReadback => ("recovery", "second-only-decrypt-insert-readback"),
            _ => throw Invalid(),
        };
    }

    internal static void RequireImplemented(CurrentAuthArchiveGenuineExecutionCase value)
    {
        _ = Identity(value);
        if (value is not (CurrentAuthArchiveGenuineExecutionCase.NativeComplete or CurrentAuthArchiveGenuineExecutionCase.ExactReviewedDelete or
            CurrentAuthArchiveGenuineExecutionCase.PreparedPublication or CurrentAuthArchiveGenuineExecutionCase.TerminalPublication or
            CurrentAuthArchiveGenuineExecutionCase.CasFieldDrift or CurrentAuthArchiveGenuineExecutionCase.PrivateJournalDrift or
            CurrentAuthArchiveGenuineExecutionCase.SequenceDrift or CurrentAuthArchiveGenuineExecutionCase.ProductionDrift or
            CurrentAuthArchiveGenuineExecutionCase.CommitAcknowledgmentLost))
        { throw Invalid(); }
    }

    internal static MigrationExecutionException Invalid()
    {
        return new("current_auth_archive_genuine_execution_invalid",
        "The fixed owned disposable archive execution family is unavailable, changed or expired.");
    }
}

// These facts never themselves grant authority. Only the authenticated fixed issuer can mint the nested capability.
internal sealed record CurrentAuthArchiveGenuineExecutionAttestation(CurrentAuthArchiveGenuineExecutionCase Case,
    CurrentAuthArchiveGenuineAttestation Owned, CurrentAuthArchiveGenuineHelperClaims Claims, string AuthorizationSha256);
internal sealed record CurrentAuthArchiveGenuineExecutionFacts(CurrentAuthArchiveGenuineExecutionCase Case,
    CurrentAuthArchiveGenuineHelperClaims Claims, CurrentAuthArchiveReceipt? Terminal,
    CurrentAuthArchiveFleet LocalBefore, CurrentAuthArchiveFleet LocalAfter,
    CurrentAuthArchiveFleet ComparisonBefore, CurrentAuthArchiveFleet ComparisonAfter,
    DateTimeOffset BeganAtUtc, DateTimeOffset ReturnedAtUtc);
internal sealed record CurrentAuthArchiveGenuineExecutionMethodResult(int ReturnCode, DateTimeOffset StartedAtUtc,
    DateTimeOffset ReturnedAtUtc, CurrentAuthArchiveGenuineDualArtifacts Artifacts);
internal sealed record CurrentAuthArchiveGenuineExecutionResult(CurrentAuthArchiveGenuineExecutionMethodResult Method,
    CurrentAuthArchiveGenuineArtifact FinalCandidate);
