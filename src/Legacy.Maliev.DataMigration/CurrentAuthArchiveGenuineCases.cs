namespace Legacy.Maliev.DataMigration;

/// <summary>Compiled case inventory only; never a case result, TRX identity or execution permission.</summary>
internal sealed record CurrentAuthArchiveGenuineCase(string Phase, string CaseId, int ExpectedProviderExitCode)
{
    internal string MethodName => "Archive_" + Phase + "_" + CaseId.Replace('-', '_');
}

internal static class CurrentAuthArchiveGenuineCases
{
    private static readonly CurrentAuthArchiveGenuineCase[] Cases =
    [
        new("helper", "dual-durable-readback", 0),
        new("helper", "first-only-recovery", 0),
        new("helper", "second-only-recovery", 0),
        new("helper", "key-corruption", 1),
        new("helper", "cipher-corruption", 1),
        new("native", "complete", 0),
        new("native", "prepared-publication", 1),
        new("native", "commit-ack-lost", 1),
        new("native", "terminal-publication", 1),
        new("native", "host-unprobed-sdk", 1),
        new("native", "local-trust", 1),
        new("delete", "exact-reviewed-delete", 0),
        new("delete", "CAS-field-drift", 1),
        new("delete", "private-journal-drift", 1),
        new("delete", "sequence-drift", 1),
        new("delete", "production-drift", 1),
        new("recovery", "first-only-decrypt-insert-readback", 0),
        new("recovery", "second-only-decrypt-insert-readback", 0),
    ];

    internal static CurrentAuthArchiveGenuineCase[] Inventory()
    {
        return [.. Cases];
    }

    internal static CurrentAuthArchiveGenuineCase Require(string phase, string caseId)
    {
        return Cases.SingleOrDefault(x => x.Phase == phase && x.CaseId == caseId) ??
        throw new MigrationExecutionException("current_auth_archive_genuine_case_invalid",
            "The archive prerequisite accepts only its fixed phase and case identity.");
    }
}
