namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveGenuineRecoveryHelpersInput(string Kind, CurrentAuthArchiveGenuineHostConfiguration Request);

internal static class CurrentAuthArchiveGenuineRecoveryHelpersInputContract
{
    internal const string Kind = "current-auth-archive-genuine-recovery-helper-input-v1";
    internal static string InputVariable(CurrentAuthArchiveGenuineRecoveryHelperCase helperCase)
    {
        return helperCase switch
        {
            CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback => CurrentAuthArchiveGenuineDualInputContract.InputVariable,
            CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery => "MALIEV_AUTH_ARCHIVE_GENUINE_FIRST_ONLY_INPUT",
            CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery => "MALIEV_AUTH_ARCHIVE_GENUINE_SECOND_ONLY_INPUT",
            CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption => "MALIEV_AUTH_ARCHIVE_GENUINE_KEY_CORRUPTION_INPUT",
            CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption => "MALIEV_AUTH_ARCHIVE_GENUINE_CIPHER_CORRUPTION_INPUT",
            _ => throw CurrentAuthArchiveGenuineHost.Invalid("recovery_helper_input"),
        };
    }

    internal static void Require(CurrentAuthArchiveGenuineRecoveryHelpersInput input, CurrentAuthArchiveGenuineRecoveryHelperCase expectedCase)
    {
        if (input is null || input.Kind != Kind || input.Request is null || expectedCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback ||
            input.Request.Phase != "helper" || input.Request.CaseId != CurrentAuthArchiveGenuineRecoveryHelpers.CaseId(expectedCase))
        { throw CurrentAuthArchiveGenuineHost.Invalid("recovery_helper_input"); }
        CurrentAuthArchiveGenuineHost.RequireInput(input.Request);
    }
}
