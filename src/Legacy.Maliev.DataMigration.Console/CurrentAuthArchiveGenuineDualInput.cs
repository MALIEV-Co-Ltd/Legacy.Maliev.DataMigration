namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveGenuineDualInput(string Kind, CurrentAuthArchiveGenuineHostConfiguration Request);

internal static class CurrentAuthArchiveGenuineDualInputContract
{
    internal const string Kind = "current-auth-archive-genuine-dual-helper-input-v1";
    internal const string InputVariable = "MALIEV_AUTH_ARCHIVE_GENUINE_DUAL_HELPER_INPUT";
    internal const string ReviewKeyName = "genuine-archive-review-private.pem";
    internal const string AuthorizationKeyName = "genuine-archive-authorization-private.pem";
    internal const string EvidenceKeyName = "genuine-archive-evidence-private.pem";

    internal static void Require(CurrentAuthArchiveGenuineDualInput input)
    {
        if (input is null || input.Kind != Kind || input.Request is null || input.Request.Phase != "helper" ||
            input.Request.CaseId != "dual-durable-readback") { throw CurrentAuthArchiveGenuineHost.Invalid("dual_helper_input"); }
        CurrentAuthArchiveGenuineHost.RequireInput(input.Request);
    }
}
