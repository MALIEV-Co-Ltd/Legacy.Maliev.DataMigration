namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveGenuinePreflightInput(string Kind, CurrentAuthArchiveGenuineHostConfiguration Request);
internal static class CurrentAuthArchiveGenuinePreflightInputContract
{
    internal const string Kind = "current-auth-archive-genuine-policy-preflight-input-v1";
    internal static void Require(CurrentAuthArchiveGenuinePreflightInput input, CurrentAuthArchiveGenuinePreflightCase expected)
    {
        string id = CurrentAuthArchiveGenuinePreflight.CaseId(expected);
        if (input is null || input.Kind != Kind || input.Request is null || input.Request.Phase != "native" || input.Request.CaseId != id) { throw CurrentAuthArchiveGenuinePreflight.Invalid(); }
        CurrentAuthArchiveGenuineHost.RequireInput(input.Request);
    }
}
