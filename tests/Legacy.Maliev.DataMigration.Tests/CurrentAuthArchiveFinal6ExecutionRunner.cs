using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal static class CurrentAuthArchiveFinal6ExecutionRunner
{
    internal static async Task<CurrentAuthArchiveFinal6CaseResult> ExecuteAsync(string inputPath,
        CurrentAuthArchiveGenuineExecutionCase expected, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); CurrentAuthArchiveGenuineExecutionCases.RequireImplemented(expected);
        var (Phase, CaseId) = CurrentAuthArchiveGenuineExecutionCases.Identity(expected);
        var selected = Enum.GetValues<CurrentAuthArchiveProofCaseV2>().Single(value =>
            CurrentAuthArchiveGeneratedCasesV2.Identity(value).Phase == Phase && CurrentAuthArchiveGeneratedCasesV2.Identity(value).CaseId == CaseId);
        var context = await CurrentAuthArchiveFinal6CaseContext.OpenAsync(inputPath, selected, ct);
        var issuer = await CurrentAuthArchiveGenuineExecutionIssuer.CreateFinal6ExecutionAsync(context, expected, ct);
        CurrentAuthArchiveGenuineExecutionMethodResult method;
        Exception? primary = null;
        try
        {
            var capability = await CurrentAuthLocalSessionArchivePermit.GenuineExecutionCapability.AuthenticateAsync(issuer, ct);
            method = await capability.ExecuteAsync(ct);
        }
        catch (Exception failure) { primary = failure; throw; }
        finally
        {
            try { await issuer.DisposeAsync(); }
            catch (Exception cleanup) when (primary is not null) { primary.Data["final6_execution_cleanup_failure"] = cleanup.GetType().Name; }
        }
        var request = context.Request;
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(CurrentAuthArchiveHelperHost.Read(request.Inputs.ParentBinding.Path, 65536));
        var effect = await CurrentAuthArchiveGenuineExecutionRunner.PublishCompletedAsync(request, binding, expected, method, ct);
        return await CurrentAuthArchiveFinal6CasePublication.FinishAsync(context,
            new(method.ReturnCode, method.StartedAtUtc, method.ReturnedAtUtc, method.Artifacts), effect, ct);
    }
}
