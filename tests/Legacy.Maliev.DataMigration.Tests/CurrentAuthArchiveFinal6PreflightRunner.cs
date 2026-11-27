using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal static class CurrentAuthArchiveFinal6PreflightRunner
{
    internal static async Task<CurrentAuthArchiveFinal6CaseResult> ExecuteAsync(string inputPath,
        CurrentAuthArchiveGenuinePreflightCase expected, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var selected = expected switch
        {
            CurrentAuthArchiveGenuinePreflightCase.HostUnprobedSdk => CurrentAuthArchiveProofCaseV2.HostUnprobed,
            CurrentAuthArchiveGenuinePreflightCase.LocalTrust => CurrentAuthArchiveProofCaseV2.LocalTrust,
            _ => throw CurrentAuthArchiveFinal6Source.Invalid(),
        };
        var context = await CurrentAuthArchiveFinal6CaseContext.OpenAsync(inputPath, selected, ct);
        var pair = await CurrentAuthArchiveGenuineOwnedPair.CreateFinal6PreflightAsync(context, expected, ct);
        CurrentAuthArchiveGenuinePreflightMethodResult method; Exception? primary = null;
        try { method = await pair.RunPreflightAsync(ct); }
        catch (Exception failure) { primary = failure; throw; }
        finally
        {
            try { await pair.DisposeAsync(); }
            catch (Exception cleanup) when (primary is not null) { primary.Data["final6_preflight_cleanup_failure"] = cleanup.GetType().Name; }
        }
        var request = context.Request;
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(CurrentAuthArchiveHelperHost.Read(request.Inputs.ParentBinding.Path, 65536));
        var effect = await CurrentAuthArchiveGenuinePreflightRunner.PublishAsync(request, binding, expected, method, ct);
        return await CurrentAuthArchiveFinal6CasePublication.FinishAsync(context,
            new(method.ReturnCode, method.StartedAtUtc, method.ReturnedAtUtc, method.Artifacts), effect, ct);
    }
}
