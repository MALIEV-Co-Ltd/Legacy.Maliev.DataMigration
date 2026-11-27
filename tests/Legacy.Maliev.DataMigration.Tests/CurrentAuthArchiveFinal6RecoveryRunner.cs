using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal static class CurrentAuthArchiveFinal6RecoveryRunner
{
    internal static async Task<CurrentAuthArchiveFinal6CaseResult> ExecuteAsync(string inputPath,
        CurrentAuthArchiveRecoveryV2Case expected, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var selected = expected switch
        {
            CurrentAuthArchiveRecoveryV2Case.FirstOnly => CurrentAuthArchiveProofCaseV2.FirstRestore,
            CurrentAuthArchiveRecoveryV2Case.SecondOnly => CurrentAuthArchiveProofCaseV2.SecondRestore,
            _ => throw CurrentAuthArchiveFinal6Source.Invalid(),
        };
        var context = await CurrentAuthArchiveFinal6CaseContext.OpenAsync(inputPath, selected, ct);
        var issuer = await CurrentAuthArchiveRecoveryV2Issuer.CreateFinal6RecoveryAsync(context, expected, ct);
        CurrentAuthArchiveGenuineExecutionMethodResult method;
        Exception? primary = null;
        try
        {
            var capability = await CurrentAuthLocalSessionArchivePermit.GenuineRecoveryV2Capability.AuthenticateAsync(issuer, ct);
            method = await capability.ExecuteAsync(ct);
        }
        catch (Exception failure) { primary = failure; throw; }
        finally
        {
            try { await issuer.DisposeAsync(); }
            catch (Exception cleanup) when (primary is not null) { primary.Data["final6_recovery_cleanup_failure"] = cleanup.GetType().Name; }
        }
        var request = context.Request;
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(CurrentAuthArchiveHelperHost.Read(request.Inputs.ParentBinding.Path, 65536));
        var effect = await CurrentAuthArchiveRecoveryV2Runner.PublishCompletedAsync(request, binding, expected, method, ct);
        return await CurrentAuthArchiveFinal6CasePublication.FinishAsync(context,
            new(method.ReturnCode, method.StartedAtUtc, method.ReturnedAtUtc, method.Artifacts), effect, ct);
    }
}
