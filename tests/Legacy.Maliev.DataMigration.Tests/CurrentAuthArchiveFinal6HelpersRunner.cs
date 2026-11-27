using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal static class CurrentAuthArchiveFinal6HelpersRunner
{
    // Only the fixed qualified Console provider invokes this method; the SDK harness is not a DB operator.
    internal static async Task<CurrentAuthArchiveFinal6CaseResult> ExecuteAsync(string inputPath,
        CurrentAuthArchiveGenuineRecoveryHelperCase expected, CancellationToken ct)
    {
        CurrentAuthArchiveProofCaseV2 selected = expected switch
        {
            CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback => CurrentAuthArchiveProofCaseV2.Dual,
            CurrentAuthArchiveGenuineRecoveryHelperCase.FirstOnlyRecovery => CurrentAuthArchiveProofCaseV2.FirstHelper,
            CurrentAuthArchiveGenuineRecoveryHelperCase.SecondOnlyRecovery => CurrentAuthArchiveProofCaseV2.SecondHelper,
            CurrentAuthArchiveGenuineRecoveryHelperCase.KeyCorruption => CurrentAuthArchiveProofCaseV2.KeyCorruption,
            CurrentAuthArchiveGenuineRecoveryHelperCase.CipherCorruption => CurrentAuthArchiveProofCaseV2.CipherCorruption,
            _ => throw CurrentAuthArchiveFinal6Source.Invalid(),
        };
        var context = await CurrentAuthArchiveFinal6CaseContext.OpenAsync(inputPath, selected, ct);
        var issuer = await CurrentAuthArchiveGenuineIssuer.CreateFinal6HelperAsync(context, expected, ct);
        CurrentAuthArchiveGenuineProviderMethodResult result;
        Exception? primary = null;
        try
        {
            result = expected == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback ?
                await issuer.ExecuteDualDurableReadbackMethodAsync(ct) : await issuer.ExecuteRecoveryHelperAsync(expected, ct);
        }
        catch (Exception failure) { primary = failure; throw; }
        finally
        {
            try { await issuer.DisposeAsync(); }
            catch (Exception cleanup) when (primary is not null) { primary.Data["final6_helper_cleanup_failure"] = cleanup.GetType().Name; }
        }
        var request = context.Request;
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(CurrentAuthArchiveHelperHost.Read(request.Inputs.ParentBinding.Path, 65536));
        var effect = await CurrentAuthArchiveGenuineDualInputReader.PublishCompletedAsync(request, binding, expected, result, ct);
        return await CurrentAuthArchiveFinal6CasePublication.FinishAsync(context,
            new(result.ReturnCode, result.StartedAtUtc, result.ReturnedAtUtc, result.Artifacts), effect, ct);
    }
}
