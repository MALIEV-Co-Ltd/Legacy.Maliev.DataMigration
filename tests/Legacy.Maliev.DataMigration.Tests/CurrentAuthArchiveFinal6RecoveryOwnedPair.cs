using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    private CurrentAuthArchiveFinal6SourceCapture.Captured? _recoveryFinal6Capture;
    private CurrentAuthArchiveRecoverySourceEvidence RecoveryActualSource => _inputs.Final6Case is not null ?
        _recoveryFinal6Capture?.Evidence.Capture ?? throw Invalid() : _recoveryCapture?.Evidence ?? throw Invalid();

    internal static async Task<ICurrentAuthArchiveRecoveryV2Lease> OpenFinal6RecoveryLeaseAsync(CurrentAuthArchiveFinal6CaseContext context,
        CurrentAuthArchiveRecoveryV2Case expected, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (CurrentAuthArchiveGeneratedCasesV2.Recovery(context.Case) != expected) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        await context.RequireFactoryAsync(ct);
        var request = context.Request;
        var bundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(Path.GetDirectoryName(request.Inputs.TestImage.Path)!, ct);
        CurrentAuthArchiveComponentReadback? inputs = null; CurrentAuthArchiveGenuineOwnedPair? pair = null;
        try
        {
            bundle.Require(); inputs = await CurrentAuthArchiveComponentReadback.OpenFinal6InitialAsync(request.Inputs, context, ct);
            var seed = await inputs.ReadSeedAsync(ct);
            CurrentAuthArchiveGenuineExecutionSeed.RequireInitial(seed, inputs.Pins, inputs.TrustStore, CurrentAuthArchiveRecoveryV2.SetupCase(expected), DateTimeOffset.UtcNow);
            pair = new(inputs, bundle, seed, ct)
            {
                _recoveryV2Case = expected,
                _recoveryAudienceClaim = context.AudienceClaim,
                _recoveryCaseClaim = context.CaseClaim,
            };
            await pair.CreateOwnedAsync(request, pair._lease.Token);
            await pair.PrepareRecoverySetupAsync(pair._lease.Token); return pair;
        }
        catch (Exception primary)
        {
            if (pair is not null) { try { await pair.DisposeAsync(); } catch (Exception cleanup) { primary.Data["final6_recovery_pair_cleanup"] = cleanup.GetType().Name; } }
            else
            {
                try { inputs?.Dispose(); } catch (Exception cleanup) { primary.Data["final6_recovery_input_cleanup"] = cleanup.GetType().Name; }
                try { bundle.Dispose(); } catch (Exception cleanup) { primary.Data["final6_recovery_bundle_cleanup"] = cleanup.GetType().Name; }
            }
            throw;
        }
    }
}
