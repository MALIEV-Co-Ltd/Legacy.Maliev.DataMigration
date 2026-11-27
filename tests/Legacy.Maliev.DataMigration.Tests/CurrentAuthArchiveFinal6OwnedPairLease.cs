using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    // The issuer chooses this exact fixed factory after authenticating the held Tests image.
    // Existing helper entrypoints still open only the old phase3 initial reader.
    internal static async Task<ICurrentAuthArchiveGenuineOwnedLease> OpenFinal6HelperLeaseAsync(CurrentAuthArchiveFinal6CaseContext context,
        CurrentAuthArchiveGenuineRecoveryHelperCase expected, CancellationToken ct)
    {
        return CurrentAuthArchiveGeneratedCasesV2.Helper(context.Case) != expected
            ? throw CurrentAuthArchiveFinal6Source.Invalid()
            : (ICurrentAuthArchiveGenuineOwnedLease)await CreateHelperCoreAsync(context.Request, expected, ct, context);
    }
}
