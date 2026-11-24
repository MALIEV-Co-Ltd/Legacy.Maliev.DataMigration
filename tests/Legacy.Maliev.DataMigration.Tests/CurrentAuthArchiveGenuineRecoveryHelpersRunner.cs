using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Fixed qualified-ALC Console-provider entry. SDK test methods never call it in
// their own process; they launch the accepted Console provider through its host.
internal static class CurrentAuthArchiveGenuineRecoveryHelpersRunner
{
    internal static async Task<CurrentAuthArchiveGenuineProviderCaseResult> ExecuteAsync(string inputPath,
        CurrentAuthArchiveGenuineRecoveryHelperCase expectedCase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        byte[] original = Read(inputPath);
        CurrentAuthArchiveGenuineHostConfiguration request;
        if (expectedCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback)
        {
            var packet = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineDualInput>(original);
            CurrentAuthArchiveGenuineDualInputContract.Require(packet); request = packet.Request;
        }
        else
        {
            var packet = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineRecoveryHelpersInput>(original);
            CurrentAuthArchiveGenuineRecoveryHelpersInputContract.Require(packet, expectedCase); request = packet.Request;
        }
        string root = Path.GetDirectoryName(request.Inputs.ParentBinding.Path)!;
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(inputPath), root)) { throw Invalid(); }
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(Read(request.Inputs.ParentBinding.Path));
        using (var authority = WindowsLocalRunAuthority.AcquireResume(root, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        { if (!files.Read(inputPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(original)) { throw Invalid(); } }
        var issuer = expectedCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback
            ? await CurrentAuthArchiveGenuineIssuer.CreateAsync(request, ct)
            : await CurrentAuthArchiveGenuineIssuer.CreateRecoveryHelperAsync(request, expectedCase, ct);
        CurrentAuthArchiveGenuineProviderMethodResult result;
        Exception? primary = null;
        try
        {
            result = expectedCase == CurrentAuthArchiveGenuineRecoveryHelperCase.DualDurableReadback
                ? await issuer.ExecuteDualDurableReadbackMethodAsync(ct) : await issuer.ExecuteRecoveryHelperAsync(expectedCase, ct);
        }
        catch (Exception failure) { primary = failure; throw; }
        finally
        {
            try { await issuer.DisposeAsync(); }
            catch (Exception cleanup) when (primary is not null) { primary.Data["helper_cleanup_failure"] = cleanup.GetType().Name; }
        }
        var candidate = await CurrentAuthArchiveGenuineDualInputReader.PublishCompletedAsync(request, binding, expectedCase, result, ct);
        return new(result, candidate);
    }

    private static byte[] Read(string path)
    {
        if (!Path.IsPathFullyQualified(path)) { throw Invalid(); }
        using var held = SecureLocalFile.OpenReadShared(path);
        if (held.Length is < 1 or > 65536 || !SecureLocalFile.HandleResolvesToApprovedPath(held, path)) { throw Invalid(); }
        byte[] bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes); return bytes;
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveGenuineHost.Invalid("helper_runner");
    }
}
