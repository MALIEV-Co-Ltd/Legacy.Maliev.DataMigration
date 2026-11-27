using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static async Task<int> RunSourceOrderOwnerIsoAsync(string action, string path, TextWriter output, TextWriter error, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            if (System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
                action is not ("observe" or "verify" or "apply" or "native-faults")) { throw SourceOrderOwnerIsoProtocol.Invalid(); }
            _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct); CurrentAuthRepairCapacity.Require(admission: true);
            if (action == "observe")
            {
                var artifact = await SourceOrderOwnerIsoInputs.ObserveAndSignAsync(path, ct);
                await output.WriteLineAsync("source_order_owner_iso_observed_configuration_sha256=" + artifact.Sha256); return 0;
            }
            if (action == "native-faults")
            {
                if (!Path.IsPathFullyQualified(path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw SourceOrderOwnerIsoProtocol.Invalid(); }
                using var held = SecureLocalFile.OpenReadShared(path);
                if (!SecureLocalFile.HandleResolvesToApprovedPath(held, path) || held.Length is < 1 or > 65536) { throw SourceOrderOwnerIsoProtocol.Invalid(); }
                byte[] bytes = new byte[checked((int)held.Length)]; await held.ReadExactlyAsync(bytes, ct);
                await SourceOrderOwnerIsoRuntime.RunNativeFaultsAsync(DecodeAuthRepair<SourceOrderOwnerIsoFaultConfiguration>(bytes), ct);
                await output.WriteLineAsync("source_order_owner_iso_five_actual_owned_fault_cases_completed_no_persistent_authority"); return 0;
            }
            using var input = SourceOrderOwnerIsoInputs.Open(path); using var runtime = await SourceOrderOwnerIsoRuntime.OpenAsync(input, ct);
            if (action == "verify") { await runtime.VerifyAsync(ct); await output.WriteLineAsync("source_order_owner_iso_live_preimages_verified_no_write"); }
            else { await runtime.ExecuteAsync(ct); await output.WriteLineAsync("source_order_owner_iso_fixed_pending_operations_committed_and_independently_readback"); }
            return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            System.Data.Common.DbException or JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or AggregateException or
            System.Reflection.TargetInvocationException or System.Security.Cryptography.CryptographicException)
        { await error.WriteLineAsync("source_order_owner_iso_refused_failed_uncertain_or_cleanup_incomplete"); return 1; }
    }
}
