using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static async Task<int> RunCompanyStorageNativeFaultsAsync(string path, TextWriter output, TextWriter error, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            if (System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly) { throw CompanyStorageRepairProtocol.Invalid(); }
            _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct); CurrentAuthRepairCapacity.Require(admission: true);
            if (!Path.IsPathFullyQualified(path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw CompanyStorageRepairProtocol.Invalid(); }
            using var held = SecureLocalFile.OpenReadShared(path);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(held, path) || held.Length is < 1 or > 65536) { throw CompanyStorageRepairProtocol.Invalid(); }
            byte[] bytes = new byte[checked((int)held.Length)]; await held.ReadExactlyAsync(bytes, ct);
            var configuration = DecodeAuthRepair<CompanyStorageNativeFaultConfiguration>(bytes);
            await CompanyStorageRuntime.RunNativeFaultSuiteAsync(configuration, ct);
            await output.WriteLineAsync("company_storage_five_actual_owned_fault_cases_completed_no_persistent_authority"); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            System.Data.Common.DbException or JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or AggregateException or System.Reflection.TargetInvocationException or System.Security.Cryptography.CryptographicException)
        { await error.WriteLineAsync("company_storage_owned_fault_suite_failed_or_cleanup_incomplete"); return 1; }
    }
}
