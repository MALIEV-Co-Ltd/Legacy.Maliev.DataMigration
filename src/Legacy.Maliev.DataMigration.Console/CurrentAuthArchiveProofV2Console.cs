using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveProofV2Configuration(string Kind, string BindingPath,
    CurrentAuthArchiveGeneratedCaseInputV2 Inputs, string ResultPath);

public static partial class MigrationConsole
{
    internal const string ArchiveProofV2Command = "produce-current-auth-archive-proof-v2";
    internal static void RequireArchiveProofV2Paths(CurrentAuthArchiveProofV2Configuration config, string path, LocalExecutionBinding binding)
    {
        string root = binding.ArtifactRootCanonicalPath;
        if (config.Kind != "current-auth-archive-full-eighteen-producer-config-v2" ||
            Path.GetDirectoryName(Path.GetFullPath(path)) != root || Path.GetDirectoryName(Path.GetFullPath(config.BindingPath)) != root ||
            Path.GetDirectoryName(Path.GetFullPath(config.ResultPath)) != root || config.ResultPath == path || config.ResultPath == config.BindingPath)
        { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        CurrentAuthArchiveCaseCustodyV2.RequireChild(root, Path.GetDirectoryName(config.Inputs.QualifiedInputBinding.Path)!);
    }
    private static async Task<int> RunCurrentAuthArchiveProofV2Async(string path, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
                Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false") { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
            CurrentAuthRepairCapacity.Require(admission: true);
            _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
            var initial = await ReadProtectedJsonAsync<CurrentAuthArchiveProofV2Configuration>(path, "archive_proof_v2_config_unprotected", ct);
            var binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(initial.BindingPath, "archive_proof_v2_binding_unprotected", ct);
            RequireArchiveProofV2Paths(initial, path, binding);
            using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            var config = DecodeAuthRepair<CurrentAuthArchiveProofV2Configuration>(files.Read(path, sharedReader: true, maximumBytes: 1024 * 1024));
            if (JsonSerializer.Serialize(config) != JsonSerializer.Serialize(initial) || File.Exists(config.ResultPath)) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
            using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(TimeSpan.FromHours(12));
            var observed = await ObserveCurrentAuthArchiveAllCasesV2Async(files, authority, config.Inputs, expiry.Token);
            var result = await AssembleCurrentAuthArchiveProofV2Async(files, authority, observed, config.Inputs, expiry.Token);
            await files.WriteNewAsync(config.ResultPath, JsonSerializer.SerializeToUtf8Bytes(result), expiry.Token);
            await output.WriteLineAsync("archive_v2_actual_eighteen_proof_and_fresh_intended_readback_published_no_persistent_authority");
            return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or AggregateException or PlatformNotSupportedException)
        { await error.WriteLineAsync("archive_v2_producer_failed_no_persistent_authority"); return 1; }
    }
}
