using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveFinal6ProofConfiguration(string Kind, CurrentAuthArchiveProofArtifact Binding,
    CurrentAuthArchiveFinal6GeneratorInput Inputs, string ResultPath);

public static partial class MigrationConsole
{
    private static async Task<int> RunCurrentAuthArchiveFinal6ProofAsync(string configPath, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
                Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false") { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            CurrentAuthRepairCapacity.Require(admission: true);
            _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
            byte[] initial = CurrentAuthArchiveHelperHost.Read(configPath, 65536);
            var config = DecodeAuthRepair<CurrentAuthArchiveFinal6ProofConfiguration>(initial);
            RequireFinal6ProofConfiguration(config, configPath);
            byte[] bytes = CurrentAuthArchiveHelperHost.Read(config.Binding.Path, 65536);
            if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != config.Binding.Sha256) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            var binding = DecodeAuthRepair<LocalExecutionBinding>(bytes);
            using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            if (!files.Read(configPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(initial) ||
                !files.Read(config.Binding.Path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct); lifetime.CancelAfter(TimeSpan.FromHours(12));
            var result = await ProduceCurrentAuthArchiveFinal6ProofAsync(files, authority, config.Inputs, lifetime.Token);
            await files.WriteNewAsync(config.ResultPath, JsonSerializer.SerializeToUtf8Bytes(result), ct);
            await output.WriteLineAsync("archive_final6_complete_eighteen_proof_published_no_execution_permit"); return 0;
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or AggregateException or System.ComponentModel.Win32Exception)
        { await error.WriteLineAsync("archive_final6_proof_failed_no_execution_permit"); return 1; }
    }

    internal static void RequireFinal6ProofConfiguration(CurrentAuthArchiveFinal6ProofConfiguration config, string path)
    {
        if (config.Kind != "current-auth-archive-final6-proof-config-v1" || config.Binding is null || config.Inputs is null || config.Inputs.Intended is null ||
            config.Inputs.QualifiedInputBinding is null || config.Inputs.Intended.LocalBinding is null || config.Inputs.Intended.ComparisonBinding is null ||
            !Path.IsPathFullyQualified(path) || !Path.IsPathFullyQualified(config.Binding.Path) || !Path.IsPathFullyQualified(config.ResultPath))
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        string root = Path.GetDirectoryName(path)!;
        string[] separate = [root, Path.GetDirectoryName(config.Inputs.QualifiedInputBinding.Path)!,
            Path.GetDirectoryName(config.Inputs.Intended.LocalBinding.Path)!, Path.GetDirectoryName(config.Inputs.Intended.ComparisonBinding.Path)!];
        if (Path.GetDirectoryName(config.Binding.Path) != root || Path.GetDirectoryName(config.ResultPath) != root ||
            separate.Any(value => !Path.IsPathFullyQualified(value)) || separate.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 4 ||
            new[] { path, config.Binding.Path, config.ResultPath }.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 3 ||
            !CurrentAuthRepairPermit.HashShape(config.Binding.Sha256) || config.Inputs.QualifiedInputBinding is null ||
            !Path.IsPathFullyQualified(config.Inputs.QualifiedInputBinding.Path)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        CurrentAuthArchiveFinal6CaseCustody.RequireChild(root, Path.GetDirectoryName(config.Inputs.QualifiedInputBinding.Path)!);
    }
}
