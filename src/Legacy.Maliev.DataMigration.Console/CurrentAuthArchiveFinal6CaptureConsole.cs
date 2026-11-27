using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveFinal6CaptureConfiguration(string Kind, string BindingPath,
    CurrentAuthArchiveProofArtifact SourceCredential, CurrentAuthArchiveProofArtifact Audience,
    CurrentAuthArchiveProofArtifact SigningPins, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys, string ResultPath);

public static partial class MigrationConsole
{
    internal const string ArchiveFinal6CaptureCommand = "capture-current-auth-archive-final6-source";

    internal static void RequireFinal6CapturePaths(CurrentAuthArchiveFinal6CaptureConfiguration config, string path, LocalExecutionBinding binding)
    {
        string root = binding.ArtifactRootCanonicalPath;
        string[] paths = [path, config.BindingPath, config.SourceCredential.Path, config.Audience.Path, config.SigningPins.Path, config.ResultPath,
            .. config.TrustedKeys.Select(key => key.SubjectPublicKeyInfoPath)];
        if (config.Kind != "current-auth-archive-final6-source-capture-config-v1" || config.TrustedKeys.Count != 3 ||
            paths.Any(candidate => !Path.IsPathFullyQualified(candidate) || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(candidate)), root)) ||
            paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length ||
            new[] { config.SourceCredential.Sha256, config.Audience.Sha256, config.SigningPins.Sha256 }.Any(hash => !CurrentAuthRepairPermit.HashShape(hash)))
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
    }

    private static async Task<int> RunCurrentAuthArchiveFinal6CaptureAsync(string path, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
                Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false") { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            CurrentAuthRepairCapacity.Require(admission: true);
            _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
            var initial = await ReadProtectedJsonAsync<CurrentAuthArchiveFinal6CaptureConfiguration>(path, "archive_final6_config_unprotected", ct).ConfigureAwait(false);
            var binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(initial.BindingPath, "archive_final6_binding_unprotected", ct).ConfigureAwait(false);
            RequireFinal6CapturePaths(initial, path, binding);
            using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            var config = DecodeAuthRepair<CurrentAuthArchiveFinal6CaptureConfiguration>(files.Read(path, sharedReader: true, maximumBytes: 1024 * 1024));
            if (JsonSerializer.Serialize(config) != JsonSerializer.Serialize(initial) || File.Exists(config.ResultPath)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            var pins = DecodeAuthRepair<CurrentAuthArchivePins>(Read(config.SigningPins, 65536));
            var trust = new ReceiptAttestationTrustStore(config.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
                files.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
            var audience = DecodeAuthRepair<CurrentAuthArchiveClaim>(Read(config.Audience, 65536));
            byte[] credential = Read(config.SourceCredential, 65536);
            CurrentAuthArchiveFinal6SourceCapture.Captured captured;
            try { captured = await CurrentAuthArchiveFinal6SourceCapture.Captured.CaptureAsync(Encoding.UTF8.GetString(credential), audience, pins, trust, ct).ConfigureAwait(false); }
            finally { CryptographicOperations.ZeroMemory(credential); }
            await captured.RequireAsync(ct).ConfigureAwait(false);
            await files.WriteNewAsync(config.ResultPath, JsonSerializer.SerializeToUtf8Bytes(captured.Evidence), ct).ConfigureAwait(false);
            await output.WriteLineAsync("archive_final6_actual_source_captured_no_case_proof_or_execution_authority").ConfigureAwait(false); return 0;

            byte[] Read(CurrentAuthArchiveProofArtifact artifact, int maximum)
            {
                byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum);
                return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw CurrentAuthArchiveFinal6Source.Invalid();
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or PlatformNotSupportedException)
        { await error.WriteLineAsync("archive_final6_capture_failed_no_case_proof_or_execution_authority").ConfigureAwait(false); return 1; }
    }
}
