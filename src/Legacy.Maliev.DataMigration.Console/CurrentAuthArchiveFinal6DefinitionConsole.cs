using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveFinal6DefinitionConfiguration(string Kind, string BindingPath,
    CurrentAuthArchiveProofArtifact QualifiedBinding, CurrentAuthArchiveProofArtifact SourceCredential,
    CurrentAuthArchiveProofArtifact Audience, CurrentAuthArchiveFinal6IntendedObservationInput Intended,
    CurrentAuthArchiveProofArtifact QualifiedTests, CurrentAuthArchiveDefinitionSigningInputs Signing, string ResultPath);

public static partial class MigrationConsole
{
    internal const string ArchiveFinal6DefinitionCommand = "produce-current-auth-archive-final6-definition";

    private static async Task<int> RunCurrentAuthArchiveFinal6DefinitionAsync(string path, TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
                Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false") { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            CurrentAuthRepairCapacity.Require(admission: true);
            _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
            var initial = await ReadProtectedJsonAsync<CurrentAuthArchiveFinal6DefinitionConfiguration>(path, "archive_final6_definition_config_unprotected", ct).ConfigureAwait(false);
            var binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(initial.BindingPath, "archive_final6_definition_binding_unprotected", ct).ConfigureAwait(false);
            RequireFinal6DefinitionPaths(initial, path, binding);
            using var parent = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var parentFiles = new CurrentAppOwnedRepairCustody(parent);
            var config = DecodeAuthRepair<CurrentAuthArchiveFinal6DefinitionConfiguration>(parentFiles.Read(path, sharedReader: true, maximumBytes: 1024 * 1024));
            if (JsonSerializer.Serialize(config) != JsonSerializer.Serialize(initial) || File.Exists(config.ResultPath)) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            var (Authority, Files) = CurrentAuthArchiveCaseCustodyV2.OpenQualified(config.QualifiedBinding, binding.ArtifactRootCanonicalPath);
            using var qualifiedAuthority = Authority;
            using var qualifiedFiles = Files;
            string[] intendedRoots = [Path.GetDirectoryName(config.Intended.LocalBinding.Path)!, Path.GetDirectoryName(config.Intended.ComparisonBinding.Path)!];
            if (intendedRoots.Any(root => StringComparer.OrdinalIgnoreCase.Equals(root, binding.ArtifactRootCanonicalPath) ||
                StringComparer.OrdinalIgnoreCase.Equals(root, qualifiedAuthority.Binding.ArtifactRootCanonicalPath))) { throw CurrentAuthArchiveFinal6Source.Invalid(); }
            RequireDefinitionSigningInputs(qualifiedFiles, config.Signing);
            var pins = new CurrentAuthArchivePins(config.Signing.Pins.ReviewKeyId, config.Signing.Pins.ReviewFingerprint,
                config.Signing.Pins.AuthorizationKeyId, config.Signing.Pins.AuthorizationFingerprint, config.Signing.Pins.ReceiptKeyId, config.Signing.Pins.ReceiptFingerprint);
            var trust = new ReceiptAttestationTrustStore(config.Signing.TrustedKeys.Select(key => new TrustedAttestationKey(key.KeyId,
                qualifiedFiles.Read(key.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536))));
            var audience = DecodeAuthRepair<CurrentAuthArchiveClaim>(Read(config.Audience, 65536));
            byte[] credential = Read(config.SourceCredential, 65536);
            CurrentAuthArchiveFinal6SourceCapture.Captured source;
            try { source = await CurrentAuthArchiveFinal6SourceCapture.Captured.CaptureAsync(Encoding.UTF8.GetString(credential), audience, pins, trust, ct); }
            finally { CryptographicOperations.ZeroMemory(credential); }
            var intended = await CurrentAuthArchiveFinal6IntendedObservationRuntime.ObserveAsync(config.Intended, source, audience, trust, pins, ct);
            var definition = await ProduceCurrentAuthArchiveFinal6FreshDefinitionAsync(parentFiles, parent, source, intended,
                config.QualifiedTests, config.Signing, qualifiedFiles, audience, ct);
            await parentFiles.WriteNewAsync(config.ResultPath, JsonSerializer.SerializeToUtf8Bytes(definition), ct);
            await output.WriteLineAsync("archive_final6_actual_disposable_definition_and_cleanup_verified_no_eighteen_case_proof_or_permit"); return 0;

            byte[] Read(CurrentAuthArchiveProofArtifact artifact, int maximum)
            {
                byte[] bytes = qualifiedFiles.Read(artifact.Path, sharedReader: true, maximumBytes: maximum);
                return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw CurrentAuthArchiveFinal6Source.Invalid();
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or AggregateException or PlatformNotSupportedException)
        { await error.WriteLineAsync("archive_final6_definition_failed_no_eighteen_case_proof_or_permit"); return 1; }
    }

    internal static void RequireFinal6DefinitionPaths(CurrentAuthArchiveFinal6DefinitionConfiguration config, string path, LocalExecutionBinding binding)
    {
        string root = binding.ArtifactRootCanonicalPath;
        string[] paths = [path, config.BindingPath, config.ResultPath];
        if (config.Kind != "current-auth-archive-final6-definition-config-v1" ||
            paths.Any(value => !Path.IsPathFullyQualified(value) || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(value)), root)) ||
            paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length ||
            Path.GetFileName(config.QualifiedTests.Path) != "Legacy.Maliev.DataMigration.Tests.dll") { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        CurrentAuthArchiveCaseCustodyV2.RequireChild(root, Path.GetDirectoryName(config.QualifiedBinding.Path)!);
        string qualifiedRoot = Path.GetDirectoryName(config.QualifiedBinding.Path)!;
        string[] qualifiedPaths = [config.QualifiedBinding.Path, config.SourceCredential.Path, config.Audience.Path, config.QualifiedTests.Path,
            config.Signing.ReviewPrivateKey.Path, config.Signing.EvidencePrivateKey.Path, .. config.Signing.TrustedKeys.Select(key => key.SubjectPublicKeyInfoPath)];
        if (qualifiedPaths.Any(value => !Path.IsPathFullyQualified(value) || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(value)), qualifiedRoot)) ||
            qualifiedPaths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != qualifiedPaths.Length)
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
        string[] roots = [root, qualifiedRoot, Path.GetDirectoryName(config.Intended.LocalBinding.Path)!, Path.GetDirectoryName(config.Intended.ComparisonBinding.Path)!];
        if (roots.Any(value => !Path.IsPathFullyQualified(value)) || roots.Distinct(StringComparer.OrdinalIgnoreCase).Count() != roots.Length)
        { throw CurrentAuthArchiveFinal6Source.Invalid(); }
    }
}
