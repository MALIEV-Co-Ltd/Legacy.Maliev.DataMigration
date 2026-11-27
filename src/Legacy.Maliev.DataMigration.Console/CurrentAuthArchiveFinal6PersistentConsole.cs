using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static void RequireFinal6PersistentArchiveCommand(string command)
    {
        if (command is not ("review-current-auth-local-session-archive-final6" or "authorize-current-auth-local-session-archive-final6" or
            "verify-current-auth-local-session-archive-final6" or "apply-current-auth-local-session-archive-final6")) { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
    }
    private static async Task<int> RunCurrentAuthArchiveFinal6PersistentAsync(string command, string path, TextWriter output, TextWriter error, CancellationToken ct)
    {
        using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(TimeSpan.FromMinutes(8)); ct = expiry.Token;
        try
        {
            RequireFinal6PersistentArchiveCommand(command);
            if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
                Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false") { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
            CurrentAuthArchiveCapacity.Require(admission: true); _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
            var config = await ReadProtectedJsonAsync<CurrentAuthArchiveFinal6PersistentConfiguration>(path, "auth_persistent_final6_config_unprotected", ct);
            var local = CurrentAuthArchiveFinal6PersistentIssuer.Binding(config.Intended.LocalBinding);
            var comparison = CurrentAuthArchiveFinal6PersistentIssuer.Binding(config.Intended.ComparisonBinding);
            var proofBinding = CurrentAuthArchiveFinal6PersistentIssuer.Binding(config.ProofBinding);
            if (config.Kind != "current-auth-final6-persistent-archive-config-v1" || Path.GetDirectoryName(path) != local.ArtifactRootCanonicalPath ||
                new[] { local.ArtifactRootCanonicalPath, comparison.ArtifactRootCanonicalPath, proofBinding.ArtifactRootCanonicalPath }.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 3)
            { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
            using var proofAuthority = WindowsLocalRunAuthority.AcquireResume(proofBinding.ArtifactRootCanonicalPath, proofBinding);
            using var proofFiles = new CurrentAppOwnedRepairCustody(proofAuthority);
            CurrentAuthArchivePins pins; ReceiptAttestationTrustStore trust; CurrentAuthArchiveClaim? review = null;
            using (var authority = WindowsLocalRunAuthority.AcquireResume(local.ArtifactRootCanonicalPath, local))
            using (var files = new CurrentAppOwnedRepairCustody(authority))
            {
                var reread = DecodeAuthRepair<CurrentAuthArchiveFinal6PersistentConfiguration>(files.Read(path, sharedReader: true, maximumBytes: 1024 * 1024));
                if (JsonSerializer.Serialize(reread) != JsonSerializer.Serialize(config)) { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
                pins = CurrentAuthArchiveFinal6PersistentIssuer.Read<CurrentAuthArchivePins>(files, config.SigningPins);
                trust = CurrentAuthArchiveFinal6PersistentIssuer.Trust(files, config, pins);
                if (command != "review-current-auth-local-session-archive-final6")
                { review = DecodeAuthRepair<CurrentAuthArchiveClaim>(files.Read(config.ReviewPath, sharedReader: true, maximumBytes: 1024 * 1024)); }
            }
            if (command is "apply-current-auth-local-session-archive-final6" or "verify-current-auth-local-session-archive-final6")
            {
                using var issuer = await CurrentAuthArchiveFinal6PersistentIssuer.OpenAsync(config, proofFiles, ct);
                var capability = await CurrentAuthLocalSessionArchivePermit.Final6PersistentCapability.AuthenticateAsync(issuer, ct);
                if (command == "verify-current-auth-local-session-archive-final6")
                { await capability.VerifyAsync(ct); await output.WriteLineAsync("auth_archive_final6_verified_no_delete"); return 0; }
                using var evidence = issuer.EvidenceSigner(config.EvidencePrivateKeyPath);
                var terminal = await capability.ExecuteAsync(evidence, ct); issuer.RequireTerminal(terminal);
                await output.WriteLineAsync("auth_archive_final6_local_sessions_committed_independent_readback_original_recovery_domains_retained"); return 0;
            }
            CurrentAuthArchiveFinal6PersistentIntent? reviewed = null;
            if (review is not null)
            {
                reviewed = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveFinal6PersistentIntent>(review,
                    CurrentAuthArchiveFinal6PersistentPolicy.ReviewDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
                CurrentAuthArchiveFinal6PersistentPolicy.RequireIntent(reviewed, DateTimeOffset.UtcNow);
                if (reviewed.ProofSha256 != config.Proof.Proof.Sha256 || reviewed.FinalReadbackSha256 != config.Proof.FinalIntendedReadback.Sha256 ||
                    reviewed.AudienceSha256 != config.Audience.Sha256) { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
            }
            await CurrentAuthArchiveFinal6ProofAssembly.RequirePublishedAsync(proofFiles, config.Proof, config.Audience, pins, trust, ct);
            var observed = await CurrentAuthArchiveFinal6PersistentIssuer.ObserveAsync(config, proofFiles, pins, trust, ct);
            using var localAuthority = WindowsLocalRunAuthority.AcquireResume(local.ArtifactRootCanonicalPath, local);
            using var localFiles = new CurrentAppOwnedRepairCustody(localAuthority);
            if (reviewed is not null)
            {
                CurrentAuthArchiveFinal6PersistentIssuer.RequireCurrent(reviewed, observed);
                if (config.AuthorizationPrivateKeyPath is null) { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
                using var authorizer = Signer(config.AuthorizationPrivateKeyPath, pins.AuthorizationKeyId, pins.AuthorizationFingerprint);
                var authorization = new CurrentAuthArchiveFinal6PersistentAuthorization("current-auth-final6-persistent-archive-authorization-v1",
                    reviewed.Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review!), DateTimeOffset.UtcNow, reviewed.Scope.ExpiresAtUtc);
                var signed = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveFinal6PersistentPolicy.AuthorizationDomain, authorization, authorizer);
                _ = CurrentAuthArchiveFinal6PersistentPolicy.Claims(review!, signed, pins, trust, DateTimeOffset.UtcNow);
                await localFiles.WriteNewAsync(config.AuthorizationPath, JsonSerializer.SerializeToUtf8Bytes(signed), ct);
                await output.WriteLineAsync("auth_archive_final6_exact_current_local_delete_authorized_no_delete"); return 0;
            }
            if (config.ReviewPrivateKeyPath is null) { throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid(); }
            var original = observed.Targets.ObservationScope;
            var scope = original with
            {
                ProofAdmission = CurrentAuthArchiveFinal6PersistentPolicy.Mode,
                ApplicationComparisonSha256 = CurrentAuthLocalSessionArchivePolicy.RequireComparison(observed.Targets.Local.Auth, observed.Targets.Comparison.Auth),
                ExpiresAtUtc = original.ExpiresAtUtc < observed.Final.ExpiresAtUtc ? original.ExpiresAtUtc : observed.Final.ExpiresAtUtc
            };
            string prefix = Path.Combine(local.ArtifactRootCanonicalPath, "archive-final6-persistent-" + scope.OperationId.ToString("N"));
            var source = await Retain(prefix + "-source.json", observed.Source.Evidence);
            var device = await Retain(prefix + "-devices.json", observed.Targets.Devices);
            var intended = await CurrentAuthArchiveFinal6IntendedRetention.RetainAsync(localFiles, prefix + "-intended.json", observed.Targets.Evidence, ct);
            var intent = new CurrentAuthArchiveFinal6PersistentIntent("current-auth-final6-persistent-archive-intent-v1", scope, config.Proof.Proof.Sha256,
                config.Proof.FinalIntendedReadback.Sha256, config.Audience.Sha256, intended.Sha256, observed.Source.Evidence.Capture.DefinitionSha256,
                observed.Source.Evidence.Capture.SourceIdentitySha256, CurrentAuthArchiveRecoveryV2Preservation.NativeSha(observed.Targets.Local.Auth.Native),
                CurrentAuthArchiveRecoveryV2Preservation.NativeSha(observed.Targets.Comparison.Auth.Native), source, device, new(intended.Path, intended.Sha256));
            CurrentAuthArchiveFinal6PersistentPolicy.RequireIntent(intent, DateTimeOffset.UtcNow);
            using var reviewer = Signer(config.ReviewPrivateKeyPath, pins.ReviewKeyId, pins.ReviewFingerprint);
            var claim = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchiveFinal6PersistentPolicy.ReviewDomain, intent, reviewer);
            await localFiles.WriteNewAsync(config.ReviewPath, JsonSerializer.SerializeToUtf8Bytes(claim), ct);
            await output.WriteLineAsync("auth_archive_final6_exact_current_local_delete_reviewed_no_delete"); return 0;
            async Task<CurrentAuthArchiveGenuineArtifact> Retain<T>(string destination, T value)
            { byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value); await localFiles.WriteNewAsync(destination, bytes, ct); return new(destination, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes)); }
            P256MigrationEvidenceSigner Signer(string keyPath, string keyId, string fingerprint)
            {
                byte[] bytes = localFiles.Read(keyPath, sharedReader: true, maximumBytes: 65536);
                try
                {
                    var signer = new P256MigrationEvidenceSigner(keyId, Encoding.UTF8.GetString(bytes));
                    if (signer.PublicKeyFingerprintSha256 == fingerprint) { return signer; }
                    signer.Dispose(); throw CurrentAuthArchiveFinal6PersistentPolicy.Invalid();
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or JsonException or
            InvalidOperationException or ArgumentException or OperationCanceledException or AggregateException or CryptographicException or Npgsql.NpgsqlException)
        { await error.WriteLineAsync("auth_archive_final6_failed_no_success_or_restore_authority"); return 1; }
    }
}
