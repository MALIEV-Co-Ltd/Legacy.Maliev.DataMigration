using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static void RequirePersistentArchiveV2Command(string command)
    {
        if (command is not ("review-current-auth-local-session-archive-v2" or "authorize-current-auth-local-session-archive-v2" or
            "verify-current-auth-local-session-archive-v2" or "apply-current-auth-local-session-archive-v2")) { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
    }
    private static async Task<int> RunCurrentAuthArchivePersistentV2Async(string command, string path, TextWriter output, TextWriter error, CancellationToken ct)
    {
        using var expiry = CancellationTokenSource.CreateLinkedTokenSource(ct); expiry.CancelAfter(TimeSpan.FromMinutes(8)); ct = expiry.Token;
        try
        {
            RequirePersistentArchiveV2Command(command);
            if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
                Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false") { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
            CurrentAuthArchiveCapacity.Require(admission: true); _ = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
            var config = await ReadProtectedJsonAsync<CurrentAuthArchivePersistentV2Configuration>(path, "auth_persistent_v2_config_unprotected", ct);
            var local = CurrentAuthArchivePersistentV2Issuer.Binding(config.Intended.LocalBinding);
            var comparison = CurrentAuthArchivePersistentV2Issuer.Binding(config.Intended.ComparisonBinding);
            var proofBinding = CurrentAuthArchivePersistentV2Issuer.Binding(config.ProofBinding);
            if (config.Kind != "current-auth-persistent-archive-config-v2" || Path.GetDirectoryName(path) != local.ArtifactRootCanonicalPath ||
                new[] { local.ArtifactRootCanonicalPath, comparison.ArtifactRootCanonicalPath, proofBinding.ArtifactRootCanonicalPath }.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 3)
            { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
            using var proofAuthority = WindowsLocalRunAuthority.AcquireResume(proofBinding.ArtifactRootCanonicalPath, proofBinding);
            using var proofFiles = new CurrentAppOwnedRepairCustody(proofAuthority);
            CurrentAuthArchivePins pins; ReceiptAttestationTrustStore trust; CurrentAuthArchiveClaim? review = null;
            using (var authority = WindowsLocalRunAuthority.AcquireResume(local.ArtifactRootCanonicalPath, local))
            using (var files = new CurrentAppOwnedRepairCustody(authority))
            {
                var reread = DecodeAuthRepair<CurrentAuthArchivePersistentV2Configuration>(files.Read(path, sharedReader: true, maximumBytes: 1024 * 1024));
                if (JsonSerializer.Serialize(reread) != JsonSerializer.Serialize(config)) { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
                pins = CurrentAuthArchivePersistentV2Issuer.Read<CurrentAuthArchivePins>(files, config.SigningPins);
                trust = CurrentAuthArchivePersistentV2Issuer.Trust(files, config, pins);
                if (command != "review-current-auth-local-session-archive-v2")
                { review = DecodeAuthRepair<CurrentAuthArchiveClaim>(files.Read(config.ReviewPath, sharedReader: true, maximumBytes: 1024 * 1024)); }
            }
            if (command is "apply-current-auth-local-session-archive-v2" or "verify-current-auth-local-session-archive-v2")
            {
                using var issuer = await CurrentAuthArchivePersistentV2Issuer.OpenAsync(config, proofFiles, ct);
                var capability = await CurrentAuthLocalSessionArchivePermit.PersistentV2Capability.AuthenticateAsync(issuer, ct);
                if (command == "verify-current-auth-local-session-archive-v2")
                { await capability.VerifyAsync(ct); await output.WriteLineAsync("auth_archive_v2_verified_no_delete"); return 0; }
                using var evidence = issuer.EvidenceSigner(config.EvidencePrivateKeyPath);
                var terminal = await capability.ExecuteAsync(evidence, ct); issuer.RequireTerminal(terminal);
                await output.WriteLineAsync("auth_archive_v2_local_sessions_committed_independent_readback_original_recovery_domains_retained"); return 0;
            }
            CurrentAuthArchivePersistentIntentV2? reviewed = null;
            if (review is not null)
            {
                reviewed = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchivePersistentIntentV2>(review,
                    CurrentAuthArchivePersistentV2Policy.ReviewDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
                CurrentAuthArchivePersistentV2Policy.RequireIntent(reviewed, DateTimeOffset.UtcNow);
                if (reviewed.ProofSha256 != config.Proof.Proof.Sha256 || reviewed.FinalReadbackSha256 != config.Proof.FinalIntendedReadback.Sha256 ||
                    reviewed.AudienceSha256 != config.Audience.Sha256) { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
            }
            await CurrentAuthArchiveProofAssemblyV2.RequirePublishedAsync(proofFiles, config.Proof, config.Audience, pins, trust, ct);
            var observed = await CurrentAuthArchivePersistentV2Issuer.ObserveAsync(config, proofFiles, pins, trust, ct);
            using var localAuthority = WindowsLocalRunAuthority.AcquireResume(local.ArtifactRootCanonicalPath, local);
            using var localFiles = new CurrentAppOwnedRepairCustody(localAuthority);
            if (reviewed is not null)
            {
                CurrentAuthArchivePersistentV2Issuer.RequireCurrent(reviewed, observed);
                if (config.AuthorizationPrivateKeyPath is null) { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
                using var authorizer = Signer(config.AuthorizationPrivateKeyPath, pins.AuthorizationKeyId, pins.AuthorizationFingerprint);
                var authorization = new CurrentAuthArchivePersistentAuthorizationV2("current-auth-persistent-archive-authorization-v2",
                    reviewed.Scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review!), DateTimeOffset.UtcNow, reviewed.Scope.ExpiresAtUtc);
                var signed = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchivePersistentV2Policy.AuthorizationDomain, authorization, authorizer);
                _ = CurrentAuthArchivePersistentV2Policy.Claims(review!, signed, pins, trust, DateTimeOffset.UtcNow);
                await localFiles.WriteNewAsync(config.AuthorizationPath, JsonSerializer.SerializeToUtf8Bytes(signed), ct);
                await output.WriteLineAsync("auth_archive_v2_exact_current_local_delete_authorized_no_delete"); return 0;
            }
            if (config.ReviewPrivateKeyPath is null) { throw CurrentAuthArchivePersistentV2Policy.Invalid(); }
            var original = observed.Targets.ObservationScope;
            var scope = original with
            {
                ProofAdmission = CurrentAuthArchivePersistentV2Policy.Mode,
                ApplicationComparisonSha256 = CurrentAuthLocalSessionArchivePolicy.RequireComparison(observed.Targets.Local.Auth, observed.Targets.Comparison.Auth),
                ExpiresAtUtc = original.ExpiresAtUtc < observed.Final.ExpiresAtUtc ? original.ExpiresAtUtc : observed.Final.ExpiresAtUtc
            };
            string prefix = Path.Combine(local.ArtifactRootCanonicalPath, "archive-persistent-v2-" + scope.OperationId.ToString("N"));
            var source = await Retain(prefix + "-source.json", observed.Source.Evidence);
            var device = await Retain(prefix + "-devices.json", observed.Targets.Devices);
            var intended = await CurrentAuthArchiveIntendedRetentionV2.RetainAsync(localFiles, prefix + "-intended.json", observed.Targets.Evidence, ct);
            var intent = new CurrentAuthArchivePersistentIntentV2("current-auth-persistent-archive-intent-v2", scope, config.Proof.Proof.Sha256,
                config.Proof.FinalIntendedReadback.Sha256, config.Audience.Sha256, intended.Sha256, observed.Source.Evidence.DefinitionSha256,
                observed.Source.Evidence.SourceIdentitySha256, CurrentAuthArchiveRecoveryV2Preservation.NativeSha(observed.Targets.Local.Auth.Native),
                CurrentAuthArchiveRecoveryV2Preservation.NativeSha(observed.Targets.Comparison.Auth.Native), source, device, new(intended.Path, intended.Sha256));
            CurrentAuthArchivePersistentV2Policy.RequireIntent(intent, DateTimeOffset.UtcNow);
            using var reviewer = Signer(config.ReviewPrivateKeyPath, pins.ReviewKeyId, pins.ReviewFingerprint);
            var claim = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthArchivePersistentV2Policy.ReviewDomain, intent, reviewer);
            await localFiles.WriteNewAsync(config.ReviewPath, JsonSerializer.SerializeToUtf8Bytes(claim), ct);
            await output.WriteLineAsync("auth_archive_v2_exact_current_local_delete_reviewed_no_delete"); return 0;
            async Task<CurrentAuthArchiveGenuineArtifact> Retain<T>(string destination, T value)
            { byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value); await localFiles.WriteNewAsync(destination, bytes, ct); return new(destination, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes)); }
            P256MigrationEvidenceSigner Signer(string keyPath, string keyId, string fingerprint)
            {
                byte[] bytes = localFiles.Read(keyPath, sharedReader: true, maximumBytes: 65536);
                try
                {
                    var signer = new P256MigrationEvidenceSigner(keyId, Encoding.UTF8.GetString(bytes));
                    if (signer.PublicKeyFingerprintSha256 == fingerprint) { return signer; }
                    signer.Dispose(); throw CurrentAuthArchivePersistentV2Policy.Invalid();
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or IOException or UnauthorizedAccessException or JsonException or
            InvalidOperationException or ArgumentException or OperationCanceledException or AggregateException or CryptographicException or Npgsql.NpgsqlException)
        { await error.WriteLineAsync("auth_archive_v2_failed_no_success_or_restore_authority"); return 1; }
    }
}
