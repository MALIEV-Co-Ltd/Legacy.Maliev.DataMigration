using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthRepairConfiguration(string SourceSchemaPath, string ScopePath, string ReviewPath,
    string AuthorizationPath, string SigningPinsPath, string RunBindingPath, string OperatorConnectionPath,
    string RejectedOrdinaryConnectionPath, string GlobalBeforePath, string TargetPinsPath,
    IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys, string ReceiptPrivateKeyPath,
    CurrentAppOwnedRepairArtifact AuthHelperProof, CurrentAppOwnedRepairArtifact NativeProof,
    CurrentAppOwnedRepairArtifact RecoveryReview, CurrentAppOwnedRepairArtifact ExactRoleTransitionReview,
    string? ReviewPrivateKeyPath = null, string? ReviewOutputPath = null, DateTimeOffset? ReviewExpiresAtUtc = null,
    string? AuthorizationPrivateKeyPath = null, string? AuthorizationOutputPath = null,
    CurrentAuthClosedBootstrapEvidence? ClosedBootstrap = null,
    CurrentAuthNamedClosedExternalEvidence? ExternalClosedEvidence = null);

public static partial class MigrationConsole
{
    // Dispatch belongs to root integration after this source slice is reviewed and validated.
    private static async Task<int> RunCurrentAuthRepairBoundaryAsync(string command, string configPath,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        try
        {
            CurrentAuthRepairCapacity.Require(admission: true);
            if (command is not ("review-current-auth-repair" or "authorize-current-auth-repair" or
                "verify-current-auth-repair" or "apply-current-auth-repair")) { throw CurrentAuthRepairPermit.Invalid(); }
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
            CurrentAuthRepairConfiguration config = await ReadProtectedJsonAsync<CurrentAuthRepairConfiguration>(configPath,
                "current_auth_config_unprotected", ct).ConfigureAwait(false);
            LocalExecutionBinding binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(config.RunBindingPath,
                "current_auth_binding_unprotected", ct).ConfigureAwait(false);
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            if (JsonSerializer.Serialize(Read<CurrentAuthRepairConfiguration>(configPath)) != JsonSerializer.Serialize(config) ||
                Read<LocalExecutionBinding>(config.RunBindingPath) != binding) { throw CurrentAuthRepairPermit.Invalid(); }
            FreshSchemaPlan source = Read<FreshSchemaPlan>(config.SourceSchemaPath);
            CurrentAuthRepairScope scope = Read<CurrentAuthRepairScope>(config.ScopePath);
            CurrentAuthRepairSigningPins pins = Read<CurrentAuthRepairSigningPins>(config.SigningPinsPath);
            CurrentAppOwnedRepairTargetPins target = Read<CurrentAppOwnedRepairTargetPins>(config.TargetPinsPath);
            string connection = Encoding.UTF8.GetString(files.Read(config.OperatorConnectionPath, maximumBytes: 65536)).Trim();
            string ordinary = Encoding.UTF8.GetString(files.Read(config.RejectedOrdinaryConnectionPath, maximumBytes: 65536)).Trim();
            if (source.SourceCommitSha != accepted || scope.SourceCommitSha != accepted) { throw CurrentAuthRepairPermit.Invalid(); }
            var keys = new List<TrustedAttestationKey>();
            foreach (DeltaTrustedKeyReference reference in config.TrustedKeys)
            { keys.Add(new(reference.KeyId, Convert.FromBase64String(Encoding.UTF8.GetString(files.Read(reference.SubjectPublicKeyInfoPath, maximumBytes: 65536)).Trim()))); }
            var trust = new ReceiptAttestationTrustStore(keys);
            CurrentAuthRepairSignedClaim? review = null, permission = null;
            string authorizationHash = new('0', 64);
            if (command != "review-current-auth-repair")
            {
                review = Read<CurrentAuthRepairSignedClaim>(config.ReviewPath);
                if (JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(scope)) { throw CurrentAuthRepairPermit.Invalid(); }
                CurrentAuthRepairPermit.ValidateReview(review, source, trust, pins, DateTimeOffset.UtcNow);
            }
            if (command is "verify-current-auth-repair" or "apply-current-auth-repair")
            {
                permission = Read<CurrentAuthRepairSignedClaim>(config.AuthorizationPath);
                CurrentAuthRepairPermit.ValidateClaims(review!, permission, source, trust, pins, DateTimeOffset.UtcNow);
                authorizationHash = CurrentAppOwnedSnapshotSerialization.Sha256(permission);
            }
            if (scope.ProofAdmission == CurrentAuthProofAdmission.DisposableNativeComponent || scope.ComponentSubject is not null) { throw CurrentAuthRepairPermit.Invalid(); }
            CurrentAuthRepairPermit.RequireProofAdmission(scope);
            bool persistent = scope.Target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg ||
                CurrentAppOwnedRepairLocalTarget.RequireClaim(scope.Target, scope.OperationId, scope.RunBindingSha256, target);
            if (persistent && scope.ProofAdmission != CurrentAuthProofAdmission.ClosedConsole) { throw CurrentAuthRepairPermit.Invalid(); }
            bool namedBootstrap = scope.ProofAdmission == CurrentAuthProofAdmission.DisposableClosedConsoleBootstrap;
            if (namedBootstrap)
            {
                var evidence = config.ClosedBootstrap ?? throw CurrentAuthRepairPermit.Invalid();
                if (persistent || config.ExternalClosedEvidence is not null || scope.ClosedBootstrapSubject is null || JsonSerializer.Serialize(scope.ClosedBootstrapSubject) != JsonSerializer.Serialize(evidence.Seed))
                { throw CurrentAuthRepairPermit.Invalid(); }
                await CurrentAuthClosedBootstrapReadback.RequireAsync(evidence, scope, source, ct).ConfigureAwait(false);
            }
            else if (config.ExternalClosedEvidence is not null)
            {
                if (scope.ProofAdmission != CurrentAuthProofAdmission.ClosedConsole || config.ClosedBootstrap is not null || scope.ClosedBootstrapSubject is not null)
                { throw CurrentAuthRepairPermit.Invalid(); }
                await CurrentAuthNamedClosedExternalReadback.RequireAsync(files, config.AuthHelperProof, scope.AuthHelperProofSha256, "helper", scope, pins, source, config.ExternalClosedEvidence, ct).ConfigureAwait(false);
                await CurrentAuthNamedClosedExternalReadback.RequireAsync(files, config.NativeProof, scope.NativeProofSha256, "native", scope, pins, source, config.ExternalClosedEvidence, ct).ConfigureAwait(false);
                await CurrentAuthNamedClosedExternalReadback.RequireAsync(files, config.RecoveryReview, scope.RecoveryReviewSha256, "recovery", scope, pins, source, config.ExternalClosedEvidence, ct).ConfigureAwait(false);
                await CurrentAuthNamedClosedExternalReadback.RequireAsync(files, config.ExactRoleTransitionReview, scope.ExactRoleTransitionReviewSha256, "maintenance", scope, pins, source, config.ExternalClosedEvidence, ct).ConfigureAwait(false);
            }
            else
            {
                if (config.ClosedBootstrap is not null || scope.ClosedBootstrapSubject is not null) { throw CurrentAuthRepairPermit.Invalid(); }
                await CurrentAuthRepairProofReader.RequireAsync(files, config.AuthHelperProof, scope.AuthHelperProofSha256, "helper", scope, trust, pins, source, ct).ConfigureAwait(false);
                await CurrentAuthRepairProofReader.RequireAsync(files, config.NativeProof, scope.NativeProofSha256, "native", scope, trust, pins, source, ct).ConfigureAwait(false);
                await CurrentAuthRepairProofReader.RequireAsync(files, config.RecoveryReview, scope.RecoveryReviewSha256, "recovery", scope, trust, pins, source, ct).ConfigureAwait(false);
                await CurrentAuthRepairProofReader.RequireAsync(files, config.ExactRoleTransitionReview, scope.ExactRoleTransitionReviewSha256, "maintenance", scope, trust, pins, source, ct).ConfigureAwait(false);
            }
            CurrentAuthRepairCapacity.Require(admission: true);
            CurrentAppOwnedDatabaseSnapshot[] baseline = await files.ReadBaselineAsync(config.GlobalBeforePath, ct).ConfigureAwait(false);
            CurrentAuthRepairCapacity.Require(admission: false);
            using var environment = new CurrentAuthRepairEnvironment(authority, files, target, connection, ordinary,
                baseline, source, scope, trust, pins, authorizationHash);
            ICurrentAuthRepairEnvironment executionEnvironment = namedBootstrap
                ? new CurrentAuthClosedProofEnvironment(environment, files, scope, binding.ArtifactRootCanonicalPath, connection)
                : environment;
            if (command == "review-current-auth-repair")
            {
                if (config.ReviewPrivateKeyPath is null || config.ReviewOutputPath is null || config.ReviewExpiresAtUtc is null)
                { throw CurrentAuthRepairPermit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.ReviewKeyId, Encoding.UTF8.GetString(files.Read(config.ReviewPrivateKeyPath, maximumBytes: 65536)));
                CurrentAuthRepairSignedClaim issued = await CurrentAuthRepairPermit.IssueReviewAsync(scope, source, baseline,
                    trust, pins, executionEnvironment, signer, config.ReviewExpiresAtUtc.Value, TimeProvider.System, ct).ConfigureAwait(false);
                await WriteClaimAsync(config.ReviewOutputPath, issued).ConfigureAwait(false);
                await output.WriteLineAsync("current_auth_review_complete_no_ddl").ConfigureAwait(false); return 0;
            }
            if (command == "authorize-current-auth-repair")
            {
                if (config.AuthorizationPrivateKeyPath is null || config.AuthorizationOutputPath is null) { throw CurrentAuthRepairPermit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.AuthorizationKeyId, Encoding.UTF8.GetString(files.Read(config.AuthorizationPrivateKeyPath, maximumBytes: 65536)));
                CurrentAuthRepairSignedClaim issued = await CurrentAuthRepairPermit.AuthorizeAsync(review!, source, trust,
                    pins, executionEnvironment, signer, TimeProvider.System, ct).ConfigureAwait(false);
                await WriteClaimAsync(config.AuthorizationOutputPath, issued).ConfigureAwait(false);
                await output.WriteLineAsync("current_auth_authorization_complete_no_ddl").ConfigureAwait(false); return 0;
            }
            CurrentAuthRepairPermit permit = await CurrentAuthRepairPermit.AdmitAsync(review!, permission!, source, trust,
                pins, executionEnvironment, TimeProvider.System, ct).ConfigureAwait(false);
            try
            {
                if (command == "verify-current-auth-repair")
                { await output.WriteLineAsync("current_auth_verify_complete_no_ddl").ConfigureAwait(false); return 0; }
                CurrentAuthNativeObservation preimage = await environment.GetAuthPreimageAsync(ct).ConfigureAwait(false);
                await using CurrentAuthClosedCommitProxy? commitProxy = namedBootstrap && scope.ClosedBootstrapSubject!.CaseId == "lost-commit-ack"
                    ? await CurrentAuthClosedCommitProxy.CreateAsync(permit, connection, files, binding.ArtifactRootCanonicalPath, ct).ConfigureAwait(false)
                    : null;
                if (commitProxy is not null) { ((CurrentAuthClosedProofEnvironment)executionEnvironment).AttachCommitProxy(commitProxy); }
                using var signer = new P256MigrationEvidenceSigner(pins.ReceiptKeyId, Encoding.UTF8.GetString(files.Read(config.ReceiptPrivateKeyPath, maximumBytes: 65536)));
                CurrentAuthRepairReceipt receipt = await PostgreSqlCurrentAuthRepair.ExecuteAsync(commitProxy?.ConnectionString ?? connection, preimage,
                    permit, signer, trust, pins, ct).ConfigureAwait(false);
                environment.RequireTerminal(receipt);
                await output.WriteLineAsync("current_auth_apply_complete_readback_verified_sessions_and_history_retained").ConfigureAwait(false);
                return 0;
            }
            finally { permit.Stop(); }

            T Read<T>(string path)
            {
                return DecodeAuthRepair<T>(files.Read(path, maximumBytes: 8 * 1024 * 1024));
            }

            async Task WriteClaimAsync(string path, CurrentAuthRepairSignedClaim claim)
            {
                if (Path.GetFileName(path).StartsWith(scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))
                { throw CurrentAuthRepairPermit.Invalid(); }
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(claim);
                await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
                if (!files.Read(path, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw CurrentAuthRepairPermit.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or JsonException or
            IOException or UnauthorizedAccessException or Npgsql.NpgsqlException or Exact25FullBackupException or
            System.Security.Cryptography.CryptographicException or FormatException or ArgumentException or InvalidOperationException)
        { await error.WriteLineAsync("current_auth_boundary_failed_no_success_claim").ConfigureAwait(false); return 1; }
    }

    internal static T DecodeAuthRepair<T>(byte[] bytes)
    {
        using JsonDocument document = JsonDocument.Parse(bytes);
        Distinct(document.RootElement);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions) ?? throw CurrentAuthRepairPermit.Invalid();
        static void Distinct(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (JsonProperty property in value.EnumerateObject())
                { if (!names.Add(property.Name)) { throw CurrentAuthRepairPermit.Invalid(); } Distinct(property.Value); }
            }
            else if (value.ValueKind == JsonValueKind.Array) { foreach (JsonElement child in value.EnumerateArray()) { Distinct(child); } }
        }
    }
}
