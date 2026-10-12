using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAppOwnedV3RepairConfiguration(string BeforeSchemaPath, string AfterSchemaPath,
    string ScopePath, string ReviewPath, string AuthorizationPath, string SigningPinsPath, string RunBindingPath,
    string OperatorConnectionPath, string RejectedOrdinaryConnectionPath, string GlobalBeforePath,
    string TargetPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string ReceiptPrivateKeyPath, CurrentAppOwnedRepairArtifact NativeProof,
    CurrentAppOwnedRepairArtifact RecoveryReview, CurrentAppOwnedRepairArtifact ExactRoleTransitionReview,
    string? ReviewPrivateKeyPath = null, string? ReviewOutputPath = null, DateTimeOffset? ReviewExpiresAtUtc = null,
    string? AuthorizationPrivateKeyPath = null, string? AuthorizationOutputPath = null);

public static partial class MigrationConsole
{
    private static readonly string[] V3RepairDatabases = ["Invoice", "PurchaseOrder", "Quotation"];
    // Routing is integrated separately after exact-head review and validation.
    private static async Task<int> RunCurrentAppOwnedV3RepairBoundaryAsync(string command, string configPath,
        TextWriter output, TextWriter error, CancellationToken cancellationToken)
    {
        try
        {
            if (command is not ("review-current-app-owned-v3-repair" or "authorize-current-app-owned-v3-repair" or
                "verify-current-app-owned-v3-repair" or "apply-current-app-owned-v3-repair"))
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(cancellationToken).ConfigureAwait(false);
            CurrentAppOwnedV3RepairConfiguration configuration = await ReadProtectedJsonAsync<CurrentAppOwnedV3RepairConfiguration>(
                configPath, "current_app_owned_v3_config_unprotected", cancellationToken).ConfigureAwait(false);
            LocalExecutionBinding binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(configuration.RunBindingPath,
                "current_app_owned_v3_binding_unprotected", cancellationToken).ConfigureAwait(false);
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            CurrentAppOwnedV3RepairConfiguration retained = ReadV3<CurrentAppOwnedV3RepairConfiguration>(configPath);
            if (JsonSerializer.Serialize(retained) != JsonSerializer.Serialize(configuration) ||
                ReadV3<LocalExecutionBinding>(configuration.RunBindingPath) != binding)
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            FreshSchemaPlan before = ReadV3<FreshSchemaPlan>(configuration.BeforeSchemaPath);
            FreshSchemaPlan after = ReadV3<FreshSchemaPlan>(configuration.AfterSchemaPath);
            CurrentAppOwnedV3RepairScope scope = ReadV3<CurrentAppOwnedV3RepairScope>(configuration.ScopePath);
            CurrentAppOwnedRepairSigningPins pins = ReadV3<CurrentAppOwnedRepairSigningPins>(configuration.SigningPinsPath);
            CurrentAppOwnedRepairTargetPins target = ReadV3<CurrentAppOwnedRepairTargetPins>(configuration.TargetPinsPath);
            CurrentAppOwnedDatabaseSnapshot[] baseline = await files.ReadBaselineAsync(configuration.GlobalBeforePath,
                cancellationToken).ConfigureAwait(false);
            string connection = Encoding.UTF8.GetString(files.Read(configuration.OperatorConnectionPath)).Trim();
            string ordinary = Encoding.UTF8.GetString(files.Read(configuration.RejectedOrdinaryConnectionPath)).Trim();
            if (before.SourceCommitSha != accepted || after.SourceCommitSha != accepted || scope.SourceCommitSha != accepted)
            { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            RequireArtifact(configuration.NativeProof, scope.NativeProofSha256);
            RequireArtifact(configuration.RecoveryReview, scope.RecoveryReviewSha256);
            RequireArtifact(configuration.ExactRoleTransitionReview, scope.ExactRoleTransitionReviewSha256);
            var keys = new List<TrustedAttestationKey>();
            foreach (DeltaTrustedKeyReference reference in configuration.TrustedKeys)
            { keys.Add(new(reference.KeyId, Convert.FromBase64String(Encoding.UTF8.GetString(files.Read(reference.SubjectPublicKeyInfoPath)).Trim()))); }
            var trust = new ReceiptAttestationTrustStore(keys);
            CurrentAppOwnedV3RepairSignedClaim? review = null;
            CurrentAppOwnedV3RepairSignedClaim? permission = null;
            string authorizationSha256 = new('0', 64);
            if (command != "review-current-app-owned-v3-repair")
            {
                review = ReadV3<CurrentAppOwnedV3RepairSignedClaim>(configuration.ReviewPath);
                if (JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(scope))
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
                CurrentAppOwnedV3RepairPermit.ValidateReview(review, before, after, trust, pins, DateTimeOffset.UtcNow);
            }
            if (command is "verify-current-app-owned-v3-repair" or "apply-current-app-owned-v3-repair")
            {
                permission = ReadV3<CurrentAppOwnedV3RepairSignedClaim>(configuration.AuthorizationPath);
                CurrentAppOwnedV3RepairPermit.ValidateClaims(review!, permission, trust, pins, DateTimeOffset.UtcNow);
                authorizationSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(permission);
            }
            using var environment = new CurrentAppOwnedV3RepairConsoleEnvironment(authority, files, target,
                connection, ordinary, baseline, before, after, scope, trust, pins, authorizationSha256);
            if (command == "review-current-app-owned-v3-repair")
            {
                if (configuration.ReviewPrivateKeyPath is null || configuration.ReviewOutputPath is null || configuration.ReviewExpiresAtUtc is null)
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.ReviewKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.ReviewPrivateKeyPath)));
                CurrentAppOwnedV3RepairSignedClaim issued = await CurrentAppOwnedV3RepairPermit.IssueReviewAsync(scope,
                    before, after, baseline, trust, pins, environment, signer, configuration.ReviewExpiresAtUtc.Value,
                    TimeProvider.System, cancellationToken).ConfigureAwait(false);
                await WriteClaimAsync(configuration.ReviewOutputPath, issued).ConfigureAwait(false);
                await output.WriteLineAsync("current_app_owned_v3_review_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            if (command == "authorize-current-app-owned-v3-repair")
            {
                if (configuration.AuthorizationPrivateKeyPath is null || configuration.AuthorizationOutputPath is null)
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.AuthorizationKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.AuthorizationPrivateKeyPath)));
                CurrentAppOwnedV3RepairSignedClaim authorization = await CurrentAppOwnedV3RepairPermit.AuthorizeAsync(review!,
                    before, after, trust, pins, environment, signer, TimeProvider.System, cancellationToken).ConfigureAwait(false);
                await WriteClaimAsync(configuration.AuthorizationOutputPath, authorization).ConfigureAwait(false);
                await output.WriteLineAsync("current_app_owned_v3_authorization_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            CurrentAppOwnedV3RepairPermit permit = await CurrentAppOwnedV3RepairPermit.AdmitAsync(review!, permission!, before,
                after, trust, pins, environment, TimeProvider.System, cancellationToken).ConfigureAwait(false);
            try
            {
                if (command == "verify-current-app-owned-v3-repair")
                {
                    await output.WriteLineAsync("current_app_owned_v3_verify_complete_no_ddl").ConfigureAwait(false);
                    return 0;
                }
                IReadOnlyList<V3AdditiveObservation> preimages = await environment.GetRepairPreimagesAsync(cancellationToken).ConfigureAwait(false);
                using var signer = new P256MigrationEvidenceSigner(pins.ReceiptKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.ReceiptPrivateKeyPath)));
                IReadOnlyList<CurrentAppOwnedV3RepairReceipt> receipts = await PostgreSqlCurrentAppOwnedV3Repair.ExecuteFleetAsync(
                    connection, before, after, preimages, permit, signer, trust, pins, cancellationToken).ConfigureAwait(false);
                if (receipts.Count != 3 || !receipts.Select(x => x.Database).SequenceEqual(V3RepairDatabases) ||
                    receipts.Any(x => x.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback))
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
                await output.WriteLineAsync("current_app_owned_v3_apply_complete_readback_verified_no_row_refresh").ConfigureAwait(false);
                return 0;
            }
            finally { permit.Stop(); }

            T ReadV3<T>(string path)
            {
                return DecodeV3<T>(files.Read(path));
            }

            void RequireArtifact(CurrentAppOwnedRepairArtifact artifact, string expected)
            {
                if (artifact.Sha256 != expected || CurrentAppOwnedRepairPermit.Hash(files.Read(artifact.Path)) != expected)
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            }
            async Task WriteClaimAsync(string path, CurrentAppOwnedV3RepairSignedClaim claim)
            {
                if (Path.GetFileName(path).StartsWith(scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))
                { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(claim);
                await files.WriteNewAsync(path, bytes, cancellationToken).ConfigureAwait(false);
                if (!files.Read(path).AsSpan().SequenceEqual(bytes)) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or
            JsonException or IOException or UnauthorizedAccessException or Npgsql.NpgsqlException or
            Exact25FullBackupException or System.Security.Cryptography.CryptographicException or FormatException or ArgumentException)
        {
            await error.WriteLineAsync("current_app_owned_v3_boundary_failed_no_success_claim").ConfigureAwait(false);
            return 1;
        }
    }

    internal static T DecodeV3<T>(byte[] bytes)
    {
        using JsonDocument document = JsonDocument.Parse(bytes);
        RequireDistinctProperties(document.RootElement);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions) ?? throw CurrentAppOwnedV3RepairPermit.Invalid();

        static void RequireDistinctProperties(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (JsonProperty property in value.EnumerateObject())
                {
                    if (!names.Add(property.Name)) { throw CurrentAppOwnedV3RepairPermit.Invalid(); }
                    RequireDistinctProperties(property.Value);
                }
            }
            else if (value.ValueKind == JsonValueKind.Array)
            { foreach (JsonElement child in value.EnumerateArray()) { RequireDistinctProperties(child); } }
        }
    }
}
