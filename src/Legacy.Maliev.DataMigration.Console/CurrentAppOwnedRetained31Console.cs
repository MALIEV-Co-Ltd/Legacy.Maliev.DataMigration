using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAppOwnedRetained31RepairConfiguration(string BeforeSchemaPath, string AfterSchemaPath,
    string ScopePath, string ReviewPath, string AuthorizationPath, string SigningPinsPath, string RunBindingPath,
    string OperatorConnectionPath, string RejectedOrdinaryConnectionPath, string GlobalBeforePath,
    string TargetPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string ReceiptPrivateKeyPath, CurrentAppOwnedRepairArtifact NativeProof,
    CurrentAppOwnedRepairArtifact RecoveryReview, CurrentAppOwnedRepairArtifact ExactRoleTransitionReview,
    string? ReviewPrivateKeyPath = null, string? ReviewOutputPath = null, DateTimeOffset? ReviewExpiresAtUtc = null,
    string? AuthorizationPrivateKeyPath = null, string? AuthorizationOutputPath = null);

public static partial class MigrationConsole
{
    // A distinct permission and command boundary for the fixed retained31 operation.
    private static async Task<int> RunCurrentAppOwnedRetained31RepairBoundaryAsync(string command, string configPath,
        TextWriter output, TextWriter error, CancellationToken cancellationToken)
    {
        try
        {
            if (command is not ("review-current-app-owned-retained31-repair" or "authorize-current-app-owned-retained31-repair" or
                "verify-current-app-owned-retained31-repair" or "apply-current-app-owned-retained31-repair"))
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(cancellationToken).ConfigureAwait(false);
            CurrentAppOwnedRetained31RepairConfiguration configuration = await ReadProtectedJsonAsync<CurrentAppOwnedRetained31RepairConfiguration>(
                configPath, "current_app_owned_retained31_config_unprotected", cancellationToken).ConfigureAwait(false);
            LocalExecutionBinding binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(configuration.RunBindingPath,
                "current_app_owned_retained31_binding_unprotected", cancellationToken).ConfigureAwait(false);
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            byte[] configBytes = files.Read(configPath);
            CurrentAppOwnedRetained31RepairConfiguration retained = DecodeRetained31<CurrentAppOwnedRetained31RepairConfiguration>(configBytes);
            if (JsonSerializer.Serialize(retained) != JsonSerializer.Serialize(configuration)) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            LocalExecutionBinding retainedBinding = Read<LocalExecutionBinding>(configuration.RunBindingPath);
            if (retainedBinding != binding) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            FreshSchemaPlan before = Read<FreshSchemaPlan>(configuration.BeforeSchemaPath);
            FreshSchemaPlan after = Read<FreshSchemaPlan>(configuration.AfterSchemaPath);
            CurrentAppOwnedRetained31Scope scope = Read<CurrentAppOwnedRetained31Scope>(configuration.ScopePath);
            CurrentAppOwnedRetained31SigningPins pins = Read<CurrentAppOwnedRetained31SigningPins>(configuration.SigningPinsPath);
            CurrentAppOwnedRepairTargetPins target = Read<CurrentAppOwnedRepairTargetPins>(configuration.TargetPinsPath);
            CurrentAppOwnedDatabaseSnapshot[] baseline = await files.ReadBaselineAsync(configuration.GlobalBeforePath,
                cancellationToken).ConfigureAwait(false);
            string connection = Encoding.UTF8.GetString(files.Read(configuration.OperatorConnectionPath)).Trim();
            string ordinary = Encoding.UTF8.GetString(files.Read(configuration.RejectedOrdinaryConnectionPath)).Trim();
            if (before.SourceCommitSha != accepted || after.SourceCommitSha != accepted || scope.SourceCommitSha != accepted)
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            RequireArtifact(configuration.NativeProof, scope.NativeProofSha256);
            RequireArtifact(configuration.RecoveryReview, scope.RecoveryReviewSha256);
            RequireArtifact(configuration.ExactRoleTransitionReview, scope.ExactRoleTransitionReviewSha256);
            var keys = new List<TrustedAttestationKey>();
            foreach (DeltaTrustedKeyReference reference in configuration.TrustedKeys)
            { keys.Add(new(reference.KeyId, Convert.FromBase64String(Encoding.UTF8.GetString(files.Read(reference.SubjectPublicKeyInfoPath)).Trim()))); }
            var trust = new ReceiptAttestationTrustStore(keys);
            CurrentAppOwnedRetained31SignedClaim? review = null;
            if (command != "review-current-app-owned-retained31-repair")
            {
                review = Read<CurrentAppOwnedRetained31SignedClaim>(configuration.ReviewPath);
                if (JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(scope))
                { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                CurrentAppOwnedRetained31Permit.ValidateReview(review, before, after, trust, pins, DateTimeOffset.UtcNow);
            }
            CurrentAppOwnedRetained31SignedClaim? permission = null;
            string authorizationSha256 = new('0', 64);
            if (command is "verify-current-app-owned-retained31-repair" or "apply-current-app-owned-retained31-repair")
            {
                permission = Read<CurrentAppOwnedRetained31SignedClaim>(configuration.AuthorizationPath);
                CurrentAppOwnedRetained31Permit.ValidateClaims(review!, permission, before, after, trust, pins, DateTimeOffset.UtcNow);
                authorizationSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(permission);
            }
            using var environment = new CurrentAppOwnedRetained31ConsoleEnvironment(authority, files, target,
                connection, ordinary, baseline, before, after, scope, trust, pins, authorizationSha256);
            if (command == "review-current-app-owned-retained31-repair")
            {
                if (configuration.ReviewPrivateKeyPath is null || configuration.ReviewOutputPath is null || configuration.ReviewExpiresAtUtc is null)
                { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.ReviewKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.ReviewPrivateKeyPath)));
                CurrentAppOwnedRetained31SignedClaim issued = await CurrentAppOwnedRetained31Permit.IssueReviewAsync(scope,
                    before, after, baseline, trust, pins, environment, signer, configuration.ReviewExpiresAtUtc.Value,
                    TimeProvider.System, cancellationToken).ConfigureAwait(false);
                await WriteClaimAsync(configuration.ReviewOutputPath, issued).ConfigureAwait(false);
                await output.WriteLineAsync("current_app_owned_retained31_review_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            if (command == "authorize-current-app-owned-retained31-repair")
            {
                if (configuration.AuthorizationPrivateKeyPath is null || configuration.AuthorizationOutputPath is null)
                { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.AuthorizationKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.AuthorizationPrivateKeyPath)));
                CurrentAppOwnedRetained31SignedClaim authorization = await CurrentAppOwnedRetained31Permit.AuthorizeAsync(review!,
                    before, after, trust, pins, environment, signer, TimeProvider.System, cancellationToken).ConfigureAwait(false);
                await WriteClaimAsync(configuration.AuthorizationOutputPath, authorization).ConfigureAwait(false);
                await output.WriteLineAsync("current_app_owned_retained31_authorization_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            CurrentAppOwnedRetained31Permit permit = await CurrentAppOwnedRetained31Permit.AdmitAsync(review!, permission!, before,
                after, trust, pins, environment, TimeProvider.System, cancellationToken).ConfigureAwait(false);
            if (await environment.InspectGlobalPreservationAsync(cancellationToken).ConfigureAwait(false) != scope.GlobalPreservationSha256)
            { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            if (command == "verify-current-app-owned-retained31-repair")
            {
                await output.WriteLineAsync("current_app_owned_retained31_verify_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            using var receiptSigner = new P256MigrationEvidenceSigner(pins.ReceiptKeyId,
                Encoding.UTF8.GetString(files.Read(configuration.ReceiptPrivateKeyPath)));
            try
            {
                await permit.BeginExecutionAsync(cancellationToken).ConfigureAwait(false);
                string previous = new('0', 64);
                foreach (string database in CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.RetainedThirtyOneTextCollations))
                {
                    CurrentAppOwnedDatabaseSnapshot expected = baseline.Single(x => x.Database == database);
                    CurrentAppOwnedRetained31Receipt receipt = await PostgreSqlCurrentAppOwnedRetained31Repair.ExecuteDatabaseAsync(
                        connection, database, before, after, expected, permit, receiptSigner, trust, pins, previous,
                        cancellationToken).ConfigureAwait(false);
                    previous = CurrentAppOwnedSnapshotSerialization.Sha256(receipt);
                }
                await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
                if (await environment.InspectGlobalPreservationAsync(cancellationToken).ConfigureAwait(false) != scope.GlobalPreservationSha256)
                { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                await output.WriteLineAsync("current_app_owned_retained31_apply_complete_readback_verified_no_row_refresh").ConfigureAwait(false);
                return 0;
            }
            finally { permit.Stop(); }

            T Read<T>(string path)
            {
                return DecodeRetained31<T>(files.Read(path));
            }

            async Task WriteClaimAsync(string path, CurrentAppOwnedRetained31SignedClaim claim)
            {
                if (Path.GetFileName(path).StartsWith(scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))
                { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(claim);
                await files.WriteNewAsync(path, bytes, cancellationToken).ConfigureAwait(false);
                if (!files.Read(path).AsSpan().SequenceEqual(bytes)) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            }

            void RequireArtifact(CurrentAppOwnedRepairArtifact artifact, string expected)
            {
                if (artifact.Sha256 != expected || CurrentAppOwnedRepairPermit.Hash(files.Read(artifact.Path)) != expected)
                { throw CurrentAppOwnedRetained31Permit.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or
            JsonException or IOException or UnauthorizedAccessException or Npgsql.NpgsqlException or
            Exact25FullBackupException or System.Security.Cryptography.CryptographicException or FormatException or ArgumentException)
        {
            await error.WriteLineAsync("current_app_owned_retained31_boundary_failed_no_success_claim").ConfigureAwait(false);
            return 1;
        }
    }

    internal static T DecodeRetained31<T>(byte[] bytes)
    {
        using JsonDocument document = JsonDocument.Parse(bytes);
        RequireDistinctProperties(document.RootElement);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions) ?? throw CurrentAppOwnedRetained31Permit.Invalid();

        static void RequireDistinctProperties(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (JsonProperty property in value.EnumerateObject())
                {
                    if (!names.Add(property.Name)) { throw CurrentAppOwnedRetained31Permit.Invalid(); }
                    RequireDistinctProperties(property.Value);
                }
            }
            else if (value.ValueKind == JsonValueKind.Array)
            { foreach (JsonElement child in value.EnumerateArray()) { RequireDistinctProperties(child); } }
        }
    }
}
