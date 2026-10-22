using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentOwnerIsoRepairConfiguration(string SourceSchemaPath, CurrentOwnerIsoRepairSourceInputs SourceInputs,
    string OwnersPath, string ScopePath, string ReviewPath, string AuthorizationPath, string SigningPinsPath, string RunBindingPath,
    string OperatorConnectionPath, string RejectedOrdinaryConnectionPath, string GlobalBeforePath,
    string TargetPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string ReceiptPrivateKeyPath, CurrentAppOwnedRepairArtifact NativeProof,
    CurrentAppOwnedRepairArtifact? RecoveryReview, CurrentAppOwnedRepairArtifact? ExactRoleTransitionReview,
    CurrentAppOwnedRepairArtifact MaintenanceProof, string MaintenanceValidatorSourcePath,
    string? ReviewPrivateKeyPath = null, string? ReviewOutputPath = null, DateTimeOffset? ReviewExpiresAtUtc = null,
    string? AuthorizationPrivateKeyPath = null, string? AuthorizationOutputPath = null,
    CurrentOwnerIsoProofAdmission ProofAdmission = CurrentOwnerIsoProofAdmission.PersistentWithClosedConsoleProof,
    IsoClosedBootstrapInputs? ClosedBootstrap = null, IsoExternalClosedEvidence? ExternalClosed = null);

public static partial class MigrationConsole
{
    // These distinct routes still require exact-head review and validation before operational acceptance.
    private static async Task<int> RunCurrentOwnerIsoRepairBoundaryAsync(string command, string configPath,
        TextWriter output, TextWriter error, CancellationToken cancellationToken)
    {
        CurrentOwnerIsoRepairScope? observedClosedScope = null; LocalExecutionBinding? observedClosedBinding = null;
        try
        {
            CurrentOwnerIsoCapacity.Require(admission: true);
            if (command is not ("review-current-owner-iso-repair" or "authorize-current-owner-iso-repair" or
                "verify-current-owner-iso-repair" or "apply-current-owner-iso-repair"))
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(cancellationToken).ConfigureAwait(false);
            CurrentOwnerIsoRepairConfiguration configuration = await ReadProtectedJsonAsync<CurrentOwnerIsoRepairConfiguration>(
                configPath, "current_owner_iso_config_unprotected", cancellationToken).ConfigureAwait(false);
            LocalExecutionBinding binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(configuration.RunBindingPath,
                "current_owner_iso_binding_unprotected", cancellationToken).ConfigureAwait(false);
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            CurrentOwnerIsoRepairConfiguration retained = ReadOwnerIso<CurrentOwnerIsoRepairConfiguration>(configPath);
            if (JsonSerializer.Serialize(retained) != JsonSerializer.Serialize(configuration) ||
                ReadOwnerIso<LocalExecutionBinding>(configuration.RunBindingPath) != binding)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            FreshSchemaPlan source = ReadOwnerIso<FreshSchemaPlan>(configuration.SourceSchemaPath);
            CurrentOwnerIsoSourceObservation[] owners = ReadOwnerIso<CurrentOwnerIsoSourceObservation[]>(configuration.OwnersPath);
            CurrentOwnerIsoRepairScope scope = ReadOwnerIso<CurrentOwnerIsoRepairScope>(configuration.ScopePath);
            CurrentOwnerIsoRepairSigningPins pins = ReadOwnerIso<CurrentOwnerIsoRepairSigningPins>(configuration.SigningPinsPath);
            CurrentAppOwnedRepairTargetPins target = ReadOwnerIso<CurrentAppOwnedRepairTargetPins>(configuration.TargetPinsPath);
            CurrentAppOwnedDatabaseSnapshot[] baseline = await files.ReadBaselineAsync(configuration.GlobalBeforePath,
                cancellationToken).ConfigureAwait(false);
            string connection = Encoding.UTF8.GetString(files.Read(configuration.OperatorConnectionPath)).Trim();
            string ordinary = Encoding.UTF8.GetString(files.Read(configuration.RejectedOrdinaryConnectionPath)).Trim();
            if (source.SourceCommitSha != accepted || scope.SourceCommitSha != accepted)
            { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            if (configuration.ProofAdmission != scope.ProofAdmission) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            if (scope.ProofAdmission != CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap)
            {
                RequireArtifact(configuration.NativeProof, scope.NativeProofSha256);
                RequireArtifact(configuration.MaintenanceProof, scope.MaintenanceProofSha256);
            }
            else if (configuration.NativeProof.Path != configuration.ClosedBootstrap?.NativeComponentPath || configuration.MaintenanceProof.Path != configuration.ClosedBootstrap?.MaintenanceComponentPath ||
                configuration.NativeProof.Sha256 != scope.NativeProofSha256 || configuration.MaintenanceProof.Sha256 != scope.MaintenanceProofSha256) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            RequireCanonicalHelper(files.Read(configuration.MaintenanceValidatorSourcePath), scope.MaintenanceValidatorSha256);
            if (scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap)
            {
                if (configuration.RecoveryReview is not null || configuration.ExactRoleTransitionReview is not null || configuration.ClosedBootstrap is null || target.CloudOptions is not null || target.CloudObservation is not null) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
            else
            {
                if (configuration.ClosedBootstrap is not null) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                RequireArtifact(configuration.RecoveryReview ?? throw CurrentOwnerIsoRepairPermit.Invalid(), scope.RecoveryReviewSha256);
                RequireArtifact(configuration.ExactRoleTransitionReview ?? throw CurrentOwnerIsoRepairPermit.Invalid(), scope.ExactRoleTransitionReviewSha256);
            }
            var keys = new List<TrustedAttestationKey>();
            foreach (DeltaTrustedKeyReference reference in configuration.TrustedKeys)
            { keys.Add(new(reference.KeyId, Convert.FromBase64String(Encoding.UTF8.GetString(files.Read(reference.SubjectPublicKeyInfoPath, sharedReader: true)).Trim()))); }
            var trust = new ReceiptAttestationTrustStore(keys);
            if (scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableNativeComponent) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            if (scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap)
            {
                CurrentOwnerIsoRepairPermit.ValidateClosedBootstrapScope(scope, source, owners, trust, pins, DateTimeOffset.UtcNow);
                await IsoClosedBootstrapReadback.RequireAsync(files, binding, scope, configuration.ClosedBootstrap!, cancellationToken).ConfigureAwait(false);
                observedClosedScope = scope; observedClosedBinding = binding;
            }
            CurrentOwnerIsoRepairSignedClaim? review = null;
            CurrentOwnerIsoRepairSignedClaim? permission = null;
            string authorizationSha256 = new('0', 64);
            if (command != "review-current-owner-iso-repair")
            {
                review = ReadOwnerIso<CurrentOwnerIsoRepairSignedClaim>(configuration.ReviewPath);
                if (JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(scope))
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                CurrentOwnerIsoRepairPermit.ValidateReview(review, source, owners, trust, pins, DateTimeOffset.UtcNow);
            }
            if (command is "verify-current-owner-iso-repair" or "apply-current-owner-iso-repair")
            {
                permission = ReadOwnerIso<CurrentOwnerIsoRepairSignedClaim>(configuration.AuthorizationPath);
                CurrentOwnerIsoRepairPermit.ValidateClaims(review!, permission, source, owners, trust, pins, DateTimeOffset.UtcNow);
                authorizationSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(permission);
            }
            if (configuration.ExternalClosed is not null)
            {
                if (scope.ProofAdmission != CurrentOwnerIsoProofAdmission.PersistentWithClosedConsoleProof || scope.BootstrapSubject is not null || target.CloudOptions is not null || target.CloudObservation is not null) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                await IsoExternalClosedReader.RequireAllAsync(files, binding, scope, pins, source, owners, configuration.NativeProof, configuration.MaintenanceProof, configuration.ExternalClosed, cancellationToken).ConfigureAwait(false);
            }
            using var actualEnvironment = new CurrentOwnerIsoRepairConsoleEnvironment(authority, files, target,
                connection, ordinary, baseline, source, owners, scope, trust, pins, authorizationSha256, configuration.SourceInputs, configuration.NativeProof, configuration.MaintenanceProof, configuration.ClosedBootstrap, configuration.ExternalClosed);
            CurrentOwnerIsoNamedClosedProofEnvironment? closedEnvironment = scope.ProofAdmission == CurrentOwnerIsoProofAdmission.DisposableClosedConsoleBootstrap
                ? new(actualEnvironment, files, scope, source, owners, baseline, connection, binding) : null;
            ICurrentOwnerIsoRepairEnvironment environment = closedEnvironment is null ? actualEnvironment : closedEnvironment;
            if (command == "review-current-owner-iso-repair")
            {
                if (configuration.ReviewPrivateKeyPath is null || configuration.ReviewOutputPath is null || configuration.ReviewExpiresAtUtc is null)
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.ReviewKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.ReviewPrivateKeyPath)));
                CurrentOwnerIsoRepairSignedClaim issued = await CurrentOwnerIsoRepairPermit.IssueReviewAsync(scope,
                    source, owners, baseline, trust, pins, environment, signer, configuration.ReviewExpiresAtUtc.Value,
                    TimeProvider.System, cancellationToken).ConfigureAwait(false);
                await WriteClaimAsync(configuration.ReviewOutputPath, issued).ConfigureAwait(false);
                await output.WriteLineAsync("current_owner_iso_review_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            if (command == "authorize-current-owner-iso-repair")
            {
                if (configuration.AuthorizationPrivateKeyPath is null || configuration.AuthorizationOutputPath is null)
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.AuthorizationKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.AuthorizationPrivateKeyPath)));
                CurrentOwnerIsoRepairSignedClaim authorization = await CurrentOwnerIsoRepairPermit.AuthorizeAsync(review!,
                    source, owners, trust, pins, environment, signer, TimeProvider.System, cancellationToken).ConfigureAwait(false);
                await WriteClaimAsync(configuration.AuthorizationOutputPath, authorization).ConfigureAwait(false);
                await output.WriteLineAsync("current_owner_iso_authorization_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            CurrentOwnerIsoRepairPermit permit = await CurrentOwnerIsoRepairPermit.AdmitAsync(review!, permission!, source, owners, trust, pins, environment, TimeProvider.System, cancellationToken).ConfigureAwait(false);
            try
            {
                if (command == "verify-current-owner-iso-repair")
                {
                    await output.WriteLineAsync("current_owner_iso_verify_complete_no_ddl").ConfigureAwait(false);
                    return 0;
                }
                using var signer = new P256MigrationEvidenceSigner(pins.ReceiptKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.ReceiptPrivateKeyPath)));
                await using CurrentOwnerIsoNamedClosedCommitProxy? proxy = closedEnvironment is not null && scope.BootstrapSubject!.CaseId == "lost-commit-ack"
                    ? await CurrentOwnerIsoNamedClosedCommitProxy.CreateAsync(permit, connection, files, binding.ArtifactRootCanonicalPath, cancellationToken).ConfigureAwait(false) : null;
                if (proxy is not null) { closedEnvironment!.Attach(proxy); }
                IReadOnlyList<CurrentOwnerIsoRepairReceipt> receipts = await PostgreSqlCurrentOwnerIsoRepair.ExecuteFleetAsync(
                    proxy?.ConnectionString ?? connection, source, owners, baseline, permit, signer, trust, pins, cancellationToken).ConfigureAwait(false);
                if (!receipts.Select(x => x.Database).SequenceEqual(PostgreSqlCurrentOwnerIsoRepair.Databases(), StringComparer.Ordinal) ||
                    receipts.Any(x => x.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback))
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                await output.WriteLineAsync("current_owner_iso_apply_complete_readback_verified_no_row_refresh").ConfigureAwait(false);
                return 0;
            }
            finally { permit.Stop(); }

            T ReadOwnerIso<T>(string path)
            {
                return DecodeOwnerIso<T>(files.Read(path, sharedReader: true));
            }

            void RequireArtifact(CurrentAppOwnedRepairArtifact artifact, string expected)
            {
                if (artifact.Sha256 != expected || CurrentAppOwnedRepairPermit.Hash(files.Read(artifact.Path)) != expected)
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
            async Task WriteClaimAsync(string path, CurrentOwnerIsoRepairSignedClaim claim)
            {
                if (Path.GetFileName(path).StartsWith(scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))
                { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(claim);
                await files.WriteNewAsync(path, bytes, cancellationToken).ConfigureAwait(false);
                if (!files.Read(path, sharedReader: true).AsSpan().SequenceEqual(bytes)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or
            JsonException or System.Xml.XmlException or IOException or UnauthorizedAccessException or Npgsql.NpgsqlException or HttpRequestException or
            InvalidOperationException or KeyNotFoundException or
            Exact25FullBackupException or System.Security.Cryptography.CryptographicException or FormatException or ArgumentException)
        {
            if (observedClosedScope is not null && observedClosedBinding is not null)
            {
                using var failedAuthority = WindowsLocalRunAuthority.AcquireResume(observedClosedBinding.ArtifactRootCanonicalPath, observedClosedBinding);
                using var failedFiles = new CurrentAppOwnedRepairCustody(failedAuthority);
                await failedFiles.WriteNewAsync(Path.Combine(observedClosedBinding.ArtifactRootCanonicalPath, $"iso-closed-boundary-{observedClosedScope.OperationId:N}-{Guid.NewGuid():N}.json"),
                    JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        observedClosedScope.OperationId,
                        command,
                        scopeSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(observedClosedScope),
                        exceptionType = failure.GetType().FullName,
                        rejectionCode = failure is MigrationExecutionException migration ? migration.Code : null,
                        observedAtUtc = DateTimeOffset.UtcNow
                    }), CancellationToken.None).ConfigureAwait(false);
            }
            await error.WriteLineAsync("current_owner_iso_boundary_failed_no_success_claim").ConfigureAwait(false);
            return 1;
        }
    }

    internal static void RequireCanonicalHelper(byte[] bytes, string expected)
    {
        // Strict UTF-8 and CRLF-to-LF only: preserve BOM and every other byte-significant character.
        string observed = CanonicalOwnerIsoHelperSha256(bytes);
        if (expected != CurrentOwnerIsoRepairPermit.MaintenanceValidator ||
            observed != expected)
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
    internal static string CanonicalOwnerIsoHelperSha256(byte[] bytes)
    {
        var utf8 = new UTF8Encoding(false, true);
        return CurrentAppOwnedRepairPermit.Hash(utf8.GetBytes(utf8.GetString(bytes).Replace("\r\n", "\n", StringComparison.Ordinal)));
    }
    internal static T DecodeOwnerIso<T>(byte[] bytes)
    {
        using JsonDocument document = JsonDocument.Parse(bytes);
        RequireDistinctProperties(document.RootElement);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions) ?? throw CurrentOwnerIsoRepairPermit.Invalid();

        static void RequireDistinctProperties(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (JsonProperty property in value.EnumerateObject())
                {
                    if (!names.Add(property.Name)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                    RequireDistinctProperties(property.Value);
                }
            }
            else if (value.ValueKind == JsonValueKind.Array)
            { foreach (JsonElement child in value.EnumerateArray()) { RequireDistinctProperties(child); } }
        }
    }
}
