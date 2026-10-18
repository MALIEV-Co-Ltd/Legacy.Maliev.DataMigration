using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentCustomerSequenceRepairConfiguration(string SourceSchemaPath, CurrentCustomerSequenceRepairSourceInputs SourceInputs,
    string ScopePath, string ReviewPath, string AuthorizationPath, string SigningPinsPath, string RunBindingPath,
    string OperatorConnectionPath, string RejectedOrdinaryConnectionPath, string GlobalBeforePath,
    string TargetPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    string ReceiptPrivateKeyPath, CurrentAppOwnedRepairArtifact NativeProof,
    CurrentAppOwnedRepairArtifact RecoveryReview, CurrentAppOwnedRepairArtifact ExactRoleTransitionReview,
    string? ReviewPrivateKeyPath = null, string? ReviewOutputPath = null, DateTimeOffset? ReviewExpiresAtUtc = null,
    string? AuthorizationPrivateKeyPath = null, string? AuthorizationOutputPath = null,
    CurrentCustomerSequenceProofAdmission ProofAdmission = CurrentCustomerSequenceProofAdmission.PersistentWithClosedConsoleProof,
    CurrentAppOwnedRepairArtifact? DefinitionProof = null, CurrentAppOwnedRepairArtifact? MaintenanceProof = null,
    string? MaintenanceValidatorSourcePath = null, CustomerClosedSeedEvidence? ClosedSeedEvidence = null, CustomerClosedEightEvidence? ClosedEight = null);

public static partial class MigrationConsole
{
    // These distinct routes still require exact-head review and validation before operational acceptance.
    private static async Task<int> RunCurrentCustomerSequenceRepairBoundaryAsync(string command, string configPath,
        TextWriter output, TextWriter error, CancellationToken cancellationToken)
    {
        try
        {
            CurrentCustomerSequenceCapacity.Require(admission: true);
            if (command is not ("review-current-customer-sequence-repair" or "authorize-current-customer-sequence-repair" or
                "verify-current-customer-sequence-repair" or "apply-current-customer-sequence-repair"))
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(cancellationToken).ConfigureAwait(false);
            CurrentCustomerSequenceRepairConfiguration configuration = await ReadProtectedJsonAsync<CurrentCustomerSequenceRepairConfiguration>(
                configPath, "current_customer_sequence_config_unprotected", cancellationToken).ConfigureAwait(false);
            LocalExecutionBinding binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(configuration.RunBindingPath,
                "current_customer_sequence_binding_unprotected", cancellationToken).ConfigureAwait(false);
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            CurrentCustomerSequenceRepairConfiguration retained = ReadCustomerSequence<CurrentCustomerSequenceRepairConfiguration>(configPath);
            if (JsonSerializer.Serialize(retained) != JsonSerializer.Serialize(configuration) ||
                ReadCustomerSequence<LocalExecutionBinding>(configuration.RunBindingPath) != binding)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            FreshSchemaPlan source = ReadCustomerSequence<FreshSchemaPlan>(configuration.SourceSchemaPath);
            CurrentCustomerSequenceRepairScope scope = ReadCustomerSequence<CurrentCustomerSequenceRepairScope>(configuration.ScopePath);
            CurrentCustomerSequenceRepairSigningPins pins = ReadCustomerSequence<CurrentCustomerSequenceRepairSigningPins>(configuration.SigningPinsPath);
            CurrentAppOwnedRepairTargetPins target = ReadCustomerSequence<CurrentAppOwnedRepairTargetPins>(configuration.TargetPinsPath);
            CurrentCustomerSequenceCapacity.Require(admission: false);
            CurrentAppOwnedDatabaseSnapshot[] baseline = await files.ReadBaselineAsync(configuration.GlobalBeforePath,
                cancellationToken).ConfigureAwait(false);
            CurrentCustomerSequenceCapacity.Require(admission: false);
            string connection = Encoding.UTF8.GetString(files.Read(configuration.OperatorConnectionPath)).Trim();
            string ordinary = Encoding.UTF8.GetString(files.Read(configuration.RejectedOrdinaryConnectionPath)).Trim();
            if (source.SourceCommitSha != accepted || scope.SourceCommitSha != accepted)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            CurrentCustomerSequenceRepairPermit.RequireProofAdmission(scope);
            if (configuration.ProofAdmission != scope.ProofAdmission || configuration.DefinitionProof is null ||
                configuration.MaintenanceProof is null || configuration.MaintenanceValidatorSourcePath is null)
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            bool namedBootstrap = scope.ProofAdmission == CurrentCustomerSequenceProofAdmission.DisposableClosedConsoleBootstrap;
            if (namedBootstrap)
            {
                if (configuration.ClosedEight is not null || target.CloudOptions is not null || target.CloudObservation is not null || configuration.ClosedSeedEvidence is not { } seedEvidence ||
                    configuration.DefinitionProof.Path != seedEvidence.Definition.Path || configuration.DefinitionProof.Sha256 != seedEvidence.Definition.Sha256 ||
                    configuration.NativeProof.Path != seedEvidence.NativeComponent.Path || configuration.NativeProof.Sha256 != seedEvidence.NativeComponent.Sha256 ||
                    configuration.MaintenanceProof.Path != seedEvidence.MaintenanceComponent.Path || configuration.MaintenanceProof.Sha256 != seedEvidence.MaintenanceComponent.Sha256 ||
                    configuration.RecoveryReview.Path != string.Empty || configuration.RecoveryReview.Sha256 != string.Empty ||
                    configuration.ExactRoleTransitionReview.Path != string.Empty || configuration.ExactRoleTransitionReview.Sha256 != string.Empty)
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            else
            {
                if (configuration.ClosedSeedEvidence is not null) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                if (configuration.ClosedEight is not null)
                {
                    RequireCustomerClosedEightConfiguration(configuration, scope);
                }
                else
                {
                    RequireArtifact(configuration.DefinitionProof, scope.DefinitionProofSha256);
                    RequireArtifact(configuration.MaintenanceProof, scope.MaintenanceProofSha256);
                    RequireArtifact(configuration.NativeProof, scope.NativeProofSha256);
                    RequireArtifact(configuration.RecoveryReview, scope.RecoveryReviewSha256);
                    RequireArtifact(configuration.ExactRoleTransitionReview, scope.ExactRoleTransitionReviewSha256);
                }
            }
            RequireCustomerSequenceCanonicalHelper(files.Read(configuration.MaintenanceValidatorSourcePath), scope.MaintenanceValidatorSha256);
            var keys = new List<TrustedAttestationKey>();
            foreach (DeltaTrustedKeyReference reference in configuration.TrustedKeys)
            { keys.Add(new(reference.KeyId, Convert.FromBase64String(Encoding.UTF8.GetString(files.Read(reference.SubjectPublicKeyInfoPath)).Trim()))); }
            var trust = new ReceiptAttestationTrustStore(keys);
            if (configuration.ClosedEight is not null)
            {
                await CurrentCustomerClosedEightConsumer.RequireAsync(configuration.ClosedEight, scope, trust, pins,
                    DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false);
            }
            if (namedBootstrap)
            {
                // Authenticate the distinct seed before constructing source/target
                // observers or making any network/file projection from its claims.
                CurrentCustomerSequenceClosedBootstrap.Require(scope.ClosedConsoleSeed!, scope, trust,
                    pins.ReviewKeyId, pins.ReviewFingerprint, DateTimeOffset.UtcNow);
            }
            CurrentCustomerSequenceRepairSignedClaim? review = null;
            CurrentCustomerSequenceRepairSignedClaim? permission = null;
            string authorizationSha256 = new('0', 64);
            if (command != "review-current-customer-sequence-repair")
            {
                review = ReadCustomerSequence<CurrentCustomerSequenceRepairSignedClaim>(configuration.ReviewPath);
                if (JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(scope))
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                CurrentCustomerSequenceRepairPermit.ValidateReview(review, source, trust, pins, DateTimeOffset.UtcNow);
            }
            if (command is "verify-current-customer-sequence-repair" or "apply-current-customer-sequence-repair")
            {
                permission = ReadCustomerSequence<CurrentCustomerSequenceRepairSignedClaim>(configuration.AuthorizationPath);
                CurrentCustomerSequenceRepairPermit.ValidateClaims(review!, permission, source, trust, pins, DateTimeOffset.UtcNow);
                authorizationSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(permission);
            }
            using var actualEnvironment = new CurrentCustomerSequenceRepairConsoleEnvironment(authority, files, target,
                connection, ordinary, baseline, source, scope, trust, pins, authorizationSha256, configuration.SourceInputs,
                configuration.DefinitionProof, configuration.NativeProof, configuration.MaintenanceProof, configuration.ClosedSeedEvidence, configuration.ClosedEight);
            await using var closedObservation = namedBootstrap ? new CurrentCustomerSequenceClosedConsoleObservation(actualEnvironment,
                files, scope, binding.ArtifactRootCanonicalPath, connection, command == "apply-current-customer-sequence-repair") : null;
            if (closedObservation is not null) { await closedObservation.RecordInitialAsync(cancellationToken).ConfigureAwait(false); }
            ICurrentCustomerSequenceRepairEnvironment environment = closedObservation is null ? actualEnvironment : closedObservation;
            if (command == "review-current-customer-sequence-repair")
            {
                if (configuration.ReviewPrivateKeyPath is null || configuration.ReviewOutputPath is null || configuration.ReviewExpiresAtUtc is null)
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.ReviewKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.ReviewPrivateKeyPath)));
                CurrentCustomerSequenceRepairSignedClaim issued = await CurrentCustomerSequenceRepairPermit.IssueReviewAsync(scope,
                    source, baseline, trust, pins, environment, signer, configuration.ReviewExpiresAtUtc.Value,
                    TimeProvider.System, cancellationToken).ConfigureAwait(false);
                await WriteClaimAsync(configuration.ReviewOutputPath, issued).ConfigureAwait(false);
                await output.WriteLineAsync("current_customer_sequence_review_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            if (command == "authorize-current-customer-sequence-repair")
            {
                if (configuration.AuthorizationPrivateKeyPath is null || configuration.AuthorizationOutputPath is null)
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.AuthorizationKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.AuthorizationPrivateKeyPath)));
                CurrentCustomerSequenceRepairSignedClaim authorization = await CurrentCustomerSequenceRepairPermit.AuthorizeAsync(review!,
                    source, trust, pins, environment, signer, TimeProvider.System, cancellationToken).ConfigureAwait(false);
                await WriteClaimAsync(configuration.AuthorizationOutputPath, authorization).ConfigureAwait(false);
                await output.WriteLineAsync("current_customer_sequence_authorization_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            CurrentCustomerSequenceRepairPermit permit = await CurrentCustomerSequenceRepairPermit.AdmitAsync(review!, permission!, source, trust, pins, environment, TimeProvider.System, cancellationToken).ConfigureAwait(false);
            try
            {
                if (command == "verify-current-customer-sequence-repair")
                {
                    await output.WriteLineAsync("current_customer_sequence_verify_complete_no_ddl").ConfigureAwait(false);
                    return 0;
                }
                if (closedObservation is not null) { await closedObservation.CreateWriterAfterActualAdmissionAsync(permit, cancellationToken).ConfigureAwait(false); }
                CurrentCustomerSequenceObservation preimage = await environment.ObserveNativeBeforeAsync(scope, cancellationToken).ConfigureAwait(false);
                using var signer = new P256MigrationEvidenceSigner(pins.ReceiptKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.ReceiptPrivateKeyPath)));
                CurrentCustomerSequenceRepairReceipt receipt = await PostgreSqlCurrentCustomerSequenceRepair.ExecuteAsync(
                    closedObservation?.WriterConnectionString ?? connection, preimage, permit, signer, trust, pins, cancellationToken).ConfigureAwait(false);
                if (receipt.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback || receipt.Database != "Customer")
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                await output.WriteLineAsync("current_customer_sequence_apply_complete_readback_verified_no_row_refresh").ConfigureAwait(false);
                return 0;
            }
            finally { permit.Stop(); }

            T ReadCustomerSequence<T>(string path)
            {
                return DecodeCustomerSequence<T>(files.Read(path, sharedReader: true));
            }

            void RequireArtifact(CurrentAppOwnedRepairArtifact artifact, string expected)
            {
                if (artifact.Sha256 != expected || CurrentAppOwnedRepairPermit.Hash(files.Read(artifact.Path, sharedReader: true)) != expected)
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            async Task WriteClaimAsync(string path, CurrentCustomerSequenceRepairSignedClaim claim)
            {
                if (Path.GetFileName(path).StartsWith(scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(claim);
                await files.WriteNewAsync(path, bytes, cancellationToken).ConfigureAwait(false);
                if (!files.Read(path).AsSpan().SequenceEqual(bytes)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or
            JsonException or System.Xml.XmlException or IOException or UnauthorizedAccessException or Npgsql.NpgsqlException or HttpRequestException or
            InvalidOperationException or KeyNotFoundException or
            Exact25FullBackupException or System.Security.Cryptography.CryptographicException or FormatException or ArgumentException)
        {
            await error.WriteLineAsync("current_customer_sequence_boundary_failed_no_success_claim").ConfigureAwait(false);
            return 1;
        }
    }

    internal static void RequireCustomerClosedEightConfiguration(CurrentCustomerSequenceRepairConfiguration configuration, CurrentCustomerSequenceRepairScope scope)
    {
        if (configuration.ClosedEight is not { } evidence || configuration.ClosedSeedEvidence is not null ||
            configuration.ProofAdmission != CurrentCustomerSequenceProofAdmission.PersistentWithClosedConsoleProof ||
            scope.ProofAdmission != configuration.ProofAdmission || scope.ClosedConsoleSeed is not null || scope.BootstrapSubject is not null ||
            configuration.NativeProof.Path != evidence.Artifacts.Native.Path || configuration.NativeProof.Sha256 != evidence.Artifacts.Native.Sha256 ||
            configuration.MaintenanceProof is null || configuration.MaintenanceProof.Path != evidence.Artifacts.Maintenance.Path || configuration.MaintenanceProof.Sha256 != evidence.Artifacts.Maintenance.Sha256 ||
            configuration.RecoveryReview.Path != evidence.Artifacts.Recovery.Path || configuration.RecoveryReview.Sha256 != evidence.Artifacts.Recovery.Sha256 ||
            configuration.ExactRoleTransitionReview.Path != evidence.Artifacts.RoleTransition.Path || configuration.ExactRoleTransitionReview.Sha256 != evidence.Artifacts.RoleTransition.Sha256 ||
            configuration.DefinitionProof is null || configuration.DefinitionProof.Sha256 != scope.DefinitionProofSha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }

    internal static void RequireCustomerSequenceCanonicalHelper(byte[] bytes, string expected)
    {
        var utf8 = new UTF8Encoding(false, true);
        string actual = CurrentCustomerSequenceRepairPermit.Hash(utf8.GetBytes(utf8.GetString(bytes).Replace("\r\n", "\n", StringComparison.Ordinal)));
        if (expected != CurrentCustomerSequenceRepairPermit.MaintenanceValidator || actual != expected)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    internal static T DecodeCustomerSequence<T>(byte[] bytes)
    {
        using JsonDocument document = JsonDocument.Parse(bytes);
        RequireDistinctProperties(document.RootElement);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions) ?? throw CurrentCustomerSequenceRepairPermit.Invalid();

        static void RequireDistinctProperties(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (JsonProperty property in value.EnumerateObject())
                {
                    if (!names.Add(property.Name)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                    RequireDistinctProperties(property.Value);
                }
            }
            else if (value.ValueKind == JsonValueKind.Array)
            { foreach (JsonElement child in value.EnumerateArray()) { RequireDistinctProperties(child); } }
        }
    }
}
