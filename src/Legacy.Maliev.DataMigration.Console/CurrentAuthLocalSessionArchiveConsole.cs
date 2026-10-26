using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthLocalSessionArchiveConfiguration(string ScopePath, string ReviewPath, string AuthorizationPath,
    string SigningPinsPath, string LocalBindingPath, string ProductionBindingPath, string SourceSchemaPath,
    string LocalTargetPinsPath, string ProductionTargetPinsPath, string LocalOperatorConnectionPath, string ProductionOperatorConnectionPath,
    string LocalOrdinaryConnectionPath, string ProductionOrdinaryConnectionPath, string LocalBaselinePath, string ProductionBaselinePath,
    string DeviceProofPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys,
    CurrentAppOwnedRepairArtifact ArchiveHelperProof, CurrentAppOwnedRepairArtifact ArchiveNativeProof,
    CurrentAppOwnedRepairArtifact ExactDeleteReview, CurrentAppOwnedRepairArtifact RecoveryReview,
    string EvidencePrivateKeyPath, string? ReviewPrivateKeyPath = null, string? ReviewOutputPath = null,
    string? AuthorizationPrivateKeyPath = null, string? AuthorizationOutputPath = null);
public static partial class MigrationConsole
{
    internal static void RequireArchiveConsoleScope(CurrentAuthArchiveScope scope)
    {
        if (scope.ComponentSubject is not null || scope.ProofAdmission == CurrentAuthArchiveProofAdmission.DisposableNativeBootstrap)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
    // Root must add these four fixed dispatch routes only after complete acceptance.
    // This method takes file configuration, never serialized environment callbacks.
    private static async Task<int> RunCurrentAuthLocalSessionArchiveBoundaryAsync(string command, string configPath,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromMinutes(8)); ct = deadline.Token;
        try
        {
            CurrentAuthArchiveCapacity.Require(admission: true);
            RequireArchiveCommand(command);
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
            CurrentAuthLocalSessionArchiveConfiguration initial = await ReadProtectedJsonAsync<CurrentAuthLocalSessionArchiveConfiguration>(configPath,
                "current_auth_archive_config_unprotected", ct).ConfigureAwait(false);
            LocalExecutionBinding localBinding = await ReadProtectedJsonAsync<LocalExecutionBinding>(initial.LocalBindingPath,
                "current_auth_archive_local_binding_unprotected", ct).ConfigureAwait(false);
            LocalExecutionBinding productionBinding = await ReadProtectedJsonAsync<LocalExecutionBinding>(initial.ProductionBindingPath,
                "current_auth_archive_production_binding_unprotected", ct).ConfigureAwait(false);
            using WindowsLocalRunAuthority localAuthority = WindowsLocalRunAuthority.AcquireResume(localBinding.ArtifactRootCanonicalPath, localBinding);
            using WindowsLocalRunAuthority productionAuthority = WindowsLocalRunAuthority.AcquireResume(productionBinding.ArtifactRootCanonicalPath, productionBinding);
            using var localFiles = new CurrentAppOwnedRepairCustody(localAuthority); using var productionFiles = new CurrentAppOwnedRepairCustody(productionAuthority);
            CurrentAuthLocalSessionArchiveConfiguration config = ReadLocal<CurrentAuthLocalSessionArchiveConfiguration>(configPath);
            if (JsonSerializer.Serialize(config) != JsonSerializer.Serialize(initial) || ReadLocal<LocalExecutionBinding>(config.LocalBindingPath) != localBinding ||
                ReadProduction<LocalExecutionBinding>(config.ProductionBindingPath) != productionBinding) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            CurrentAuthArchiveScope scope = ReadLocal<CurrentAuthArchiveScope>(config.ScopePath);
            RequireArchiveConsoleScope(scope);
            CurrentAuthArchivePins pins = ReadLocal<CurrentAuthArchivePins>(config.SigningPinsPath);
            FreshSchemaPlan source = ReadLocal<FreshSchemaPlan>(config.SourceSchemaPath);
            CurrentAuthLocalSessionArchivePolicy.RequireScope(scope, DateTimeOffset.UtcNow);
            if (accepted != scope.LocalObservationPolicy.SourceCommitSha || source.SourceCommitSha != accepted) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            await BaselineAsync(localFiles, config.LocalBaselinePath, scope.LocalObservationPolicy).ConfigureAwait(false);
            await BaselineAsync(productionFiles, config.ProductionBaselinePath, scope.ProductionObservationPolicy).ConfigureAwait(false);
            CurrentAuthArchiveDeviceProof devices = ReadLocal<CurrentAuthArchiveDeviceProof>(config.DeviceProofPath);
            var keys = new List<TrustedAttestationKey>();
            foreach (DeltaTrustedKeyReference reference in config.TrustedKeys)
            { keys.Add(new(reference.KeyId, Convert.FromBase64String(Encoding.UTF8.GetString(localFiles.Read(reference.SubjectPublicKeyInfoPath, maximumBytes: 65536)).Trim()))); }
            var trust = new ReceiptAttestationTrustStore(keys); CurrentAuthLocalSessionArchivePolicy.RequirePins(pins, trust);
            CurrentAuthArchiveProofReader.Require(localFiles, config.ArchiveHelperProof, scope.ArchiveHelperProofSha256, "helper", scope, trust, pins, source);
            CurrentAuthArchiveProofReader.Require(localFiles, config.ArchiveNativeProof, scope.ArchiveNativeProofSha256, "native", scope, trust, pins, source);
            CurrentAuthArchiveProofReader.Require(localFiles, config.ExactDeleteReview, scope.ExactDeleteReviewSha256, "delete", scope, trust, pins, source);
            CurrentAuthArchiveProofReader.Require(localFiles, config.RecoveryReview, scope.RecoveryReviewSha256, "recovery", scope, trust, pins, source);
            CurrentAuthArchiveClaim? review = null, authorization = null; string authorizationHash = new('0', 64);
            if (command != "review-current-auth-local-session-archive")
            {
                review = ReadLocal<CurrentAuthArchiveClaim>(config.ReviewPath);
                CurrentAuthArchiveScope reviewed = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveScope>(review,
                    CurrentAuthLocalSessionArchivePolicy.ReviewDomain, pins.ReviewKeyId, pins.ReviewFingerprint, trust);
                if (CurrentAuthLocalSessionArchivePolicy.Hash(reviewed) != CurrentAuthLocalSessionArchivePolicy.Hash(scope)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            }
            if (command is "verify-current-auth-local-session-archive" or "apply-current-auth-local-session-archive")
            {
                authorization = ReadLocal<CurrentAuthArchiveClaim>(config.AuthorizationPath);
                CurrentAuthArchiveAuthorization value = CurrentAuthLocalSessionArchivePolicy.Verify<CurrentAuthArchiveAuthorization>(authorization,
                    CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, pins.AuthorizationKeyId, pins.AuthorizationFingerprint, trust);
                RequireAuthorization(value, scope, review!, DateTimeOffset.UtcNow); authorizationHash = CurrentAuthLocalSessionArchivePolicy.Hash(authorization);
            }
            // Authentic existing claims have been independently verified before any target contact.
            CurrentAppOwnedRepairTargetPins localTarget = ReadLocal<CurrentAppOwnedRepairTargetPins>(config.LocalTargetPinsPath);
            CurrentAppOwnedRepairTargetPins productionTarget = ReadProduction<CurrentAppOwnedRepairTargetPins>(config.ProductionTargetPinsPath);
            string localConnection = Text(localFiles, config.LocalOperatorConnectionPath), productionConnection = Text(productionFiles, config.ProductionOperatorConnectionPath);
            using var environment = new CurrentAuthLocalSessionArchiveEnvironment(localFiles, productionFiles, localAuthority, productionAuthority,
                scope, source, localTarget, productionTarget, localConnection, productionConnection,
                Text(localFiles, config.LocalOrdinaryConnectionPath), Text(productionFiles, config.ProductionOrdinaryConnectionPath), devices, trust, pins, authorizationHash);
            if (command is "review-current-auth-local-session-archive" or "authorize-current-auth-local-session-archive")
            {
                await environment.RequireAcceptedSourceOwnerCustodyAndTargetsAsync(scope, ct).ConfigureAwait(false);
                CurrentAuthArchiveFleet local = await environment.CaptureLocalFleetAsync(scope, ct).ConfigureAwait(false);
                CurrentAuthArchiveFleet production = await environment.CaptureProductionFleetAsync(scope, ct).ConfigureAwait(false);
                CurrentAuthLocalSessionArchivePolicy.RequireFleet(local, scope.LocalObservationPolicy, DateTimeOffset.UtcNow);
                CurrentAuthLocalSessionArchivePolicy.RequireFleet(production, scope.ProductionObservationPolicy, DateTimeOffset.UtcNow, comparison: true);
                byte[] rows = CurrentAuthLocalSessionArchivePolicy.EncodeRows(local.Auth.Sessions);
                try
                {
                    if (local.Auth.Sessions.Count != scope.DeleteCount || CurrentAuthLocalSessionArchivePolicy.HashBytes(rows) != scope.DeleteSetSha256 ||
                        CurrentAuthLocalSessionArchivePolicy.RequireComparison(local.Auth, production.Auth) != scope.ApplicationComparisonSha256)
                    { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(rows); }
                await environment.RequireAcceptedSourceOwnerCustodyAndTargetsAsync(scope, ct).ConfigureAwait(false);
                if (command == "review-current-auth-local-session-archive")
                {
                    if (config.ReviewPrivateKeyPath is null || config.ReviewOutputPath is null) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                    using var signer = Signer(pins.ReviewKeyId, config.ReviewPrivateKeyPath, pins.ReviewFingerprint);
                    CurrentAuthArchiveClaim issued = CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.ReviewDomain, scope, signer);
                    await ClaimAsync(config.ReviewOutputPath, issued).ConfigureAwait(false);
                    await output.WriteLineAsync("current_auth_session_archive_review_complete_no_delete").ConfigureAwait(false); return 0;
                }
                if (config.AuthorizationPrivateKeyPath is null || config.AuthorizationOutputPath is null) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                using var authorizer = Signer(pins.AuthorizationKeyId, config.AuthorizationPrivateKeyPath, pins.AuthorizationFingerprint);
                var permission = new CurrentAuthArchiveAuthorization(scope.OperationId, CurrentAuthLocalSessionArchivePolicy.Hash(review!), DateTimeOffset.UtcNow, scope.ExpiresAtUtc);
                RequireAuthorization(permission, scope, review!, DateTimeOffset.UtcNow);
                await ClaimAsync(config.AuthorizationOutputPath, CurrentAuthLocalSessionArchivePolicy.Sign(CurrentAuthLocalSessionArchivePolicy.AuthorizationDomain, permission, authorizer)).ConfigureAwait(false);
                await output.WriteLineAsync("current_auth_session_archive_authorization_complete_no_delete").ConfigureAwait(false); return 0;
            }
            CurrentAuthLocalSessionArchivePermit permit = await CurrentAuthLocalSessionArchivePermit.AdmitAsync(review!, authorization!, trust, pins, environment, TimeProvider.System, ct).ConfigureAwait(false);
            try
            {
                if (command == "verify-current-auth-local-session-archive")
                { await output.WriteLineAsync("current_auth_session_archive_verify_complete_no_delete").ConfigureAwait(false); return 0; }
                using var evidence = Signer(pins.EvidenceKeyId, config.EvidencePrivateKeyPath, pins.EvidenceFingerprint);
                CurrentAuthArchiveReceipt terminal = await PostgreSqlCurrentAuthLocalSessionArchive.ExecuteAsync(localConnection, permit, evidence, ct).ConfigureAwait(false);
                environment.RequireTerminal(terminal);
                await output.WriteLineAsync("current_auth_session_archive_complete_readback_verified_history_retained").ConfigureAwait(false); return 0;
            }
            finally { permit.Stop(); }
            T ReadLocal<T>(string path)
            {
                return DecodeAuthRepair<T>(localFiles.Read(path, maximumBytes: 8 * 1024 * 1024));
            }

            T ReadProduction<T>(string path)
            {
                return DecodeAuthRepair<T>(productionFiles.Read(path, maximumBytes: 8 * 1024 * 1024));
            }

            static string Text(CurrentAppOwnedRepairCustody files, string path)
            {
                return Encoding.UTF8.GetString(files.Read(path, maximumBytes: 65536)).Trim();
            }

            P256MigrationEvidenceSigner Signer(string id, string path, string fingerprint)
            {
                var signer = new P256MigrationEvidenceSigner(id, Encoding.UTF8.GetString(localFiles.Read(path, maximumBytes: 65536)));
                if (signer.PublicKeyFingerprintSha256 != fingerprint) { signer.Dispose(); throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                return signer;
            }
            async Task ClaimAsync(string path, CurrentAuthArchiveClaim claim)
            {
                if (Path.GetFileName(path).StartsWith(scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(claim); await localFiles.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
                if (!localFiles.Read(path, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            }
            async Task BaselineAsync(CurrentAppOwnedRepairCustody files, string path, CurrentAuthRepairScope policy)
            {
                CurrentAuthArchiveCapacity.Require(admission: false);
                CurrentAppOwnedDatabaseSnapshot[] values = await files.ReadBaselineAsync(path, ct).ConfigureAwait(false);
                CurrentAuthArchiveCapacity.Require(admission: false);
                if (values.Length != policy.BeforeDatabaseSha256.Count || values.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != values.Length ||
                    values.Any(db => !policy.BeforeDatabaseSha256.TryGetValue(db.Database, out string? hash) || db.Sha256 != hash)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or JsonException or System.Xml.XmlException or IOException or UnauthorizedAccessException or
            Npgsql.NpgsqlException or Exact25FullBackupException or System.Security.Cryptography.CryptographicException or FormatException or ArgumentException or InvalidOperationException)
        { await error.WriteLineAsync("current_auth_session_archive_boundary_failed_no_success_claim").ConfigureAwait(false); return 1; }
    }
    internal static void RequireArchiveCommand(string command)
    {
        if (command is not ("review-current-auth-local-session-archive" or "authorize-current-auth-local-session-archive" or
            "verify-current-auth-local-session-archive" or "apply-current-auth-local-session-archive")) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
    private static void RequireAuthorization(CurrentAuthArchiveAuthorization permission, CurrentAuthArchiveScope scope, CurrentAuthArchiveClaim review, DateTimeOffset now)
    {
        if (permission.OperationId != scope.OperationId || permission.ReviewSha256 != CurrentAuthLocalSessionArchivePolicy.Hash(review) ||
            permission.IssuedAtUtc.Offset != TimeSpan.Zero || permission.ExpiresAtUtc.Offset != TimeSpan.Zero || permission.IssuedAtUtc < scope.CapturedAtUtc ||
            permission.IssuedAtUtc > now || permission.ExpiresAtUtc <= now || permission.ExpiresAtUtc > scope.ExpiresAtUtc) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }
}
