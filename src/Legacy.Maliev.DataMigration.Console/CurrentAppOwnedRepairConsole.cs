using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    // Parent integrates exactly three dispatch names; no shared command enum/config edits here.
    private static async Task<int> RunCurrentAppOwnedEightRepairBoundaryAsync(string command, string configPath,
        TextWriter output, TextWriter error, CancellationToken cancellationToken)
    {
        try
        {
            if (command is not ("authorize-current-app-owned-eight-repair" or
                "verify-current-app-owned-eight-repair" or "apply-current-app-owned-eight-repair"))
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(cancellationToken).ConfigureAwait(false);
            CurrentAppOwnedRepairConfiguration configuration = await ReadProtectedJsonAsync<CurrentAppOwnedRepairConfiguration>(
                configPath, "current_app_owned_eight_config_unprotected", cancellationToken).ConfigureAwait(false);
            LocalExecutionBinding binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(configuration.RunBindingPath,
                "current_app_owned_eight_binding_unprotected", cancellationToken).ConfigureAwait(false);
            using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            byte[] configBytes = files.Read(configPath);
            CurrentAppOwnedRepairConfiguration retained = Decode<CurrentAppOwnedRepairConfiguration>(configBytes);
            if (JsonSerializer.Serialize(retained) != JsonSerializer.Serialize(configuration)) { throw CurrentAppOwnedRepairPermit.Invalid(); }
            LocalExecutionBinding retainedBinding = Read<LocalExecutionBinding>(configuration.RunBindingPath);
            if (retainedBinding != binding) { throw CurrentAppOwnedRepairPermit.Invalid(); }
            FreshSchemaPlan before = Read<FreshSchemaPlan>(configuration.BeforeSchemaPath);
            FreshSchemaPlan after = Read<FreshSchemaPlan>(configuration.AfterSchemaPath);
            CurrentAppOwnedRepairSignedClaim review = Read<CurrentAppOwnedRepairSignedClaim>(configuration.ReviewPath);
            CurrentAppOwnedRepairSigningPins pins = Read<CurrentAppOwnedRepairSigningPins>(configuration.SigningPinsPath);
            CurrentAppOwnedRepairTargetPins target = Read<CurrentAppOwnedRepairTargetPins>(configuration.TargetPinsPath);
            CurrentAppOwnedDatabaseSnapshot[] baseline = await files.ReadBaselineAsync(configuration.GlobalBeforePath,
                cancellationToken).ConfigureAwait(false);
            string connection = Encoding.UTF8.GetString(files.Read(configuration.OperatorConnectionPath)).Trim();
            string ordinary = Encoding.UTF8.GetString(files.Read(configuration.RejectedOrdinaryConnectionPath)).Trim();
            if (before.SourceCommitSha != accepted || after.SourceCommitSha != accepted || review.Scope.SourceCommitSha != accepted)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            RequireArtifact(configuration.NativeProof, review.Scope.NativeProofSha256);
            RequireArtifact(configuration.RecoveryReview, review.Scope.RecoveryReviewSha256);
            RequireArtifact(configuration.ExactRoleTransitionReview, review.Scope.ExactRoleTransitionReviewSha256);
            var keys = new List<TrustedAttestationKey>();
            foreach (DeltaTrustedKeyReference reference in configuration.TrustedKeys)
            { keys.Add(new(reference.KeyId, Convert.FromBase64String(Encoding.UTF8.GetString(files.Read(reference.SubjectPublicKeyInfoPath)).Trim()))); }
            var trust = new ReceiptAttestationTrustStore(keys);
            using var environment = new CurrentAppOwnedRepairConsoleEnvironment(authority, files, target,
                connection, ordinary, baseline, before, after, review.Scope);
            if (command == "authorize-current-app-owned-eight-repair")
            {
                if (configuration.AuthorizationPrivateKeyPath is null || configuration.AuthorizationOutputPath is null)
                { throw CurrentAppOwnedRepairPermit.Invalid(); }
                using var signer = new P256MigrationEvidenceSigner(pins.AuthorizationKeyId,
                    Encoding.UTF8.GetString(files.Read(configuration.AuthorizationPrivateKeyPath)));
                CurrentAppOwnedRepairSignedClaim authorization = await CurrentAppOwnedRepairPermit.AuthorizeAsync(review,
                    before, after, trust, pins, environment, signer, TimeProvider.System, cancellationToken).ConfigureAwait(false);
                await files.WriteNewAsync(configuration.AuthorizationOutputPath, JsonSerializer.SerializeToUtf8Bytes(authorization),
                    cancellationToken).ConfigureAwait(false);
                await output.WriteLineAsync("current_app_owned_eight_authorization_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            CurrentAppOwnedRepairSignedClaim permission = Read<CurrentAppOwnedRepairSignedClaim>(configuration.AuthorizationPath);
            CurrentAppOwnedRepairPermit permit = await CurrentAppOwnedRepairPermit.AdmitAsync(review, permission, before,
                after, trust, pins, environment, TimeProvider.System, cancellationToken).ConfigureAwait(false);
            if (await environment.InspectGlobalPreservationAsync(cancellationToken).ConfigureAwait(false) != review.Scope.GlobalPreservationSha256)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            if (command == "verify-current-app-owned-eight-repair")
            {
                await output.WriteLineAsync("current_app_owned_eight_verify_complete_no_ddl").ConfigureAwait(false);
                return 0;
            }
            using var receiptSigner = new P256MigrationEvidenceSigner(pins.ReceiptKeyId,
                Encoding.UTF8.GetString(files.Read(configuration.ReceiptPrivateKeyPath)));
            string previous = new('0', 64);
            foreach (string database in CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables))
            {
                CurrentAppOwnedDatabaseSnapshot expected = baseline.Single(x => x.Database == database);
                CurrentAppOwnedRepairReceipt receipt = await PostgreSqlCurrentAppOwnedEightRepair.ExecuteDatabaseAsync(
                    connection, database, before, after, expected, permit, receiptSigner, trust, pins, previous,
                    cancellationToken).ConfigureAwait(false);
                previous = CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(receipt));
            }
            await permit.RequireAsync(cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync("current_app_owned_eight_apply_complete_readback_verified_no_row_refresh").ConfigureAwait(false);
            return 0;

            T Read<T>(string path)
            {
                return Decode<T>(files.Read(path));
            }

            void RequireArtifact(CurrentAppOwnedRepairArtifact artifact, string expected)
            {
                if (artifact.Sha256 != expected || CurrentAppOwnedRepairPermit.Hash(files.Read(artifact.Path)) != expected)
                { throw CurrentAppOwnedRepairPermit.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or MigrationConsoleException or
            JsonException or IOException or UnauthorizedAccessException or Npgsql.NpgsqlException or
            Exact25FullBackupException or System.Security.Cryptography.CryptographicException or FormatException or ArgumentException)
        {
            await error.WriteLineAsync("current_app_owned_eight_boundary_failed_no_success_claim").ConfigureAwait(false);
            return 1;
        }
        static T Decode<T>(byte[] bytes)
        {
            return JsonSerializer.Deserialize<T>(bytes, JsonOptions)
            ?? throw CurrentAppOwnedRepairPermit.Invalid();
        }
    }
}
