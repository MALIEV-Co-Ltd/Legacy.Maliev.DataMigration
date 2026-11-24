using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record ConsumerColumnBootstrapOperationalConfiguration(string Kind, string SourcePath, string ScopePath, string ReviewPath,
    string AuthorizationPath, string SigningPinsPath, string RunBindingPath, string OperatorConnectionPath, string RejectedOrdinaryConnectionPath,
    string BeforeFleetPath, string TargetPinsPath, IReadOnlyList<DeltaTrustedKeyReference> TrustedKeys, CurrentAppOwnedRepairArtifact NativePreparation,
    CurrentAppOwnedRepairArtifact RecoveryPreparation, CurrentAppOwnedRepairArtifact RolePreparation,
    string? ReviewPrivateKeyPath = null, string? AuthorizationPrivateKeyPath = null, string? ReceiptPrivateKeyPath = null,
    string? SourceConnectionPath = null);

public static partial class MigrationConsole
{
    // Fixed composition seam; registration remains a separately reviewed patch.
    internal static async Task<int> RunConsumerColumnBootstrapOperationalAsync(string command, string configurationPath,
        TextWriter output, TextWriter error, CancellationToken ct, ConsumerColumnBootstrapProofFixture? fixture = null,
        ConsumerColumnBootstrapReviewedInvocation? reviewed = null)
    {
        ct.ThrowIfCancellationRequested();
        bool persistent = command.EndsWith("-reviewed", StringComparison.Ordinal);
        if (persistent) { command = command.Replace("-reviewed", "-proof", StringComparison.Ordinal); }
        if (command is not ("review-consumer-column-bootstrap-proof" or "authorize-consumer-column-bootstrap-proof" or
            "verify-consumer-column-bootstrap-proof" or "apply-consumer-column-bootstrap-proof")) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromMinutes(8)); ct = deadline.Token;
        try
        {
            if (persistent ? fixture is not null || reviewed is null : fixture is null || reviewed is not null)
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            var config = await ReadProtectedJsonAsync<ConsumerColumnBootstrapOperationalConfiguration>(configurationPath,
                "consumer_column_bootstrap_configuration_unprotected", ct, maximumByteLength: 65536).ConfigureAwait(false);
            if (config.Kind != (persistent ? "consumer-column-bootstrap-reviewed-configuration-v1" : "consumer-column-bootstrap-disposable-configuration-v1"))
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            using var bindingFile = SecureLocalFile.OpenReadShared(config.RunBindingPath);
            if (bindingFile.Length is < 1 or > 65536 || !SecureLocalFile.HandleResolvesToApprovedPath(bindingFile, config.RunBindingPath)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            byte[] bindingBytes = new byte[checked((int)bindingFile.Length)]; bindingFile.ReadExactly(bindingBytes);
            var binding = DecodeAuthRepair<LocalExecutionBinding>(bindingBytes);
            using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            T Read<T>(string path)
            {
                return DecodeAuthRepair<T>(files.Read(path, sharedReader: true, maximumBytes: 12 * 1024 * 1024));
            }

            if (JsonSerializer.Serialize(DecodeAuthRepair<ConsumerColumnBootstrapOperationalConfiguration>(files.Read(configurationPath, sharedReader: true, maximumBytes: 65536))) != JsonSerializer.Serialize(config) ||
                !files.Read(config.RunBindingPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bindingBytes)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            var source = Read<FreshSchemaPlan>(config.SourcePath); var scope = Read<ConsumerColumnBootstrapOperationalScope>(config.ScopePath);
            if (persistent ? scope.Mode != ConsumerColumnBootstrapOperationalMode.PersistentReviewed :
                scope.Mode != ConsumerColumnBootstrapOperationalMode.DisposableClosedProof &&
                (scope.Mode != ConsumerColumnBootstrapOperationalMode.OwnedForwardRecoveryCharacterization || fixture is null || !fixture.AcceptsRecovery(scope)))
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            ConsumerColumnBootstrapOperationalContract.RequireScope(scope, source, DateTimeOffset.UtcNow);
            var pins = Read<CurrentAppOwnedRepairSigningPins>(config.SigningPinsPath);
            var baseline = Read<CurrentAppOwnedDatabaseSnapshot[]>(config.BeforeFleetPath); var target = Read<CurrentAppOwnedRepairTargetPins>(config.TargetPinsPath);
            var keys = config.TrustedKeys.Select(x => new TrustedAttestationKey(x.KeyId,
                Convert.FromBase64String(Encoding.UTF8.GetString(files.Read(x.SubjectPublicKeyInfoPath, sharedReader: true, maximumBytes: 65536)).Trim()))).ToArray();
            var trust = new ReceiptAttestationTrustStore(keys);
            string connection = Encoding.UTF8.GetString(files.Read(config.OperatorConnectionPath, sharedReader: true, maximumBytes: 65536)).Trim();
            string ordinary = Encoding.UTF8.GetString(files.Read(config.RejectedOrdinaryConnectionPath, sharedReader: true, maximumBytes: 65536)).Trim();
            using var environment = persistent
                ? await ConsumerColumnBootstrapOperationalEnvironment.CreatePersistentAsync(authority, files, scope, reviewed!.Source, target, connection, ordinary,
                    reviewed.SourceConnection, config, trust, pins, reviewed.Acceptance, ct).ConfigureAwait(false)
                : await ConsumerColumnBootstrapOperationalEnvironment.CreateAsync(authority, files, scope, source, target, connection, ordinary, config, trust, pins, fixture!, ct).ConfigureAwait(false);
            await environment.RequireScopeAsync(scope, ct).ConfigureAwait(false);
            if (command == "review-consumer-column-bootstrap-proof")
            {
                await RequireFleetAsync(scope.BeforeDatabaseSha256).ConfigureAwait(false);
                using var signer = Signer(config.ReviewPrivateKeyPath, pins.ReviewKeyId);
                var review = ConsumerColumnBootstrapOperationalPermit.IssueReview(scope, source, signer, pins, DateTimeOffset.UtcNow,
                    DateTimeOffset.UtcNow.AddMinutes(10) < scope.Maintenance.ExpiresAtUtc ? DateTimeOffset.UtcNow.AddMinutes(10) : scope.Maintenance.ExpiresAtUtc);
                await WriteAsync(config.ReviewPath, review).ConfigureAwait(false);
            }
            else
            {
                var review = Read<ConsumerColumnBootstrapOperationalClaim>(config.ReviewPath);
                if (JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(review.Scope)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                if (command == "authorize-consumer-column-bootstrap-proof")
                {
                    await RequireFleetAsync(scope.BeforeDatabaseSha256).ConfigureAwait(false);
                    using var signer = Signer(config.AuthorizationPrivateKeyPath, pins.AuthorizationKeyId);
                    await WriteAsync(config.AuthorizationPath, ConsumerColumnBootstrapOperationalPermit.IssueAuthorization(review, source, trust, pins, signer, DateTimeOffset.UtcNow)).ConfigureAwait(false);
                }
                else
                {
                    var authorization = Read<ConsumerColumnBootstrapOperationalClaim>(config.AuthorizationPath);
                    if (JsonSerializer.Serialize(scope) != JsonSerializer.Serialize(review.Scope)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                    var permit = await ConsumerColumnBootstrapOperationalPermit.AdmitAsync(review, authorization, source, trust, pins, environment, TimeProvider.System, ct, reviewed?.Acceptance).ConfigureAwait(false);
                    try
                    {
                        if (command == "apply-consumer-column-bootstrap-proof")
                        {
                            using var signer = Signer(config.ReceiptPrivateKeyPath, pins.ReceiptKeyId);
                            var receipts = await PostgreSqlConsumerColumnBootstrapRepair.ExecuteAsync(source, baseline, permit, signer, trust, pins, ct).ConfigureAwait(false);
                            if (receipts.Count != scope.PendingDatabases.Count || receipts.Any(x => x.Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
                        }
                    }
                    finally { permit.Stop(); }
                }
            }
            await output.WriteLineAsync(persistent ? "consumer_column_bootstrap_reviewed_step_complete" : "consumer_column_bootstrap_disposable_step_complete").ConfigureAwait(false); return 0;

            P256MigrationEvidenceSigner Signer(string? path, string id)
            {
                return path is null ? throw ConsumerColumnBootstrapOperationalContract.Invalid() :
                new(id, Encoding.UTF8.GetString(files.Read(path, sharedReader: true, maximumBytes: 65536)));
            }

            async Task WriteAsync<T>(string path, T value)
            {
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value); await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
                if (!files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            }
            async Task RequireFleetAsync(IReadOnlyDictionary<string, string> expected)
            {
                var observed = await environment.ObserveFleetAsync(scope, ct).ConfigureAwait(false);
                if (observed.Count != expected.Count || observed.Any(x => !expected.TryGetValue(x.Database, out string? hash) || x.Sha256 != hash)) { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            }
        }
        catch (Exception failure) when (failure is MigrationExecutionException or JsonException or FormatException)
        { await error.WriteLineAsync("consumer_column_bootstrap_boundary_failed").ConfigureAwait(false); return 1; }
    }
}
