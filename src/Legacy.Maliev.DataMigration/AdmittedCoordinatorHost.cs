using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Mandatory protected host dependencies for explicitly authorized execution; construction never acquires local run authority.</summary>
public sealed record AdmittedCoordinatorHostOptions(
    InitialMigrationAdmission Admission, RecoveryAuthorityVerificationOptions Verification, IMigrationEvidenceSigner Signer,
    string SourceConnectionString, PostgreSqlMigrationRunJournalOptions Journal, string ShadowAdministrativeConnectionString,
    CloudNativePgShadowDatabaseProvisionerOptions Provisioning, CloudNativePgTargetObserverOptions TargetObservation,
    LocalPostgreSqlArchiveVerificationOptions LocalVerification, string PgDumpPath, string RunnerPublishDirectory,
    string SnapshotId, ReadOnlyMemory<byte> RootKey, string OutputDirectory);

public sealed partial class AdmittedSequentialMigrationCoordinator
{
    /// <summary>Builds concrete admitted adapters. Actual source, target, native and local identities are revalidated during execution.</summary>
    public static AdmittedSequentialMigrationCoordinator CreateForHost(AdmittedCoordinatorHostOptions options,
        Action<IncrementalMigrationProgress>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var verification = new RecoveryAuthorityVerifier(options.Verification);
        // A deserialized target is never used to construct host authority before signature validation.
        verification.ValidateAdmission(options.Admission, DateTimeOffset.UtcNow);
        Require(Path.IsPathFullyQualified(options.PgDumpPath) && File.Exists(options.PgDumpPath), "host_native_runtime_required");
        ArgumentNullException.ThrowIfNull(options.LocalVerification);
        Require(Path.IsPathFullyQualified(options.LocalVerification.PgRestorePath) && File.Exists(options.LocalVerification.PgRestorePath) &&
            Path.IsPathFullyQualified(options.RunnerPublishDirectory) && Directory.Exists(options.RunnerPublishDirectory), "host_native_runtime_required");
        FreshSchemaPlan plan = JsonSerializer.Deserialize<FreshSchemaPlan>(options.Admission.Payload.OriginalSchemaPlanJson)!;
        ExecutionAuthorizationReceipt authorization = JsonSerializer.Deserialize<ExecutionAuthorizationReceipt>(options.Admission.Payload.OriginalAuthorizationJson)!;
        VerifiedRestoreReceipt restore = JsonSerializer.Deserialize<VerifiedRestoreReceipt>(options.Admission.Payload.OriginalVerifiedRestoreReceiptJson)!;
        CloudNativePgTargetObservation expected = authorization.TargetObservation!;
        Require(options.Provisioning.Namespace == expected.Namespace && options.Provisioning.Cluster == expected.Cluster &&
            options.Provisioning.ApiServer == options.TargetObservation.ApiServer &&
            options.Provisioning.ServiceAccountTokenFile == options.TargetObservation.ServiceAccountTokenFile &&
            options.Provisioning.ServiceAccountCaFile == options.TargetObservation.ServiceAccountCaFile, "host_target_configuration_mismatch");
        CloudNativePgTargetObserver observer = CloudNativePgTargetObserver.CreateForHost(options.TargetObservation);
        CloudNativePgShadowDatabaseProvisioner? provisioner = null;
        try
        {
            provisioner = CloudNativePgShadowDatabaseProvisioner.CreateForHost(options.Provisioning);
            var controlBoundary = new RemotePostgreSqlHostBoundary(options.Journal.ConnectionString, expected, observer);
            var targetBoundary = new RemotePostgreSqlHostBoundary(options.ShadowAdministrativeConnectionString, expected, observer);
            var checkpointOptions = new DatabaseMigrationCheckpointVerificationOptions(options.Admission.Payload.Identity, plan, options.Verification.TrustStore);
            var journal = new PostgreSqlMigrationRunJournal(options.Journal with
            { CheckpointVerification = checkpointOptions, RecoveryVerification = options.Verification, HostBoundary = controlBoundary });
            var target = new PostgreSqlShadowTarget(new(options.ShadowAdministrativeConnectionString, provisioner, options.Provisioning.OwnerRole)
            { HostBoundary = targetBoundary });
            var source = new SqlServerMigrationSource(new(options.SourceConnectionString));
            var sourceObserver = new DockerSqlRestoredSourceObserver(options.Verification.TrustStore);
            var local = new LocalPostgreSqlArchiveVerifier(options.LocalVerification, checkpointOptions);
            var runtime = new AdmittedCoordinatorRuntime(source, target, target, journal, PgDumpSource.CreateForHost(options.PgDumpPath, targetBoundary), local,
                local.VerifyExecutionReadinessAsync,
                token => sourceObserver.ObserveAsync(options.SourceConnectionString, restore, plan, token),
                async token => new(DateTimeOffset.UtcNow, (await RunnerArtifactManifestMeasurer.MeasureAsync(options.RunnerPublishDirectory, token).ConfigureAwait(false)).ManifestSha256),
                async token => new(DateTimeOffset.UtcNow, await observer.ObserveAsync(expected.Namespace, expected.Cluster, token).ConfigureAwait(false)),
                provisioner.ObserveSettlementAsync,
                async () =>
                {
                    try { await source.DisposeAsync().ConfigureAwait(false); }
                    finally { try { provisioner.Dispose(); } finally { observer.Dispose(); } }
                });
            return new(options.Admission, options.Verification, options.Signer, runtime, options.SnapshotId, options.RootKey, options.OutputDirectory, progress);
        }
        catch { provisioner?.Dispose(); observer.Dispose(); throw; }
    }
}
