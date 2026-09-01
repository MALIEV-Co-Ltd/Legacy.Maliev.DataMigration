namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PostExportShadowCleanupTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 2, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task CleanupAsync_ValidExact24DeletesEveryFencedShadowAndSignsCompleteReceipt()
    {
        Fixture fixture = CreateFixture();

        PostExportShadowCleanupReceipt receipt = await fixture.Service.CleanupAsync(
            fixture.Execution, fixture.Backup, fixture.Plan, fixture.Authorization,
            fixture.Snapshot, fixture.Key, CancellationToken.None);

        Assert.True(receipt.IsComplete);
        Assert.Equal(24, fixture.Target.Deleted.Count);
        Assert.Equal(24, fixture.Verifier.CallCount);
        Assert.Equal(fixture.Execution.Receipt.RunId, receipt.RunId);
        Assert.Equal(CleanupContract.ExecutionDigest(fixture.Execution.Receipt), receipt.ExecutionReceiptSha256);
        Assert.True(PostExportShadowCleanupAttestation.Verify(receipt, new AcceptingTrust()));
    }

    [Fact]
    public async Task CleanupAsync_PartialFailureIsSignedIncompleteAndRetryCanFinishIdempotently()
    {
        Fixture fixture = CreateFixture();
        fixture.Target.FailOnceName = fixture.Execution.Receipt.Databases[5].ShadowName;

        PostExportShadowCleanupReceipt first = await fixture.Service.CleanupAsync(
            fixture.Execution, fixture.Backup, fixture.Plan, fixture.Authorization,
            fixture.Snapshot, fixture.Key, CancellationToken.None);
        PostExportShadowCleanupReceipt retry = await fixture.Service.CleanupAsync(
            fixture.Execution, fixture.Backup, fixture.Plan, fixture.Authorization,
            fixture.Snapshot, fixture.Key, CancellationToken.None);

        Assert.False(first.IsComplete);
        _ = Assert.Single(first.Cleanup, item => !item.Deleted);
        Assert.True(retry.IsComplete);
        Assert.Equal(48, fixture.Verifier.CallCount);
    }

    [Fact]
    public async Task CleanupAsync_ExpiredOrReplayedAuthorizationStopsBeforeDelete()
    {
        Fixture fixture = CreateFixture();
        CleanupAuthorizationReceipt expired = fixture.Authorization with
        {
            IssuedAtUtc = Now.AddHours(-2),
            ExpiresAtUtc = Now.AddHours(-1),
        };

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Service.CleanupAsync(
            fixture.Execution, fixture.Backup, fixture.Plan, expired, fixture.Snapshot, fixture.Key, CancellationToken.None));

        Assert.Equal("cleanup_authorization_invalid", failure.Code);
        Assert.Empty(fixture.Target.Deleted);
    }

    [Fact]
    public async Task CleanupAsync_AuthorizationSignatureFailureOrDifferentRunReplayStopsBeforeDelete()
    {
        Fixture fixture = CreateFixture();
        var signatureRejecting = new PostExportShadowCleanupService(
            fixture.Target, new AcceptingTrust('a'), new AcceptingTrust('b'), new RejectingTrust(),
            new FakeSigner(), fixture.Verifier, new FixedTimeProvider(Now));
        MigrationExecutionException badSignature = await Assert.ThrowsAsync<MigrationExecutionException>(() => signatureRejecting.CleanupAsync(
            fixture.Execution, fixture.Backup, fixture.Plan, fixture.Authorization,
            fixture.Snapshot, fixture.Key, CancellationToken.None));
        CleanupAuthorizationReceipt replay = fixture.Authorization with { RunId = Guid.NewGuid() };
        MigrationExecutionException wrongRun = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Service.CleanupAsync(
            fixture.Execution, fixture.Backup, fixture.Plan, replay,
            fixture.Snapshot, fixture.Key, CancellationToken.None));

        Assert.Equal("cleanup_authorization_invalid", badSignature.Code);
        Assert.Equal("cleanup_authorization_invalid", wrongRun.Code);
        Assert.Empty(fixture.Target.Deleted);
    }

    [Fact]
    public void CleanupAuthorizationProducer_RequiresExplicitReviewAndBindsSignedArtifacts()
    {
        Fixture fixture = CreateFixture();
        var request = new ReviewedCleanupAuthorizationRequest(
            Now.AddMinutes(-1), Now.AddMinutes(30), HealthyTarget(), true);

        CleanupAuthorizationReceipt authorization = ReviewedCleanupAuthorizationProducer.Produce(
            request, fixture.Execution, fixture.Snapshot, fixture.Key,
            new AcceptingTrust('b'), new FakeSigner(), Now);
        OperatorAttestationException denied = Assert.Throws<OperatorAttestationException>(() =>
            ReviewedCleanupAuthorizationProducer.Produce(
                request with { AllowCleanupAuthorization = false }, fixture.Execution, fixture.Snapshot,
                fixture.Key, new AcceptingTrust('b'), new FakeSigner(), Now));

        Assert.Equal("cleanup-run-owned-shadows", authorization.Mode);
        Assert.True(authorization.OwnerApproved);
        Assert.Equal(CleanupContract.ExecutionDigest(fixture.Execution.Receipt), authorization.ExecutionReceiptSha256);
        Assert.Equal(fixture.Snapshot.ManifestDigestSha256, authorization.SnapshotManifestDigestSha256);
        Assert.Equal("cleanup_authorization_owner_review_required", denied.Code);
    }

    [Fact]
    public void CleanupAuthorizationProducer_RejectsAuthorizationIssuedBeforeExecutionCompleted()
    {
        Fixture fixture = CreateFixture();
        var request = new ReviewedCleanupAuthorizationRequest(
            fixture.Execution.Receipt.CompletedAtUtc.AddSeconds(-1), Now.AddMinutes(30), HealthyTarget(), true);

        OperatorAttestationException failure = Assert.Throws<OperatorAttestationException>(() =>
            ReviewedCleanupAuthorizationProducer.Produce(
                request, fixture.Execution, fixture.Snapshot, fixture.Key,
                new AcceptingTrust('b'), new FakeSigner(), Now));

        Assert.Equal("cleanup_authorization_time_window_invalid", failure.Code);
    }

    [Fact]
    public async Task CleanupAsync_SnapshotMismatchStopsBeforeDelete()
    {
        Fixture fixture = CreateFixture();
        LocalSnapshotManifest mismatched = fixture.Snapshot with { ManifestDigestSha256 = new string('f', 64) };

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Service.CleanupAsync(
            fixture.Execution, fixture.Backup, fixture.Plan, fixture.Authorization, mismatched, fixture.Key, CancellationToken.None));

        Assert.Equal("cleanup_authorization_invalid", failure.Code);
        Assert.Empty(fixture.Target.Deleted);
    }

    [Fact]
    public async Task CleanupAsync_TargetDriftAfterPartialDeletesProducesSignedFailureAndRetryCanFinish()
    {
        Fixture fixture = CreateFixture(failVerificationAt: 4);

        PostExportShadowCleanupReceipt failure = await fixture.Service.CleanupAsync(
            fixture.Execution, fixture.Backup, fixture.Plan, fixture.Authorization,
            fixture.Snapshot, fixture.Key, CancellationToken.None);
        PostExportShadowCleanupReceipt retry = await fixture.Service.CleanupAsync(
            fixture.Execution, fixture.Backup, fixture.Plan, fixture.Authorization,
            fixture.Snapshot, fixture.Key, CancellationToken.None);

        Assert.False(failure.IsComplete);
        ShadowCleanupOutcome drift = Assert.Single(failure.Cleanup, item => !item.Deleted);
        Assert.Equal("cleanup_target_drift", drift.ErrorCode);
        Assert.True(PostExportShadowCleanupAttestation.Verify(failure, new AcceptingTrust()));
        Assert.True(retry.IsComplete);
        Assert.Equal(27, fixture.Target.Deleted.Count);
        Assert.Equal(28, fixture.Verifier.CallCount);
    }

    [Fact]
    public async Task CleanupAsync_InvalidExecutionFailsBeforeAnyTargetMutation()
    {
        var target = new RecordingTarget();
        var service = new PostExportShadowCleanupService(
            target, new AcceptingTrust('a'), new AcceptingTrust('b'), new AcceptingTrust('c'),
            new FakeSigner(), new AcceptingTargetVerifier(), TimeProvider.System);
        var receipt = new MigrationExecutionReceipt(
            Guid.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty,
            DateTimeOffset.UtcNow, [], [], "execution-key", Convert.ToBase64String([1]));

        var backup = new BackupReceipt("1.1", DateTimeOffset.UtcNow, string.Empty, string.Empty, [], "backup-key", null);
        var plan = new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow, string.Empty, []);
        var authorization = new CleanupAuthorizationReceipt(
            "1.0", Guid.NewGuid(), string.Empty, string.Empty, DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5), "cleanup-run-owned-shadows",
            new("maliev-legacy", "legacy-postgres-main", "uid", "1", 1, 1,
                "Cluster in healthy state", 1, 1, "primary", "primary", true, true, true, true),
            "authorization-key", null);
        var snapshot = new LocalSnapshotManifest(2, "MLVSNP02", "AES-256-GCM-chunked-v2", "snapshot", string.Empty, string.Empty, []);

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => service.CleanupAsync(
            new(MigrationExecutionStatus.Completed, receipt), backup, plan, authorization, snapshot, new byte[32], CancellationToken.None));

        Assert.Equal("cleanup_execution_receipt_invalid", failure.Code);
        Assert.Equal(0, target.DeleteCount);
    }

    [Fact]
    public void CleanupEvidence_IsDomainSeparatedFromExecutionEvidence()
    {
        var cleanup = new PostExportShadowCleanupReceipt(
            "1.0", Guid.NewGuid(), new string('a', 64), new string('b', 64),
            DateTimeOffset.UtcNow, [], "execution-key", null);

        Assert.NotEqual(
            MigrationEvidenceAttestation.CreatePayload(cleanup),
            MigrationEvidenceAttestation.CreatePayload(new MigrationExecutionReceipt(
                cleanup.RunId, "source", "plan", "backup", "runner", "target",
                cleanup.CleanedAtUtc, [], [], "execution-key", null)));
    }

    private sealed class RecordingTarget : IPostgreSqlShadowTarget
    {
        public int DeleteCount => Deleted.Count;

        public List<string> Deleted { get; } = [];

        public string? FailOnceName { get; set; }

        public Task<ShadowDatabase> CreateUniqueEmptyShadowAsync(ShadowDatabase plannedShadow, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<bool> IsEmptyAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IPostgreSqlWholeDatabaseTransaction> BeginWholeDatabaseTransactionAsync(
            ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task DeleteRunOwnedShadowAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            if (FailOnceName == shadow.Name)
            {
                FailOnceName = null;
                throw new MigrationExecutionException("injected_delete_failure", "Injected cleanup failure.");
            }
            Deleted.Add(shadow.Name);
            return Task.CompletedTask;
        }
    }

    private sealed class AcceptingTrust(char fingerprint = 'a') : IReceiptAttestationTrustStore
    {
        public bool ContainsKey(string keyId)
        {
            return true;
        }

        public bool TryGetPublicKeyFingerprintSha256(string keyId, out string fingerprintSha256)
        {
            fingerprintSha256 = new string(fingerprint, 64);
            return true;
        }

        public bool Verify(string keyId, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
        {
            return true;
        }
    }

    private sealed class RejectingTrust : IReceiptAttestationTrustStore
    {
        public bool ContainsKey(string keyId)
        {
            return false;
        }

        public bool TryGetPublicKeyFingerprintSha256(string keyId, out string fingerprintSha256)
        {
            fingerprintSha256 = string.Empty;
            return false;
        }

        public bool Verify(string keyId, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
        {
            return false;
        }
    }

    private sealed class FakeSigner : IMigrationEvidenceSigner
    {
        public string KeyId => "execution-key";

        public string PublicKeyFingerprintSha256 => new('a', 64);

        public byte[] Sign(ReadOnlySpan<byte> payload)
        {
            return [1];
        }
    }

    private sealed class AcceptingTargetVerifier(int? failAt = null) : ICleanupTargetVerifier
    {
        private readonly int? _failAt = failAt;

        public int CallCount { get; private set; }

        public Task VerifyAsync(CleanupAuthorizationReceipt authorization, CancellationToken cancellationToken)
        {
            return ++CallCount == _failAt
                ? throw new RuntimeAttestationException("cleanup_target_drift", "Injected target drift.")
                : Task.CompletedTask;
        }
    }

    private static Fixture CreateFixture(int? failVerificationAt = null)
    {
        Guid runId = Guid.Parse("11111111-1111-4111-8111-111111111111");
        string source = new('a', 40);
        string backupHash = new('b', 64);
        var plan = new FreshSchemaPlan("2.0", Now.AddMinutes(-10), source, []);
        string planHash = SchemaPlanCanonicalizer.ComputeSha256(plan);
        IReadOnlyList<MigratedShadowDatabase> migrated = [.. DatabaseInventory.ActiveDatabases.Select((database, index) =>
            new MigratedShadowDatabase(database, GuardedShadowMigrationRunner.CreateShadowName(database, runId), index, new string('c', 64))
            {
                OwnerAttempt = 1,
                FencingToken = Guid.Parse($"{index + 1:x8}-1111-4111-8111-111111111111"),
            })];
        var executionReceipt = new MigrationExecutionReceipt(
            runId, source, planHash, backupHash, new string('d', 64), "7", Now.AddMinutes(-5),
            migrated, [], "execution-key", Convert.ToBase64String([1]));
        var execution = new MigrationExecutionResult(MigrationExecutionStatus.Completed, executionReceipt);
        IReadOnlyList<BackupArtifact?> artifacts = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            (BackupArtifact?)new BackupArtifact(database, "Full", $"Full_{database}.bak", 1, new string('e', 64), new string('e', 64))
            {
                CompletedAtUtc = Now.AddMinutes(-20),
                GcsObject = $"database/full/{database}.bak",
                GcsGeneration = 1,
                GcsSha256 = new string('e', 64),
            })];
        var backup = new BackupReceipt("1.1", Now.AddMinutes(-20), DatabaseInventory.InventorySha256,
            backupHash, artifacts, "backup-key", Convert.ToBase64String([1]))
        {
            SourceObservedAtUtc = Now.AddMinutes(-30),
        };
        byte[] key = Enumerable.Range(0, 32).Select(index => (byte)index).ToArray();
        IReadOnlyList<LocalSnapshotDatabase> entries = [.. migrated.Select(item => new LocalSnapshotDatabase(
            item.Database, item.ShadowName, $"{item.Database}.dump.aes256", 1, new string('1', 64), 2, new string('2', 64)))];
        string digest = SnapshotManifestAuthentication.ComputeSemanticDigest(runId.ToString("D"), entries);
        var unsignedSnapshot = new LocalSnapshotManifest(
            2, "MLVSNP02", "AES-256-GCM-chunked-v2", runId.ToString("D"), digest, string.Empty, entries);
        LocalSnapshotManifest snapshot = unsignedSnapshot with
        {
            ManifestMacSha256 = SnapshotManifestAuthentication.ComputeMac(unsignedSnapshot, key),
        };
        CloudNativePgTargetObservation targetObservation = HealthyTarget();
        var authorization = new CleanupAuthorizationReceipt(
            "1.0", runId, CleanupContract.ExecutionDigest(executionReceipt), digest,
            Now.AddMinutes(-1), Now.AddMinutes(30), "cleanup-run-owned-shadows", targetObservation,
            "authorization-key", Convert.ToBase64String([1]))
        {
            OwnerApproved = true,
        };
        var target = new RecordingTarget();
        var verifier = new AcceptingTargetVerifier(failVerificationAt);
        var service = new PostExportShadowCleanupService(
            target, new AcceptingTrust('a'), new AcceptingTrust('b'), new AcceptingTrust('c'),
            new FakeSigner(), verifier, new FixedTimeProvider(Now));
        return new(execution, backup, plan, authorization, snapshot, key, target, verifier, service);
    }

    private static CloudNativePgTargetObservation HealthyTarget()
    {
        return new("maliev-legacy", "legacy-postgres-main", "uid", "1", 7, 7,
            "Cluster in healthy state", 1, 1, "primary", "primary", true, true, true, true)
        {
            ReconciliationEvidence = "observed-generation",
            ObservationReadCount = 1,
            StatusInstances = 1,
            SystemId = "system-id",
            InstanceNames = "primary",
            HealthyInstances = "primary",
            PvcCount = 1,
            HealthyPvcs = "pvc-1",
            ReadyReason = "ClusterIsReady",
            ConsistentSystemIdReason = "Unique",
            ContinuousArchivingReason = "ContinuousArchivingSuccess",
            LastBackupSucceededReason = "LastBackupSucceeded",
        };
    }

    private sealed record Fixture(
        MigrationExecutionResult Execution,
        BackupReceipt Backup,
        FreshSchemaPlan Plan,
        CleanupAuthorizationReceipt Authorization,
        LocalSnapshotManifest Snapshot,
        byte[] Key,
        RecordingTarget Target,
        AcceptingTargetVerifier Verifier,
        PostExportShadowCleanupService Service);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
