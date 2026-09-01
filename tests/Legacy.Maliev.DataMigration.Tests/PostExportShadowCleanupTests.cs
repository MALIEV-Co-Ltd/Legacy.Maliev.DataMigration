namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PostExportShadowCleanupTests
{
    [Fact]
    public async Task CleanupAsync_InvalidExecutionFailsBeforeAnyTargetMutation()
    {
        var target = new RecordingTarget();
        var service = new PostExportShadowCleanupService(
            target, new AcceptingTrust(), new AcceptingTrust(), new AcceptingTrust(),
            new FakeSigner(), TimeProvider.System);
        var receipt = new MigrationExecutionReceipt(
            Guid.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty,
            DateTimeOffset.UtcNow, [], [], "execution-key", Convert.ToBase64String([1]));

        var backup = new BackupReceipt("1.1", DateTimeOffset.UtcNow, string.Empty, string.Empty, [], "backup-key", null);
        var plan = new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow, string.Empty, []);
        var authorization = new ExecutionAuthorizationReceipt(
            "2.1", Guid.NewGuid(), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5),
            string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, [], "shadow-only", "authorization-key", null)
        {
            TargetObservation = new("maliev-legacy", "legacy-postgres-main", "uid", "1", 1, 1,
                "Cluster in healthy state", 1, 1, "primary", "primary", true, true, true, true),
        };
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
        public int DeleteCount { get; private set; }

        public Task<ShadowDatabase> CreateUniqueEmptyShadowAsync(ShadowDatabase plannedShadow, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<bool> IsEmptyAsync(ShadowDatabase shadow, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<IPostgreSqlWholeDatabaseTransaction> BeginWholeDatabaseTransactionAsync(
            ShadowDatabase shadow, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task DeleteRunOwnedShadowAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            DeleteCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class AcceptingTrust : IReceiptAttestationTrustStore
    {
        public bool ContainsKey(string keyId) => true;

        public bool TryGetPublicKeyFingerprintSha256(string keyId, out string fingerprintSha256)
        {
            fingerprintSha256 = new string('a', 64);
            return true;
        }

        public bool Verify(string keyId, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature) => true;
    }

    private sealed class FakeSigner : IMigrationEvidenceSigner
    {
        public string KeyId => "execution-key";

        public string PublicKeyFingerprintSha256 => new('a', 64);

        public byte[] Sign(ReadOnlySpan<byte> payload) => [1];
    }
}
