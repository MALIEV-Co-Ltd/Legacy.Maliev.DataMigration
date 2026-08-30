namespace Legacy.Maliev.DataMigration.Tests;

public sealed class GoogleCloudImmutablePostgreSqlSnapshotObserverTests
{
    [Fact]
    public async Task ObserveAsync_ReadsExactGenerationAndRequiredRecoveryMetadata()
    {
        byte[] content = "immutable quotation snapshot"u8.ToArray();
        string checksum = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content)).ToLowerInvariant();
        var gateway = new Gateway(new(42, content.Length, new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["maliev-snapshot-id"] = "cnpg-20260830-001",
            ["maliev-sha256"] = checksum,
            ["maliev-recovery-point-utc"] = "2026-08-30T12:00:00.0000000+00:00",
        }), content);
        var observer = new GoogleCloudImmutablePostgreSqlSnapshotObserver(gateway);

        ImmutablePostgreSqlSnapshotObservation result = await observer.ObserveAsync(
            "gs://maliev-backups/quotation/snapshot.dump", 42, CancellationToken.None);

        Assert.Equal(42, result.BackupObjectGeneration);
        Assert.Equal(content.Length, result.BackupObjectByteLength);
        Assert.Equal("quotation/snapshot.dump", gateway.ObjectName);
        Assert.Equal(42, gateway.Generation);
    }

    [Fact]
    public async Task ObserveAsync_RejectsMissingMetadataOrGenerationDrift()
    {
        byte[] content = "snapshot"u8.ToArray();
        string checksum = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content)).ToLowerInvariant();
        var missing = new GoogleCloudImmutablePostgreSqlSnapshotObserver(new Gateway(new(42, content.Length,
            new Dictionary<string, string>(StringComparer.Ordinal)), content));
        var drift = new GoogleCloudImmutablePostgreSqlSnapshotObserver(new Gateway(new(43, content.Length,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["maliev-snapshot-id"] = "cnpg-20260830-001",
                ["maliev-sha256"] = checksum,
                ["maliev-recovery-point-utc"] = "2026-08-30T12:00:00.0000000+00:00",
            }), content));

        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => missing.ObserveAsync(
            "gs://maliev-backups/quotation/snapshot.dump", 42, CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => drift.ObserveAsync(
            "gs://maliev-backups/quotation/snapshot.dump", 42, CancellationToken.None));
    }

    [Fact]
    public async Task ObserveAsync_RejectsMetadataChecksumThatDoesNotMatchExactGenerationBytes()
    {
        byte[] content = "snapshot"u8.ToArray();
        var observer = new GoogleCloudImmutablePostgreSqlSnapshotObserver(new Gateway(new(42, content.Length,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["maliev-snapshot-id"] = "cnpg-20260830-001",
                ["maliev-sha256"] = new string('a', 64),
                ["maliev-recovery-point-utc"] = "2026-08-30T12:00:00.0000000+00:00",
            }), content));

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() => observer.ObserveAsync(
            "gs://maliev-backups/quotation/snapshot.dump", 42, CancellationToken.None));

        Assert.Equal("quotation_snapshot_object_observation_invalid", exception.Code);
    }

    private sealed class Gateway(ImmutablePostgreSqlSnapshotObjectState state, byte[] content) : IImmutablePostgreSqlSnapshotObjectGateway
    {
        public string? ObjectName { get; private set; }
        public long Generation { get; private set; }
        public Task<ImmutablePostgreSqlSnapshotObjectState> ReadAsync(string bucket, string objectName, long generation, CancellationToken cancellationToken)
        {
            ObjectName = objectName;
            Generation = generation;
            return Task.FromResult(state);
        }

        public Task DownloadAsync(string bucket, string objectName, long generation, Stream destination, CancellationToken cancellationToken)
        {
            return destination.WriteAsync(content, cancellationToken).AsTask();
        }
    }
}
