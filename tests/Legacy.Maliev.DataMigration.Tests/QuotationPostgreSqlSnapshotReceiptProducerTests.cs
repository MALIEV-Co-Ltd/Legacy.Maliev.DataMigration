using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class QuotationPostgreSqlSnapshotReceiptProducerTests
{
    [Fact]
    public async Task Produce_BindsImmutableObjectAndObservedCluster()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("quotation-snapshot-v1", key.ExportECPrivateKeyPem());
        DateTimeOffset now = DateTimeOffset.UtcNow;

        var request = Request(now);
        QuotationPostgreSqlSnapshotReceipt receipt = await QuotationPostgreSqlSnapshotReceiptProducer.ProduceAsync(
            request, signer, new SnapshotObserver(Snapshot(now)), new TargetObserver(Target()), TimeProvider.System, CancellationToken.None);

        using JsonDocument envelope = JsonDocument.Parse(receipt.EnvelopeJson);
        string json = envelope.RootElement.GetProperty("Payload").GetString()!;
        var payload = JsonSerializer.Deserialize<QuotationPostgreSqlSnapshotReceiptPayload>(json)!;
        Assert.Equal("gs://maliev-backups/quotation/snapshot.dump", payload.BackupObjectUri);
        Assert.Equal(42, payload.BackupObjectGeneration);
        Assert.Equal(8192, payload.BackupObjectByteLength);
        Assert.Equal("cluster-uid", payload.ClusterUid);
        byte[] signature = Convert.FromBase64String(envelope.RootElement.GetProperty("Signature").GetString()!);
        Assert.True(key.VerifyData(QuotationPostgreSqlSnapshotReceiptCanonicalizer.CreatePayload(payload), signature, HashAlgorithmName.SHA256));
    }

    [Fact]
    public async Task Produce_RejectsRoleReuseOrUnhealthyTarget()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("quotation-snapshot-v1", key.ExportECPrivateKeyPem());
        DateTimeOffset now = DateTimeOffset.UtcNow;
        QuotationPostgreSqlSnapshotReceiptRequest request = Request(now);

        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => QuotationPostgreSqlSnapshotReceiptProducer.ProduceAsync(
            request with { ForbiddenSignerFingerprints = [signer.PublicKeyFingerprintSha256] }, signer,
            new SnapshotObserver(Snapshot(now)), new TargetObserver(Target()), TimeProvider.System, CancellationToken.None));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => QuotationPostgreSqlSnapshotReceiptProducer.ProduceAsync(
            request, signer, new SnapshotObserver(Snapshot(now)), new TargetObserver(Target() with { Ready = false }),
            TimeProvider.System, CancellationToken.None));
    }

    [Fact]
    public async Task Produce_RejectsImmutableObjectDriftBetweenObservations()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("quotation-snapshot-v1", key.ExportECPrivateKeyPem());
        DateTimeOffset now = DateTimeOffset.UtcNow;
        ImmutablePostgreSqlSnapshotObservation first = Snapshot(now);
        var observer = new SequenceSnapshotObserver(first, first with { BackupObjectByteLength = first.BackupObjectByteLength + 1 });

        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => QuotationPostgreSqlSnapshotReceiptProducer.ProduceAsync(
            Request(now), signer, observer, new TargetObserver(Target()), TimeProvider.System, CancellationToken.None));
        Assert.Equal(2, observer.Calls);
    }

    private static QuotationPostgreSqlSnapshotReceiptRequest Request(DateTimeOffset now)
    {
        return new("quotation", Guid.Parse("34829fe9-1b24-42b5-8bdf-e38c9ed1e4bb"), "source-20260830", "copy-plan-20260830",
            new string('a', 64), "legacy-postgres-pooler-rw.maliev-legacy.svc.cluster.local", 5432, "Quotation",
            "cnpg-20260830-001", "gs://maliev-backups/quotation/snapshot.dump", 42,
            "maliev-legacy", "legacy-postgres-main", now.AddMinutes(10), [new string('c', 64)]);
    }

    private static ImmutablePostgreSqlSnapshotObservation Snapshot(DateTimeOffset now)
    {
        return new("cnpg-20260830-001", "gs://maliev-backups/quotation/snapshot.dump", 42, 8192, new string('b', 64), now.AddMinutes(-2));
    }

    private static CloudNativePgTargetObservation Target()
    {
        return new(
            "maliev-legacy", "legacy-postgres-main", "cluster-uid", "123", 7, 7, "Cluster in healthy state", 2, 2,
            "primary-1", "primary-1", true, true, true, true)
        {
            ReconciliationEvidence = "observed-generation",
            ObservationReadCount = 1,
            StatusInstances = 2,
            SystemId = "123456789",
            InstanceNames = "primary-1\nreplica-1",
            HealthyInstances = "primary-1\nreplica-1",
            PvcCount = 2,
            HealthyPvcs = "primary-1\nreplica-1",
            ReadyReason = "ClusterIsReady",
            ConsistentSystemIdReason = "Unique",
            ContinuousArchivingReason = "ContinuousArchivingSuccess",
            LastBackupSucceededReason = "LastBackupSucceeded",
        };
    }

    private sealed class SnapshotObserver(ImmutablePostgreSqlSnapshotObservation observation) : IImmutablePostgreSqlSnapshotObserver
    {
        public Task<ImmutablePostgreSqlSnapshotObservation> ObserveAsync(string backupObjectUri, long backupObjectGeneration, CancellationToken cancellationToken)
        {
            return Task.FromResult(observation);
        }
    }
    private sealed class TargetObserver(CloudNativePgTargetObservation observation) : ICloudNativePgTargetObserver
    {
        public Task<CloudNativePgTargetObservation> ObserveAsync(string namespaceName, string cluster, CancellationToken cancellationToken)
        {
            return Task.FromResult(observation);
        }
    }

    private sealed class SequenceSnapshotObserver(params ImmutablePostgreSqlSnapshotObservation[] observations) : IImmutablePostgreSqlSnapshotObserver
    {
        public int Calls { get; private set; }
        public Task<ImmutablePostgreSqlSnapshotObservation> ObserveAsync(string backupObjectUri, long backupObjectGeneration, CancellationToken cancellationToken)
        {
            return Task.FromResult(observations[Calls++]);
        }
    }
}
