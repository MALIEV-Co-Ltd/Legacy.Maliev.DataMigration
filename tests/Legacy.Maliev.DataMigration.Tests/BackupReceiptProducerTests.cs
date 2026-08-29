using System.Security.Cryptography;
using System.Text;
using System.Globalization;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class BackupReceiptProducerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"legacy-receipt-{Guid.NewGuid():N}");

    [Fact]
    public async Task ProduceAsync_ReReadsExactlyTwentyFiveLocalAndCloudArtifactsAndSignsCanonicalReceipt()
    {
        _ = Directory.CreateDirectory(_root);
        var states = new List<VerifiedBackupStateArtifact>();
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            string path = Path.Combine(_root, $"Full_{database}_2026-08-30_000000.bak");
            byte[] content = Encoding.UTF8.GetBytes($"verified-backup:{database}");
            await File.WriteAllBytesAsync(path, content);
            string sha256 = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            states.Add(new(database, path, $"database/full/run/{database}.bak", 1000 + states.Count, content.Length, sha256));
        }

        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        BackupReceipt receipt = await BackupReceiptProducer.ProduceAsync(
            states,
            "backup-producer-2026",
            key,
            DateTimeOffset.Parse("2026-08-30T00:00:00Z", CultureInfo.InvariantCulture),
            CancellationToken.None);

        Assert.Equal(25, receipt.Artifacts!.Count);
        Assert.All(receipt.Artifacts, artifact =>
        {
            Assert.NotNull(artifact);
            Assert.StartsWith("database/full/run/", artifact!.GcsObject, StringComparison.Ordinal);
            Assert.True(artifact.GcsGeneration > 0);
            Assert.Equal(artifact.Sha256, artifact.GcsSha256);
        });
        Assert.True(ReceiptAttestation.TryCreatePayload(receipt, out byte[] payload));
        Assert.True(key.VerifyData(payload, Convert.FromBase64String(receipt.AttestationSignature!), HashAlgorithmName.SHA256));
    }

    [Fact]
    public async Task ProduceAsync_MissingOrUnexpectedDatabaseFailsClosed()
    {
        _ = Directory.CreateDirectory(_root);
        var states = DatabaseInventory.ActiveDatabases.Skip(1)
            .Select(database => new VerifiedBackupStateArtifact(database, Path.Combine(_root, database), database, 1, 1, new string('a', 64)))
            .Append(new("Unexpected", Path.Combine(_root, "unexpected"), "unexpected", 1, 1, new string('a', 64)))
            .ToArray();
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        BackupReceiptProductionException exception = await Assert.ThrowsAsync<BackupReceiptProductionException>(() =>
            BackupReceiptProducer.ProduceAsync(states, "key", key, DateTimeOffset.UtcNow, CancellationToken.None));

        Assert.Equal("backup_state_database_coverage_invalid", exception.Code);
    }

    [Fact]
    public async Task ProduceAsync_TamperedLocalArtifactFailsBeforeSigning()
    {
        _ = Directory.CreateDirectory(_root);
        var states = new List<VerifiedBackupStateArtifact>();
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            string path = Path.Combine(_root, $"Full_{database}_2026-08-30_000000.bak");
            await File.WriteAllTextAsync(path, database);
            states.Add(new(database, path, database, 1, new FileInfo(path).Length, new string('0', 64)));
        }
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        BackupReceiptProductionException exception = await Assert.ThrowsAsync<BackupReceiptProductionException>(() =>
            BackupReceiptProducer.ProduceAsync(states, "key", key, DateTimeOffset.UtcNow, CancellationToken.None));

        Assert.Equal("backup_state_local_hash_mismatch", exception.Code);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}
