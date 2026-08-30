using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class LocalSnapshotExporterTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"legacy-export-{Guid.NewGuid():N}");

    [Fact]
    public void Producer_UsesEncryptedOnlyStagingAndZeroesPlaintextBuffers()
    {
        string repository = FindRepositoryRoot();
        string exporter = File.ReadAllText(Path.Combine(repository, "src", "Legacy.Maliev.DataMigration", "LocalSnapshotExporter.cs"));
        string encryption = File.ReadAllText(Path.Combine(repository, "src", "Legacy.Maliev.DataMigration", "EncryptedSnapshotStream.cs"));
        Assert.DoesNotContain(".plain.tmp", exporter, StringComparison.Ordinal);
        Assert.Contains(".staged.aes256.tmp", exporter, StringComparison.Ordinal);
        Assert.Contains("DeriveProvisionalStagingKey", encryption, StringComparison.Ordinal);
        Assert.Contains("CryptographicOperations.ZeroMemory(plain", encryption, StringComparison.Ordinal);
        Assert.Contains("AggregateException", exporter, StringComparison.Ordinal);
        Assert.Contains("encrypted staging cleanup", exporter, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExportAsync_WritesExactTwentyFiveEncryptedSnapshotsAndCredentialFreeManifest()
    {
        var source = new FakeDumpSource();
        byte[] key = RandomNumberGenerator.GetBytes(32);
        IReadOnlyList<MigratedShadowDatabase> databases = DatabaseInventory.ActiveDatabases
            .Select(database => new MigratedShadowDatabase(database, $"legacy_shadow_{database.ToLowerInvariant()}_{Guid.NewGuid():N}", 1, new string('a', 64)))
            .ToArray();

        LocalSnapshotManifest manifest = await LocalSnapshotExporter.ExportAsync(
            databases, _root, "run-20260830", key, source, CancellationToken.None);

        Assert.Equal(2, manifest.SchemaVersion);
        Assert.Equal("AES-256-GCM-chunked-v2", manifest.Encryption);
        Assert.Equal("run-20260830", manifest.SnapshotId);
        Assert.Matches("^[0-9a-f]{64}$", manifest.ManifestDigestSha256);
        Assert.Matches("^[0-9a-f]{64}$", manifest.ManifestMacSha256);
        Assert.Equal(25, manifest.Databases.Count);
        Assert.Equal(DatabaseInventory.ActiveDatabases, source.Opened);
        Assert.All(manifest.Databases, database =>
        {
            Assert.EndsWith(".dump.aes256", database.FileName, StringComparison.Ordinal);
            Assert.True(File.Exists(Path.Combine(_root, database.FileName)));
            Assert.Matches("^[0-9a-f]{64}$", database.PlaintextSha256);
        });
        string json = await File.ReadAllTextAsync(Path.Combine(_root, "manifest.json"));
        Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(key), json, StringComparison.Ordinal);
        Assert.DoesNotContain(Directory.EnumerateFiles(_root), path => path.EndsWith(".tmp", StringComparison.Ordinal));
        Assert.DoesNotContain(Directory.EnumerateFiles(_root), path => path.Contains("plain", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ExportAsync_DumpFailureRemovesEncryptedStagingAndIncompleteOutput()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        IReadOnlyList<MigratedShadowDatabase> databases = DatabaseInventory.ActiveDatabases
            .Select(database => new MigratedShadowDatabase(database, $"legacy_shadow_{database.ToLowerInvariant()}_{Guid.NewGuid():N}", 1, new string('a', 64)))
            .ToArray();
        _ = await Assert.ThrowsAsync<IOException>(() => LocalSnapshotExporter.ExportAsync(databases, _root, "run-failure", key,
            new FailingDumpSource(), CancellationToken.None));
        Assert.False(Directory.Exists(_root));
    }

    [Fact]
    public async Task ExportAsync_InvalidSnapshotIdentityCreatesNoOutputDirectory()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        IReadOnlyList<MigratedShadowDatabase> databases = DatabaseInventory.ActiveDatabases
            .Select(database => new MigratedShadowDatabase(database, $"legacy_shadow_{database.ToLowerInvariant()}_{Guid.NewGuid():N}", 1, new string('a', 64)))
            .ToArray();

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            LocalSnapshotExporter.ExportAsync(databases, _root, "invalid identity", key, new FakeDumpSource(), CancellationToken.None));

        Assert.Equal("snapshot_identity_invalid", failure.Code);
        Assert.False(Directory.Exists(_root));
    }

    [Fact]
    public void SnapshotKeyDerivation_SeparatesEncryptionAndManifestAuthenticationKeys()
    {
        byte[] rootKey = RandomNumberGenerator.GetBytes(32);
        byte[] encryption = SnapshotKeyDerivation.DeriveEncryptionKey(rootKey);
        byte[] authentication = SnapshotKeyDerivation.DeriveManifestMacKey(rootKey);
        byte[] staging = SnapshotKeyDerivation.DeriveProvisionalStagingKey(rootKey);
        try { Assert.False(encryption.SequenceEqual(authentication)); Assert.False(encryption.SequenceEqual(staging)); Assert.False(authentication.SequenceEqual(staging)); }
        finally { CryptographicOperations.ZeroMemory(encryption); CryptographicOperations.ZeroMemory(authentication); CryptographicOperations.ZeroMemory(staging); }
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class FakeDumpSource : IPostgreSqlDumpSource
    {
        public List<string> Opened { get; } = [];

        public Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken)
        {
            Opened.Add(database);
            return Task.FromResult<Stream>(new MemoryStream(System.Text.Encoding.UTF8.GetBytes($"dump:{database}:{shadowDatabase}")));
        }
    }

    private sealed class FailingDumpSource : IPostgreSqlDumpSource
    {
        public Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken)
        {
            throw new IOException("controlled dump failure");
        }
    }

    private static string FindRepositoryRoot()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.DataMigration.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("Repository root not found.");
    }
}
