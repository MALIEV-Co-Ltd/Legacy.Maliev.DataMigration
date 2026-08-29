using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class LocalSnapshotExporterTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"legacy-export-{Guid.NewGuid():N}");

    [Fact]
    public async Task ExportAsync_WritesExactTwentyFiveEncryptedSnapshotsAndCredentialFreeManifest()
    {
        var source = new FakeDumpSource();
        byte[] key = RandomNumberGenerator.GetBytes(32);
        IReadOnlyList<MigratedShadowDatabase> databases = DatabaseInventory.ActiveDatabases
            .Select(database => new MigratedShadowDatabase(database, $"legacy_shadow_{database.ToLowerInvariant()}_{Guid.NewGuid():N}", 1, new string('a', 64)))
            .ToArray();

        LocalSnapshotManifest manifest = await LocalSnapshotExporter.ExportAsync(
            databases, _root, key, source, CancellationToken.None);

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
}
