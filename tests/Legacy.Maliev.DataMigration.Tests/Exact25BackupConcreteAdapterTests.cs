using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact25BackupConcreteAdapterTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"exact25-adapters-{Guid.NewGuid():N}");

    [Fact]
    public async Task KubernetesAdapter_UsesPinnedPodIdentityExactInventoryAndSafeFixedCommands()
    {
        var runner = new RecordingBackupProcessRunner([
            Success(PodJson()),
            Success(InventoryOutput()),
            Success(),
            Success(),
            Success("35|" + Hash("verified-full-backup:ContactRequest")),
            Success(),
            Success(),
        ]);
        var adapter = new KubernetesSqlServerFullBackupProcess(runner);
        Exact25FullBackupRequest request = Request();
        var credential = new SecureSqlBackupCredential("backup-user", "backup-password");

        Exact25BackupSourceObservation source = await adapter.InspectSourceAsync(request, credential, CancellationToken.None);
        await adapter.PrepareRunAsync(source, request.RunId, CancellationToken.None);
        RemoteFullBackupArtifact artifact = await adapter.CreateUniqueFullBackupAsync(
            source, "ContactRequest", "maliev-backups/run-1/Full_ContactRequest_run-1.bak", credential, CancellationToken.None);
        await adapter.VerifyRestoreAsync(source, artifact, credential, CancellationToken.None);
        OwnerProtectedDirectory.CreateNew(_root);
        await adapter.CopyToLocalAsync(source, artifact, "Full_ContactRequest_run-1.bak", _root, CancellationToken.None);

        Assert.Equal("pod-uid-1", source.PodUid);
        Assert.Equal(DatabaseInventory.Entries.Keys.Order(StringComparer.Ordinal), source.UserDatabases.Select(item => item.Name));
        Assert.Equal(Hash("verified-full-backup:ContactRequest"), artifact.Sha256);
        Assert.Equal(7, runner.Invocations.Count);
        Assert.All(runner.Invocations, invocation =>
        {
            Assert.DoesNotContain("backup-user", invocation.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("backup-password", invocation.ToString(), StringComparison.Ordinal);
        });
        Assert.Contains("COPY_ONLY", runner.Invocations[3].StandardInput, StringComparison.Ordinal);
        Assert.Contains("CHECKSUM", runner.Invocations[3].StandardInput, StringComparison.Ordinal);
        Assert.Contains("RESTORE VERIFYONLY", runner.Invocations[5].StandardInput, StringComparison.Ordinal);
        Assert.DoesNotContain("ContactRequest", string.Join(' ', runner.Invocations[3].Arguments), StringComparison.Ordinal);
        Assert.Equal("kubectl", runner.Invocations[6].FileName);
        Assert.Contains("cp", runner.Invocations[6].Arguments);
        Assert.True(File.Exists(Path.Combine(_root, "Full_ContactRequest_run-1.bak")));
    }

    [Fact]
    public async Task KubernetesAdapter_CopyFailureCleansTemporaryFileAndIsExplicitlyRetryable()
    {
        var runner = new RecordingBackupProcessRunner([new BackupProcessResult(1, string.Empty, "transport is closing")]);
        var adapter = new KubernetesSqlServerFullBackupProcess(runner);
        Exact25BackupSourceObservation source = Source();
        var artifact = new RemoteFullBackupArtifact(
            "ContactRequest", "maliev-backups/run-1/Full_ContactRequest_run-1.bak", 35,
            Hash("verified-full-backup:ContactRequest"));
        OwnerProtectedDirectory.CreateNew(_root);

        Exact25BackupTransportException exception = await Assert.ThrowsAsync<Exact25BackupTransportException>(() =>
            adapter.CopyToLocalAsync(source, artifact, "Full_ContactRequest_run-1.bak", _root, CancellationToken.None));

        Assert.True(exception.Retryable);
        Assert.Empty(Directory.EnumerateFiles(_root));
    }

    [Fact]
    public async Task GoogleCloudAdapter_UsesCreateOnlyGenerationAndReadsExactGenerationBack()
    {
        _ = Directory.CreateDirectory(_root);
        string local = Path.Combine(_root, "backup.bak");
        await File.WriteAllTextAsync(local, "backup");
        string sha256 = Hash("backup");
        var gateway = new RecordingGoogleCloudBackupGateway(
            new GoogleCloudBackupObjectState("maliev.com", "database/full/2026-08-30/run-1/backup.bak", 42, 6, sha256),
            new GoogleCloudBackupObjectState("maliev.com", "database/full/2026-08-30/run-1/backup.bak", 42, 6, sha256));
        var storage = new GoogleCloudImmutableBackupObjectStorage(gateway);

        ImmutableBackupObject result = await storage.UploadNewAndReadBackAsync(
            local, "gs://maliev.com/database/full/2026-08-30/run-1/backup.bak", sha256, CancellationToken.None);

        Assert.Equal(0, gateway.UploadRequest!.IfGenerationMatch);
        Assert.Equal(42, gateway.ReadGeneration);
        Assert.True(result.Immutable);
        Assert.Equal(42, result.Generation);
        Assert.Equal(sha256, result.Sha256);
    }

    [Fact]
    public async Task GoogleCloudAdapter_ReadbackDriftFailsClosed()
    {
        _ = Directory.CreateDirectory(_root);
        string local = Path.Combine(_root, "backup.bak");
        await File.WriteAllTextAsync(local, "backup");
        string sha256 = Hash("backup");
        var gateway = new RecordingGoogleCloudBackupGateway(
            new GoogleCloudBackupObjectState("maliev.com", "database/full/2026-08-30/run-1/backup.bak", 42, 6, sha256),
            new GoogleCloudBackupObjectState("maliev.com", "database/full/2026-08-30/run-1/backup.bak", 42, 6, new string('0', 64)));
        var storage = new GoogleCloudImmutableBackupObjectStorage(gateway);

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            storage.UploadNewAndReadBackAsync(
                local, "gs://maliev.com/database/full/2026-08-30/run-1/backup.bak", sha256, CancellationToken.None));

        Assert.Equal("cloud_backup_parity_invalid", exception.Code);
    }

    private static BackupProcessResult Success(string stdout = "")
    {
        return new(0, stdout, string.Empty);
    }

    private static string Hash(string value)
    {
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private static string InventoryOutput()
    {
        return string.Join('\n', DatabaseInventory.Entries.Keys.Order(StringComparer.Ordinal).Select(name => $"{name}|ONLINE"));
    }

    private static string PodJson()
    {
        return JsonSerializer.Serialize(new
        {
            metadata = new { uid = "pod-uid-1", name = "maliev-mssql-0", @namespace = "maliev" },
            spec = new { containers = new[] { new { name = "mssql" } } },
            status = new { conditions = new[] { new { type = "Ready", status = "True" } } },
        });
    }

    private static Exact25FullBackupRequest Request()
    {
        return new(
        "maliev", "maliev-mssql-0", "pod-uid-1", "mssql",
        "gs://maliev.com/database/full/2026-08-30/run-1/", "unused", "run-1",
        new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero), 3);
    }

    private static Exact25BackupSourceObservation Source()
    {
        return new(
        "maliev", "maliev-mssql-0", "pod-uid-1", "mssql", true,
        new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero), true,
        DatabaseInventory.Entries.Keys.Order(StringComparer.Ordinal).Select(name => new SqlServerDatabaseState(name, "ONLINE")).ToArray());
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class RecordingBackupProcessRunner(IEnumerable<BackupProcessResult> results) : IBackupProcessRunner
    {
        private readonly Queue<BackupProcessResult> _results = new(results);
        public List<SecureBackupProcessInvocation> Invocations { get; } = [];

        public Task<BackupProcessResult> RunAsync(SecureBackupProcessInvocation invocation, CancellationToken cancellationToken)
        {
            Invocations.Add(invocation);
            BackupProcessResult result = _results.Dequeue();
            if (invocation.Arguments.Contains("cp", StringComparer.Ordinal) && result.ExitCode == 0)
            {
                string destination = invocation.Arguments[^3];
                return WriteCopyAsync(destination, result, cancellationToken);
            }

            return Task.FromResult(result);
        }

        private static async Task<BackupProcessResult> WriteCopyAsync(string destination, BackupProcessResult result, CancellationToken cancellationToken)
        {
            await File.WriteAllTextAsync(destination, "verified-full-backup:ContactRequest", cancellationToken);
            return result;
        }
    }

    private sealed class RecordingGoogleCloudBackupGateway(
        GoogleCloudBackupObjectState upload,
        GoogleCloudBackupObjectState readback) : IGoogleCloudBackupGateway
    {
        public GoogleCloudBackupUploadRequest? UploadRequest { get; private set; }
        public long ReadGeneration { get; private set; }

        public Task<GoogleCloudBackupObjectState> UploadNewAsync(
            GoogleCloudBackupUploadRequest request,
            Stream source,
            CancellationToken cancellationToken)
        {
            UploadRequest = request;
            return Task.FromResult(upload);
        }

        public Task<GoogleCloudBackupObjectState> ReadAsync(
            string bucket,
            string objectName,
            long generation,
            CancellationToken cancellationToken)
        {
            ReadGeneration = generation;
            return Task.FromResult(readback);
        }
    }
}
