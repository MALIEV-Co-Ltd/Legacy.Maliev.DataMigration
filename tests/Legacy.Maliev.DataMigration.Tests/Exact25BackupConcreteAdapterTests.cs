using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact25BackupConcreteAdapterTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"exact25-adapters-{Guid.NewGuid():N}");

    [Theory]
    [InlineData("abc123", "run-1", "abc123", "run-1", true)]
    [InlineData("abc123", "run-1", "replacement", "run-1", false)]
    [InlineData("abc123", "run-1", "abc123", "other-run", false)]
    public void DockerCleanup_RequiresImmutableIdAndRunLabel(
        string expectedId,
        string expectedRun,
        string observedId,
        string observedRun,
        bool expected)
    {
        Assert.Equal(expected, DockerDisposableSqlServerProvisioner.IsOwnedResourceEvidence(
            expectedId, expectedRun, observedId, observedRun));
    }

    [Theory]
    [InlineData("", "run-1", "daemon-id", "run-1", "daemon-id")]
    [InlineData("", "run-1", "daemon-id", "other-run", null)]
    [InlineData("abc123", "run-1", "abc123", "run-1", "abc123")]
    [InlineData("abc123", "run-1", "replacement", "run-1", null)]
    public void DockerCleanup_ReconcilesAmbiguousCreateOnlyByRunLabelAndUsesObservedImmutableId(
        string expectedId,
        string expectedRun,
        string observedId,
        string observedRun,
        string? removalId)
    {
        Assert.Equal(removalId, DockerDisposableSqlServerProvisioner.SelectOwnedResourceId(
            expectedId, expectedRun, observedId, observedRun));
    }

    [Theory]
    [InlineData(1, 0, "", true)]
    [InlineData(1, 0, "resource-still-present", false)]
    [InlineData(1, 1, "", false)]
    [InlineData(0, 0, "", false)]
    public void DockerCleanup_TreatsResourceAsAbsentOnlyAfterIndependentSuccessfulEmptyListing(
        int inspectExitCode,
        int listExitCode,
        string listing,
        bool absent)
    {
        Assert.Equal(absent, DockerDisposableSqlServerProvisioner.IsConfirmedAbsent(
            inspectExitCode, listExitCode, listing));
    }

    [Fact]
    public void DockerCleanup_RecordsNonZeroExitAndPreservesMachineReadableCode()
    {
        var failures = new List<Exception>();

        DockerDisposableSqlServerProvisioner.AddCleanupFailure(
            failures,
            exitCode: 1,
            code: "restore_container_cleanup_failed");

        Exact25FullBackupException failure = Assert.IsType<Exact25FullBackupException>(Assert.Single(failures));
        Assert.Equal("restore_container_cleanup_failed", failure.Code);
    }

    [Fact]
    public void DockerCleanup_AcceptsOnlySuccessfulRemoval()
    {
        var failures = new List<Exception>();

        DockerDisposableSqlServerProvisioner.AddCleanupFailure(
            failures,
            exitCode: 0,
            code: "restore_volume_cleanup_failed");

        Assert.Empty(failures);
    }

    [Theory]
    [InlineData(0, false, true)]
    [InlineData(0, true, false)]
    [InlineData(1, false, false)]
    public void DockerCleanup_RequiresSuccessfulCommandAndConfirmedPostRemovalAbsence(
        int removalExitCode,
        bool resourceStillExists,
        bool confirmed)
    {
        Assert.Equal(confirmed, DockerDisposableSqlServerProvisioner.IsRemovalConfirmed(
            removalExitCode, resourceStillExists));
    }

    [Fact]
    public async Task KubernetesAdapter_UsesPinnedPodIdentityExactInventoryAndSafeFixedCommands()
    {
        var runner = new RecordingBackupProcessRunner([
            Success(PodJson()),
            Success(),
            Success(PodJson()),
            Success(InventoryOutput()),
            Success(PodJson()),
            Success(PodJson()),
            Success(),
            Success(PodJson()),
            Success(PodJson()),
            Success(),
            Success("BACKUP_COMPLETED_AT_UTC|2026-08-30T01:04:05.0000000+00:00"),
            Success(PodJson()),
            Success(),
            Success("35|" + Hash("verified-full-backup:ContactRequest")),
            Success(PodJson()),
            Success(PodJson()),
            Success(),
            Success(PodJson()),
            Success(PodJson()),
            Success(),
            Success(PodJson()),
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
        Assert.Equal(new DateTimeOffset(2026, 8, 30, 1, 2, 3, TimeSpan.Zero), source.ObservedAtUtc);
        Assert.Equal(DatabaseInventory.Entries.Keys.Order(StringComparer.Ordinal), source.UserDatabases.Select(item => item.Name));
        Assert.Equal(Hash("verified-full-backup:ContactRequest"), artifact.Sha256);
        Assert.Equal(new DateTimeOffset(2026, 8, 30, 1, 4, 5, TimeSpan.Zero), artifact.CompletedAtUtc);
        Assert.All(runner.Invocations, invocation =>
        {
            Assert.DoesNotContain("backup-user", invocation.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("backup-password", invocation.ToString(), StringComparison.Ordinal);
        });
        SecureBackupProcessInvocation backup = Assert.Single(runner.Invocations, item => item.StandardInput.Contains("BACKUP DATABASE", StringComparison.Ordinal));
        Assert.Contains("COPY_ONLY", backup.StandardInput, StringComparison.Ordinal);
        Assert.Contains("CHECKSUM", backup.StandardInput, StringComparison.Ordinal);
        Assert.Contains(runner.Invocations, item => item.StandardInput.Contains("RESTORE VERIFYONLY", StringComparison.Ordinal));
        Assert.DoesNotContain("ContactRequest", string.Join(' ', backup.Arguments), StringComparison.Ordinal);
        SecureBackupProcessInvocation copy = Assert.Single(runner.StreamingInvocations);
        Assert.Equal("kubectl", copy.FileName);
        Assert.Contains("exec cat", string.Join(' ', copy.Arguments), StringComparison.Ordinal);
        Assert.Contains("/dev/shm/maliev-backup-session-", string.Join(' ', copy.Arguments), StringComparison.Ordinal);
        SecureBackupProcessInvocation metadata = Assert.Single(runner.Invocations, item =>
            string.Join(' ', item.Arguments).Contains("sha256sum", StringComparison.Ordinal));
        string metadataArguments = string.Join(' ', metadata.Arguments);
        Assert.Contains("stat -c %u", metadataArguments, StringComparison.Ordinal);
        Assert.Contains("stat -c %a", metadataArguments, StringComparison.Ordinal);
        Assert.Contains("realpath -e", metadataArguments, StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(_root, "Full_ContactRequest_run-1.bak")));
    }

    [Fact]
    public async Task KubernetesAdapter_PodReplacementAfterInventoryFailsClosed()
    {
        var runner = new RecordingBackupProcessRunner([
            Success(PodJson()),
            Success(),
            Success(PodJson(uid: "replacement-uid")),
        ]);
        var adapter = new KubernetesSqlServerFullBackupProcess(runner);

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            adapter.InspectSourceAsync(Request(), new("user", "password"), CancellationToken.None));

        Assert.Equal("source_identity_changed", exception.Code);
    }

    [Fact]
    public async Task KubernetesAdapter_ContainerRestartBeforeCredentialsFailsAtSessionFence()
    {
        var runner = new RecordingBackupProcessRunner([
            Success(PodJson()),
            Success(),
            Success(PodJson(containerId: "containerd://replacement")),
        ]);
        var adapter = new KubernetesSqlServerFullBackupProcess(runner);

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            adapter.InspectSourceAsync(Request(), new("user", "password"), CancellationToken.None));

        Assert.Equal("source_identity_changed", exception.Code);
        Assert.DoesNotContain(runner.Invocations, invocation => invocation.StandardInput.Contains("user", StringComparison.Ordinal));
    }

    [Fact]
    public async Task KubernetesAdapter_UnsafeRemoteParentFailsBeforeBackupMutation()
    {
        var runner = new RecordingBackupProcessRunner([
            Success(PodJson()),
            new BackupProcessResult(1, string.Empty, "unsafe remote parent"),
        ]);
        var adapter = new KubernetesSqlServerFullBackupProcess(runner);

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            adapter.PrepareRunAsync(Source(), "run-1", CancellationToken.None));

        Assert.Equal("remote_backup_destination_exists_or_unavailable", exception.Code);
        Assert.DoesNotContain(runner.Invocations, item => item.StandardInput.Contains("BACKUP DATABASE", StringComparison.Ordinal));
    }

    [Fact]
    public async Task KubernetesAdapter_CopyFailureCleansTemporaryFileAndIsExplicitlyRetryable()
    {
        var runner = new RecordingBackupProcessRunner([
            Success(PodJson()),
            new BackupProcessResult(1, string.Empty, "transport is closing"),
        ]);
        var adapter = new KubernetesSqlServerFullBackupProcess(runner);
        Exact25BackupSourceObservation source = Source();
        var artifact = new RemoteFullBackupArtifact(
            "ContactRequest", "maliev-backups/run-1/Full_ContactRequest_run-1.bak", 35,
            Hash("verified-full-backup:ContactRequest"),
            new DateTimeOffset(2026, 8, 30, 1, 4, 5, TimeSpan.Zero));
        OwnerProtectedDirectory.CreateNew(_root);

        Exact25BackupTransportException exception = await Assert.ThrowsAsync<Exact25BackupTransportException>(() =>
            adapter.CopyToLocalAsync(source, artifact, "Full_ContactRequest_run-1.bak", _root, CancellationToken.None));

        Assert.True(exception.Retryable);
        Assert.Empty(Directory.EnumerateFiles(_root));
    }

    [Fact]
    public async Task GoogleCloudAdapter_UsesCreateOnlyGenerationAndReadsExactGenerationBack()
    {
        OwnerProtectedDirectory.CreateNew(_root);
        string local = Path.Combine(_root, "backup.bak");
        await File.WriteAllTextAsync(local, "backup");
        string sha256 = Hash("backup");
        var gateway = new RecordingGoogleCloudBackupGateway(
            new GoogleCloudBackupObjectState("maliev.com", "database/full/2026-08-30/run-1/backup.bak", 42, 6, sha256),
            new GoogleCloudBackupObjectState("maliev.com", "database/full/2026-08-30/run-1/backup.bak", 42, 6, sha256),
            Encoding.UTF8.GetBytes("backup"));
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
        OwnerProtectedDirectory.CreateNew(_root);
        string local = Path.Combine(_root, "backup.bak");
        await File.WriteAllTextAsync(local, "backup");
        string sha256 = Hash("backup");
        var gateway = new RecordingGoogleCloudBackupGateway(
            new GoogleCloudBackupObjectState("maliev.com", "database/full/2026-08-30/run-1/backup.bak", 42, 6, sha256),
            new GoogleCloudBackupObjectState("maliev.com", "database/full/2026-08-30/run-1/backup.bak", 42, 6, new string('0', 64)),
            Encoding.UTF8.GetBytes("backup"));
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
        return "OBSERVED_AT_UTC|2026-08-30T01:02:03.0000000+00:00\n" +
            string.Join('\n', DatabaseInventory.Entries.Keys.Order(StringComparer.Ordinal).Select(name => $"{name}|ONLINE"));
    }

    [Fact]
    public async Task GoogleCloudAdapter_SameLengthCorruptDownloadedGenerationFailsClosed()
    {
        OwnerProtectedDirectory.CreateNew(_root);
        string local = Path.Combine(_root, "backup.bak");
        await File.WriteAllTextAsync(local, "backup");
        string sha256 = Hash("backup");
        var state = new GoogleCloudBackupObjectState("maliev.com", "database/full/2026-08-30/run-1/backup.bak", 42, 6, sha256);
        var storage = new GoogleCloudImmutableBackupObjectStorage(
            new RecordingGoogleCloudBackupGateway(state, state, Encoding.UTF8.GetBytes("tamper")));

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            storage.UploadNewAndReadBackAsync(local, "gs://maliev.com/database/full/2026-08-30/run-1/backup.bak", sha256, CancellationToken.None));

        Assert.Equal("cloud_backup_parity_invalid", exception.Code);
    }

    private static string PodJson(string uid = "pod-uid-1", string containerId = "containerd://container-1")
    {
        return JsonSerializer.Serialize(new
        {
            metadata = new { uid, name = "maliev-mssql-0", @namespace = "maliev" },
            spec = new { containers = new[] { new { name = "mssql" } } },
            status = new
            {
                conditions = new[] { new { type = "Ready", status = "True" } },
                containerStatuses = new[] { new
                {
                    name = "mssql", ready = true, containerID = containerId, imageID = "sha256:image-1",
                    state = new { running = new { startedAt = "2026-08-30T01:00:00Z" } },
                } },
            },
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
        new DateTimeOffset(2026, 8, 30, 1, 2, 3, TimeSpan.Zero),
        DatabaseInventory.Entries.Keys.Order(StringComparer.Ordinal).Select(name => new SqlServerDatabaseState(name, "ONLINE")).ToArray())
        { ContainerId = "containerd://container-1", ImageId = "sha256:image-1", SessionNonce = new string('a', 64) };
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
        public List<SecureBackupProcessInvocation> StreamingInvocations { get; } = [];

        public Task<BackupProcessResult> RunAsync(SecureBackupProcessInvocation invocation, CancellationToken cancellationToken)
        {
            Invocations.Add(invocation);
            BackupProcessResult result = _results.Dequeue();
            return Task.FromResult(result);
        }

        public Task<BackupProcessResult> RunToNewFileAsync(SecureBackupProcessInvocation invocation, string destinationPath, CancellationToken cancellationToken)
        {
            Invocations.Add(invocation);
            StreamingInvocations.Add(invocation);
            BackupProcessResult result = _results.Dequeue();
            return result.ExitCode == 0 ? WriteCopyAsync(destinationPath, result, cancellationToken) : Task.FromResult(result);
        }

        private static async Task<BackupProcessResult> WriteCopyAsync(string destination, BackupProcessResult result, CancellationToken cancellationToken)
        {
            await File.WriteAllTextAsync(destination, "verified-full-backup:ContactRequest", cancellationToken);
            return result;
        }
    }

    private sealed class RecordingGoogleCloudBackupGateway(
        GoogleCloudBackupObjectState upload,
        GoogleCloudBackupObjectState readback,
        byte[] downloadedBytes) : IGoogleCloudBackupGateway
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

        public Task DownloadAsync(string bucket, string objectName, long generation, Stream destination, CancellationToken cancellationToken)
        {
            Assert.Equal(ReadGeneration, generation);
            return destination.WriteAsync(downloadedBytes, cancellationToken).AsTask();
        }
    }
}
