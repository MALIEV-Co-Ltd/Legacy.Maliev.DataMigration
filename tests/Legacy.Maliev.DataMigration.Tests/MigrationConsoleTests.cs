using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class MigrationConsoleTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"legacy-console-{Guid.NewGuid():N}");

    [Fact]
    public async Task RunAsync_Receipt_ReadsKeyFromEnvironmentReferencedFileAndWritesNoLocalPaths()
    {
        _ = Directory.CreateDirectory(_root);
        var states = new List<VerifiedBackupStateArtifact>();
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            string path = Path.Combine(_root, $"Full_{database}_2026-08-30_000000.bak");
            await File.WriteAllTextAsync(path, database);
            byte[] content = await File.ReadAllBytesAsync(path);
            string hash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            states.Add(new(database, path, $"database/full/run/{database}.bak", states.Count + 1, content.Length, hash));
        }
        string statePath = Path.Combine(_root, "backup-state.json");
        await File.WriteAllTextAsync(statePath, JsonSerializer.Serialize(new { artifacts = states }, JsonOptions));
        string outputPath = Path.Combine(_root, "receipt.json");
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            receipt = new { backupStatePath = statePath, outputPath, keyId = "producer-key" },
        }, JsonOptions));
        string keyPath = Path.Combine(_root, "signing-key.pem");
        using (ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            await File.WriteAllTextAsync(keyPath, key.ExportECPrivateKeyPem());
        }
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["receipt", "--config", configPath],
            output,
            error,
            name => name == "LEGACY_MIGRATION_RECEIPT_SIGNING_KEY_FILE" ? keyPath : null,
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(outputPath));
        string receiptJson = await File.ReadAllTextAsync(outputPath);
        Assert.DoesNotContain(_root, receiptJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PRIVATE KEY", receiptJson, StringComparison.Ordinal);
        Assert.Contains("receipt_complete", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task RunAsync_Plan_MissingSourceReferenceFailsWithoutPrintingConfiguration()
    {
        _ = Directory.CreateDirectory(_root);
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            plan = new { outputPath = Path.Combine(_root, "plan.json"), sourceCommitSha = new string('a', 40) },
        }, JsonOptions));
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["plan", "--config", configPath], output, error, _ => null, CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal("plan_source_reference_missing" + Environment.NewLine, error.ToString());
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task RunAsync_ExecuteShadow_MissingRuntimeReferencesFailsClosed()
    {
        _ = Directory.CreateDirectory(_root);
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            executeShadow = new
            {
                receiptPath = "receipt.json",
                planPath = "plan.json",
                authorizationPath = "authorization.json",
                outputPath = "execution.json",
                runnerDigestSha256 = new string('a', 64),
                receiptTrustedKeys = Array.Empty<object>(),
                authorizationTrustedKeys = Array.Empty<object>(),
                evidenceKeyId = "evidence-key",
            },
        }, JsonOptions));
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["execute-shadow", "--config", configPath], output, error, _ => null, CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal("shadow_runtime_reference_missing" + Environment.NewLine, error.ToString());
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task RunAsync_Evidence_MissingProtectedSigningKeyFailsClosed()
    {
        _ = Directory.CreateDirectory(_root);
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            evidence = new
            {
                executionResultPath = "execution.json",
                provenancePath = "provenance.json",
                receiptPath = "receipt.json",
                planPath = "plan.json",
                authorizationPath = "authorization.json",
                publicationDirectory = "publication",
                sourceSnapshotId = "source-current",
                backupUri = "gs://maliev.com/database/full/2026-08-30/",
                backupObjectGeneration = "generation-20260830",
                restoreId = "restore-current",
                evidenceId = Guid.NewGuid(),
                leaseId = Guid.NewGuid(),
                leaseAcquiredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5),
                leaseExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(30),
                backupTrustedKeys = Array.Empty<object>(),
                authorizationTrustedKeys = Array.Empty<object>(),
                executionTrustedKeys = Array.Empty<object>(),
                provenanceTrustedKeys = Array.Empty<object>(),
                evidenceKeyId = "evidence-key",
            },
        }, JsonOptions));
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["evidence", "--config", configPath], output, error, _ => null, CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal("evidence_runtime_reference_missing" + Environment.NewLine, error.ToString());
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task RunAsync_ExportLocalSnapshot_MissingProtectedRuntimeReferencesFailsClosed()
    {
        _ = Directory.CreateDirectory(_root);
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            exportLocalSnapshot = new
            {
                executionResultPath = "execution.json",
                outputDirectory = Path.Combine(_root, "snapshot"),
                pgDumpPath = "pg_dump",
            },
        }, JsonOptions));
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunAsync(
            ["export-local-snapshot", "--config", configPath], output, error, _ => null, CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal("snapshot_runtime_reference_missing" + Environment.NewLine, error.ToString());
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task RunAsync_BackupFull_ProtectedConfigurationAndEnvironmentComposeExactProducer()
    {
        _ = Directory.CreateDirectory(_root);
        string workingDirectory = Path.Combine(_root, "recovery");
        string publicationDirectory = Path.Combine(_root, "receipt-publication");
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            fullBackup = new
            {
                @namespace = "maliev",
                expectedPodName = "maliev-mssql-0",
                expectedPodUid = "pod-uid-1",
                containerName = "mssql",
                gcsPrefix = "gs://maliev.com/database/full/2026-08-30/run-1/",
                localWorkingDirectory = workingDirectory,
                runId = "run-1",
                immutableCutoffUtc = new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero),
                maximumTransportAttempts = 3,
                publicationDirectory,
                keyId = "backup-key",
                allowSourceBackup = true,
            },
        }, JsonOptions));
        string keyPath = Path.Combine(_root, "signing-key.pem");
        using (ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            await File.WriteAllTextAsync(keyPath, key.ExportECPrivateKeyPem());
        }

        var factory = new FakeExact25BackupRuntimeFactory();
        using var output = new StringWriter();
        using var error = new StringWriter();
        var environment = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["LEGACY_DEPLOY_ENABLED"] = "false",
            ["LEGACY_MIGRATION_BACKUP_SQL_USERNAME"] = "backup-user",
            ["LEGACY_MIGRATION_BACKUP_SQL_PASSWORD"] = "backup-password",
            ["LEGACY_MIGRATION_RECEIPT_SIGNING_KEY_FILE"] = keyPath,
        };

        int exitCode = await MigrationConsole.RunForTestsAsync(
            ["backup-full", "--config", configPath], output, error,
            name => environment.GetValueOrDefault(name), factory, CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(1, factory.CreateAttempts);
        Assert.True(File.Exists(Path.Combine(publicationDirectory, AtomicBackupReceiptPublisher.ReceiptFileName)));
        Assert.Contains("backup_full_complete", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
        Assert.DoesNotContain("backup-password", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("backup-password", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_BackupFull_DeployEnabledFailsBeforeRuntimeComposition()
    {
        _ = Directory.CreateDirectory(_root);
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            fullBackup = new
            {
                @namespace = "maliev",
                expectedPodName = "maliev-mssql-0",
                expectedPodUid = "pod-uid-1",
                containerName = "mssql",
                gcsPrefix = "gs://maliev.com/database/full/2026-08-30/run-1/",
                localWorkingDirectory = Path.Combine(_root, "recovery"),
                runId = "run-1",
                immutableCutoffUtc = new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero),
                maximumTransportAttempts = 3,
                publicationDirectory = Path.Combine(_root, "publication"),
                keyId = "backup-key",
                allowSourceBackup = true,
            },
        }, JsonOptions));
        var factory = new FakeExact25BackupRuntimeFactory();
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunForTestsAsync(
            ["backup-full", "--config", configPath], output, error,
            name => name == "LEGACY_DEPLOY_ENABLED" ? "true" : "not-used", factory, CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal(0, factory.CreateAttempts);
        Assert.Equal("backup_deploy_gate_invalid" + Environment.NewLine, error.ToString());
        Assert.Equal(string.Empty, output.ToString());
    }

    private static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class FakeExact25BackupRuntimeFactory : IExact25BackupRuntimeFactory
    {
        public int CreateAttempts { get; private set; }

        public Task<Exact25BackupRuntime> CreateAsync(CancellationToken cancellationToken)
        {
            CreateAttempts++;
            return Task.FromResult(new Exact25BackupRuntime(new FakeBackupProcess(), new FakeBackupStorage()));
        }
    }

    private sealed class FakeBackupProcess : IExact25FullBackupProcess
    {
        public Task<Exact25BackupSourceObservation> InspectSourceAsync(
            Exact25FullBackupRequest request,
            SecureSqlBackupCredential credential,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(new Exact25BackupSourceObservation(
                request.Namespace, request.ExpectedPodName, request.ExpectedPodUid, request.ContainerName, true,
                request.ImmutableCutoffUtc, true,
                DatabaseInventory.Entries.Keys.Order(StringComparer.Ordinal)
                    .Select(name => new SqlServerDatabaseState(name, "ONLINE")).ToArray()));
        }

        public Task PrepareRunAsync(Exact25BackupSourceObservation source, string runId, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<RemoteFullBackupArtifact> CreateUniqueFullBackupAsync(
            Exact25BackupSourceObservation source,
            string database,
            string remoteRelativePath,
            SecureSqlBackupCredential credential,
            CancellationToken cancellationToken)
        {
            byte[] content = System.Text.Encoding.UTF8.GetBytes(database);
            string sha256 = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            return Task.FromResult(new RemoteFullBackupArtifact(database, remoteRelativePath, content.Length, sha256));
        }

        public Task VerifyRestoreAsync(
            Exact25BackupSourceObservation source,
            RemoteFullBackupArtifact artifact,
            SecureSqlBackupCredential credential,
            CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task CopyToLocalAsync(
            Exact25BackupSourceObservation source,
            RemoteFullBackupArtifact artifact,
            string localRelativePath,
            string workingDirectory,
            CancellationToken cancellationToken)
        {
            return File.WriteAllTextAsync(Path.Combine(workingDirectory, localRelativePath), artifact.Database, cancellationToken);
        }
    }

    private sealed class FakeBackupStorage : IImmutableBackupObjectStorage
    {
        private long _generation;

        public Task<ImmutableBackupObject> UploadNewAndReadBackAsync(
            string localPath,
            string objectUri,
            string sha256,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(new ImmutableBackupObject(
                objectUri, Interlocked.Increment(ref _generation), new FileInfo(localPath).Length, sha256, true));
        }
    }
}
