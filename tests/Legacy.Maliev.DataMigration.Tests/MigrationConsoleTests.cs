using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class MigrationConsoleTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"legacy-console-{Guid.NewGuid():N}");

    [Theory]
    [InlineData("receipt")]
    [InlineData("verify-backup")]
    public async Task RunAsync_StandaloneReceiptAndManifestCommandsAreDisabledBeforeReadingCallerSuppliedStateOrKey(
        string command)
    {
        _ = Directory.CreateDirectory(_root);
        string statePath = Path.Combine(_root, "backup-state.json");
        await File.WriteAllTextAsync(statePath, "must-not-be-read");
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
            [command, "--config", configPath],
            output,
            error,
            name => name == "LEGACY_MIGRATION_RECEIPT_SIGNING_KEY_FILE" ? keyPath : null,
            CancellationToken.None);

        Assert.Equal(64, exitCode);
        Assert.False(File.Exists(outputPath));
        Assert.Equal(string.Empty, output.ToString());
        Assert.Equal("subcommand_invalid" + Environment.NewLine, error.ToString());
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
        OwnerProtectedDirectory.CreateNew(_root);
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
                approvedRunUtc = new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero),
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
        ProtectFileOnUnix(configPath);
        ProtectFileOnUnix(keyPath);

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
    public async Task RunAsync_BackupFull_UnprotectedConfigurationFailsBeforeRuntimeComposition()
    {
        _ = Directory.CreateDirectory(_root);
        string configPath = Path.Combine(_root, "config.json");
        await File.WriteAllTextAsync(configPath, "{}");
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(configPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }
        var factory = new FakeExact25BackupRuntimeFactory();
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunForTestsAsync(
            ["backup-full", "--config", configPath], output, error,
            name => name == "LEGACY_DEPLOY_ENABLED" ? "false" : null, factory, CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal(0, factory.CreateAttempts);
        Assert.Equal("backup_config_unprotected" + Environment.NewLine, error.ToString());
    }

    [Fact]
    public async Task RunAsync_BackupFull_UnprotectedSigningKeyFailsBeforeRuntimeComposition()
    {
        OwnerProtectedDirectory.CreateNew(_root);
        string configPath = Path.Combine(_root, "config.json");
        string keyPath = Path.Combine(_root, "key.pem");
        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(new
        {
            fullBackup = new { allowSourceBackup = true },
        }, JsonOptions));
        await File.WriteAllTextAsync(keyPath, "not-read");
        ProtectFileOnUnix(configPath);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        }
        else
        {
            var security = new System.Security.AccessControl.FileSecurity();
            System.Security.Principal.SecurityIdentifier owner = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
            security.SetOwner(owner);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new(owner, System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
            security.AddAccessRule(new(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null),
                System.Security.AccessControl.FileSystemRights.Read, System.Security.AccessControl.AccessControlType.Allow));
            new FileInfo(keyPath).SetAccessControl(security);
        }
        var factory = new FakeExact25BackupRuntimeFactory();
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunForTestsAsync(
            ["backup-full", "--config", configPath], output, error,
            name => name switch
            {
                "LEGACY_DEPLOY_ENABLED" => "false",
                "LEGACY_MIGRATION_BACKUP_SQL_USERNAME" => "user",
                "LEGACY_MIGRATION_BACKUP_SQL_PASSWORD" => "password",
                "LEGACY_MIGRATION_RECEIPT_SIGNING_KEY_FILE" => keyPath,
                _ => null,
            }, factory, CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal(0, factory.CreateAttempts);
        Assert.Equal("backup_signing_key_unprotected" + Environment.NewLine, error.ToString());
    }

    [Fact]
    public async Task RunAsync_BackupFull_ProtectedFileThroughSymlinkAncestorFailsBeforeComposition()
    {
        string actual = Path.Combine(_root, "actual");
        OwnerProtectedDirectory.CreateNew(actual);
        string configPath = Path.Combine(actual, "config.json");
        await File.WriteAllTextAsync(configPath, "{}");
        ProtectFileOnUnix(configPath);
        string linked = Path.Combine(_root, "linked");
        _ = Directory.CreateSymbolicLink(linked, actual);
        var factory = new FakeExact25BackupRuntimeFactory();
        using var output = new StringWriter();
        using var error = new StringWriter();

        int exitCode = await MigrationConsole.RunForTestsAsync(
            ["backup-full", "--config", Path.Combine(linked, "config.json")], output, error,
            name => name == "LEGACY_DEPLOY_ENABLED" ? "false" : null, factory, CancellationToken.None);

        Assert.Equal(65, exitCode);
        Assert.Equal(0, factory.CreateAttempts);
        Assert.Equal("backup_config_unprotected" + Environment.NewLine, error.ToString());
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
                approvedRunUtc = new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero),
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

    private static void ProtectFileOnUnix(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
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
                request.ApprovedRunUtc.AddMinutes(1),
                DatabaseInventory.Entries.Keys.Order(StringComparer.Ordinal)
                    .Select(name => new SqlServerDatabaseState(name, "ONLINE")).ToArray())
            { ContainerId = "containerd://container-1", ImageId = "sha256:image-1", SessionNonce = new string('a', 64) });
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
            return Task.FromResult(new RemoteFullBackupArtifact(
                database, remoteRelativePath, content.Length, sha256, source.ObservedAtUtc.AddMinutes(1)));
        }

        public Task VerifyRestoreAsync(
            Exact25BackupSourceObservation source,
            RemoteFullBackupArtifact artifact,
            SecureSqlBackupCredential credential,
            CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public async Task CopyToLocalAsync(
            Exact25BackupSourceObservation source,
            RemoteFullBackupArtifact artifact,
            string localRelativePath,
            string workingDirectory,
            CancellationToken cancellationToken)
        {
            string path = Path.Combine(workingDirectory, localRelativePath);
            await File.WriteAllTextAsync(path, artifact.Database, cancellationToken);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
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
