using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Exact25FullBackupProducerTests : IDisposable
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"exact25-backup-{Guid.NewGuid():N}");
    private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public void ActiveBackupInventory_IsTheApprovedExact25Contract()
    {
        string[] expected = [
            "ContactRequest", "Country", "Currency", "Customer", "CustomerIdentity", "DataProtectionKeys",
            "DataProtectionKeysEmployee", "Employee", "EmployeeIdentity", "Hangfire", "Invoice", "JobOffers",
            "LocationData", "Log", "Material", "Message", "Order", "OrderStatus", "Payment", "PurchaseOrder",
            "Quotation", "QuotationRequest", "Receipt", "Supplier", "Upload",
        ];

        Assert.Equal(expected, DatabaseInventory.ActiveDatabases);
    }

    [Fact]
    public async Task ProduceAsync_ExactOnlineSource_VerifiesUploadsAndPublishesSignedCaptureProvenance()
    {
        var process = new FakeProcess();
        var storage = new FakeStorage();
        var publisher = new FakePublisher();
        Exact25FullBackupRequest request = Request();

        BackupReceipt receipt = await Exact25FullBackupProducer.ProduceAsync(
            request, Credential(), process, storage, publisher, "backup-key", _signingKey, CancellationToken.None);

        Assert.Equal(25, receipt.Artifacts!.Count);
        Assert.Equal(DatabaseInventory.ActiveDatabases, process.Created);
        Assert.Equal(DatabaseInventory.ActiveDatabases, process.Verified);
        Assert.Equal(DatabaseInventory.ActiveDatabases, process.Copied);
        Assert.Equal(25, storage.Uploads.Count);
        Assert.Same(receipt, publisher.Published);
        Assert.Equal("1.1", receipt.SchemaVersion);
        Assert.True(ReceiptAttestation.TryCreatePayload(receipt, out byte[] payload));
        Assert.True(_signingKey.VerifyData(
            payload, Convert.FromBase64String(receipt.AttestationSignature!), HashAlgorithmName.SHA256));
        var trust = new ReceiptAttestationTrustStore([
            new TrustedAttestationKey("backup-key", _signingKey.ExportSubjectPublicKeyInfo()),
        ]);
        var restoreTarget = new FakeRestoreTarget();
        await VerifiedBackupRestorer.RestoreAsync(
            receipt, trust, request.LocalWorkingDirectory, restoreTarget, CancellationToken.None);
        Assert.Equal(DatabaseInventory.ActiveDatabases, restoreTarget.Restored);
        Assert.All(receipt.Artifacts!, artifact =>
        {
            Assert.Equal("Full", artifact!.BackupType);
            Assert.True(artifact.GcsGeneration > 0);
            Assert.Equal(artifact.Sha256, artifact.GcsSha256);
        });
        Assert.DoesNotContain("MachineLearning", string.Join('|', process.Created), StringComparison.Ordinal);
        Assert.DoesNotContain("MachineLearningData", string.Join('|', process.Created), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RestoreAsync_TamperedSignedReceiptFailsBeforeRestore()
    {
        BackupReceipt receipt = await ProduceReceiptAsync();
        BackupArtifact first = receipt.Artifacts![0]!;
        BackupReceipt tampered = receipt with
        {
            Artifacts = [first with { Sha256 = new string('0', 64) }, .. receipt.Artifacts.Skip(1)],
        };
        var target = new FakeRestoreTarget();

        Exact25FullBackupException failure = await Assert.ThrowsAsync<Exact25FullBackupException>(
            () => VerifiedBackupRestorer.RestoreAsync(tampered, Trust(), _root, target, CancellationToken.None));

        Assert.Equal("restore_receipt_invalid", failure.Code);
        Assert.Empty(target.Restored);
    }

    [Fact]
    public async Task RestoreAsync_SameLengthArtifactCorruptionFailsBeforeRestore()
    {
        BackupReceipt receipt = await ProduceReceiptAsync();
        string path = Path.Combine(_root, receipt.Artifacts![0]!.FileName!);
        byte[] bytes = await File.ReadAllBytesAsync(path);
        bytes[0] ^= 0xff;
        await File.WriteAllBytesAsync(path, bytes);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        var target = new FakeRestoreTarget();

        Exact25FullBackupException failure = await Assert.ThrowsAsync<Exact25FullBackupException>(
            () => VerifiedBackupRestorer.RestoreAsync(receipt, Trust(), _root, target, CancellationToken.None));

        Assert.Equal("restore_artifact_invalid", failure.Code);
        Assert.Empty(target.Restored);
    }

    [Fact]
    public async Task RestoreAsync_UnprotectedOrSymlinkedArtifactFailsBeforeRestore()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        BackupReceipt receipt = await ProduceReceiptAsync();
        string path = Path.Combine(_root, receipt.Artifacts![0]!.FileName!);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        var target = new FakeRestoreTarget();
        _ = await Assert.ThrowsAsync<Exact25FullBackupException>(
            () => VerifiedBackupRestorer.RestoreAsync(receipt, Trust(), _root, target, CancellationToken.None));
        Assert.Empty(target.Restored);

        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        string outside = Path.Combine(Path.GetTempPath(), $"restore-link-{Guid.NewGuid():N}.bak");
        File.Move(path, outside);
        try
        {
            _ = File.CreateSymbolicLink(path, outside);
            _ = await Assert.ThrowsAsync<Exact25FullBackupException>(
                () => VerifiedBackupRestorer.RestoreAsync(receipt, Trust(), _root, target, CancellationToken.None));
            Assert.Empty(target.Restored);
        }
        finally
        {
            File.Delete(path);
            File.Delete(outside);
        }
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("offline")]
    [InlineData("duplicate")]
    public async Task ProduceAsync_NonExactOnlineInventoryFailsBeforeBackup(string drift)
    {
        var process = new FakeProcess { InventoryDrift = drift };

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            Exact25FullBackupProducer.ProduceAsync(
                Request(), Credential(), process, new FakeStorage(), new FakePublisher(), "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal("source_database_inventory_invalid", exception.Code);
        Assert.Empty(process.Created);
    }

    [Theory]
    [InlineData("namespace")]
    [InlineData("pod")]
    [InlineData("uid")]
    [InlineData("not-ready")]
    public async Task ProduceAsync_SourceIdentityMismatchFailsBeforeBackup(string drift)
    {
        var process = new FakeProcess { SourceDrift = drift };

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            Exact25FullBackupProducer.ProduceAsync(
                Request(), Credential(), process, new FakeStorage(), new FakePublisher(), "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal("source_identity_invalid", exception.Code);
        Assert.Empty(process.Created);
    }

    [Fact]
    public async Task ProduceAsync_ReceiptUsesLatestObservedBackupCompletionNotApprovedRunTime()
    {
        var process = new FakeProcess();

        BackupReceipt receipt = await Exact25FullBackupProducer.ProduceAsync(
            Request(), Credential(), process, new FakeStorage(), new FakePublisher(),
            "backup-key", _signingKey, CancellationToken.None);

        Assert.Equal(process.CompletedAtUtc.Values.Max(), receipt.CapturedAtUtc);
        Assert.NotEqual(Request().ApprovedRunUtc, receipt.CapturedAtUtc);
        Assert.Equal(Request().ApprovedRunUtc.AddMinutes(1), receipt.SourceObservedAtUtc);
        Assert.All(receipt.Artifacts!, artifact =>
            Assert.Equal(process.CompletedAtUtc[artifact!.Database!], artifact.CompletedAtUtc));
    }

    [Fact]
    public async Task ProduceAsync_BackupCompletionBeforeSourceObservationFailsWithoutPublishing()
    {
        var process = new FakeProcess { CompleteBeforeObservation = true };
        var publisher = new FakePublisher();

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            Exact25FullBackupProducer.ProduceAsync(Request(), Credential(), process, new FakeStorage(), publisher,
                "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal("backup_capture_time_invalid", exception.Code);
        Assert.Null(publisher.Published);
    }

    [Fact]
    public async Task ProduceAsync_AmbiguousBackupFailureIsNeverRetried()
    {
        var process = new FakeProcess { FailCreate = true };

        _ = await Assert.ThrowsAsync<Exact25FullBackupException>(() => Exact25FullBackupProducer.ProduceAsync(
            Request(), Credential(), process, new FakeStorage(), new FakePublisher(), "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal(1, process.CreateAttempts);
    }

    [Fact]
    public async Task ProduceAsync_UnambiguousCopyTransportFailureUsesBoundedRetry()
    {
        var process = new FakeProcess { CopyTransportFailuresRemaining = 2 };

        _ = await Exact25FullBackupProducer.ProduceAsync(
            Request(), Credential(), process, new FakeStorage(), new FakePublisher(), "backup-key", _signingKey, CancellationToken.None);

        Assert.Equal(27, process.CopyAttempts);
    }

    [Fact]
    public async Task ProduceAsync_LocalOrCloudParityMismatchFailsWithoutPublishingAndRetainsBackups()
    {
        var process = new FakeProcess();
        var storage = new FakeStorage { ReturnWrongSize = true };
        var publisher = new FakePublisher();

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            Exact25FullBackupProducer.ProduceAsync(
                Request(), Credential(), process, storage, publisher, "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal("cloud_backup_parity_invalid", exception.Code);
        Assert.Null(publisher.Published);
        Assert.NotEmpty(Directory.EnumerateFiles(_root, "*.bak", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task ProduceAsync_SameLengthCopyCorruptionFailsBeforeUploadOrPublication()
    {
        var process = new FakeProcess { CorruptCopiedBytes = true };
        var storage = new FakeStorage();
        var publisher = new FakePublisher();

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            Exact25FullBackupProducer.ProduceAsync(
                Request(), Credential(), process, storage, publisher, "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal("local_backup_hash_invalid", exception.Code);
        Assert.Empty(storage.Uploads);
        Assert.Null(publisher.Published);
    }

    [Theory]
    [InlineData("gs://maliev.com/database/full/2026-08-29/run-1/")]
    [InlineData("gs://maliev.com/database/full/2026-08-30/run-2/")]
    public async Task ProduceAsync_GcsPrefixNotBoundToApprovedRunDateAndRunIdFailsBeforeInspection(string gcsPrefix)
    {
        var process = new FakeProcess();

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            Exact25FullBackupProducer.ProduceAsync(
                Request() with { GcsPrefix = gcsPrefix }, Credential(), process, new FakeStorage(), new FakePublisher(),
                "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal("backup_request_invalid", exception.Code);
        Assert.Equal(0, process.InspectAttempts);
    }

    [Fact]
    public async Task ProduceAsync_RecoveryDirectoryIsOwnerOnly()
    {
        _ = await Exact25FullBackupProducer.ProduceAsync(
            Request(), Credential(), new FakeProcess(), new FakeStorage(), new FakePublisher(),
            "backup-key", _signingKey, CancellationToken.None);

        if (OperatingSystem.IsWindows())
        {
            AssertOwnerOnlyWindowsDirectory(_root);
        }
        else
        {
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                File.GetUnixFileMode(_root));
        }
    }

    [Fact]
    public async Task ProduceAsync_PreExistingSymbolicLinkDestinationIsRejectedWithoutTouchingTarget()
    {
        string target = _root + "-target";
        _ = Directory.CreateDirectory(target);
        string marker = Path.Combine(target, "owner-data.txt");
        await File.WriteAllTextAsync(marker, "preserve");
        _ = Directory.CreateSymbolicLink(_root, target);

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() => Exact25FullBackupProducer.ProduceAsync(
            Request(), Credential(), new FakeProcess(), new FakeStorage(), new FakePublisher(),
            "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal("local_backup_destination_exists", exception.Code);
        Assert.Equal("preserve", await File.ReadAllTextAsync(marker));
        Directory.Delete(_root);
        Directory.Delete(target, recursive: true);
    }

    [Fact]
    public async Task ProduceAsync_SymbolicLinkAncestorIsRejectedWithoutWritingThroughIt()
    {
        string realParent = _root + "-real-parent";
        string linkedParent = _root + "-linked-parent";
        _ = Directory.CreateDirectory(realParent);
        _ = Directory.CreateSymbolicLink(linkedParent, realParent);

        _ = await Assert.ThrowsAsync<IOException>(() => Exact25FullBackupProducer.ProduceAsync(
            Request() with { LocalWorkingDirectory = Path.Combine(linkedParent, "recovery") },
            Credential(), new FakeProcess(), new FakeStorage(), new FakePublisher(),
            "backup-key", _signingKey, CancellationToken.None));

        Assert.Empty(Directory.EnumerateFileSystemEntries(realParent));
        Directory.Delete(linkedParent);
        Directory.Delete(realParent);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void AssertOwnerOnlyWindowsDirectory(string path)
    {
        System.Security.AccessControl.DirectorySecurity security = new DirectoryInfo(path).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        System.Security.Principal.SecurityIdentifier owner = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
        Assert.All(
            security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(System.Security.Principal.SecurityIdentifier))
                .Cast<System.Security.AccessControl.FileSystemAccessRule>()
                .Where(rule => rule.AccessControlType == System.Security.AccessControl.AccessControlType.Allow),
            rule => Assert.Equal(owner, rule.IdentityReference));
    }

    [Fact]
    public async Task ProduceAsync_ReceiptPublicationFailureRetainsAllRecoveryBackups()
    {
        var publisher = new FakePublisher { Fail = true };

        _ = await Assert.ThrowsAsync<IOException>(() => Exact25FullBackupProducer.ProduceAsync(
            Request(), Credential(), new FakeProcess(), new FakeStorage(), publisher,
            "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal(25, Directory.EnumerateFiles(_root, "*.bak", SearchOption.AllDirectories).Count());
    }

    [Fact]
    public void SecureCredential_ToStringNeverRevealsUsernameOrPassword()
    {
        var credential = new SecureSqlBackupCredential("secret-user", "secret-password");

        Assert.Equal("[REDACTED]", credential.ToString());
        Assert.DoesNotContain("secret", credential.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SecureKubectlSqlCmdInvocation_KeepsCredentialsOutOfArgumentsAndDiagnostics()
    {
        var credential = new SecureSqlBackupCredential("secret-user", "secret-password");

        SecureBackupProcessInvocation invocation = SecureKubectlSqlCmdInvocation.Create(
            "maliev", "maliev-mssql-0", "mssql", "SELECT name FROM sys.databases;", credential);

        string arguments = string.Join(' ', invocation.Arguments);
        Assert.DoesNotContain("secret-user", arguments, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-password", arguments, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-user", invocation.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret-password", invocation.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("SELECT name", arguments, StringComparison.Ordinal);
        Assert.DoesNotContain("-P", invocation.Arguments);
        Assert.DoesNotContain("-U", invocation.Arguments);
        Assert.Equal("secret-user\nsecret-password\nSELECT name FROM sys.databases;\n", invocation.StandardInput);
    }

    [Fact]
    public async Task AtomicBackupReceiptPublisher_PublishesNewOwnerProtectedDirectory()
    {
        string publication = Path.Combine(_root, "receipt-publication");
        BackupReceipt receipt = SampleReceipt();

        await new AtomicBackupReceiptPublisher(publication).PublishNewAsync(receipt, CancellationToken.None);

        string receiptPath = Path.Combine(publication, AtomicBackupReceiptPublisher.ReceiptFileName);
        Assert.True(File.Exists(receiptPath));
        BackupReceipt? roundTrip = JsonSerializer.Deserialize<BackupReceipt>(
            await File.ReadAllTextAsync(receiptPath),
            WebJson);
        Assert.Equal(receipt.ManifestSha256, roundTrip?.ManifestSha256);
        Assert.Empty(Directory.EnumerateDirectories(_root, ".*.tmp"));
    }

    [Fact]
    public async Task AtomicBackupReceiptPublisher_ExistingDestinationIsNeverOverwritten()
    {
        string publication = Path.Combine(_root, "existing-publication");
        _ = Directory.CreateDirectory(publication);
        string marker = Path.Combine(publication, "owner-data.txt");
        await File.WriteAllTextAsync(marker, "preserve");

        _ = await Assert.ThrowsAsync<IOException>(() =>
            new AtomicBackupReceiptPublisher(publication).PublishNewAsync(SampleReceipt(), CancellationToken.None));

        Assert.Equal("preserve", await File.ReadAllTextAsync(marker));
        Assert.False(File.Exists(Path.Combine(publication, AtomicBackupReceiptPublisher.ReceiptFileName)));
    }

    [Fact]
    public async Task AtomicBackupReceiptPublisher_WriteFailureCleansStagingAndPublishesNothing()
    {
        string publication = Path.Combine(_root, "failed-publication");
        var publisher = new AtomicBackupReceiptPublisher(
            publication,
            (_, _, _) => throw new IOException("injected write failure"));

        _ = await Assert.ThrowsAsync<IOException>(() => publisher.PublishNewAsync(SampleReceipt(), CancellationToken.None));

        Assert.False(Directory.Exists(publication));
        Assert.Empty(Directory.EnumerateDirectories(_root, ".*.tmp"));
    }

    [Fact]
    public async Task ProduceAsync_RestoreVerificationFailureStopsBeforeCopyAndUpload()
    {
        var process = new FakeProcess { FailVerify = true };
        var storage = new FakeStorage();

        _ = await Assert.ThrowsAsync<Exact25FullBackupException>(() => Exact25FullBackupProducer.ProduceAsync(
            Request(), Credential(), process, storage, new FakePublisher(), "backup-key", _signingKey, CancellationToken.None));

        _ = Assert.Single(process.Created);
        Assert.Empty(process.Copied);
        Assert.Empty(storage.Uploads);
    }

    [Fact]
    public async Task ProduceAsync_NonRetryableCopyFailureIsAttemptedOnlyOnce()
    {
        var process = new FakeProcess { NonRetryableCopyFailure = true };

        _ = await Assert.ThrowsAsync<Exact25BackupTransportException>(() => Exact25FullBackupProducer.ProduceAsync(
            Request(), Credential(), process, new FakeStorage(), new FakePublisher(),
            "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal(1, process.CopyAttempts);
    }

    [Theory]
    [InlineData("hash")]
    [InlineData("generation")]
    [InlineData("mutable")]
    [InlineData("uri")]
    public async Task ProduceAsync_InvalidCloudReadbackFailsClosedWithoutReceipt(string drift)
    {
        var publisher = new FakePublisher();

        Exact25FullBackupException exception = await Assert.ThrowsAsync<Exact25FullBackupException>(() =>
            Exact25FullBackupProducer.ProduceAsync(
                Request(), Credential(), new FakeProcess(), new FakeStorage { ReadbackDrift = drift }, publisher,
                "backup-key", _signingKey, CancellationToken.None));

        Assert.Equal("cloud_backup_parity_invalid", exception.Code);
        Assert.Null(publisher.Published);
    }

    private static BackupReceipt SampleReceipt()
    {
        return new(
        "maliev-backup-receipt.v1",
        new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero),
        new string('a', 64),
        new string('b', 64),
        [],
        "backup-key",
        "signature");
    }

    private Exact25FullBackupRequest Request()
    {
        return new(
            "maliev",
            "maliev-mssql-0",
            "pod-uid-1",
            "mssql",
            "gs://maliev.com/database/full/2026-08-30/run-1/",
            _root,
            "run-1",
            new DateTimeOffset(2026, 8, 30, 1, 0, 0, TimeSpan.Zero),
            3);
    }

    private static SecureSqlBackupCredential Credential()
    {
        return new("KubernetesAccess", "test-only-password");
    }

    private async Task<BackupReceipt> ProduceReceiptAsync()
    {
        return await Exact25FullBackupProducer.ProduceAsync(
            Request(), Credential(), new FakeProcess(), new FakeStorage(), new FakePublisher(),
            "backup-key", _signingKey, CancellationToken.None);
    }

    private ReceiptAttestationTrustStore Trust()
    {
        return new([new TrustedAttestationKey("backup-key", _signingKey.ExportSubjectPublicKeyInfo())]);
    }

    public void Dispose()
    {
        _signingKey.Dispose();
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class FakeProcess : IExact25FullBackupProcess
    {
        public string? InventoryDrift { get; init; }
        public string? SourceDrift { get; init; }
        public bool FailCreate { get; init; }
        public bool FailVerify { get; init; }
        public int CopyTransportFailuresRemaining { get; set; }
        public bool NonRetryableCopyFailure { get; init; }
        public bool CorruptCopiedBytes { get; init; }
        public bool CompleteBeforeObservation { get; init; }
        public int InspectAttempts { get; private set; }
        public int CreateAttempts { get; private set; }
        public int CopyAttempts { get; private set; }
        public List<string> Created { get; } = [];
        public List<string> Verified { get; } = [];
        public List<string> Copied { get; } = [];
        public Dictionary<string, DateTimeOffset> CompletedAtUtc { get; } = [];

        public Task<Exact25BackupSourceObservation> InspectSourceAsync(Exact25FullBackupRequest request, SecureSqlBackupCredential credential, CancellationToken cancellationToken)
        {
            InspectAttempts++;
            string ns = SourceDrift == "namespace" ? "other" : request.Namespace;
            string pod = SourceDrift == "pod" ? "other" : request.ExpectedPodName;
            string uid = SourceDrift == "uid" ? "other" : request.ExpectedPodUid;
            bool ready = SourceDrift != "not-ready";
            DateTimeOffset observedAtUtc = request.ApprovedRunUtc.AddMinutes(1);
            List<SqlServerDatabaseState> databases = DatabaseInventory.Entries.Keys
                .Order(StringComparer.Ordinal)
                .Select(name => new SqlServerDatabaseState(name, "ONLINE")).ToList();
            switch (InventoryDrift)
            {
                case "missing": databases.RemoveAt(0); break;
                case "extra": databases.Add(new("Unexpected", "ONLINE")); break;
                case "offline": databases[0] = databases[0] with { State = "OFFLINE" }; break;
                case "duplicate": databases.Add(databases[0]); break;
                default:
                    break;
            }

            return Task.FromResult(new Exact25BackupSourceObservation(ns, pod, uid, request.ContainerName, ready, observedAtUtc, databases)
            { ContainerId = "containerd://container-1", ImageId = "sha256:image-1", SessionNonce = new string('a', 64) });
        }

        public Task PrepareRunAsync(Exact25BackupSourceObservation source, string runId, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<RemoteFullBackupArtifact> CreateUniqueFullBackupAsync(Exact25BackupSourceObservation source, string database, string remoteRelativePath, SecureSqlBackupCredential credential, CancellationToken cancellationToken)
        {
            CreateAttempts++;
            if (FailCreate)
            {
                throw new Exact25FullBackupException("backup_create_failed", "ambiguous backup failure");
            }

            Created.Add(database);
            byte[] content = System.Text.Encoding.UTF8.GetBytes($"verified-full-backup:{database}");
            string sha256 = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            DateTimeOffset completedAtUtc = CompleteBeforeObservation
                ? source.ObservedAtUtc.AddSeconds(-1)
                : source.ObservedAtUtc.AddSeconds(CreateAttempts);
            CompletedAtUtc[database] = completedAtUtc;
            return Task.FromResult(new RemoteFullBackupArtifact(database, remoteRelativePath, content.LongLength, sha256, completedAtUtc));
        }

        public Task VerifyRestoreAsync(Exact25BackupSourceObservation source, RemoteFullBackupArtifact artifact, SecureSqlBackupCredential credential, CancellationToken cancellationToken)
        {
            if (FailVerify)
            {
                throw new Exact25FullBackupException("restore_verify_failed", "RESTORE VERIFYONLY failed");
            }

            Verified.Add(artifact.Database);
            return Task.CompletedTask;
        }

        public async Task CopyToLocalAsync(Exact25BackupSourceObservation source, RemoteFullBackupArtifact artifact, string localRelativePath, string workingDirectory, CancellationToken cancellationToken)
        {
            CopyAttempts++;
            if (NonRetryableCopyFailure)
            {
                throw new Exact25BackupTransportException("copy_policy", "copy failed", retryable: false);
            }

            if (CopyTransportFailuresRemaining-- > 0)
            {
                throw new Exact25BackupTransportException("copy_transport", "copy failed", retryable: true);
            }

            string path = Path.Combine(workingDirectory, localRelativePath);
            _ = Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string content = $"verified-full-backup:{artifact.Database}";
            if (CorruptCopiedBytes)
            {
                content = "x" + content[1..];
            }

            await File.WriteAllTextAsync(path, content, cancellationToken);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            Copied.Add(artifact.Database);
        }
    }

    private sealed class FakeStorage : IImmutableBackupObjectStorage
    {
        public bool ReturnWrongSize { get; init; }
        public string? ReadbackDrift { get; init; }
        public List<string> Uploads { get; } = [];

        public Task<ImmutableBackupObject> UploadNewAndReadBackAsync(string localPath, string objectUri, string sha256, CancellationToken cancellationToken)
        {
            Uploads.Add(objectUri);
            long size = new FileInfo(localPath).Length + (ReturnWrongSize ? 1 : 0);
            string uri = ReadbackDrift == "uri" ? objectUri + ".wrong" : objectUri;
            long generation = ReadbackDrift == "generation" ? 0 : Uploads.Count;
            string hash = ReadbackDrift == "hash" ? new string('0', 64) : sha256;
            bool immutable = ReadbackDrift != "mutable";
            return Task.FromResult(new ImmutableBackupObject(uri, generation, size, hash, immutable));
        }
    }

    private sealed class FakePublisher : IBackupReceiptPublisher
    {
        public bool Fail { get; init; }
        public BackupReceipt? Published { get; private set; }
        public Task PublishNewAsync(BackupReceipt receipt, CancellationToken cancellationToken)
        {
            if (Fail)
            {
                throw new IOException("publication failed");
            }

            Published = receipt;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeRestoreTarget : IVerifiedBackupRestoreTarget
    {
        public List<string> Restored { get; } = [];

        public Task RestoreAsync(VerifiedBackupRestoreArtifact artifact, CancellationToken cancellationToken)
        {
            Assert.True(artifact.RetainedHandle.CanRead);
            Assert.Equal(artifact.ByteLength, artifact.RetainedHandle.Length);
            Assert.StartsWith(Path.GetFullPath(Path.GetDirectoryName(artifact.LocalPath)!), artifact.LocalPath, StringComparison.Ordinal);
            Restored.Add(artifact.Database);
            return Task.CompletedTask;
        }
    }
}
