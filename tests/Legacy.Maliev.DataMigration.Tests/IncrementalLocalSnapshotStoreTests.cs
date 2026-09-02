using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class LocalSnapshotIoTestGroup
{
    public const string Name = "Local snapshot encryption IO";
}

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class IncrementalLocalSnapshotStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"incremental-local-{Guid.NewGuid():N}");
    private readonly LocalArtifactTestData _data = new();
    private readonly RecordingDumpSource _source = new();
    private readonly RecordingArchiveVerifier _verifier = new();
    private bool _rejectPublication;
    private string Staging => Path.Combine(_root, "staging");
    private string Output => Path.Combine(_root, "final");

    [WindowsLocalRunFact]
    public async Task DeliveryAndReadback_HeldRunAuthority_AllowOnlySafeReservedLock()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Staging);
        using var store = CreateStore();
        await store.DeliverAndVerifyAsync(_data.Checkpoints[0], default);
        _ = Assert.Single(await store.ReadVerifiedCheckpointsAsync(default));
        authority.ValidateHeld();
        await File.WriteAllTextAsync(Path.Combine(Staging, ".run.lock.extra"), "unrecognized");
        _ = await Assert.ThrowsAsync<InvalidDataException>(() => store.ReadVerifiedCheckpointsAsync(default));
    }

    [WindowsLocalRunTheory]
    [InlineData("directory")]
    [InlineData("nonempty")]
    [InlineData("link")]
    public async Task Readback_UnsafeReservedRunLock_Rejects(string kind)
    {
        using var store = CreateStore();
        await store.DeliverAndVerifyAsync(_data.Checkpoints[0], default);
        string path = Path.Combine(Staging, WindowsLocalRunAuthority.RunLockRelativeName);
        if (kind == "directory") { _ = Directory.CreateDirectory(path); }
        else if (kind == "link") { _ = File.CreateSymbolicLink(path, Path.Combine(Staging, ".store.lock")); }
        else { await File.WriteAllTextAsync(path, "not a lock"); }
        _ = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.ReadVerifiedCheckpointsAsync(default));
    }

    [Fact]
    public async Task Deliver_SecondDumpFails_RetryPreservesFirstBytesAndDoesNotRedownload()
    {
        using var store = CreateStore();
        DatabaseMigrationCheckpoint first = _data.Checkpoints[0], second = _data.Checkpoints[1];
        await store.DeliverAndVerifyAsync(first, default);
        string path = Archive(first);
        byte[] before = await File.ReadAllBytesAsync(path);
        byte[] metadata = await File.ReadAllBytesAsync(Metadata(first));
        DateTime timestamp = File.GetLastWriteTimeUtc(path);
        _source.FailingDatabase = second.Database.Database;
        _ = await Assert.ThrowsAsync<IOException>(() => store.DeliverAndVerifyAsync(second, default));
        _source.FailingDatabase = null;
        await store.DeliverAndVerifyAsync(first, default);
        await store.DeliverAndVerifyAsync(second, default);
        Assert.Equal(before, await File.ReadAllBytesAsync(path));
        Assert.Equal(metadata, await File.ReadAllBytesAsync(Metadata(first)));
        Assert.Equal(timestamp, File.GetLastWriteTimeUtc(path));
        Assert.Equal(1, _source.OpenCount[first.Database.Database]);
        Assert.False(File.Exists(Path.Combine(Output, "manifest.json")));
        Assert.True(_source.DisposedBeforeVerify);
    }

    [Fact]
    public async Task Deliver_DestinationCreationFailureSurvivesDumpCleanup_WithoutPublication()
    {
        using var store = CreateStore();
        _source.FailDispose = true;
        _source.OnOpen = () => Directory.CreateDirectory(Path.Combine(
            Assert.Single(Directory.EnumerateDirectories(Staging, ".pending-*")), "archive.aes256"));

        Exception failure = await Record.ExceptionAsync(() => store.DeliverAndVerifyAsync(_data.Checkpoints[0], default));

        _ = Assert.IsType<UnauthorizedAccessException>(failure);
        Assert.Equal(nameof(IOException), failure.Data["snapshot_dump_cleanup_failure"]);
        Assert.False(Directory.Exists(Path.GetDirectoryName(Archive(_data.Checkpoints[0]))));
        Assert.Empty(Directory.EnumerateFiles(Staging, "artifact.json", SearchOption.AllDirectories));
        Assert.Equal(0, _verifier.Calls);
    }

    [Fact]
    public async Task Deliver_DestinationCancellationSurvivesDumpCleanup_WithoutPublication()
    {
        using var store = CreateStore();
        using var cancellation = new CancellationTokenSource();
        _source.FailDispose = true;
        _source.OnOpen = cancellation.Cancel;

        Exception failure = await Record.ExceptionAsync(() => store.DeliverAndVerifyAsync(_data.Checkpoints[0], cancellation.Token));

        Assert.Equal(cancellation.Token, Assert.IsType<OperationCanceledException>(failure, exactMatch: false).CancellationToken);
        Assert.Equal(nameof(IOException), failure.Data["snapshot_dump_cleanup_failure"]);
        Assert.False(Directory.Exists(Path.GetDirectoryName(Archive(_data.Checkpoints[0]))));
        Assert.Empty(Directory.EnumerateFiles(Staging, "artifact.json", SearchOption.AllDirectories));
        Assert.Equal(0, _verifier.Calls);
    }

    [Fact]
    public async Task Deliver_DumpDisposeFails_DoesNotPublishOrRestore()
    {
        using var store = CreateStore();
        _source.FailDispose = true;
        _ = await Assert.ThrowsAsync<IOException>(() => store.DeliverAndVerifyAsync(_data.Checkpoints[0], default));
        Assert.False(Directory.Exists(Path.GetDirectoryName(Archive(_data.Checkpoints[0]))));
        Assert.Equal(0, _verifier.Calls);
    }

    [Theory]
    [InlineData("metadata")]
    [InlineData("ciphertext")]
    [InlineData("truncate")]
    [InlineData("terminator")]
    [InlineData("missing")]
    [InlineData("wrong-key")]
    public async Task Replay_CorruptState_FailsBeforeRestoreOrRedownload(string corruption)
    {
        DatabaseMigrationCheckpoint checkpoint = _data.Checkpoints[0];
        using (var store = CreateStore()) { await store.DeliverAndVerifyAsync(checkpoint, default); }
        string path = Archive(checkpoint);
        if (corruption == "metadata") { await File.WriteAllTextAsync(Metadata(checkpoint), "{"); }
        if (corruption == "missing") { File.Delete(path); }
        if (corruption is "ciphertext" or "truncate" or "terminator")
        {
            byte[] bytes = await File.ReadAllBytesAsync(path);
            if (corruption == "ciphertext") { bytes[^8] ^= 0x20; }
            if (corruption == "truncate") { bytes = bytes[..^5]; }
            if (corruption == "terminator") { bytes = [.. bytes[..16], 0, 0, 0, 0]; }
            await File.WriteAllBytesAsync(path, bytes);
        }
        using var replay = CreateStore(corruption == "wrong-key" ? RandomNumberGenerator.GetBytes(32) : null);
        int restores = _verifier.Calls;
        _ = await Assert.ThrowsAnyAsync<Exception>(() => replay.DeliverAndVerifyAsync(checkpoint, default));
        Assert.Equal(restores, _verifier.Calls);
        Assert.Equal(1, _source.OpenCount[checkpoint.Database.Database]);
    }

    [Theory]
    [InlineData("plaintext-length")]
    [InlineData("plaintext-hash")]
    [InlineData("ciphertext-tag")]
    [InlineData("ciphertext-shortened-at-terminator")]
    public async Task Replay_AuthenticatedMetadataDoesNotBypassFullPlaintextIntegrity(string corruption)
    {
        using var store = CreateStore();
        DatabaseMigrationCheckpoint checkpoint = _data.Checkpoints[0];
        await store.DeliverAndVerifyAsync(checkpoint, default);
        LocalDatabaseArtifact artifact = JsonSerializer.Deserialize<LocalDatabaseArtifact>(await File.ReadAllTextAsync(Metadata(checkpoint)))!;
        LocalSnapshotDatabase archive = artifact.Archive;
        if (corruption == "plaintext-length") { archive = archive with { PlaintextByteLength = archive.PlaintextByteLength + 1 }; }
        if (corruption == "plaintext-hash") { archive = archive with { PlaintextSha256 = new string('0', 64) }; }
        if (corruption.StartsWith("ciphertext", StringComparison.Ordinal))
        {
            byte[] bytes = await File.ReadAllBytesAsync(Archive(checkpoint));
            if (corruption == "ciphertext-tag") { bytes[^8] ^= 0x01; }
            else { bytes = [.. bytes[..16], 0, 0, 0, 0]; }
            await File.WriteAllBytesAsync(Archive(checkpoint), bytes);
            archive = archive with { EncryptedByteLength = bytes.Length, EncryptedSha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() };
        }
        artifact = artifact with { Archive = archive, MetadataMacSha256 = string.Empty };
        byte[] macKey = SnapshotKeyDerivation.DeriveManifestMacKey(_data.Key);
        try
        {
            string mac = Convert.ToHexString(HMACSHA256.HashData(macKey, Encoding.UTF8.GetBytes("MALIEV-local-database-artifact-v1\n" + JsonSerializer.Serialize(artifact)))).ToLowerInvariant();
            await File.WriteAllTextAsync(Metadata(checkpoint), JsonSerializer.Serialize(artifact with { MetadataMacSha256 = mac }));
        }
        finally { CryptographicOperations.ZeroMemory(macKey); }
        int calls = _verifier.Calls;
        _ = await Assert.ThrowsAnyAsync<CryptographicException>(() => store.DeliverAndVerifyAsync(checkpoint, default));
        Assert.Equal(calls, _verifier.Calls);
        Assert.Equal(1, _source.OpenCount[checkpoint.Database.Database]);
    }

    [Fact]
    public async Task Replay_ChangedTrustedCheckpoint_LeavesOriginalArtifactUntouched()
    {
        using var store = CreateStore();
        DatabaseMigrationCheckpoint first = _data.Checkpoints[0];
        await store.DeliverAndVerifyAsync(first, default);
        byte[] metadata = await File.ReadAllBytesAsync(Metadata(first));
        DatabaseMigrationCheckpoint changed = _data.Sign(first with { CommittedAtUtc = first.CommittedAtUtc.AddSeconds(1) });
        _ = await Assert.ThrowsAnyAsync<Exception>(() => store.DeliverAndVerifyAsync(changed, default));
        Assert.Equal(metadata, await File.ReadAllBytesAsync(Metadata(first)));
        Assert.Equal(1, _source.OpenCount[first.Database.Database]);
    }

    [Fact]
    public async Task Replay_DictionaryOrderingMatchesJournalCanonicalBytes_ButResigningIsRejected()
    {
        using var store = CreateStore();
        DatabaseMigrationCheckpoint checkpoint = _data.Checkpoints[0];
        await store.DeliverAndVerifyAsync(checkpoint, default);
        TableReconciliationEvidence table = checkpoint.Reconciliation.Tables[0];
        DatabaseMigrationCheckpoint reordered = checkpoint with
        {
            Reconciliation = checkpoint.Reconciliation with
            {
                Tables = [table with { NullCounts = new Dictionary<string, long> { ["value"] = 0, ["id"] = 0 } }],
            },
        };
        await store.DeliverAndVerifyAsync(reordered, default);
        _ = await Assert.ThrowsAsync<InvalidDataException>(() => store.DeliverAndVerifyAsync(_data.Sign(checkpoint), default));
        Assert.Equal(1, _source.OpenCount[checkpoint.Database.Database]);
    }

    [Fact]
    public async Task Deliver_CallerAndVerifierMutateCheckpoint_DurableCheckpointRemainsOriginal()
    {
        using var store = CreateStore();
        DatabaseMigrationCheckpoint checkpoint = _data.Checkpoints[0];
        byte[] original = MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint);
        _source.OnOpen = () => ((Dictionary<string, long>)checkpoint.Reconciliation.Tables[0].NullCounts)["id"] = 1;
        _verifier.OnVerify = value => ((Dictionary<string, long>)value.Reconciliation.Tables[0].NullCounts)["value"] = 1;
        await store.DeliverAndVerifyAsync(checkpoint, default);
        IReadOnlyList<DatabaseMigrationCheckpoint> restored = await store.ReadVerifiedCheckpointsAsync(default);
        Assert.Equal(original, MigrationEvidenceAttestation.SerializeCheckpoint(Assert.Single(restored)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Deliver_VerifierFailsOrReturnsEarly_DoesNotPublishOrHang(bool returnEarly)
    {
        using var store = CreateStore();
        _source.Payload = new byte[8 * 1024 * 1024];
        _verifier.Fail = !returnEarly;
        _verifier.ReturnEarly = returnEarly;
        Task delivery = store.DeliverAndVerifyAsync(_data.Checkpoints[0], default);
        if (returnEarly)
        {
            _ = await Assert.ThrowsAsync<InvalidDataException>(() => delivery).WaitAsync(TimeSpan.FromSeconds(10));
        }
        else
        {
            _ = await Assert.ThrowsAsync<IOException>(() => delivery).WaitAsync(TimeSpan.FromSeconds(10));
        }
        Assert.False(Directory.Exists(Path.GetDirectoryName(Archive(_data.Checkpoints[0]))));
    }

    [Fact]
    public async Task Deliver_ConcurrentStoreCannotAcquireOsLock()
    {
        using var first = CreateStore();
        using var second = CreateStore();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _verifier.Wait = async () => { entered.SetResult(); await release.Task; };
        Task delivery = first.DeliverAndVerifyAsync(_data.Checkpoints[0], default);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try { _ = await Assert.ThrowsAsync<IOException>(() => second.DeliverAndVerifyAsync(_data.Checkpoints[1], default)); }
        finally { release.SetResult(); }
        await delivery;
    }

    [Fact]
    public async Task Replay_LinkedArtifact_IsRejectedWithoutTouchingTarget()
    {
        using var store = CreateStore();
        DatabaseMigrationCheckpoint checkpoint = _data.Checkpoints[0];
        await store.DeliverAndVerifyAsync(checkpoint, default);
        string outside = Path.Combine(_root, "outside");
        File.Move(Archive(checkpoint), outside);
        byte[] before = await File.ReadAllBytesAsync(outside);
        _ = File.CreateSymbolicLink(Archive(checkpoint), outside);
        _ = await Assert.ThrowsAnyAsync<Exception>(() => store.DeliverAndVerifyAsync(checkpoint, default));
        Assert.Equal(before, await File.ReadAllBytesAsync(outside));
    }

    [Theory]
    [InlineData("../escape")]
    [InlineData("bad/name")]
    [InlineData("bad\\name")]
    public void Constructor_UnsafeSnapshotId_RejectsBeforeCreatingFiles(string identity)
    {
        _ = Assert.ThrowsAny<Exception>(() => new IncrementalLocalSnapshotStore(Staging, identity, _data.Key, _data.Verifier, _source, _verifier, _ => Task.CompletedTask));
        Assert.False(Directory.Exists(Staging));
    }

    [Fact]
    public async Task Finalize_CompleteInventory_UsesOnlyLocalArtifactsAndCompatibleManifest()
    {
        using var store = CreateStore();
        foreach (DatabaseMigrationCheckpoint checkpoint in _data.Checkpoints) { await store.DeliverAndVerifyAsync(checkpoint, default); }
        byte[] original = await File.ReadAllBytesAsync(Archive(_data.Checkpoints[0]));
        _source.FailAll = true;
        LocalSnapshotManifest manifest = await store.FinalizeAsync(Output, await store.ReadVerifiedCheckpointsAsync(default), default);
        Assert.Equal(DatabaseInventory.ActiveDatabases, manifest.Databases.Select(item => item.Database));
        Assert.Equal("MLVSNP02", manifest.Format);
        Assert.Equal(SnapshotManifestAuthentication.ComputeMac(manifest, _data.Key), manifest.ManifestMacSha256);
        foreach (LocalSnapshotDatabase archive in manifest.Databases)
        {
            await using FileStream encrypted = File.OpenRead(Path.Combine(Output, archive.FileName));
            using var plaintext = new MemoryStream();
            await SnapshotEncryption.DecryptAsync(encrypted, plaintext, _data.Key,
                SnapshotArchiveContext.Create("snapshot-test", archive.Database, manifest.ManifestDigestSha256), default);
            Assert.Equal(_source.Payload, plaintext.ToArray());
        }
        Assert.Equal(original, await File.ReadAllBytesAsync(Archive(_data.Checkpoints[0])));
        LocalSnapshotManifest readback = JsonSerializer.Deserialize<LocalSnapshotManifest>(await File.ReadAllTextAsync(Path.Combine(Output, "manifest.json")))!;
        Assert.Equal(manifest.ManifestMacSha256, readback.ManifestMacSha256);
    }

    [Fact]
    public async Task Finalize_AcknowledgementLost_ReplaysExactOutputWithoutWritesOrDumps()
    {
        using var store = CreateStore();
        foreach (DatabaseMigrationCheckpoint checkpoint in _data.Checkpoints) { await store.DeliverAndVerifyAsync(checkpoint, default); }
        LocalSnapshotManifest first = await store.FinalizeAsync(Output, _data.Checkpoints, default);
        string[] paths = [.. Directory.EnumerateFiles(Output).Order(StringComparer.Ordinal)];
        byte[][] bytes = await Task.WhenAll(paths.Select(path => File.ReadAllBytesAsync(path)));
        DateTime[] timestamps = [.. paths.Select(File.GetLastWriteTimeUtc)];
        _source.FailAll = true;
        _rejectPublication = true;
        LocalSnapshotManifest replay = await store.FinalizeAsync(Output, _data.Checkpoints, default);
        Assert.Equal(first.ManifestMacSha256, replay.ManifestMacSha256);
        for (int index = 0; index < paths.Length; index++)
        {
            Assert.Equal(bytes[index], await File.ReadAllBytesAsync(paths[index]));
            Assert.Equal(timestamps[index], File.GetLastWriteTimeUtc(paths[index]));
        }
    }

    [Theory]
    [InlineData("manifest")]
    [InlineData("archive")]
    [InlineData("extra")]
    public async Task Finalize_ExistingInvalidOutput_FailsWithoutOverwriting(string corruption)
    {
        using var store = CreateStore();
        foreach (DatabaseMigrationCheckpoint checkpoint in _data.Checkpoints) { await store.DeliverAndVerifyAsync(checkpoint, default); }
        LocalSnapshotManifest manifest = await store.FinalizeAsync(Output, _data.Checkpoints, default);
        string changed = corruption switch
        {
            "manifest" => Path.Combine(Output, "manifest.json"),
            "archive" => Path.Combine(Output, manifest.Databases[0].FileName),
            _ => Path.Combine(Output, "unexpected"),
        };
        await File.WriteAllTextAsync(changed, "corruption");
        _ = await Assert.ThrowsAnyAsync<Exception>(() => store.FinalizeAsync(Output, _data.Checkpoints, default));
        Assert.Equal("corruption", await File.ReadAllTextAsync(changed));
    }

    [Fact]
    public async Task Finalize_PublicationAuthorityRejected_LeavesAllStagingForRetry()
    {
        using var store = CreateStore();
        foreach (DatabaseMigrationCheckpoint checkpoint in _data.Checkpoints) { await store.DeliverAndVerifyAsync(checkpoint, default); }
        _rejectPublication = true;
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => store.FinalizeAsync(Output, _data.Checkpoints, default));
        Assert.False(Directory.Exists(Output));
        Assert.Equal(DatabaseInventory.ActiveDatabases.Count, (await store.ReadVerifiedCheckpointsAsync(default)).Count);
    }

    [Fact]
    public async Task Finalize_IncompleteOrChangedInventory_IsRejectedWithoutOutput()
    {
        using var store = CreateStore();
        foreach (DatabaseMigrationCheckpoint checkpoint in _data.Checkpoints) { await store.DeliverAndVerifyAsync(checkpoint, default); }
        _ = await Assert.ThrowsAnyAsync<Exception>(() => store.FinalizeAsync(Output, _data.Checkpoints[..^1], default));
        DatabaseMigrationCheckpoint[] changed = [.. _data.Checkpoints];
        changed[0] = _data.Sign(changed[0] with { CommittedAtUtc = changed[0].CommittedAtUtc.AddSeconds(1) });
        _ = await Assert.ThrowsAnyAsync<Exception>(() => store.FinalizeAsync(Output, changed, default));
        Assert.False(Directory.Exists(Output));
    }

    [Fact]
    public async Task Finalize_CancelledDuringAssembly_RetainsAllStagingForLocalRetry()
    {
        using var store = CreateStore();
        foreach (DatabaseMigrationCheckpoint checkpoint in _data.Checkpoints) { await store.DeliverAndVerifyAsync(checkpoint, default); }
        byte[][] before = await Task.WhenAll(_data.Checkpoints.Select(checkpoint => File.ReadAllBytesAsync(Archive(checkpoint))));
        using var cancellation = new CancellationTokenSource();
        // Cancel once the final-assembly temporary directory exists, after local validation.
        using var watcher = new FileSystemWatcher(_root) { NotifyFilter = NotifyFilters.DirectoryName, EnableRaisingEvents = true };
        watcher.Created += (_, args) => { if (Path.GetFileName(args.FullPath).StartsWith(".final-", StringComparison.Ordinal)) { cancellation.Cancel(); } };
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.FinalizeAsync(Output, _data.Checkpoints, cancellation.Token));
        Assert.False(File.Exists(Path.Combine(Output, "manifest.json")));
        for (int index = 0; index < before.Length; index++) { Assert.Equal(before[index], await File.ReadAllBytesAsync(Archive(_data.Checkpoints[index]))); }
        _source.FailAll = true;
        _ = await store.FinalizeAsync(Output, _data.Checkpoints, default);
    }

    private IncrementalLocalSnapshotStore CreateStore(byte[]? key = null)
    {
        _verifier.Source = _source;
        return new(Staging, "snapshot-test", key ?? _data.Key, _data.Verifier, _source, _verifier,
            _ => _rejectPublication ? Task.FromException(new InvalidOperationException("publication authority lost")) : Task.CompletedTask);
    }

    [Fact]
    public async Task Deliver_AuthorityLostAfterRestore_RejectsPublicationAndRetainsPriorArtifact()
    {
        using var store = CreateStore();
        await store.DeliverAndVerifyAsync(_data.Checkpoints[0], default);
        byte[] original = await File.ReadAllBytesAsync(Archive(_data.Checkpoints[0]));
        _verifier.OnVerify = _ => _rejectPublication = true;
        _ = await Assert.ThrowsAsync<InvalidOperationException>(() => store.DeliverAndVerifyAsync(_data.Checkpoints[1], default));
        Assert.Equal(original, await File.ReadAllBytesAsync(Archive(_data.Checkpoints[0])));
        Assert.False(Directory.Exists(Path.GetDirectoryName(Archive(_data.Checkpoints[1]))));
    }

    private string Archive(DatabaseMigrationCheckpoint checkpoint)
    {
        return Path.Combine(Staging, checkpoint.Database.Database, "archive.aes256");
    }

    private string Metadata(DatabaseMigrationCheckpoint checkpoint)
    {
        return Path.Combine(Staging, checkpoint.Database.Database, "artifact.json");
    }

    public void Dispose()
    {
        _data.Dispose();
        if (Directory.Exists(_root)) { Directory.Delete(_root, recursive: true); }
    }

    private sealed class RecordingArchiveVerifier : ILocalDatabaseArchiveVerifier
    {
        public int Calls { get; private set; }
        public bool Fail { get; set; }
        public bool ReturnEarly { get; set; }
        public RecordingDumpSource Source { get; set; } = null!;
        public Action<DatabaseMigrationCheckpoint>? OnVerify { get; set; }
        public Func<Task>? Wait { get; set; }
        public async Task VerifyAsync(Stream plaintext, DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken)
        {
            Calls++;
            Assert.True(Source.DisposedBeforeVerify);
            if (Wait is not null) { await Wait(); }
            if (Fail) { throw new IOException("controlled restore failure"); }
            if (ReturnEarly) { return; }
            await plaintext.CopyToAsync(Stream.Null, cancellationToken);
            OnVerify?.Invoke(checkpoint);
        }
    }

    private sealed class RecordingDumpSource : IPostgreSqlDumpSource
    {
        public Dictionary<string, int> OpenCount { get; } = [];
        public string? FailingDatabase { get; set; }
        public bool FailDispose { get; set; }
        public bool FailAll { get; set; }
        public bool DisposedBeforeVerify { get; private set; }
        public byte[] Payload { get; set; } = Encoding.UTF8.GetBytes("synthetic custom archive");
        public Action? OnOpen { get; set; }
        public Task<Stream> OpenDumpAsync(string database, string shadowDatabase, CancellationToken cancellationToken)
        {
            OpenCount[database] = OpenCount.GetValueOrDefault(database) + 1;
            if (FailAll || database == FailingDatabase) { throw new IOException("controlled dump failure"); }
            DisposedBeforeVerify = false;
            OnOpen?.Invoke();
            return Task.FromResult<Stream>(new DisposalStream(Payload, () =>
            {
                if (FailDispose) { throw new IOException("controlled nonzero dump exit"); }
                DisposedBeforeVerify = true;
            }));
        }
    }

    private sealed class DisposalStream(byte[] bytes, Action disposed) : MemoryStream(bytes)
    {
        public override async ValueTask DisposeAsync()
        {
            await base.DisposeAsync();
            disposed();
        }
    }
}

internal sealed class LocalArtifactTestData : IDisposable
{
    private readonly ECDsa _signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public byte[] Key { get; } = RandomNumberGenerator.GetBytes(32);
    public DatabaseMigrationCheckpoint[] Checkpoints { get; }
    public DatabaseMigrationCheckpointVerifier Verifier { get; }

    public LocalArtifactTestData()
    {
        DatabaseSchemaPlan[] databases = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new DatabaseSchemaPlan(database, "1.0", new string('a', 64), new string('b', 64),
                [new("dbo", "snapshot_probe", "public", "snapshot_probe", ["id", "value"], ["id"])]))];
        var plan = new FreshSchemaPlan("2.0", DateTimeOffset.UtcNow.AddMinutes(-1), new string('a', 40), databases);
        var identity = new MigrationRunIdentity(Guid.NewGuid(), plan.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(plan),
            new string('c', 64), new string('d', 64), "local-artifact-test");
        Verifier = new(new(identity, plan, new ReceiptAttestationTrustStore([new("local-test", _signer.ExportSubjectPublicKeyInfo())])));
        Checkpoints = [.. databases.Select(database =>
        {
            var shadow = new ShadowDatabase(GuardedShadowMigrationRunner.CreateShadowName(database.Database, identity.RunId),
                identity.RunId.ToString("D"), database.Database) { OwnerAttempt = 1, FencingToken = Guid.NewGuid() };
            using var collector = new TableEvidenceCollector(database.Tables[0]);
            collector.Append(new(new Dictionary<string, object?> { ["id"] = 1, ["value"] = "pg18" }));
            TableReconciliationEvidence collected = collector.Finish();
            TableReconciliationEvidence table = collected with { NullCounts = new Dictionary<string, long>(collected.NullCounts) };
            string content = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"public.snapshot_probe|1|{table.ContentSha256}|{table.AggregateSha256}"))).ToLowerInvariant();
            return Sign(new(identity, shadow, new(database.Database, shadow.Name, 1, content)
            {
                OwnerAttempt = 1, FencingToken = shadow.FencingToken,
            }, new(database.Database, database.SourceSchemaSha256, database.TargetSchemaSha256, [table]),
                DateTimeOffset.UtcNow, "local-test", null));
        })];
    }

    public DatabaseMigrationCheckpoint Sign(DatabaseMigrationCheckpoint checkpoint)
    {
        return checkpoint with
        {
            AttestationSignature = Convert.ToBase64String(_signer.SignData(MigrationEvidenceAttestation.CreatePayload(checkpoint), HashAlgorithmName.SHA256)),
        };
    }

    public void Dispose()
    {
        _signer.Dispose();
        CryptographicOperations.ZeroMemory(Key);
    }
}
