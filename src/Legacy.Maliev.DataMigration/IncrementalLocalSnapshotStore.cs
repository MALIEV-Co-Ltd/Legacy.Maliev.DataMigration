using System.IO.Pipelines;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

/// <summary>Durable encrypted delivery of trusted checkpoints, independent of remote shadow availability.</summary>
public sealed partial class IncrementalLocalSnapshotStore : IDatabaseCheckpointDelivery, IDisposable
{
    private const string ArchiveName = "archive.aes256", MetadataName = "artifact.json";
    private readonly string _root, _snapshotId;
    private readonly byte[] _key;
    private readonly DatabaseMigrationCheckpointVerifier _checkpointVerifier;
    private readonly IPostgreSqlDumpSource _dumpSource;
    private readonly ILocalDatabaseArchiveVerifier _localVerifier;
    private readonly Func<CancellationToken, Task> _publicationAuthorityGuard;
    private bool _disposed;

    public IncrementalLocalSnapshotStore(string root, string snapshotId, ReadOnlyMemory<byte> rootKey,
        DatabaseMigrationCheckpointVerifier checkpointVerifier, IPostgreSqlDumpSource dumpSource,
        ILocalDatabaseArchiveVerifier localVerifier, Func<CancellationToken, Task> publicationAuthorityGuard)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentException.ThrowIfNullOrWhiteSpace(snapshotId);
        if (!SnapshotIdentity().IsMatch(snapshotId)) { throw new ArgumentException("Invalid snapshot identity.", nameof(snapshotId)); }
        if (rootKey.Length != 32) { throw new ArgumentException("A 256-bit external root key is required.", nameof(rootKey)); }
        _checkpointVerifier = checkpointVerifier ?? throw new ArgumentNullException(nameof(checkpointVerifier));
        _dumpSource = dumpSource ?? throw new ArgumentNullException(nameof(dumpSource));
        _localVerifier = localVerifier ?? throw new ArgumentNullException(nameof(localVerifier));
        _publicationAuthorityGuard = publicationAuthorityGuard ?? throw new ArgumentNullException(nameof(publicationAuthorityGuard));
        _root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (Path.GetDirectoryName(_root) is null) { throw new ArgumentException("A dedicated local artifact directory is required.", nameof(root)); }
        SecureSnapshotFileCreation.RejectLinkedAncestors(_root);
        _snapshotId = snapshotId;
        _key = rootKey.ToArray();
    }

    public async Task DeliverAndVerifyAsync(DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken)
    {
        // Freeze the exact signed bytes before calling asynchronous or caller-provided code.
        string checkpointJson = Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint));
        DatabaseMigrationCheckpoint frozen = ValidateCheckpoint(checkpointJson);
        await using FileStream gate = AcquireLock();
        cancellationToken.ThrowIfCancellationRequested();
        string destination = Path.Combine(_root, frozen.Database.Database);
        if (Path.Exists(destination))
        {
            LocalDatabaseArtifact existing = await ReadArtifactAsync(destination, checkpointJson, cancellationToken).ConfigureAwait(false);
            await using FileStream archive = OpenArchive(destination);
            await AuthenticateArchiveAsync(archive, existing, cancellationToken).ConfigureAwait(false);
            await VerifyRestoreAsync(archive, existing, cancellationToken).ConfigureAwait(false);
            return;
        }

        string pending = Path.Combine(_root, $".pending-{Guid.NewGuid():N}");
        SecureSnapshotFileCreation.CreateRestrictedDirectory(pending);
        // Failed/crashed private pending directories are retained; never delete the shared staging root.
        string path = Path.Combine(pending, ArchiveName);
        string checkpointHash = HashText(checkpointJson);
        SnapshotEncryptionResult result;
        await using (Stream dump = await _dumpSource.OpenDumpAsync(frozen.Database.Database, frozen.Shadow.Name, cancellationToken).ConfigureAwait(false))
        await using (FileStream encrypted = CreateFile(path))
        {
            result = await SnapshotEncryption.EncryptStagingAsync(dump, encrypted, _key,
                Context(frozen.Database.Database, checkpointHash), cancellationToken).ConfigureAwait(false);
            await FlushDurablyAsync(encrypted, cancellationToken).ConfigureAwait(false);
        } // PgDumpSource disposal observes process exit; no metadata/publication/restore before success.

        long encryptedLength;
        string encryptedHash;
        await using (FileStream encrypted = SecureSnapshotFileCreation.OpenValidatedRead(path))
        {
            encryptedLength = encrypted.Length;
            encryptedHash = await HashAsync(encrypted, cancellationToken).ConfigureAwait(false);
        }
        var entry = new LocalSnapshotDatabase(frozen.Database.Database, frozen.Shadow.Name, ArchiveName,
            result.PlaintextByteLength, result.PlaintextSha256, encryptedLength, encryptedHash);
        var unsigned = new LocalDatabaseArtifact(1, _snapshotId, checkpointJson, checkpointHash, entry, string.Empty);
        LocalDatabaseArtifact artifact = unsigned with { MetadataMacSha256 = ComputeMac(unsigned) };
        await using (FileStream metadata = CreateFile(Path.Combine(pending, MetadataName)))
        {
            await JsonSerializer.SerializeAsync(metadata, artifact, cancellationToken: cancellationToken).ConfigureAwait(false);
            await FlushDurablyAsync(metadata, cancellationToken).ConfigureAwait(false);
        }
        artifact = await ReadArtifactAsync(pending, checkpointJson, cancellationToken).ConfigureAwait(false);
        await using (FileStream archive = OpenArchive(pending))
        {
            await AuthenticateArchiveAsync(archive, artifact, cancellationToken).ConfigureAwait(false);
            await VerifyRestoreAsync(archive, artifact, cancellationToken).ConfigureAwait(false);
        }
        SecureSnapshotFileCreation.ValidateRestrictedDirectory(_root);
        SecureSnapshotFileCreation.ValidateRestrictedDirectory(pending);
        await _publicationAuthorityGuard(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        Directory.Move(pending, destination);
        _ = await ReadArtifactAsync(destination, checkpointJson, cancellationToken).ConfigureAwait(false);
        await using FileStream published = OpenArchive(destination);
        await AuthenticateArchiveAsync(published, artifact, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Authenticates local evidence for recovery after remote completion. Does not redump or restore.</summary>
    public async Task<IReadOnlyList<DatabaseMigrationCheckpoint>> ReadVerifiedCheckpointsAsync(CancellationToken cancellationToken)
    {
        await using FileStream gate = AcquireLock();
        IReadOnlyList<LocalDatabaseArtifact> artifacts = await ReadInventoryAsync(cancellationToken).ConfigureAwait(false);
        return artifacts.Select(artifact => ValidateCheckpoint(artifact.CheckpointJson)).ToArray();
    }

    public async Task<LocalSnapshotManifest> FinalizeAsync(string outputDirectory,
        IReadOnlyList<DatabaseMigrationCheckpoint> checkpoints, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(checkpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        string[] frozenJson = [.. checkpoints.Select(checkpoint => Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint)))];
        DatabaseMigrationCheckpoint[] frozen = [.. frozenJson.Select(ValidateCheckpoint)];
        if (!frozen.Select(checkpoint => checkpoint.Database.Database).Order(StringComparer.Ordinal)
            .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw new InvalidDataException("Finalization requires the exact active signed checkpoint inventory.");
        }
        string output = Path.TrimEndingDirectorySeparator(Path.GetFullPath(outputDirectory));
        SecureSnapshotFileCreation.RejectLinkedAncestors(output);
        if (output.StartsWith(_root + Path.DirectorySeparatorChar, PathComparison) || string.Equals(output, _root, PathComparison))
        {
            throw new IOException("Final output must be a new directory outside durable staging.");
        }
        await using FileStream gate = AcquireLock();
        IReadOnlyList<LocalDatabaseArtifact> artifacts = await ReadInventoryAsync(cancellationToken).ConfigureAwait(false);
        if (artifacts.Count != frozen.Length || artifacts.Any(artifact => !frozenJson.Contains(artifact.CheckpointJson, StringComparer.Ordinal)))
        {
            throw new InvalidDataException("Finalization checkpoints differ from the authenticated local inventory.");
        }
        LocalSnapshotDatabase[] semantic = [.. artifacts.Select(artifact => artifact.Archive with { FileName = $"{artifact.Archive.Database}.dump.aes256" })];
        string digest = SnapshotManifestAuthentication.ComputeSemanticDigest(_snapshotId, semantic);
        if (Path.Exists(output)) { return await ReadFinalAsync(output, semantic, digest, cancellationToken).ConfigureAwait(false); }
        string parent = Path.GetDirectoryName(output) ?? throw new IOException("Final output requires a parent directory.");
        string pending = Path.Combine(parent, $".final-{Guid.NewGuid():N}");
        SecureSnapshotFileCreation.CreateRestrictedDirectory(pending);
        var exported = new List<LocalSnapshotDatabase>();
        foreach (LocalDatabaseArtifact artifact in artifacts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LocalSnapshotDatabase entry = semantic.Single(item => item.Database == artifact.Archive.Database);
            string path = Path.Combine(pending, entry.FileName);
            await using (FileStream staging = OpenArchive(Path.Combine(_root, entry.Database)))
            {
                // Keep one verified handle across full authentication and bounded re-encryption.
                await AuthenticateArchiveAsync(staging, artifact, cancellationToken).ConfigureAwait(false);
                staging.Position = 0;
                await using FileStream encrypted = CreateFile(path);
                SnapshotEncryptionResult result = await SnapshotEncryption.ReencryptStagingAsync(staging, encrypted, _key,
                    Context(entry.Database, artifact.CheckpointSha256), Context(entry.Database, digest), cancellationToken).ConfigureAwait(false);
                RequireContent(result.PlaintextByteLength, result.PlaintextSha256, entry);
                await FlushDurablyAsync(encrypted, cancellationToken).ConfigureAwait(false);
            }
            await using FileStream final = SecureSnapshotFileCreation.OpenValidatedRead(path);
            string hash = await HashAsync(final, cancellationToken).ConfigureAwait(false);
            final.Position = 0;
            using var sink = new HashSink();
            await SnapshotEncryption.DecryptAsync(final, sink, _key, Context(entry.Database, digest), cancellationToken).ConfigureAwait(false);
            RequireContent(sink.Count, sink.FinishHash(), entry);
            exported.Add(entry with { EncryptedByteLength = final.Length, EncryptedSha256 = hash });
        }
        var unsigned = new LocalSnapshotManifest(2, "MLVSNP02", "AES-256-GCM-chunked-v2", _snapshotId, digest, string.Empty, exported);
        LocalSnapshotManifest manifest = unsigned with { ManifestMacSha256 = SnapshotManifestAuthentication.ComputeMac(unsigned, _key) };
        string manifestPath = Path.Combine(pending, "manifest.json");
        await using (FileStream stream = CreateFile(manifestPath))
        {
            await JsonSerializer.SerializeAsync(stream, manifest, cancellationToken: cancellationToken).ConfigureAwait(false);
            await FlushDurablyAsync(stream, cancellationToken).ConfigureAwait(false);
        }
        await using (FileStream stream = SecureSnapshotFileCreation.OpenValidatedRead(manifestPath))
        {
            LocalSnapshotManifest readback = await JsonSerializer.DeserializeAsync<LocalSnapshotManifest>(stream, cancellationToken: cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("Final manifest readback is empty.");
            if (readback.ManifestMacSha256 != manifest.ManifestMacSha256 || SnapshotManifestAuthentication.ComputeMac(readback, _key) != manifest.ManifestMacSha256)
            {
                throw new CryptographicException("Final manifest readback authentication failed.");
            }
        }
        SecureSnapshotFileCreation.RejectLinkedAncestors(output);
        SecureSnapshotFileCreation.ValidateRestrictedDirectory(pending);
        await _publicationAuthorityGuard(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        Directory.Move(pending, output);
        return await ReadFinalAsync(output, semantic, digest, cancellationToken).ConfigureAwait(false);
    }

    private async Task<LocalSnapshotManifest> ReadFinalAsync(string directory, LocalSnapshotDatabase[] expected,
        string digest, CancellationToken token)
    {
        SecureSnapshotFileCreation.ValidateRestrictedDirectory(directory);
        if (!Directory.EnumerateFileSystemEntries(directory).Select(Path.GetFileName).Order(StringComparer.Ordinal)
            .SequenceEqual(expected.Select(entry => entry.FileName).Append("manifest.json").Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw new InvalidDataException("Final output is torn or contains unexpected entries.");
        }
        LocalSnapshotManifest manifest;
        await using (FileStream stream = SecureSnapshotFileCreation.OpenValidatedRead(Path.Combine(directory, "manifest.json")))
        {
            if (stream.Length > 16 * 1024 * 1024) { throw new InvalidDataException("Final manifest exceeds its size limit."); }
            manifest = await JsonSerializer.DeserializeAsync<LocalSnapshotManifest>(stream, cancellationToken: token).ConfigureAwait(false)
                ?? throw new InvalidDataException("Final manifest is missing.");
        }
        if (manifest.SchemaVersion != 2 || manifest.Format != "MLVSNP02" || manifest.Encryption != "AES-256-GCM-chunked-v2" ||
            manifest.SnapshotId != _snapshotId || manifest.ManifestDigestSha256 != digest || manifest.Databases is null ||
            manifest.Databases.Count != expected.Length || SnapshotManifestAuthentication.ComputeMac(manifest, _key) != manifest.ManifestMacSha256 ||
            SnapshotManifestAuthentication.ComputeSemanticDigest(_snapshotId, manifest.Databases) != digest)
        {
            throw new CryptographicException("Final manifest does not match the authenticated local checkpoint inventory.");
        }
        foreach (LocalSnapshotDatabase entry in expected)
        {
            LocalSnapshotDatabase[] matches = [.. manifest.Databases.Where(item => item.Database == entry.Database)];
            if (matches.Length != 1 || (matches[0] with { EncryptedByteLength = entry.EncryptedByteLength, EncryptedSha256 = entry.EncryptedSha256 }) != entry)
            {
                throw new InvalidDataException("Final archive identity differs from local staging.");
            }
            LocalSnapshotDatabase final = matches[0];
            await using FileStream archive = SecureSnapshotFileCreation.OpenValidatedRead(Path.Combine(directory, entry.FileName));
            if (archive.Length != final.EncryptedByteLength || await HashAsync(archive, token).ConfigureAwait(false) != final.EncryptedSha256)
            {
                throw new CryptographicException("Final archive ciphertext length or hash is invalid.");
            }
            archive.Position = 0;
            using var sink = new HashSink();
            await SnapshotEncryption.DecryptAsync(archive, sink, _key, Context(entry.Database, digest), token).ConfigureAwait(false);
            RequireContent(sink.Count, sink.FinishHash(), entry);
        }
        return manifest;
    }

    private async Task<IReadOnlyList<LocalDatabaseArtifact>> ReadInventoryAsync(CancellationToken token)
    {
        var artifacts = new List<LocalDatabaseArtifact>();
        foreach (string path in Directory.EnumerateFileSystemEntries(_root).Order(StringComparer.Ordinal))
        {
            string name = Path.GetFileName(path);
            if (name == ".store.lock" || PendingName().IsMatch(name)) { continue; }
            if (!DatabaseInventory.ActiveDatabases.Contains(name, StringComparer.Ordinal)) { throw new InvalidDataException("Unknown local artifact entry."); }
            LocalDatabaseArtifact artifact = await ReadArtifactAsync(path, null, token).ConfigureAwait(false);
            if (artifact.Archive.Database != name) { throw new InvalidDataException("Artifact directory does not match its database."); }
            await using FileStream archive = OpenArchive(path);
            await AuthenticateArchiveAsync(archive, artifact, token).ConfigureAwait(false);
            artifacts.Add(artifact);
        }
        return artifacts;
    }

    private async Task<LocalDatabaseArtifact> ReadArtifactAsync(string directory, string? expectedCheckpoint, CancellationToken token)
    {
        SecureSnapshotFileCreation.ValidateRestrictedDirectory(directory);
        if (!Directory.EnumerateFileSystemEntries(directory).Select(Path.GetFileName).Order(StringComparer.Ordinal)
            .SequenceEqual(new[] { ArchiveName, MetadataName }.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw new InvalidDataException("Local artifact publication is incomplete or contains unknown entries.");
        }
        await using FileStream metadata = SecureSnapshotFileCreation.OpenValidatedRead(Path.Combine(directory, MetadataName));
        if (metadata.Length > 16 * 1024 * 1024) { throw new InvalidDataException("Local artifact metadata exceeds its size limit."); }
        LocalDatabaseArtifact artifact = await JsonSerializer.DeserializeAsync<LocalDatabaseArtifact>(metadata, cancellationToken: token).ConfigureAwait(false)
            ?? throw new InvalidDataException("Local artifact metadata is empty.");
        string expectedMac = ComputeMac(artifact);
        if (artifact.MetadataMacSha256 is null || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expectedMac), Encoding.UTF8.GetBytes(artifact.MetadataMacSha256)))
        {
            throw new CryptographicException("Local artifact metadata authentication failed.");
        }
        DatabaseMigrationCheckpoint checkpoint = ValidateCheckpoint(artifact.CheckpointJson);
        return artifact.SchemaVersion != 1 || artifact.SnapshotId != _snapshotId || artifact.Archive is null ||
            artifact.CheckpointSha256 != HashText(artifact.CheckpointJson) || artifact.Archive.Database != checkpoint.Database.Database ||
            artifact.Archive.ShadowDatabase != checkpoint.Shadow.Name || artifact.Archive.FileName != ArchiveName ||
            artifact.Archive.PlaintextByteLength < 0 || artifact.Archive.EncryptedByteLength < 20 ||
            (expectedCheckpoint is not null && artifact.CheckpointJson != expectedCheckpoint)
            ? throw new InvalidDataException("Local artifact does not match the exact signed checkpoint and snapshot identity.")
            : artifact;
    }

    private async Task AuthenticateArchiveAsync(FileStream archive, LocalDatabaseArtifact artifact, CancellationToken token)
    {
        archive.Position = 0;
        if (archive.Length != artifact.Archive.EncryptedByteLength || await HashAsync(archive, token).ConfigureAwait(false) != artifact.Archive.EncryptedSha256)
        {
            throw new CryptographicException("Local encrypted archive length or hash is invalid.");
        }
        archive.Position = 0;
        using var sink = new HashSink();
        await SnapshotEncryption.DecryptStagingAsync(archive, sink, _key, Context(artifact.Archive.Database, artifact.CheckpointSha256), token).ConfigureAwait(false);
        RequireContent(sink.Count, sink.FinishHash(), artifact.Archive);
    }

    private async Task VerifyRestoreAsync(FileStream archive, LocalDatabaseArtifact artifact, CancellationToken token)
    {
        archive.Position = 0;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var pipe = new Pipe(new PipeOptions(pauseWriterThreshold: 2 * 1024 * 1024, resumeWriterThreshold: 1024 * 1024, useSynchronizationContext: false));
        Task producer = ProduceAsync();
        await using Stream reader = pipe.Reader.AsStream(leaveOpen: true);
        using var counted = new CountingReader(reader);
        try
        {
            await _localVerifier.VerifyAsync(counted, ValidateCheckpoint(artifact.CheckpointJson), cancellation.Token).ConfigureAwait(false);
            if (counted.Count != artifact.Archive.PlaintextByteLength) { throw new InvalidDataException("Local verifier did not consume the entire authenticated archive."); }
            await producer.ConfigureAwait(false);
        }
        finally
        {
            await cancellation.CancelAsync().ConfigureAwait(false);
            await pipe.Reader.CompleteAsync().ConfigureAwait(false);
            try { await producer.ConfigureAwait(false); } catch (Exception exception) when (exception is not OutOfMemoryException and not AccessViolationException) { }
        }

        async Task ProduceAsync()
        {
            Exception? failure = null;
            try
            {
                await SnapshotEncryption.DecryptStagingAsync(archive, pipe.Writer.AsStream(leaveOpen: true), _key,
                    Context(artifact.Archive.Database, artifact.CheckpointSha256), cancellation.Token).ConfigureAwait(false);
            }
            catch (Exception exception) { failure = exception; throw; }
            finally { await pipe.Writer.CompleteAsync(failure).ConfigureAwait(false); }
        }
    }

    private DatabaseMigrationCheckpoint ValidateCheckpoint(string json)
    {
        DatabaseMigrationCheckpoint checkpoint = JsonSerializer.Deserialize<DatabaseMigrationCheckpoint>(json)
            ?? throw new InvalidDataException("Signed checkpoint is missing.");
        // Validates signed original ownership, not live remote ownership; the runner owns that check.
        _checkpointVerifier.Validate(checkpoint, checkpoint.Shadow);
        return !DatabaseInventory.ActiveDatabases.Contains(checkpoint.Database.Database, StringComparer.Ordinal)
            ? throw new InvalidDataException("Checkpoint is not an active database.")
            : checkpoint;
    }

    private FileStream AcquireLock()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SecureSnapshotFileCreation.CreateRestrictedDirectory(_root);
        string path = Path.Combine(_root, ".store.lock");
        if (new FileInfo(path).LinkTarget is not null) { throw new UnauthorizedAccessException("Local store lock cannot be a link."); }
        FileStreamOptions options = LocalSnapshotExporter.CreateSecureOptions(FileAccess.ReadWrite, FileOptions.WriteThrough);
        options.Mode = FileMode.OpenOrCreate;
        var stream = new FileStream(path, options);
        try { SecureSnapshotFileCreation.Validate(stream, path); return stream; }
        catch { stream.Dispose(); throw; }
    }

    private static FileStream CreateFile(string path)
    {
        var stream = new FileStream(path, LocalSnapshotExporter.CreateSecureOptions(FileAccess.Write, FileOptions.Asynchronous | FileOptions.WriteThrough));
        try { SecureSnapshotFileCreation.Validate(stream, path); return stream; }
        catch { stream.Dispose(); throw; }
    }

    private static FileStream OpenArchive(string directory)
    {
        return SecureSnapshotFileCreation.OpenValidatedRead(Path.Combine(directory, ArchiveName));
    }

    private SnapshotArchiveContext Context(string database, string digest)
    {
        return SnapshotArchiveContext.Create(_snapshotId, database, digest);
    }

    private static string HashText(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private static async Task<string> HashAsync(Stream stream, CancellationToken token)
    {
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, token).ConfigureAwait(false)).ToLowerInvariant();
    }

    private static async Task FlushDurablyAsync(FileStream stream, CancellationToken token)
    {
        await stream.FlushAsync(token).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
    }

    private string ComputeMac(LocalDatabaseArtifact artifact)
    {
        byte[] key = SnapshotKeyDerivation.DeriveManifestMacKey(_key);
        try { return Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes("MALIEV-local-database-artifact-v1\n" + JsonSerializer.Serialize(artifact with { MetadataMacSha256 = string.Empty })))).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static void RequireContent(long length, string hash, LocalSnapshotDatabase entry)
    {
        if (length != entry.PlaintextByteLength || hash != entry.PlaintextSha256) { throw new CryptographicException("Authenticated archive plaintext length or hash is invalid."); }
    }

    public void Dispose()
    {
        _disposed = true;
        CryptographicOperations.ZeroMemory(_key);
    }

    private static StringComparison PathComparison => OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex SnapshotIdentity();
    [GeneratedRegex("^\\.pending-[a-f0-9]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex PendingName();

    private sealed class HashSink : Stream
    {
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        public long Count { get; private set; }
        public string FinishHash()
        {
            return Convert.ToHexString(_hash.GetHashAndReset()).ToLowerInvariant();
        }

        public override void Write(byte[] buffer, int offset, int count) { _hash.AppendData(buffer, offset, count); Count += count; }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested(); _hash.AppendData(buffer.Span); Count += buffer.Length; return ValueTask.CompletedTask;
        }
        protected override void Dispose(bool disposing) { if (disposing) { _hash.Dispose(); } base.Dispose(disposing); }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => Count;
        public override long Position { get => Count; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class CountingReader(Stream inner) : Stream
    {
        public long Count { get; private set; }
        public override int Read(byte[] buffer, int offset, int count) { int read = inner.Read(buffer, offset, count); Count += read; return read; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int read = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false); Count += read; return read;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => Count; set => throw new NotSupportedException(); }
        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}
