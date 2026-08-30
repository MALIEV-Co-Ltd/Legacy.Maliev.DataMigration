using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration;

public sealed record SnapshotEncryptionResult(long PlaintextByteLength, string PlaintextSha256, int MaximumPlaintextChunkBytes);

public sealed record SnapshotArchiveContext(string SnapshotId, string Database, string ManifestDigestSha256)
{
    public static SnapshotArchiveContext Create(string snapshotId, string database, string manifestDigestSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(snapshotId);
        ArgumentException.ThrowIfNullOrWhiteSpace(database);
        return manifestDigestSha256.Length != 64 || !manifestDigestSha256.All(Uri.IsHexDigit)
            ? throw new ArgumentException("Manifest digest must be hexadecimal SHA-256.", nameof(manifestDigestSha256))
            : new(snapshotId, database, manifestDigestSha256.ToLowerInvariant());
    }
}

public static class SnapshotKeyDerivation
{
    private static readonly byte[] Salt = "MALIEV-Legacy-Snapshot-v2"u8.ToArray();
    public static byte[] DeriveEncryptionKey(ReadOnlySpan<byte> rootKey)
    {
        return Derive(rootKey, "archive-encryption");
    }

    public static byte[] DeriveManifestMacKey(ReadOnlySpan<byte> rootKey)
    {
        return Derive(rootKey, "manifest-authentication");
    }

    private static byte[] Derive(ReadOnlySpan<byte> rootKey, string purpose)
    {
        if (rootKey.Length != 32)
        {
            throw new ArgumentException("Snapshot root key must contain exactly 32 bytes.", nameof(rootKey));
        }

        byte[] input = rootKey.ToArray();
        try { return HKDF.DeriveKey(HashAlgorithmName.SHA256, input, 32, Salt, Encoding.UTF8.GetBytes(purpose)); }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    public static byte[] DeriveProvisionalStagingKey(ReadOnlySpan<byte> rootKey)
    {
        return Derive(rootKey, "provisional-staging-encryption");
    }
}

public static class SnapshotEncryption
{
    private static ReadOnlySpan<byte> Magic => "MLVSNP02"u8;
    private const int ChunkSize = 1024 * 1024;
    private const int TagSize = 16;

    public static async Task<SnapshotEncryptionResult> EncryptStagingAsync(Stream plaintext, Stream encrypted,
        ReadOnlyMemory<byte> rootKey, SnapshotArchiveContext context, CancellationToken cancellationToken)
    {
        byte[] stagingKey = SnapshotKeyDerivation.DeriveProvisionalStagingKey(rootKey.Span);
        try { return await EncryptWithKeyAsync(plaintext, encrypted, stagingKey, context, cancellationToken).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(stagingKey); }
    }

    public static async Task<SnapshotEncryptionResult> EncryptAsync(Stream plaintext, Stream encrypted,
        ReadOnlyMemory<byte> rootKey, SnapshotArchiveContext context, CancellationToken cancellationToken)
    {
        ValidateArguments(plaintext, encrypted, rootKey, context);
        byte[] encryptionKey = SnapshotKeyDerivation.DeriveEncryptionKey(rootKey.Span);
        try
        {
            return await EncryptWithKeyAsync(plaintext, encrypted, encryptionKey, context, cancellationToken).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(encryptionKey); }
    }

    private static async Task<SnapshotEncryptionResult> EncryptWithKeyAsync(Stream plaintext, Stream encrypted,
        byte[] encryptionKey, SnapshotArchiveContext context, CancellationToken cancellationToken)
    {
        byte[] plainBuffer = new byte[ChunkSize], cipherBuffer = new byte[ChunkSize], tag = new byte[TagSize], header = new byte[4];
        try
        {
            byte[] baseNonce = RandomNumberGenerator.GetBytes(8);
            await encrypted.WriteAsync(Magic.ToArray(), cancellationToken).ConfigureAwait(false);
            await encrypted.WriteAsync(baseNonce, cancellationToken).ConfigureAwait(false);
            long total = 0; int maximum = 0; uint counter = 0;
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var aes = new AesGcm(encryptionKey, TagSize);
            while (true)
            {
                int read = await ReadChunkAsync(plaintext, plainBuffer, cancellationToken).ConfigureAwait(false);
                BinaryPrimitives.WriteInt32BigEndian(header, read);
                await encrypted.WriteAsync(header, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                if (counter == uint.MaxValue)
                {
                    throw new CryptographicException("The encrypted snapshot exceeds the supported chunk count.");
                }

                aes.Encrypt(CreateNonce(baseNonce, counter), plainBuffer.AsSpan(0, read), cipherBuffer.AsSpan(0, read), tag,
                    CreateAssociatedData(context, counter, read));
                counter++;
                await encrypted.WriteAsync(cipherBuffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                await encrypted.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
                hash.AppendData(plainBuffer, 0, read); total += read; maximum = Math.Max(maximum, read);
            }
            await encrypted.FlushAsync(cancellationToken).ConfigureAwait(false);
            return new(total, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant(), maximum);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBuffer);
            CryptographicOperations.ZeroMemory(cipherBuffer);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(header);
        }
    }

    public static async Task<SnapshotEncryptionResult> ReencryptStagingAsync(Stream staging, Stream encrypted,
        ReadOnlyMemory<byte> rootKey, SnapshotArchiveContext stagingContext, SnapshotArchiveContext finalContext,
        CancellationToken cancellationToken)
    {
        byte[] stagingKey = SnapshotKeyDerivation.DeriveProvisionalStagingKey(rootKey.Span);
        byte[] finalKey = SnapshotKeyDerivation.DeriveEncryptionKey(rootKey.Span);
        var pipe = new System.IO.Pipelines.Pipe(new System.IO.Pipelines.PipeOptions(pauseWriterThreshold: 2 * ChunkSize,
            resumeWriterThreshold: ChunkSize, useSynchronizationContext: false));
        Task decrypt = PumpStagingAsync();
        try
        {
            SnapshotEncryptionResult result = await EncryptWithKeyAsync(pipe.Reader.AsStream(leaveOpen: false), encrypted,
                finalKey, finalContext, cancellationToken).ConfigureAwait(false);
            await decrypt.ConfigureAwait(false);
            return result;
        }
        catch
        {
            await pipe.Reader.CompleteAsync().ConfigureAwait(false);
            try { await decrypt.ConfigureAwait(false); } catch { }
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stagingKey);
            CryptographicOperations.ZeroMemory(finalKey);
        }

        async Task PumpStagingAsync()
        {
            await using Stream writer = pipe.Writer.AsStream(leaveOpen: false);
            await DecryptWithKeyAsync(staging, writer, stagingKey, stagingContext, cancellationToken).ConfigureAwait(false);
        }
    }

    public static async Task DecryptAsync(Stream encrypted, Stream plaintext, ReadOnlyMemory<byte> rootKey,
        SnapshotArchiveContext context, CancellationToken cancellationToken)
    {
        ValidateArguments(encrypted, plaintext, rootKey, context);
        byte[] encryptionKey = SnapshotKeyDerivation.DeriveEncryptionKey(rootKey.Span);
        try
        {
            await DecryptWithKeyAsync(encrypted, plaintext, encryptionKey, context, cancellationToken).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(encryptionKey); }
    }

    private static async Task DecryptWithKeyAsync(Stream encrypted, Stream plaintext, byte[] encryptionKey,
        SnapshotArchiveContext context, CancellationToken cancellationToken)
    {
        byte[] magic = new byte[Magic.Length], baseNonce = new byte[8], header = new byte[4], cipher = new byte[ChunkSize],
            plain = new byte[ChunkSize], tag = new byte[TagSize], trailing = new byte[1];
        try
        {
            await ReadExactlyAsync(encrypted, magic, cancellationToken).ConfigureAwait(false);
            if (!magic.AsSpan().SequenceEqual(Magic))
            {
                throw new CryptographicException("The encrypted snapshot header is invalid.");
            }

            await ReadExactlyAsync(encrypted, baseNonce, cancellationToken).ConfigureAwait(false);
            uint counter = 0; using var aes = new AesGcm(encryptionKey, TagSize);
            while (true)
            {
                await ReadExactlyAsync(encrypted, header, cancellationToken).ConfigureAwait(false);
                int length = BinaryPrimitives.ReadInt32BigEndian(header);
                if (length == 0)
                {
                    if (await encrypted.ReadAsync(trailing, cancellationToken).ConfigureAwait(false) != 0)
                    {
                        throw new CryptographicException("The encrypted snapshot contains trailing data.");
                    }

                    return;
                }
                if (length < 0 || length > ChunkSize || counter == uint.MaxValue)
                {
                    throw new CryptographicException("The encrypted snapshot chunk is invalid.");
                }

                await ReadExactlyAsync(encrypted, cipher.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                await ReadExactlyAsync(encrypted, tag, cancellationToken).ConfigureAwait(false);
                aes.Decrypt(CreateNonce(baseNonce, counter), cipher.AsSpan(0, length), tag, plain.AsSpan(0, length),
                    CreateAssociatedData(context, counter, length));
                counter++;
                await plaintext.WriteAsync(plain.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(magic);
            CryptographicOperations.ZeroMemory(baseNonce);
            CryptographicOperations.ZeroMemory(header);
            CryptographicOperations.ZeroMemory(cipher);
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(trailing);
        }
    }

    private static byte[] CreateAssociatedData(SnapshotArchiveContext context, uint counter, int length)
    {
        byte[] identityHash = SHA256.HashData(Encoding.UTF8.GetBytes($"{context.SnapshotId}\n{context.Database}\n{context.ManifestDigestSha256}"));
        byte[] associated = new byte[48]; Magic.CopyTo(associated); BinaryPrimitives.WriteUInt32BigEndian(associated.AsSpan(8), counter);
        BinaryPrimitives.WriteInt32BigEndian(associated.AsSpan(12), length); identityHash.CopyTo(associated, 16); return associated;
    }

    private static void ValidateArguments(Stream input, Stream output, ReadOnlyMemory<byte> key, SnapshotArchiveContext context)
    {
        ArgumentNullException.ThrowIfNull(input); ArgumentNullException.ThrowIfNull(output); ArgumentNullException.ThrowIfNull(context);
        if (!input.CanRead || !output.CanWrite || key.Length != 32)
        {
            throw new ArgumentException("Snapshot encryption requires readable/writable streams and a 256-bit root key.");
        }
    }

    private static async Task<int> ReadChunkAsync(Stream stream, byte[] buffer, CancellationToken token)
    { int total = 0; while (total < buffer.Length) { int read = await stream.ReadAsync(buffer.AsMemory(total), token).ConfigureAwait(false); if (read == 0) { break; } total += read; } return total; }
    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken token)
    { int total = 0; while (total < buffer.Length) { int read = await stream.ReadAsync(buffer[total..], token).ConfigureAwait(false); if (read == 0) { throw new EndOfStreamException("The encrypted snapshot is truncated."); } total += read; } }
    private static byte[] CreateNonce(byte[] baseNonce, uint counter)
    { byte[] nonce = new byte[12]; baseNonce.CopyTo(nonce, 0); BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8), counter); return nonce; }
}
