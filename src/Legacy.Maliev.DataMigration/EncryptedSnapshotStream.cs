using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

public sealed record SnapshotEncryptionResult(long PlaintextByteLength, string PlaintextSha256, int MaximumPlaintextChunkBytes);

public static class SnapshotEncryption
{
    private static ReadOnlySpan<byte> Magic => "MLVSNP01"u8;
    private const int ChunkSize = 1024 * 1024;
    private const int TagSize = 16;

    public static async Task<SnapshotEncryptionResult> EncryptAsync(
        Stream plaintext,
        Stream encrypted,
        ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken)
    {
        ValidateArguments(plaintext, encrypted, key);
        byte[] baseNonce = RandomNumberGenerator.GetBytes(8);
        await encrypted.WriteAsync(Magic.ToArray(), cancellationToken).ConfigureAwait(false);
        await encrypted.WriteAsync(baseNonce, cancellationToken).ConfigureAwait(false);
        byte[] plainBuffer = new byte[ChunkSize];
        byte[] cipherBuffer = new byte[ChunkSize];
        byte[] tag = new byte[TagSize];
        byte[] header = new byte[4];
        long total = 0;
        int maximum = 0;
        uint counter = 0;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var aes = new AesGcm(key.Span, TagSize);
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
            byte[] nonce = CreateNonce(baseNonce, counter++);
            byte[] associatedData = CreateAssociatedData(counter - 1, read);
            aes.Encrypt(nonce, plainBuffer.AsSpan(0, read), cipherBuffer.AsSpan(0, read), tag, associatedData);
            await encrypted.WriteAsync(cipherBuffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            await encrypted.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
            hash.AppendData(plainBuffer, 0, read);
            total += read;
            maximum = Math.Max(maximum, read);
        }

        await encrypted.FlushAsync(cancellationToken).ConfigureAwait(false);
        return new(total, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant(), maximum);
    }

    public static async Task DecryptAsync(
        Stream encrypted,
        Stream plaintext,
        ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken)
    {
        ValidateArguments(encrypted, plaintext, key);
        byte[] magic = new byte[Magic.Length];
        await ReadExactlyAsync(encrypted, magic, cancellationToken).ConfigureAwait(false);
        if (!magic.AsSpan().SequenceEqual(Magic))
        {
            throw new CryptographicException("The encrypted snapshot header is invalid.");
        }
        byte[] baseNonce = new byte[8];
        await ReadExactlyAsync(encrypted, baseNonce, cancellationToken).ConfigureAwait(false);
        byte[] header = new byte[4];
        byte[] cipherBuffer = new byte[ChunkSize];
        byte[] plainBuffer = new byte[ChunkSize];
        byte[] tag = new byte[TagSize];
        uint counter = 0;
        using var aes = new AesGcm(key.Span, TagSize);
        while (true)
        {
            await ReadExactlyAsync(encrypted, header, cancellationToken).ConfigureAwait(false);
            int length = BinaryPrimitives.ReadInt32BigEndian(header);
            if (length == 0)
            {
                if (await encrypted.ReadAsync(new byte[1], cancellationToken).ConfigureAwait(false) != 0)
                {
                    throw new CryptographicException("The encrypted snapshot contains trailing data.");
                }
                return;
            }
            if (length < 0 || length > ChunkSize || counter == uint.MaxValue)
            {
                throw new CryptographicException("The encrypted snapshot chunk is invalid.");
            }
            await ReadExactlyAsync(encrypted, cipherBuffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            await ReadExactlyAsync(encrypted, tag, cancellationToken).ConfigureAwait(false);
            aes.Decrypt(CreateNonce(baseNonce, counter), cipherBuffer.AsSpan(0, length), tag,
                plainBuffer.AsSpan(0, length), CreateAssociatedData(counter, length));
            counter++;
            await plaintext.WriteAsync(plainBuffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        }
    }

    private static void ValidateArguments(Stream input, Stream output, ReadOnlyMemory<byte> key)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (!input.CanRead || !output.CanWrite || key.Length != 32)
        {
            throw new ArgumentException("Snapshot encryption requires readable/writable streams and a 256-bit key.");
        }
    }

    private static async Task<int> ReadChunkAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            total += read;
        }
        return total;
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The encrypted snapshot is truncated.");
            }
            total += read;
        }
    }

    private static byte[] CreateNonce(byte[] baseNonce, uint counter)
    {
        byte[] nonce = new byte[12];
        baseNonce.CopyTo(nonce, 0);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8), counter);
        return nonce;
    }

    private static byte[] CreateAssociatedData(uint counter, int length)
    {
        byte[] associated = new byte[16];
        Magic.CopyTo(associated);
        BinaryPrimitives.WriteUInt32BigEndian(associated.AsSpan(8), counter);
        BinaryPrimitives.WriteInt32BigEndian(associated.AsSpan(12), length);
        return associated;
    }
}
