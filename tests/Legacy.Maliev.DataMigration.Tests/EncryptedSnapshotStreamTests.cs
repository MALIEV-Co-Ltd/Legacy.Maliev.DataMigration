using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class EncryptedSnapshotStreamTests
{
    [Fact]
    public async Task EncryptAndDecrypt_LargeSnapshot_IsChunkBoundedAndLossless()
    {
        byte[] plaintext = new byte[(5 * 1024 * 1024) + 17];
        RandomNumberGenerator.Fill(plaintext);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        await using var encrypted = new MemoryStream();

        SnapshotEncryptionResult result = await SnapshotEncryption.EncryptAsync(
            new MemoryStream(plaintext, writable: false), encrypted, key, CancellationToken.None);
        encrypted.Position = 0;
        await using var decrypted = new MemoryStream();
        await SnapshotEncryption.DecryptAsync(encrypted, decrypted, key, CancellationToken.None);

        Assert.Equal(plaintext, decrypted.ToArray());
        Assert.Equal(plaintext.LongLength, result.PlaintextByteLength);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(plaintext)).ToLowerInvariant(), result.PlaintextSha256);
        Assert.True(result.MaximumPlaintextChunkBytes <= 1024 * 1024);
    }

    [Fact]
    public async Task Decrypt_TamperedCiphertextFailsAuthentication()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        await using var encrypted = new MemoryStream();
        _ = await SnapshotEncryption.EncryptAsync(new MemoryStream("snapshot"u8.ToArray()), encrypted, key, CancellationToken.None);
        byte[] bytes = encrypted.ToArray();
        bytes[20] ^= 1;

        _ = await Assert.ThrowsAsync<AuthenticationTagMismatchException>(() => SnapshotEncryption.DecryptAsync(
            new MemoryStream(bytes), Stream.Null, key, CancellationToken.None));
    }
}
