using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class EncryptedSnapshotStreamTests
{
    [Fact]
    public void SnapshotRootKey_LoadsOwnerOnlyNonLinkFile()
    {
        string directory = Path.Combine(Path.GetTempPath(), $"snapshot-key-{Guid.NewGuid():N}");
        _ = Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "snapshot.key");
        byte[] expected = RandomNumberGenerator.GetBytes(32);
        File.WriteAllText(path, Convert.ToBase64String(expected));
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        else
        {
            var owner = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
            var security = new System.Security.AccessControl.FileSecurity();
            security.SetOwner(owner); security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(owner,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        }
        try { Assert.Equal(expected, SnapshotRootKey.Load(path)); }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void SnapshotRootKey_RejectsSymbolicLink()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string directory = Path.Combine(Path.GetTempPath(), $"snapshot-key-link-{Guid.NewGuid():N}");
        _ = Directory.CreateDirectory(directory);
        string target = Path.Combine(directory, "target.key"), link = Path.Combine(directory, "snapshot.key");
        File.WriteAllText(target, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        _ = File.CreateSymbolicLink(link, target);
        try { _ = Assert.ThrowsAny<Exception>(() => SnapshotRootKey.Load(link)); }
        finally { Directory.Delete(directory, true); }
    }
    [Fact]
    public async Task EncryptAndDecrypt_LargeSnapshot_IsChunkBoundedAndLossless()
    {
        byte[] plaintext = new byte[(5 * 1024 * 1024) + 17];
        RandomNumberGenerator.Fill(plaintext);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        await using var encrypted = new MemoryStream();

        SnapshotEncryptionResult result = await SnapshotEncryption.EncryptAsync(
            new MemoryStream(plaintext, writable: false), encrypted, key,
            SnapshotArchiveContext.Create("run-1", "Customer", new string('a', 64)), CancellationToken.None);
        encrypted.Position = 0;
        await using var decrypted = new MemoryStream();
        await SnapshotEncryption.DecryptAsync(encrypted, decrypted, key,
            SnapshotArchiveContext.Create("run-1", "Customer", new string('a', 64)), CancellationToken.None);

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
        SnapshotArchiveContext context = SnapshotArchiveContext.Create("run-1", "Customer", new string('a', 64));
        _ = await SnapshotEncryption.EncryptAsync(new MemoryStream("snapshot"u8.ToArray()), encrypted, key, context, CancellationToken.None);
        byte[] bytes = encrypted.ToArray();
        bytes[20] ^= 1;

        _ = await Assert.ThrowsAsync<AuthenticationTagMismatchException>(() => SnapshotEncryption.DecryptAsync(
            new MemoryStream(bytes), Stream.Null, key, context, CancellationToken.None));
    }

    [Fact]
    public async Task Decrypt_DatabaseRemapFailsAuthentication()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        await using var encrypted = new MemoryStream();
        _ = await SnapshotEncryption.EncryptAsync(new MemoryStream("snapshot"u8.ToArray()), encrypted, key,
            SnapshotArchiveContext.Create("run-1", "Customer", new string('a', 64)), CancellationToken.None);
        encrypted.Position = 0;
        _ = await Assert.ThrowsAsync<AuthenticationTagMismatchException>(() => SnapshotEncryption.DecryptAsync(
            encrypted, Stream.Null, key,
            SnapshotArchiveContext.Create("run-1", "Employee", new string('a', 64)), CancellationToken.None));
    }

    [Fact]
    public async Task EncryptStagingAsync_KeepsDerivedKeyAliveAcrossForcedAsynchronousRead()
    {
        byte[] rootKey = RandomNumberGenerator.GetBytes(32);
        byte[] payload = "forced asynchronous staging"u8.ToArray();
        SnapshotArchiveContext context = SnapshotArchiveContext.Create("run-async", "Customer", new string('b', 64));
        await using var encrypted = new MemoryStream();
        _ = await SnapshotEncryption.EncryptStagingAsync(new ForcedAsyncReadStream(payload), encrypted, rootKey, context,
            CancellationToken.None);
        encrypted.Position = 0;
        byte[] stagingKey = SnapshotKeyDerivation.DeriveProvisionalStagingKey(rootKey);
        try
        {
            await using var restored = new MemoryStream();
            await InvokeStagingDecryptAsync(encrypted, restored, stagingKey, context);
            Assert.Equal(payload, restored.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(stagingKey); }
    }

    private static async Task InvokeStagingDecryptAsync(Stream encrypted, Stream restored, byte[] stagingKey,
        SnapshotArchiveContext context)
    {
        var method = typeof(SnapshotEncryption).GetMethod("DecryptWithKeyAsync",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        await (Task)method.Invoke(null, [encrypted, restored, stagingKey, context, CancellationToken.None])!;
    }

    private sealed class ForcedAsyncReadStream(byte[] payload) : MemoryStream(payload, writable: false)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            return await base.ReadAsync(buffer, cancellationToken);
        }
    }
}
