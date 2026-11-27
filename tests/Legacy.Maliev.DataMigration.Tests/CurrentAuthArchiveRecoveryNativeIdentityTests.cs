using System.Security.Cryptography;
using System.Text;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAuthArchiveRecoveryNativeIdentityTests
{
    [WindowsLocalRunTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void Original_observation_and_selected_or_exclusive_reopen_reject_identical_byte_replacement(bool exclusive)
    {
        if (!OperatingSystem.IsWindows()) { return; }
        string parent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
        string root = WindowsRunFileIdentity.ValidateRootPath(Path.Combine(parent, "auth-recovery-native-id-" + Guid.NewGuid().ToString("N")));
        string path = Path.Combine(root, "synthetic-original.bin"), retired = Path.Combine(root, "retired-original.bin");
        byte[] bytes = Encoding.UTF8.GetBytes("synthetic recovery identity regression");
        string sha = CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes);
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root);
        try
        {
            File.WriteAllBytes(path, bytes);
            CurrentAuthArchiveRecoveryOriginalFile original;
            string legacyPathIdentity;
            using (var held = SecureLocalFile.OpenReadShared(path))
            {
                original = CurrentAuthArchiveRecoveryV2Storage.ObserveOriginalHandle(held, path, sha, bytes.Length);
                legacyPathIdentity = SecureLocalFile.GetHandleIdentity(held);
                CurrentAuthArchiveRecoveryV2Storage.RequireOriginalHandle(held, original);
            }
            FileShare sharing = exclusive ? FileShare.None : FileShare.Read;
            using (var unchanged = new FileStream(path, FileMode.Open, FileAccess.Read, sharing))
            { CurrentAuthArchiveRecoveryV2Storage.RequireOriginalHandle(unchanged, original); }

            // Keep the original object alive under another name so NTFS cannot reuse its ID.
            File.Move(path, retired);
            File.WriteAllBytes(path, bytes);
            using var replacement = new FileStream(path, FileMode.Open, FileAccess.Read, sharing);
            Assert.Equal(original.Length, replacement.Length);
            Assert.Equal(original.Sha256, Convert.ToHexStringLower(SHA256.HashData(replacement)));
            Assert.Equal(legacyPathIdentity, SecureLocalFile.GetHandleIdentity(replacement));
            var current = CurrentAuthArchiveRecoveryV2Storage.ObserveOriginalHandle(replacement, path, sha, bytes.Length);
            Assert.NotEqual(original.Identity, current.Identity);
            Assert.True(CurrentAuthArchiveRecoveryNativeIdentity.IsValid(original.Identity));
            Assert.True(CurrentAuthArchiveRecoveryNativeIdentity.IsValid(current.Identity));
            CurrentAuthArchiveRecoveryV2Storage.RequireOriginalHandle(replacement, current);
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveRecoveryV2Storage.RequireOriginalHandle(replacement, original));
            if (exclusive)
            {
                var failure = Assert.Throws<IOException>(() => { using var impossible = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); });
                Assert.Equal(32, failure.HResult & 0xffff);
            }
        }
        finally
        {
            // Delete only the two files and new directory owned by this test; never recurse into another root.
            if (Directory.Exists(root))
            {
                SecureSnapshotFileCreation.ValidateRestrictedDirectory(root);
                File.Delete(path); File.Delete(retired); Directory.Delete(root, recursive: false);
            }
        }
    }

    [Theory]
    [InlineData("current-auth-recovery-ntfs-file-v1|windows-ntfs:11111111-1111-1111-1111-111111111111:0000000000000001|file-id-128:00000000000000000000000000000001", true)]
    [InlineData("windows:path-only:c:\\original.bin", false)]
    [InlineData("current-auth-recovery-ntfs-file-v1|windows-ntfs:11111111-1111-1111-1111-111111111111:0000000000000000|file-id-128:00000000000000000000000000000001", false)]
    [InlineData("current-auth-recovery-ntfs-file-v1|windows-ntfs:11111111-1111-1111-1111-111111111111:0000000000000001|file-id-128:00000000000000000000000000000000", false)]
    [InlineData("current-auth-recovery-ntfs-file-v1|windows-ntfs:11111111-1111-1111-1111-111111111111:0000000000000001|file-id-128:00000000000000000000000000000001|extra", false)]
    public void Retained_wire_identity_requires_explicit_volume_and_native_object_version(string value, bool valid)
    {
        Assert.Equal(valid, CurrentAuthArchiveRecoveryNativeIdentity.IsValid(value));
    }
}
