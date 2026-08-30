using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SecureFileBoundaryTests
{
    [Theory]
    [InlineData(@"\\?\C:\recovery\backup.bak", @"C:\recovery\backup.bak")]
    [InlineData(@"\\?\UNC\server\share\backup.bak", @"\\server\share\backup.bak")]
    public void SecureLocalFile_NormalizesWindowsDeviceAndUncHandlePaths(string observed, string expected)
    {
        Assert.Equal(expected, SecureLocalFile.NormalizeWindowsFinalPath(observed));
    }

    [Theory]
    [InlineData(@"\\?\C:\config\backup.json", @"C:\config\backup.json")]
    [InlineData(@"\\?\UNC\server\share\signing.pem", @"\\server\share\signing.pem")]
    public void OwnerProtectedFilePolicy_NormalizesWindowsDeviceAndUncHandlePaths(string observed, string expected)
    {
        Assert.Equal(expected, OwnerProtectedFilePolicy.NormalizeWindowsFinalPath(observed));
    }

    [Fact]
    public void UnixOwnershipPolicies_RejectOwnerUidMismatchEvenWhenModeCouldBeOwnerOnly()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        uint effectiveUid = SecureLocalFile.GetEffectiveUserId();
        uint attackerUid = effectiveUid == uint.MaxValue ? effectiveUid - 1 : effectiveUid + 1;

        Assert.True(SecureLocalFile.IsEffectiveUnixUserId(effectiveUid));
        Assert.False(SecureLocalFile.IsEffectiveUnixUserId(attackerUid));
        Assert.True(OwnerProtectedFilePolicy.IsEffectiveUnixUserId(effectiveUid));
        Assert.False(OwnerProtectedFilePolicy.IsEffectiveUnixUserId(attackerUid));
    }
}
