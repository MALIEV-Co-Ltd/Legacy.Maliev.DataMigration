using System.Security.AccessControl;
using System.Security.Principal;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class SourceBackedLocalRepairRunningBundleTests : IDisposable
{
    private readonly string _parent = Path.Combine(Path.GetTempPath(), $"running-bundle-{Guid.NewGuid():N}");
    private string Accepted => Path.Combine(_parent, "accepted");
    private string Running => Path.Combine(_parent, "running");
    private string Dependency => Path.Combine(Running, "dependency.dll");

    [WindowsLocalRunFact]
    public async Task RunningBundle_LoaderLikeReadHandle_VerifiesBytesWithoutChangingStrictKeyReads()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        CreatePair();
        using (var loader = new FileStream(Dependency, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            MigrationConsoleException original = Assert.Throws<MigrationConsoleException>(() =>
            {
                using FileStream strict = OwnerProtectedFilePolicy.OpenRead(Dependency, "key_read_unprotected");
            });
            Assert.Equal("key_read_unprotected", original.Code);
            IOException sharing = Assert.Throws<IOException>(() =>
            {
                using var exclusive = new FileStream(Dependency, FileMode.Open, FileAccess.Read, FileShare.None);
            });
            Assert.Equal(unchecked((int)0x80070020), sharing.HResult);
            await SourceBackedLocalRepairSourceAcceptance.RequireBundleForPathsAsync(Accepted, Running, CancellationToken.None);
        }
        using FileStream strict = OwnerProtectedFilePolicy.OpenRead(Dependency, "key_read_unprotected");
        Assert.Equal(4, strict.Length);
    }

    [WindowsLocalRunFact]
    public void RunningBundle_SharedReaderStillExcludesWritesAndReplacement()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        CreatePair();
        using FileStream verified = SecureLocalFile.OpenReadShared(Dependency);
        using var otherReader = new FileStream(Dependency, FileMode.Open, FileAccess.Read, FileShare.Read);
        _ = Assert.Throws<IOException>(() =>
        {
            using var writer = new FileStream(Dependency, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        });
        _ = Assert.Throws<IOException>(() => File.Move(Dependency, Dependency + ".replacement"));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, File.ReadAllBytes(Dependency));
    }

    [WindowsLocalRunTheory]
    [InlineData("tampered")]
    [InlineData("missing")]
    [InlineData("extra")]
    [InlineData("nested-extra")]
    [InlineData("empty")]
    [InlineData("same-root")]
    [InlineData("missing-root")]
    public async Task RunningBundle_ByteAndInventoryDriftRejects(string mutation)
    {
        if (!OperatingSystem.IsWindows()) { return; }
        CreatePair();
        string running = Running;
        switch (mutation)
        {
            case "tampered": File.WriteAllBytes(Dependency, [1, 2, 3, 5]); break;
            case "missing": File.Delete(Dependency); break;
            case "extra": File.WriteAllText(Path.Combine(Running, "extra.json"), "{}"); break;
            case "nested-extra": File.WriteAllText(Path.Combine(Running, "nested", "extra.json"), "{}"); break;
            case "empty":
                Directory.Delete(Accepted, recursive: true);
                Directory.Delete(Running, recursive: true);
                SecureSnapshotFileCreation.CreateRestrictedDirectory(Accepted);
                SecureSnapshotFileCreation.CreateRestrictedDirectory(Running);
                break;
            case "same-root": running = Accepted; break;
            case "missing-root": running = Path.Combine(_parent, "absent"); break;
            default:
                break;
        }
        MigrationConsoleException error = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            SourceBackedLocalRepairSourceAcceptance.RequireBundleForPathsAsync(Accepted, running, CancellationToken.None));
        Assert.Equal("delta_source_repair_source_unaccepted", error.Code);
    }

    [WindowsLocalRunFact]
    public async Task RunningBundle_ForeignReadAclRejectsEvenWithIdenticalBytes()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        CreatePair();
        var file = new FileInfo(Dependency);
        FileSecurity acl = file.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.Read, AccessControlType.Allow));
        file.SetAccessControl(acl);
        MigrationConsoleException error = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            SourceBackedLocalRepairSourceAcceptance.RequireBundleForPathsAsync(Accepted, Running, CancellationToken.None));
        Assert.Equal("delta_source_repair_build_unprotected", error.Code);
    }

    [WindowsLocalRunTheory]
    [InlineData("file")]
    [InlineData("ancestor")]
    public async Task RunningBundle_LinkRejectsEvenWithIdenticalBytesAndInventory(string kind)
    {
        if (!OperatingSystem.IsWindows()) { return; }
        CreatePair();
        string running = Running;
        string alias = Path.Combine(_parent, "alias");
        if (kind == "file")
        {
            File.Delete(Dependency);
            _ = File.CreateSymbolicLink(Dependency, Path.Combine(Accepted, "dependency.dll"));
        }
        else
        {
            _ = Directory.CreateSymbolicLink(alias, Running);
            running = alias;
        }
        try
        {
            MigrationConsoleException error = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
                SourceBackedLocalRepairSourceAcceptance.RequireBundleForPathsAsync(Accepted, running, CancellationToken.None));
            Assert.Equal("delta_source_repair_build_unprotected", error.Code);
        }
        finally
        {
            if (kind == "file") { File.Delete(Dependency); }
            else { Directory.Delete(alias); }
        }
    }

    private void CreatePair()
    {
        SecureSnapshotFileCreation.CreateRestrictedDirectory(_parent);
        foreach (string root in new[] { Accepted, Running })
        {
            SecureSnapshotFileCreation.CreateRestrictedDirectory(root);
            SecureSnapshotFileCreation.CreateRestrictedDirectory(Path.Combine(root, "nested"));
            File.WriteAllBytes(Path.Combine(root, "dependency.dll"), [1, 2, 3, 4]);
            File.WriteAllText(Path.Combine(root, "nested", "runner.runtimeconfig.json"), "{}");
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_parent)) { Directory.Delete(_parent, recursive: true); }
    }
}
