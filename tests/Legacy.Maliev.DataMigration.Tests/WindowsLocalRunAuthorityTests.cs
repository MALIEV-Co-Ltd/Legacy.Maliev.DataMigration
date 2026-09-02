using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class WindowsLocalRunFactAttribute : FactAttribute
{
    public WindowsLocalRunFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) { Skip = "The permanent coordinator authority supports Windows NTFS only."; }
    }
}

public sealed class WindowsLocalRunTheoryAttribute : TheoryAttribute
{
    public WindowsLocalRunTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows()) { Skip = "The permanent coordinator authority supports Windows NTFS only."; }
    }
}

public sealed class UnsupportedLocalRunPlatformFactAttribute : FactAttribute
{
    public UnsupportedLocalRunPlatformFactAttribute()
    {
        if (OperatingSystem.IsWindows()) { Skip = "Unsupported-platform rejection executes on non-Windows hosts."; }
    }
}

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class WindowsLocalRunAuthorityTests : IDisposable
{
    private readonly string _parent = Path.Combine(Path.GetTempPath(), $"run-authority-{Guid.NewGuid():N}");
    private string Root => Path.Combine(_parent, "artifacts");

    [WindowsLocalRunFact]
    public void AcquireResume_WhileHeld_RejectsSecondCoordinatorThenRetainsExactBindingAfterRelease()
    {
        LocalExecutionBinding expected;
        using (WindowsLocalRunAuthority first = WindowsLocalRunAuthority.AcquireFresh(Root))
        {
            expected = first.Binding;
            _ = Assert.Throws<IOException>(() => WindowsLocalRunAuthority.AcquireResume(Root, expected));
            first.ValidateHeld();
        }
        Assert.True(File.Exists(Path.Combine(Root, WindowsLocalRunAuthority.RunLockRelativeName)));
        using WindowsLocalRunAuthority resumed = WindowsLocalRunAuthority.AcquireResume(Root, expected);
        Assert.Equal(expected, resumed.Binding);
        resumed.ValidateHeld();
    }

    [WindowsLocalRunFact]
    public void AcquireFresh_PreviouslyUsedRoot_RejectsWithoutReplacingPermanentLock()
    {
        LocalExecutionBinding expected = CreateReleasedAuthority();
        _ = Assert.Throws<IOException>(() => WindowsLocalRunAuthority.AcquireFresh(Root));
        using WindowsLocalRunAuthority resumed = WindowsLocalRunAuthority.AcquireResume(Root, expected);
        Assert.Equal(expected, resumed.Binding);
    }

    [WindowsLocalRunFact]
    public void AcquireFresh_OwnerOnlyRootWithoutInheritableRules_CreatesSecurePermanentLock()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(Root);
        using WindowsIdentity current = WindowsIdentity.GetCurrent();
        var security = new DirectorySecurity();
        security.SetOwner(current.User!);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(current.User!, FileSystemRights.FullControl, AccessControlType.Allow));
        new DirectoryInfo(Root).SetAccessControl(security);
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        authority.ValidateHeld();
    }

    [WindowsLocalRunTheory]
    [InlineData("root-missing")]
    [InlineData("lock-missing")]
    [InlineData("root-replaced")]
    [InlineData("lock-replaced")]
    public void AcquireResume_MissingOrReplacedOriginalIdentity_RejectsWithoutCreatingAnything(string change)
    {
        LocalExecutionBinding expected = CreateReleasedAuthority();
        string lockPath = Path.Combine(Root, WindowsLocalRunAuthority.RunLockRelativeName);
        if (change.StartsWith("root", StringComparison.Ordinal))
        {
            Directory.Move(Root, Root + "-original");
            if (change == "root-replaced")
            {
                SecureSnapshotFileCreation.CreateRestrictedDirectory(Root);
                File.Copy(Path.Combine(Root + "-original", WindowsLocalRunAuthority.RunLockRelativeName), lockPath);
            }
        }
        else
        {
            File.Move(lockPath, lockPath + ".original");
            if (change == "lock-replaced") { using var replacement = File.Create(lockPath); }
        }
        string[] before = Directory.GetFileSystemEntries(_parent, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToArray();
        _ = Assert.ThrowsAny<IOException>(() => WindowsLocalRunAuthority.AcquireResume(Root, expected));
        Assert.Equal(before, Directory.GetFileSystemEntries(_parent, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal));
    }

    [WindowsLocalRunFact]
    public void AcquireResume_CopiedRootAtDifferentPath_RejectsOriginalBinding()
    {
        LocalExecutionBinding expected = CreateReleasedAuthority();
        string copy = Root + "-copy";
        SecureSnapshotFileCreation.CreateRestrictedDirectory(copy);
        File.Copy(Path.Combine(Root, WindowsLocalRunAuthority.RunLockRelativeName), Path.Combine(copy, WindowsLocalRunAuthority.RunLockRelativeName));
        _ = Assert.Throws<IOException>(() => WindowsLocalRunAuthority.AcquireResume(copy, expected));
    }

    [WindowsLocalRunFact]
    public void HeldAuthority_BlocksRootParentAndLockReplacementUntilDisposed()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        _ = Assert.Throws<IOException>(() => Directory.Move(Root, Root + "-moved"));
        _ = Assert.Throws<IOException>(() => Directory.Move(_parent, _parent + "-moved"));
        _ = Assert.Throws<IOException>(() => File.Move(Path.Combine(Root, WindowsLocalRunAuthority.RunLockRelativeName), Path.Combine(Root, "moved")));
        _ = Assert.Throws<IOException>(() => File.Delete(Path.Combine(Root, WindowsLocalRunAuthority.RunLockRelativeName)));
        authority.ValidateHeld();
    }

    [WindowsLocalRunFact]
    public async Task HeldAuthority_BlocksAnIndependentProcess()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        string path = Path.Combine(Root, WindowsLocalRunAuthority.RunLockRelativeName).Replace("'", "''", StringComparison.Ordinal);
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell/v1.0/powershell.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-Command", $"try {{ $f = [IO.File]::Open('{path}', 'Open', 'ReadWrite', 'None'); $f.Dispose(); exit 1 }} catch [IO.IOException] {{ exit 42 }}" })
        {
            start.ArgumentList.Add(argument);
        }
        using Process process = Process.Start(start)!;
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(42, process.ExitCode);
            Assert.Empty(await process.StandardError.ReadToEndAsync());
        }
        finally
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); }
        }
    }

    [WindowsLocalRunTheory]
    [InlineData(@"\\server\share\artifacts")]
    [InlineData(@"\\?\UNC\server\share\artifacts")]
    [InlineData(@"\\?\C:\artifacts")]
    [InlineData(@"C:\")]
    [InlineData(@"C:\artifacts:stream")]
    public void AcquireFresh_UnsupportedOrAliasedPath_RejectsBeforeMutation(string path)
    {
        _ = Assert.Throws<ArgumentException>(() => WindowsLocalRunAuthority.AcquireFresh(path));
    }

    [WindowsLocalRunTheory]
    [InlineData("root")]
    [InlineData("ancestor")]
    [InlineData("lock")]
    public void AcquireResume_ReparsePath_RejectsWithoutFollowingIt(string kind)
    {
        LocalExecutionBinding expected = CreateReleasedAuthority();
        string redirected = Root;
        if (kind == "root")
        {
            Directory.Move(Root, Root + "-original");
            _ = Directory.CreateSymbolicLink(Root, Root + "-original");
        }
        else if (kind == "ancestor")
        {
            _ = Directory.CreateSymbolicLink(Path.Combine(_parent, "alias"), _parent);
            redirected = Path.Combine(_parent, "alias", "artifacts");
        }
        else
        {
            string path = Path.Combine(Root, WindowsLocalRunAuthority.RunLockRelativeName);
            File.Move(path, path + ".original");
            _ = File.CreateSymbolicLink(path, path + ".original");
        }
        _ = Assert.Throws<UnauthorizedAccessException>(() => WindowsLocalRunAuthority.AcquireResume(redirected, expected));
    }

    [WindowsLocalRunTheory]
    [InlineData("root")]
    [InlineData("lock")]
    public void ValidateHeld_OpenedObjectAclBecomesUnsafe_Rejects(string kind)
    {
        if (!OperatingSystem.IsWindows()) { return; }
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        GrantEveryoneRead(kind);
        _ = Assert.Throws<UnauthorizedAccessException>(authority.ValidateHeld);
    }

    [WindowsLocalRunTheory]
    [InlineData("root")]
    [InlineData("lock")]
    public void AcquireResume_UnsafeAcl_Rejects(string kind)
    {
        if (!OperatingSystem.IsWindows()) { return; }
        LocalExecutionBinding expected = CreateReleasedAuthority();
        GrantEveryoneRead(kind);
        _ = Assert.Throws<UnauthorizedAccessException>(() => WindowsLocalRunAuthority.AcquireResume(Root, expected));
    }

    [WindowsLocalRunFact]
    public void AcquireResume_HardLinkedLock_RejectsAnAliasDomain()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        LocalExecutionBinding expected = CreateReleasedAuthority();
        Assert.True(CreateHardLink(Path.Combine(Root, "lock-alias"), Path.Combine(Root, WindowsLocalRunAuthority.RunLockRelativeName), IntPtr.Zero));
        _ = Assert.Throws<UnauthorizedAccessException>(() => WindowsLocalRunAuthority.AcquireResume(Root, expected));
    }

    [WindowsLocalRunFact]
    public void Binding_EveryIdentityFieldIsBoundAndDetachedSerializationResumes()
    {
        LocalExecutionBinding expected = CreateReleasedAuthority();
        var mutations = new[]
        {
            expected with { LocalExecutionBindingVersion = 2 }, expected with { HostIdentity = "different-host" },
            expected with { LocalVolumeIdentity = "different-volume" }, expected with { ArtifactRootCanonicalPath = Root + "-copy" },
            expected with { ArtifactRootFilesystemObjectIdentity = "different-directory-id" }, expected with { RunLockRelativeName = ".different.lock" },
            expected with { RunLockFilesystemObjectIdentity = "different-file-id" }, expected with { LockProtocolVersion = 2 },
        };
        foreach (LocalExecutionBinding mutation in mutations)
        {
            Assert.NotEqual(expected.ComputeSha256(), mutation.ComputeSha256());
            _ = Assert.Throws<IOException>(() => WindowsLocalRunAuthority.AcquireResume(Root, mutation));
        }
        LocalExecutionBinding detached = JsonSerializer.Deserialize<LocalExecutionBinding>(JsonSerializer.Serialize(expected))!;
        using WindowsLocalRunAuthority resumed = WindowsLocalRunAuthority.AcquireResume(Root, detached);
        Assert.Equal(expected.ComputeSha256(), resumed.Binding.ComputeSha256());
    }

    [WindowsLocalRunFact]
    public void Dispose_RevokesAuthorityButKeepsPermanentFile()
    {
        WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        authority.Dispose();
        authority.Dispose();
        _ = Assert.Throws<ObjectDisposedException>(authority.ValidateHeld);
        _ = Assert.Throws<ObjectDisposedException>(() => authority.Binding);
        Assert.True(File.Exists(Path.Combine(Root, WindowsLocalRunAuthority.RunLockRelativeName)));
    }

    [UnsupportedLocalRunPlatformFact]
    public void Acquire_UnsupportedPlatform_FailsExplicitlyWithoutCreatingRoot()
    {
        if (OperatingSystem.IsWindows()) { return; }
        _ = Assert.Throws<PlatformNotSupportedException>(() => WindowsLocalRunAuthority.AcquireFresh(Root));
        Assert.False(Directory.Exists(Root));
    }

    private LocalExecutionBinding CreateReleasedAuthority()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        return authority.Binding;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void GrantEveryoneRead(string kind)
    {
        var rule = new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read, AccessControlType.Allow);
        if (kind == "root")
        {
            var directory = new DirectoryInfo(Root);
            DirectorySecurity acl = directory.GetAccessControl();
            acl.AddAccessRule(rule);
            directory.SetAccessControl(acl);
        }
        else
        {
            var file = new FileInfo(Path.Combine(Root, WindowsLocalRunAuthority.RunLockRelativeName));
            FileSecurity acl = file.GetAccessControl();
            acl.AddAccessRule(rule);
            file.SetAccessControl(acl);
        }
    }

#pragma warning disable SYSLIB1054
    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string newName, string existingName, IntPtr securityAttributes);
#pragma warning restore SYSLIB1054

    public void Dispose()
    {
        if (Directory.Exists(_parent)) { Directory.Delete(_parent, recursive: true); }
    }
}
