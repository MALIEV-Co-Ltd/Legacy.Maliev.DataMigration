using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAuthArchiveAcceptedConsoleBundleTests
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate SafeFileHandle OpenJunction(string path, uint access, uint sharing, nint security, uint creation, uint flags, nint template);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool SetJunction(SafeFileHandle file, uint code, byte[] input, uint inputLength, nint output, uint outputLength, out uint returned, nint overlapped);

    [Fact]
    public async Task Cancellation_precedes_bundle_or_tool_access()
    {
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAuthArchiveAcceptedConsoleBundle.HoldAsync("not-a-path", canceled.Token));
    }

    [WindowsLocalRunFact]
    public async Task Candidate_junction_is_rejected_and_outside_target_is_preserved()
    {
        const string accepted = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\src\Legacy.Maliev.DataMigration.Console\bin\Release\net10.0";
        Assert.True(Directory.Exists(accepted), "This filesystem test requires the fixed canonical Console build output.");
        string parent = Path.Combine(Path.GetTempPath(), "archive-console-junction-" + Guid.NewGuid().ToString("N"));
        string candidate = Path.Combine(parent, "candidate"), outside = Path.Combine(parent, "outside"), link = Path.Combine(candidate, "junction");
        Assert.False(Directory.Exists(parent)); SecureSnapshotFileCreation.CreateRestrictedDirectory(parent);
        try
        {
            SecureSnapshotFileCreation.CreateRestrictedDirectory(candidate); SecureSnapshotFileCreation.CreateRestrictedDirectory(outside);
            SecureSnapshotFileCreation.CreateRestrictedDirectory(link);
            string marker = Path.Combine(outside, "marker.txt"); File.WriteAllText(marker, "outside-copy-marker");
            CreateOwnedJunction(link, outside);
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthArchiveAcceptedConsoleBundle.HoldAsync(
                Path.Combine(candidate, "Legacy.Maliev.DataMigration.Console.dll"), CancellationToken.None));
            Assert.Equal("outside-copy-marker", File.ReadAllText(marker));
        }
        finally
        {
            // Remove this exact link without following it before deleting only this fresh owned parent.
            if (Directory.Exists(link)) { Directory.Delete(link, recursive: false); }
            Assert.StartsWith(Path.GetFullPath(Path.GetTempPath()), Path.GetFullPath(parent), StringComparison.OrdinalIgnoreCase);
            Assert.Equal((FileAttributes)0, new DirectoryInfo(parent).Attributes & FileAttributes.ReparsePoint);
            Directory.Delete(parent, recursive: true);
        }
    }

    private static void CreateOwnedJunction(string link, string target)
    {
        // NTFS mount-point junction creation does not need the symbolic-link privilege.
        byte[] substitute = Encoding.Unicode.GetBytes(@"\??\" + Path.GetFullPath(target)), print = Encoding.Unicode.GetBytes(Path.GetFullPath(target));
        using var buffer = new MemoryStream();
        using (var writer = new BinaryWriter(buffer, Encoding.Unicode, leaveOpen: true))
        {
            writer.Write(0xA0000003u); writer.Write(checked((ushort)(8 + substitute.Length + print.Length + 4))); writer.Write((ushort)0);
            writer.Write((ushort)0); writer.Write(checked((ushort)substitute.Length)); writer.Write(checked((ushort)(substitute.Length + 2))); writer.Write(checked((ushort)print.Length));
            writer.Write(substitute); writer.Write((ushort)0); writer.Write(print); writer.Write((ushort)0);
        }
        nint library = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        try
        {
            var open = Marshal.GetDelegateForFunctionPointer<OpenJunction>(NativeLibrary.GetExport(library, "CreateFileW"));
            var set = Marshal.GetDelegateForFunctionPointer<SetJunction>(NativeLibrary.GetExport(library, "DeviceIoControl"));
            using var file = open(link, 0x40000000, 0, 0, 3, 0x02200000, 0);
            if (file.IsInvalid) { throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()); }
            byte[] bytes = buffer.ToArray();
            if (!set(file, 0x000900A4, bytes, checked((uint)bytes.Length), 0, 0, out _, 0))
            { throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()); }
        }
        finally { NativeLibrary.Free(library); }
    }

    [WindowsLocalRunTheory]
    [InlineData("inventory")]
    [InlineData("bytes")]
    [InlineData("held")]
    public async Task Fixed_anchor_rejects_changes_and_holds_accepted_copy_without_process_start(string fault)
    {
        const string accepted = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\src\Legacy.Maliev.DataMigration.Console\bin\Release\net10.0";
        Assert.True(Directory.Exists(accepted), "This filesystem test requires the fixed canonical Console build output.");
        string root = Path.Combine(Path.GetTempPath(), "archive-console-preexec-" + Guid.NewGuid().ToString("N"));
        Assert.False(Directory.Exists(root));
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root);
        try
        {
            foreach (string source in Directory.GetFiles(accepted, "*", SearchOption.AllDirectories))
            {
                string target = Path.Combine(root, Path.GetRelativePath(accepted, source));
                string directory = Path.GetDirectoryName(target)!;
                if (!Directory.Exists(directory)) { SecureSnapshotFileCreation.CreateRestrictedDirectory(directory); }
                File.Copy(source, target);
                // CopyFile may preserve the source DACL; run-owned output must be owner-only.
                if (OperatingSystem.IsWindows())
                {
                    var security = new System.Security.AccessControl.FileSecurity();
                    using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                    var owner = identity.User!;
                    security.SetOwner(owner); security.SetAccessRuleProtection(true, false);
                    security.AddAccessRule(new(owner, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
                    new FileInfo(target).SetAccessControl(security);
                }
            }
            string image = Path.Combine(root, "Legacy.Maliev.DataMigration.Console.dll");
            if (fault == "inventory")
            {
                File.WriteAllBytes(Path.Combine(root, "unreviewed-" + Guid.NewGuid().ToString("N") + ".dll"), [1, 2, 3]);
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthArchiveAcceptedConsoleBundle.HoldAsync(image, CancellationToken.None));
            }
            else if (fault == "bytes")
            {
                using (var changed = new FileStream(image, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    int first = changed.ReadByte(); Assert.NotEqual(-1, first); changed.Position = 0; changed.WriteByte((byte)(first ^ 1)); changed.Flush(true);
                }
                _ = await Assert.ThrowsAsync<MigrationConsoleException>(() => CurrentAuthArchiveAcceptedConsoleBundle.HoldAsync(image, CancellationToken.None));
            }
            else
            {
                using var bundle = await CurrentAuthArchiveAcceptedConsoleBundle.HoldAsync(image, CancellationToken.None);
                bundle.Require();
                _ = Assert.Throws<IOException>(() => { using var writer = new FileStream(image, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
                _ = Assert.Throws<IOException>(() => File.Move(image, image + ".replacement"));
                bundle.Require();
            }
        }
        finally
        {
            // Only this fresh run-owned copy is removed; canonical bytes are never changed.
            Assert.StartsWith(Path.GetFullPath(Path.GetTempPath()), Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase);
            Assert.Equal((FileAttributes)0, new DirectoryInfo(root).Attributes & FileAttributes.ReparsePoint);
            Directory.Delete(root, recursive: true);
        }
    }
}
