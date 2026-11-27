using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration.Console;

// Fixed run-owned secret names only. Deletion acts on the same opened NTFS object whose
// volume/object ID was captured at creation; neither path equality nor a Linux-only inode API is used.
internal static class CompanyStorageSecretCustody
{
    private static readonly HashSet<string> Names = ["source.secret", "operator.secret", "ordinary.secret", "review-private.pem", "authorization-private.pem", "evidence-private.pem", "operator.txt", "ordinary.txt"];
    internal static WindowsRunFileIdentity.Identity Observe(FileStream stream, string path)
    {
        return !OperatingSystem.IsWindows() || !SecureLocalFile.HandleResolvesToApprovedPath(stream, path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path)) ||
            !GetInformation(stream.SafeFileHandle, out FileInformation info) || info.Links != 1 || (info.Attributes & 0x410) != 0
            ? throw CompanyStorageRepairProtocol.Invalid()
            : WindowsRunFileIdentity.Observe(stream.SafeFileHandle);
    }
    internal static void Remove(string root, LocalExecutionBinding binding, DateTimeOffset createdAtUtc, IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity> secrets)
    {
        if (!OperatingSystem.IsWindows()) { throw CompanyStorageRepairProtocol.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding); authority.ValidateHeld();
        foreach (var secret in secrets)
        {
            string path = Path.GetFullPath(secret.Key);
            if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(path), binding.ArtifactRootCanonicalPath) || !Names.Contains(Path.GetFileName(path))) { throw CompanyStorageRepairProtocol.Invalid(); }
            using (SafeFileHandle handle = CreateFile(path, 0x80000000 | 0x10000 | 0x80, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
            {
                if (handle.IsInvalid) { throw new IOException("company_owned_secret_cleanup_open_failed"); }
                using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
                if (Observe(stream, path) != secret.Value || stream.Length > 65536 || File.GetCreationTimeUtc(path) < createdAtUtc.UtcDateTime.AddSeconds(-1)) { throw CompanyStorageRepairProtocol.Invalid(); }
                authority.ValidateHeld(); var disposition = new Disposition { DeleteFile = 1 };
                if (!SetInformation(handle, 4, ref disposition, 1)) { throw new IOException("company_owned_secret_cleanup_delete_failed"); }
            }
            authority.ValidateHeld(); if (File.Exists(path)) { throw new IOException("company_owned_secret_cleanup_absence_failed"); }
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Disposition { internal byte DeleteFile; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
#pragma warning disable SYSLIB1054 // Fixed Windows file-handle ABI, matching existing custody without requiring unsafe source generation.
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint sharing, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetInformation(SafeFileHandle handle, out FileInformation information);
    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformation(SafeFileHandle handle, int informationClass, ref Disposition value, uint size);
#pragma warning restore SYSLIB1054
}
