using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration.Console;

// Exact same-handle deletion of newly generated disposable fixture secrets. No supplied
// cleanup paths, ancestry selection, recursive removal, recovery-key deletion or journal deletion.
internal static partial class CurrentCustomerClosedSecretCleanup
{
    internal static void RequireRemoved(string root, LocalExecutionBinding binding, Guid operation)
    {
        if (!OperatingSystem.IsWindows() || operation == Guid.Empty) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding); authority.ValidateHeld();
        string suffix = operation.ToString("N");
        string[] names = ["operator.txt", "ordinary.txt", "source-connection.txt", "source-token.txt", "customer-closed-review-" + suffix + ".private.pem",
            "customer-closed-authorization-" + suffix + ".private.pem", "customer-closed-receipt-" + suffix + ".private.pem"];
        foreach (string name in names)
        {
            string path = Path.Combine(binding.ArtifactRootCanonicalPath, name);
            if (!File.Exists(path)) { continue; } // An interrupted preparation may not have reached this create-new file.
            SecureLocalFile.EnsureOwnerOnlyDirectory(binding.ArtifactRootCanonicalPath);
            if (!SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            using (SafeFileHandle handle = CreateFile(path, 0x80000000 | 0x00010000 | 0x00000080, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
            {
                if (handle.IsInvalid) { throw new IOException("customer_closed_secret_cleanup_open_failed"); }
                using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
                if (!SecureLocalFile.HandleResolvesToApprovedPath(stream, path) || !GetInformation(handle, out FileInformation info) || info.Links != 1 ||
                    (info.Attributes & 0x00000400) != 0 || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                authority.ValidateHeld(); var disposition = new Disposition { DeleteFile = 1 };
                if (!SetInformation(handle, 4, ref disposition, 1)) { throw new IOException("customer_closed_secret_cleanup_delete_failed"); }
            }
            authority.ValidateHeld();
            if (File.Exists(path)) { throw new IOException("customer_closed_secret_cleanup_absence_failed"); }
        }
        authority.ValidateHeld();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Disposition { internal byte DeleteFile; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFile(string path, uint access, uint sharing, IntPtr security, uint creation, uint flags, IntPtr template);
    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetInformation(SafeFileHandle handle, out FileInformation information);
    [LibraryImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetInformation(SafeFileHandle handle, int informationClass, ref Disposition value, uint size);
}
