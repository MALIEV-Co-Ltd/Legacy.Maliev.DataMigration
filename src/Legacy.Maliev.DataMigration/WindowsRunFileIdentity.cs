using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration;

/// <summary>Opened-handle NTFS identity and security checks for the permanent coordinator authority.</summary>
[SupportedOSPlatform("windows")]
internal static class WindowsRunFileIdentity
{
    private const uint ReadAttributesAndSecurity = 0x80 | 0x20000;
    private const uint OpenReparsePoint = 0x00200000, BackupSemantics = 0x02000000;
    internal sealed record Identity(string Volume, string ObjectId);

    internal static string ValidateRootPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal) ||
            path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\' ||
            path.AsSpan(2).Contains(':'))
        {
            throw new ArgumentException("A dedicated canonical local drive path is required; network, device, and stream paths are unsupported.", nameof(path));
        }
        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (Path.GetDirectoryName(full) is null) { throw new ArgumentException("A volume root is not a dedicated artifact directory.", nameof(path)); }
        var drive = new DriveInfo(Path.GetPathRoot(full)!);
        return drive.DriveType != DriveType.Fixed || !string.Equals(drive.DriveFormat, "NTFS", StringComparison.Ordinal)
            ? throw new PlatformNotSupportedException("Coordinator authority supports local fixed NTFS volumes only; network, ReFS, and other filesystems are unsupported.")
            : full;
    }

    internal static SafeFileHandle OpenDirectory(string path)
    {
        return Open(path, ReadAttributesAndSecurity, 3, 3, BackupSemantics | OpenReparsePoint);
    }

    internal static SafeFileHandle OpenRunLock(string path, bool create)
    {
        SafeFileHandle handle = create ? CreateRestrictedLock(path) : Open(path, 0x80000000 | 0x40000000, 0, 3, OpenReparsePoint);
        if (create && !FlushFileBuffers(handle))
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw NativeFailure(error);
        }
        return handle;
    }

    private static SafeFileHandle CreateRestrictedLock(string path)
    {
        using WindowsIdentity current = WindowsIdentity.GetCurrent();
        SecurityIdentifier owner = current.User ?? throw new UnauthorizedAccessException("The operator identity could not be observed.");
        var security = new FileSecurity();
        security.SetOwner(owner);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
        GCHandle descriptor = GCHandle.Alloc(security.GetSecurityDescriptorBinaryForm(), GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor.AddrOfPinnedObject(),
            };
            SafeFileHandle handle = CreateProtectedFile(path, 0x80000000 | 0x40000000, 0, in attributes, 1, OpenReparsePoint, IntPtr.Zero);
            if (!handle.IsInvalid) { return handle; }
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw NativeFailure(error);
        }
        finally { descriptor.Free(); }
    }

    internal static SafeFileHandle OpenMetadata(string path)
    {
        return Open(path, ReadAttributesAndSecurity, 7, 3, BackupSemantics | OpenReparsePoint);
    }

    private static SafeFileHandle Open(string path, uint access, uint sharing, uint creation, uint flags)
    {
        SafeFileHandle handle = CreateFile(path, access, sharing, IntPtr.Zero, creation, flags, IntPtr.Zero);
        if (!handle.IsInvalid) { return handle; }
        int error = Marshal.GetLastPInvokeError();
        handle.Dispose();
        throw NativeFailure(error);
    }

    internal static void RejectLinkedFile(string path)
    {
        var file = new FileInfo(path);
        file.Refresh();
        if (file.LinkTarget is not null || (file.Exists && (file.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0) || Directory.Exists(path))
        {
            throw new UnauthorizedAccessException("The permanent run lock must be a regular non-link file.");
        }
    }

    internal static void ValidateDirectory(SafeFileHandle handle, string path, bool ownerOnly)
    {
        FileInformation info = Information(handle);
        if ((info.Attributes & (uint)FileAttributes.ReparsePoint) != 0 || (info.Attributes & (uint)FileAttributes.Directory) == 0)
        {
            throw new UnauthorizedAccessException("The opened artifact path is not a regular non-reparse directory.");
        }
        ValidatePath(handle, path);
        if (ownerOnly) { ValidateOwnerOnly(handle, requireProtected: true); }
        _ = Observe(handle);
    }

    internal static void ValidateLock(SafeFileHandle handle, string path)
    {
        FileInformation info = Information(handle);
        if ((info.Attributes & (uint)(FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 ||
            info.NumberOfLinks != 1 || info.FileSizeHigh != 0 || info.FileSizeLow != 0)
        {
            throw new UnauthorizedAccessException("The permanent run lock must be an empty, single-link regular file.");
        }
        ValidatePath(handle, path);
        ValidateOwnerOnly(handle, requireProtected: false);
        _ = Observe(handle);
    }

    private static void ValidatePath(SafeFileHandle handle, string expected)
    {
        string observed = SecureLocalFile.NormalizeWindowsFinalPath(FinalPath(handle, 0));
        if (!string.Equals(Path.TrimEndingDirectorySeparator(observed), Path.TrimEndingDirectorySeparator(expected), StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("The opened object does not resolve to its canonical approved path.");
        }
    }

    internal static Identity Observe(SafeFileHandle handle)
    {
        if (!GetFileIdInformation(handle, 18, out FileIdInformation id, 24)) { throw NativeFailure(Marshal.GetLastPInvokeError()); }
        string path = FinalPath(handle, 1); // VOLUME_NAME_GUID, never a drive letter identity.
        const string prefix = @"\\?\Volume{";
        int close = path.IndexOf('}');
        return !path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || close < prefix.Length ||
            !Guid.TryParse(path.AsSpan(prefix.Length - 1, close - prefix.Length + 2), out Guid volumeGuid) ||
            id.VolumeSerialNumber == 0 || (id.FileIdLow == 0 && id.FileIdHigh == 0)
            ? throw new UnauthorizedAccessException("The opened object has no verifiable local volume and filesystem identity.")
            : new($"windows-ntfs:{volumeGuid:D}:{id.VolumeSerialNumber:x16}", $"file-id-128:{id.FileIdHigh:x16}{id.FileIdLow:x16}");
    }

    internal static string HostIdentity()
    {
        using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using RegistryKey? cryptography = machine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", writable: false);
        using WindowsIdentity current = WindowsIdentity.GetCurrent();
        return cryptography?.GetValue("MachineGuid") is not string value || !Guid.TryParse(value, out Guid guid) || guid == Guid.Empty ||
            current.User is not SecurityIdentifier owner
            ? throw new UnauthorizedAccessException("The protected local Windows host and operator identity could not be observed.")
            : $"windows-machine:{guid:D}:operator:{owner.Value}";
    }

    private static void ValidateOwnerOnly(SafeFileHandle handle, bool requireProtected)
    {
        uint result = GetSecurityInfo(handle, 1, 0x1 | 0x4, out _, out _, out _, out _, out IntPtr descriptor);
        if (result != 0) { throw NativeFailure(checked((int)result)); }
        try
        {
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length is 0 or > 1024 * 1024) { throw new UnauthorizedAccessException("Invalid opened-object security descriptor."); }
            var bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var security = new RawSecurityDescriptor(bytes, 0);
            using WindowsIdentity current = WindowsIdentity.GetCurrent();
            SecurityIdentifier owner = current.User ?? throw new UnauthorizedAccessException("The operator identity could not be observed.");
            if (security.Owner is null || !owner.Equals(security.Owner) || security.DiscretionaryAcl is null ||
                (security.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 ||
                (requireProtected && (security.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0))
            {
                throw new UnauthorizedAccessException("The opened artifact object must have an owner-only protected boundary.");
            }
            bool ownerAllowed = false;
            foreach (GenericAce ace in security.DiscretionaryAcl)
            {
                if (ace is not CommonAce common || common.IsCallback ||
                    common.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied))
                {
                    throw new UnauthorizedAccessException("The opened artifact object has unsupported access rules.");
                }
                if (common.AceQualifier == AceQualifier.AccessAllowed)
                {
                    if (!owner.Equals(common.SecurityIdentifier)) { throw new UnauthorizedAccessException("The opened artifact object grants another principal access."); }
                    ownerAllowed |= (common.AceFlags & AceFlags.InheritOnly) == 0;
                }
            }
            if (!ownerAllowed) { throw new UnauthorizedAccessException("The opened artifact object does not grant the operator access."); }
        }
        finally { _ = LocalFree(descriptor); }
    }

    private static FileInformation Information(SafeFileHandle handle)
    {
        return GetFileInformationByHandle(handle, out FileInformation value) ? value : throw NativeFailure(Marshal.GetLastPInvokeError());
    }

    private static string FinalPath(SafeFileHandle handle, uint flags)
    {
        var buffer = new char[32768];
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, flags);
        return length == 0 || length >= buffer.Length
            ? throw new IOException("The opened object's canonical local path could not be observed.")
            : new string(buffer, 0, checked((int)length));
    }

    private static IOException NativeFailure(int error)
    {
        return new("The local execution lock or filesystem identity could not be acquired or inspected.", new Win32Exception(error));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInformation { public ulong VolumeSerialNumber, FileIdLow, FileIdHigh; }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { public int Length; public IntPtr SecurityDescriptor; public int InheritHandle; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

#pragma warning disable SYSLIB1054
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateProtectedFile(string name, uint access, uint share, in SecurityAttributes security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, [Out] char[] path, uint capacity, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileIdInformation(SafeFileHandle handle, int informationClass, out FileIdInformation information, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle handle);
    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, uint objectType, uint securityInformation,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern IntPtr LocalFree(IntPtr memory);
#pragma warning restore SYSLIB1054
}
