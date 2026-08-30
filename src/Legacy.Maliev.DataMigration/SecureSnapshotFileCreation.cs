using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration;

internal static class SecureSnapshotFileCreation
{
    public static FileStream OpenValidatedRead(string path)
    {
        string fullPath = Path.GetFullPath(path);
        var info = new FileInfo(fullPath); info.Refresh();
        if (!info.Exists || info.LinkTarget is not null ||
            (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new UnauthorizedAccessException("Snapshot key must be a regular non-link file.");
        }

        var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.None, 4096,
            FileOptions.SequentialScan);
        try { ValidateReadHandle(stream, fullPath); return stream; }
        catch { stream.Dispose(); throw; }
    }

    private static void ValidateReadHandle(FileStream stream, string expectedPath)
    {
        string? observed = OperatingSystem.IsWindows() ? FinalWindowsPath(stream.SafeFileHandle) :
            OperatingSystem.IsLinux() ? File.ResolveLinkTarget($"/proc/self/fd/{stream.SafeFileHandle.DangerousGetHandle()}", true)?.FullName : null;
        if (observed is null || !string.Equals(Path.GetFullPath(observed), expectedPath,
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("Snapshot key opened-handle identity is unsafe.");
        }

        if (OperatingSystem.IsWindows()) { ValidateWindowsOwnerOnly(expectedPath); return; }
        if (!OperatingSystem.IsLinux() || Statx(checked((int)stream.SafeFileHandle.DangerousGetHandle()), string.Empty,
            AtEmptyPath, StatxBasicStats, out LinuxStatx stat) != 0)
        {
            throw new UnauthorizedAccessException("Snapshot key ownership cannot be verified.");
        }

        const ushort fileTypeMask = 0xF000, regularFile = 0x8000, groupOtherMask = 0x003F, ownerRead = 0x0100;
        if (stat.Uid != GetEffectiveUserIdNative() || (stat.Mode & fileTypeMask) != regularFile ||
            (stat.Mode & groupOtherMask) != 0 || (stat.Mode & ownerRead) == 0)
        {
            throw new UnauthorizedAccessException("Snapshot key must be an owner-only regular file.");
        }
    }

    public static void Validate(FileStream stream, string expectedPath)
    {
        ArgumentNullException.ThrowIfNull(stream);
        string? observed = OperatingSystem.IsWindows() ? FinalWindowsPath(stream.SafeFileHandle) :
            OperatingSystem.IsLinux() ? File.ResolveLinkTarget($"/proc/self/fd/{stream.SafeFileHandle.DangerousGetHandle()}", true)?.FullName : null;
        if (observed is null || !string.Equals(Path.GetFullPath(observed), Path.GetFullPath(expectedPath),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("Snapshot output opened-handle identity is unsafe.");
        }

        if (OperatingSystem.IsWindows())
        {
            ValidateWindowsOwnerOnly(expectedPath);
            return;
        }

        if (!OperatingSystem.IsLinux() || Statx(checked((int)stream.SafeFileHandle.DangerousGetHandle()), string.Empty,
            AtEmptyPath, StatxBasicStats, out LinuxStatx stat) != 0)
        {
            throw new UnauthorizedAccessException("Snapshot output ownership cannot be verified.");
        }

        const ushort fileTypeMask = 0xF000, regularFile = 0x8000, groupOtherMask = 0x003F, ownerReadWrite = 0x0180;
        if (stat.Uid != GetEffectiveUserIdNative() || (stat.Mode & fileTypeMask) != regularFile ||
            (stat.Mode & groupOtherMask) != 0 || (stat.Mode & ownerReadWrite) != ownerReadWrite)
        {
            throw new UnauthorizedAccessException("Snapshot output must be an owner-only regular file.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsOwnerOnly(string path)
    {
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().User!;
        FileSecurity security = new FileInfo(path).GetAccessControl();
        if (!owner.Equals(security.GetOwner(typeof(SecurityIdentifier))) ||
            security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Any(rule => rule.AccessControlType == AccessControlType.Allow && !owner.Equals(rule.IdentityReference)))
        {
            throw new UnauthorizedAccessException("Snapshot output must be owner-only.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? FinalWindowsPath(SafeFileHandle handle)
    {
        var buffer = new char[4096]; uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0 || length >= buffer.Length)
        {
            return null;
        }

        string value = new(buffer, 0, checked((int)length));
        const string unc = @"\\?\UNC\", device = @"\\?\";
        return value.StartsWith(unc, StringComparison.OrdinalIgnoreCase) ? @"\\" + value[unc.Length..] :
            value.StartsWith(device, StringComparison.Ordinal) ? value[device.Length..] : value;
    }

#pragma warning disable SYSLIB1054
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, [Out] char[] path, uint capacity, uint flags);
#pragma warning restore SYSLIB1054

    private const int AtEmptyPath = 0x1000;
    private const uint StatxBasicStats = 0x7ff;
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStatx { [FieldOffset(20)] public uint Uid; [FieldOffset(28)] public ushort Mode; }
#pragma warning disable SYSLIB1054, CA2101
    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)] private static extern uint GetEffectiveUserIdNative();
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(int directoryFileDescriptor, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        int flags, uint mask, out LinuxStatx stat);
#pragma warning restore SYSLIB1054, CA2101
}
