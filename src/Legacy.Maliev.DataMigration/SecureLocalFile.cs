using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration;

internal static class SecureLocalFile
{
    public static void EnsureOwnerOnlyDirectory(string path)
    {
        string full = Path.GetFullPath(path);
        EnsureNoLinkAncestors(full);
        var directory = new DirectoryInfo(full);
        directory.Refresh();
        if (!directory.Exists || directory.LinkTarget is not null || (directory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new Exact25FullBackupException("local_backup_directory_invalid", "The local backup directory is not a regular owner-controlled directory.");
        }
        if (OperatingSystem.IsWindows())
        {
            if (!IsOwnerOnlyWindows(full, directory: true, requireProtected: true))
            {
                throw new Exact25FullBackupException("local_backup_directory_invalid", "The local backup directory permissions are not owner-only.");
            }
        }
        else
        {
            UnixFileMode mode = File.GetUnixFileMode(full);
            const UnixFileMode forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
            if ((mode & forbidden) != 0 || (mode & UnixFileMode.UserWrite) == 0)
            {
                throw new Exact25FullBackupException("local_backup_directory_invalid", "The local backup directory permissions are not owner-only.");
            }
        }
        EnsureNoLinkAncestors(full);
    }

    public static FileStream OpenRead(string path)
    {
        string full = Path.GetFullPath(path);
        EnsureNoLinkAncestors(full);
        var file = new FileInfo(full);
        if (!IsOwnerOnlyFile(file))
        {
            throw new Exact25FullBackupException("local_backup_type_invalid", "The local backup is not a regular non-link file.");
        }
        var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.None, 1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (!HandleResolvesTo(stream.SafeFileHandle, full))
        {
            stream.Dispose();
            throw new Exact25FullBackupException("local_backup_type_invalid", "The opened local backup does not resolve to the approved path.");
        }
        file.Refresh();
        if (!IsOwnerOnlyFile(file))
        {
            stream.Dispose();
            throw new Exact25FullBackupException("local_backup_type_invalid", "The local backup changed while opening it.");
        }
        return stream;
    }

    public static bool IsRegularNonLink(FileInfo file)
    {
        file.Refresh();
        return file.Exists && file.LinkTarget is null && (file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0;
    }

    public static bool IsOwnerOnlyFile(FileInfo file)
    {
        if (!IsRegularNonLink(file))
        {
            return false;
        }

        if (OperatingSystem.IsWindows())
        {
            return IsOwnerOnlyWindows(file.FullName, directory: false, requireProtected: false);
        }

        UnixFileMode mode = File.GetUnixFileMode(file.FullName);
        const UnixFileMode forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        return (mode & forbidden) == 0 && (mode & UnixFileMode.UserRead) != 0;
    }

    public static async Task<string> ComputeSha256Async(FileStream stream, CancellationToken cancellationToken)
    {
        byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static void EnsurePathWithin(string root, string path)
    {
        string relative = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
        if (relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) || Path.IsPathRooted(relative))
        {
            throw new Exact25FullBackupException("local_backup_path_invalid", "The local backup path escaped its working directory.");
        }
    }

    private static void EnsureNoLinkAncestors(string path)
    {
        for (DirectoryInfo? current = new(Path.GetDirectoryName(Path.GetFullPath(path))!); current is not null; current = current.Parent)
        {
            current.Refresh();
            if (current.Exists && (current.LinkTarget is not null || (current.Attributes & FileAttributes.ReparsePoint) != 0))
            {
                throw new Exact25FullBackupException("local_backup_path_invalid", "The local backup path contains a symbolic link or reparse point.");
            }
        }
    }

    private static bool HandleResolvesTo(SafeFileHandle handle, string expectedPath)
    {
        string? observed = OperatingSystem.IsWindows()
            ? FinalWindowsPath(handle)
            : OperatingSystem.IsLinux() ? FinalLinuxPath(handle) : expectedPath;
        return observed is not null && string.Equals(
            Path.GetFullPath(observed).TrimEnd(Path.DirectorySeparatorChar),
            Path.GetFullPath(expectedPath).TrimEnd(Path.DirectorySeparatorChar),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }

    [SupportedOSPlatform("windows")]
    private static string? FinalWindowsPath(SafeFileHandle handle)
    {
        var buffer = new char[4096];
        uint length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Length, 0);
        if (length == 0 || length >= buffer.Length)
        {
            return null;
        }

        const string devicePrefix = @"\\?\";
        string value = new(buffer, 0, checked((int)length));
        return value.StartsWith(devicePrefix, StringComparison.Ordinal) ? value[devicePrefix.Length..] : value;
    }

    [SupportedOSPlatform("linux")]
    private static string? FinalLinuxPath(SafeFileHandle handle)
    {
        string fdPath = $"/proc/self/fd/{handle.DangerousGetHandle()}";
        return File.ResolveLinkTarget(fdPath, returnFinalTarget: true)?.FullName;
    }

#pragma warning disable SYSLIB1054
    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle handle,
        [Out] char[] path,
        uint capacity,
        uint flags);
#pragma warning restore SYSLIB1054

    [SupportedOSPlatform("windows")]
    private static bool IsOwnerOnlyWindows(string path, bool directory, bool requireProtected)
    {
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().User!;
        FileSystemSecurity security = directory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
        if (!owner.Equals(security.GetOwner(typeof(SecurityIdentifier))) || (requireProtected && !security.AreAccessRulesProtected))
        {
            return false;
        }
        AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        return rules.Cast<FileSystemAccessRule>().All(rule => rule.AccessControlType == AccessControlType.Deny || owner.Equals(rule.IdentityReference));
    }
}
