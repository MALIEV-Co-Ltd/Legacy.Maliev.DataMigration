using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record DualTargetNativeProofGeneratedSecret(string Path, string Sha256, WindowsRunFileIdentity.Identity Identity, long CreationFileTime);

internal static partial class DualTargetNativeProofSecret
{
    internal static async Task WriteGeneratedAsync(CurrentAppOwnedRepairCustody files, string root, string path, byte[] bytes,
        List<DualTargetNativeProofGeneratedSecret> generated, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || bytes.Length is < 1 or > 65536 || !FixedPath(root, path) || generated.Any(x => x.Path == path))
        { throw DualTargetNativeProofPreimage.Invalid(); }
        files.Require();
        await using var created = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(created, path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path)) ||
            !GetInformation(created.SafeFileHandle, out FileInformation info) || info.Links != 1 || (info.Attributes & 0x410) != 0)
        { throw DualTargetNativeProofPreimage.Invalid(); }
        var identity = WindowsRunFileIdentity.Observe(created.SafeFileHandle); long creation = Creation(info);
        int index = generated.Count;
        generated.Add(new(path, Convert.ToHexStringLower(SHA256.HashData([])), identity, creation));
        try
        {
            await created.WriteAsync(bytes, ct).ConfigureAwait(false); await created.FlushAsync(ct).ConfigureAwait(false); created.Flush(true);
            created.Position = 0; string actual = Convert.ToHexStringLower(SHA256.HashData(created));
            generated[index] = new(path, actual, identity, creation);
            if (actual != Convert.ToHexStringLower(SHA256.HashData(bytes))) { throw DualTargetNativeProofPreimage.Invalid(); }
            files.Require();
        }
        catch (Exception primary)
        {
            // Retain custody of a partial write too; cleanup never reconstructs identity by reopening a path.
            try { created.Position = 0; generated[index] = new(path, Convert.ToHexStringLower(SHA256.HashData(created)), identity, creation); }
            catch (Exception observation) { primary.Data["DualNativeSecretPartialObservation"] = observation; }
            throw;
        }
    }
    // Only this run's generated operator files, after all consumers/targets have closed.
    internal static void RemoveGenerated(string root, LocalExecutionBinding binding,
        IReadOnlyList<DualTargetNativeProofGeneratedSecret> generated)
    {
        if (!OperatingSystem.IsWindows()) { throw DualTargetNativeProofPreimage.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding); authority.ValidateHeld();
        foreach (var secret in generated)
        {
            if (!FixedPath(root, secret.Path) || !DualTargetNativeProofPreimage.IsHash(secret.Sha256) ||
                !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(secret.Path))) { throw DualTargetNativeProofPreimage.Invalid(); }
            using (SafeFileHandle handle = CreateFile(secret.Path, 0x80000000 | 0x00010000 | 0x00000080, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
            {
                if (handle.IsInvalid) { throw DualTargetNativeProofPreimage.Invalid(); }
                using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
                if (!SecureLocalFile.HandleResolvesToApprovedPath(stream, secret.Path) ||
                    !GetInformation(handle, out FileInformation info) || info.Links != 1 || (info.Attributes & 0x410) != 0 ||
                    WindowsRunFileIdentity.Observe(handle) != secret.Identity || Creation(info) != secret.CreationFileTime ||
                    stream.Length > 65536 || Convert.ToHexStringLower(SHA256.HashData(stream)) != secret.Sha256)
                { throw DualTargetNativeProofPreimage.Invalid(); }
                authority.ValidateHeld(); var disposition = new Disposition { DeleteFile = 1 };
                if (!SetInformation(handle, 4, ref disposition, 1)) { throw DualTargetNativeProofPreimage.Invalid(); }
            }
            authority.ValidateHeld(); if (File.Exists(secret.Path)) { throw DualTargetNativeProofPreimage.Invalid(); }
        }
    }
    private static bool FixedPath(string root, string path)
    {
        string name = Path.GetFileName(path);
        return Path.IsPathFullyQualified(root) && Path.IsPathFullyQualified(path) && Path.GetDirectoryName(Path.GetFullPath(path)) == root &&
            name.StartsWith("native-proof-", StringComparison.Ordinal) && name.EndsWith("-operator.txt", StringComparison.Ordinal) && name.Length == 58 &&
            Guid.TryParseExact(name.AsSpan(13, 32), "N", out _);
    }
    private static long Creation(FileInformation info)
    {
        return ((long)info.CreationHigh << 32) | info.CreationLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Disposition { internal byte DeleteFile; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
        internal uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, Links, FileIndexHigh, FileIndexLow;
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
