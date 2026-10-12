using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Held owner-only inputs and create-new/readback evidence inside the retained NTFS run root.</summary>
internal sealed class CurrentAppOwnedRepairCustody(WindowsLocalRunAuthority authority) : IDisposable
{
    private readonly List<(FileStream Stream, string Path, string Identity)> _held = [];
    internal byte[] Read(string path, bool sharedReader = false)
    {
        string full = RequireInside(path);
        FileStream stream = sharedReader ? SecureLocalFile.OpenReadShared(full) : SecureLocalFile.OpenRead(full);
        try
        {
            ValidateHandle(stream, full);
            using var bytes = new MemoryStream();
            stream.CopyTo(bytes);
            _held.Add((stream, full, SecureLocalFile.GetHandleIdentity(stream)));
            return bytes.ToArray();
        }
        catch { stream.Dispose(); throw; }
    }
    internal void Require()
    {
        _ = authority.Binding;
        foreach ((FileStream stream, string path, string identity) in _held)
        {
            ValidateHandle(stream, path);
            if (SecureLocalFile.GetHandleIdentity(stream) != identity) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
    }
    internal async Task WriteNewAsync(string path, byte[] bytes, CancellationToken ct)
    {
        string full = RequireInside(path);
        Require();
        await using var stream = new FileStream(full, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        ValidateHandle(stream, full);
        await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
        stream.Position = 0;
        var observed = new byte[bytes.Length];
        await stream.ReadExactlyAsync(observed, ct).ConfigureAwait(false);
        if (stream.Length != bytes.Length || !observed.AsSpan().SequenceEqual(bytes)) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        ValidateHandle(stream, full);
        Require();
    }
    private string RequireInside(string path)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(path)) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        string full = Path.GetFullPath(path);
        string root = Path.TrimEndingDirectorySeparator(authority.Binding.ArtifactRootCanonicalPath);
        return !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetDirectoryName(full), root, StringComparison.OrdinalIgnoreCase)
            ? throw CurrentAppOwnedRepairPermit.Invalid()
            : full;
    }
    private static void ValidateHandle(FileStream stream, string path)
    {
        if (!OperatingSystem.IsWindows() || !SecureLocalFile.HandleResolvesToApprovedPath(stream, path) ||
            !GetFileInformationByHandle(stream.SafeFileHandle, out FileInformation information) ||
            information.NumberOfLinks != 1 || (information.Attributes & 0x410) != 0)
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
        FileSecurity security = stream.GetAccessControl();
        SecurityIdentifier actor = WindowsIdentity.GetCurrent().User ?? throw CurrentAppOwnedRepairPermit.Invalid();
        if (!actor.Equals(security.GetOwner(typeof(SecurityIdentifier)))) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                ((SecurityIdentifier)rule.IdentityReference).Value is var value &&
                value != actor.Value && value != "S-1-5-18")
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
    }
    public void Dispose() { foreach (var item in _held) { item.Stream.Dispose(); } _held.Clear(); }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
            VolumeSerial, SizeHigh, SizeLow, NumberOfLinks, IndexHigh, IndexLow;
    }
#pragma warning disable SYSLIB1054 // Fixed Windows handle ABI, matching WindowsRunFileIdentity without enabling unsafe marshalling.
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
#pragma warning restore SYSLIB1054
}
