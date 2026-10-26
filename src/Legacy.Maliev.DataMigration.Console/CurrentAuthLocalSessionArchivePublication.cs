using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration.Console;

internal enum CurrentAuthArchivePublicationFault { None, AfterCreate, DuringWrite, AfterFlush, AfterReadback }

internal sealed class CurrentAuthLocalSessionArchivePublication(CurrentAppOwnedRepairCustody files,
    WindowsLocalRunAuthority local, WindowsLocalRunAuthority production, Guid operationId,
    CurrentAuthArchivePublicationFault fault = CurrentAuthArchivePublicationFault.None) : IDisposable
{
    private sealed class Attempt(FileStream stream, string path)
    {
        internal readonly FileStream Stream = stream;
        internal readonly string Path = path;
        internal WindowsRunFileIdentity.Identity? Identity;
        internal byte[]? Acknowledged;
    }
    private readonly Dictionary<string, Attempt> _attempted = new(StringComparer.Ordinal);
    private CurrentAuthArchivePublicationFault _fault = fault;
    private bool _disposed;

    internal bool IsAcknowledged(string name)
    {
        return _attempted.TryGetValue(name, out Attempt? item) && item.Acknowledged is not null;
    }

    internal async Task WriteAndRetainAsync(string name, byte[] bytes, CancellationToken ct)
    {
        RequireInventory(); files.Require();
        string prefix = $"{operationId:D}-Auth-session-archive-";
        string[] suffixes = ["operation-start.json", "recovery-manifest.json", "prepared.json", "committed-readback.json", "failed-or-uncertain.json"];
        if (!OperatingSystem.IsWindows() || name != Path.GetFileName(name) || bytes.Length > 65536 ||
            !suffixes.Any(suffix => name == prefix + suffix) || _attempted.ContainsKey(name))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        string path = Path.Combine(local.Binding.ArtifactRootCanonicalPath, name);
        var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        // Retain the create-new handle even if identity validation or publication fails.
        var attempt = new Attempt(stream, path);
        _attempted.Add(name, attempt);
        attempt.Identity = WindowsRunFileIdentity.Observe(stream.SafeFileHandle);
        RequireHeld(attempt);
        Fail(CurrentAuthArchivePublicationFault.AfterCreate);
        if (_fault == CurrentAuthArchivePublicationFault.DuringWrite)
        {
            await stream.WriteAsync(bytes.AsMemory(0, bytes.Length / 2), ct).ConfigureAwait(false);
            Fail(CurrentAuthArchivePublicationFault.DuringWrite);
        }
        await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false); stream.Flush(flushToDisk: true);
        Fail(CurrentAuthArchivePublicationFault.AfterFlush);
        stream.Position = 0;
        var observed = new byte[bytes.Length];
        await stream.ReadExactlyAsync(observed, ct).ConfigureAwait(false);
        if (stream.Length != bytes.Length || !observed.AsSpan().SequenceEqual(bytes)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        RequireInventory(); files.Require();
        Fail(CurrentAuthArchivePublicationFault.AfterReadback);
        ct.ThrowIfCancellationRequested();
        attempt.Acknowledged = observed;
    }

    internal string[] Names()
    {
        return Directory.EnumerateFileSystemEntries(local.Binding.ArtifactRootCanonicalPath)
            .Select(Path.GetFileName).Where(x => x is not null && x.StartsWith(operationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))
            .Select(x => x!).Order(StringComparer.Ordinal).ToArray();
    }

    internal void RequireInventory()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        foreach (Attempt attempt in _attempted.Values) { RequireHeld(attempt); }
        if (!Names().SequenceEqual(_attempted.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            Directory.EnumerateFileSystemEntries(production.Binding.ArtifactRootCanonicalPath).Select(Path.GetFileName)
                .Any(name => name is not null && name.StartsWith(operationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase)))
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
    }

    private static void RequireHeld(Attempt attempt)
    {
        if (!OperatingSystem.IsWindows() || attempt.Identity is null ||
            WindowsRunFileIdentity.Observe(attempt.Stream.SafeFileHandle) != attempt.Identity ||
            !SecureLocalFile.HandleResolvesToApprovedPath(attempt.Stream, attempt.Path) ||
            !GetFileInformationByHandle(attempt.Stream.SafeFileHandle, out FileInformation info) ||
            info.NumberOfLinks != 1 || (info.Attributes & 0x410) != 0)
        { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        FileSecurity security = attempt.Stream.GetAccessControl();
        using WindowsIdentity current = WindowsIdentity.GetCurrent();
        SecurityIdentifier actor = current.User ?? throw CurrentAuthLocalSessionArchivePolicy.Invalid();
        if (!actor.Equals(security.GetOwner(typeof(SecurityIdentifier)))) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                ((SecurityIdentifier)rule.IdentityReference).Value is var value && value != actor.Value && value != "S-1-5-18")
            { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
        if (attempt.Acknowledged is { } bytes)
        {
            if (attempt.Stream.Length != bytes.Length) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
            attempt.Stream.Position = 0;
            var observed = new byte[bytes.Length]; attempt.Stream.ReadExactly(observed);
            if (!observed.AsSpan().SequenceEqual(bytes)) { throw CurrentAuthLocalSessionArchivePolicy.Invalid(); }
        }
    }
    private void Fail(CurrentAuthArchivePublicationFault stage)
    {
        if (_fault != stage) { return; }
        _fault = CurrentAuthArchivePublicationFault.None;
        throw new IOException("Synthetic archive publication failure.");
    }
    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        foreach (Attempt attempt in _attempted.Values) { attempt.Stream.Dispose(); }
        _attempted.Clear();
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
            VolumeSerial, SizeHigh, SizeLow, NumberOfLinks, IndexHigh, IndexLow;
    }
#pragma warning disable SYSLIB1054 // Fixed Windows handle ABI, matching permanent custody validation.
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
#pragma warning restore SYSLIB1054
}
