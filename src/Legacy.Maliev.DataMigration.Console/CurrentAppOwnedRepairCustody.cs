using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Held owner-only inputs and create-new/readback evidence inside the retained NTFS run root.</summary>
internal sealed class CurrentAppOwnedRepairCustody(WindowsLocalRunAuthority authority) : IDisposable
{
    private readonly List<(FileStream Stream, string Path, string Identity)> _held = [];
    private readonly Dictionary<FileStream, long> _borrowedLengths = [];
    private readonly Dictionary<Guid, string[]> _retainedReceiptNames = [];
    private static readonly string[] ReceiptSuffixes = ["prepared", "committed-readback", "failed-or-uncertain"];
    private bool _disposed;

    // Observe the original operation's complete current receipt slots directly
    // under held custody; a caller-supplied list is not storage completeness.
    internal IReadOnlyList<CurrentAppOwnedRetainedReceipt> ReadRetainedReceipts(Guid operationId)
    {
        Require();
        if (operationId == Guid.Empty || _retainedReceiptNames.ContainsKey(operationId))
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
        string[] names = EnumerateReceiptNames(operationId);
        var receipts = names.Select(name => new CurrentAppOwnedRetainedReceipt(name,
            Read(Path.Combine(authority.Binding.ArtifactRootCanonicalPath, name), maximumBytes: 65536))).ToArray();
        _retainedReceiptNames.Add(operationId, names);
        Require();
        return Array.AsReadOnly(receipts);
    }
    internal byte[] Read(string path, bool sharedReader = false, int maximumBytes = int.MaxValue)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        string full = RequireInside(path);
        FileStream stream = sharedReader ? SecureLocalFile.OpenReadShared(full) : SecureLocalFile.OpenRead(full);
        try
        {
            ValidateHandle(stream, full);
            if (stream.Length > maximumBytes) { throw CurrentAppOwnedRepairPermit.Invalid(); }
            using var bytes = new MemoryStream();
            stream.CopyTo(bytes);
            _held.Add((stream, full, SecureLocalFile.GetHandleIdentity(stream)));
            return bytes.ToArray();
        }
        catch { stream.Dispose(); throw; }
    }
    // Borrowed read-only stream: custody owns it until Dispose. Callers must not dispose it.
    // Streaming consumers call Require before/after use; identity, length and hardlink fences remain held.
    internal FileStream BorrowReadStream(string path, long maximumBytes = 512L * 1024 * 1024)
    {
        Require();
        if (maximumBytes is < 1 or > 512L * 1024 * 1024) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        string full = RequireInside(path);
        FileStream stream = SecureLocalFile.OpenReadShared(full);
        bool held = false;
        try
        {
            ValidateHandle(stream, full);
            long length = stream.Length;
            if (length < 1 || length > maximumBytes) { throw CurrentAppOwnedRepairPermit.Invalid(); }
            string identity = SecureLocalFile.GetHandleIdentity(stream);
            _held.Add((stream, full, identity));
            _borrowedLengths.Add(stream, length);
            held = true;
            Require();
            return stream;
        }
        catch
        {
            if (held) { _held.RemoveAt(_held.Count - 1); _borrowedLengths.Remove(stream); }
            stream.Dispose();
            throw;
        }
    }
    internal async Task<CurrentAppOwnedDatabaseSnapshot[]> ReadBaselineAsync(string path, CancellationToken ct, bool sharedReader = false)
    {
        Require();
        string full = RequireInside(path);
        FileStream stream = sharedReader ? SecureLocalFile.OpenReadShared(full) : SecureLocalFile.OpenRead(full);
        var pool = new CurrentAppOwnedSnapshotInternPool();
        bool held = false;
        try
        {
            ValidateHandle(stream, full);
            long length = stream.Length;
            if (length > pool.Limits.MaximumJsonBytes) { throw CurrentAppOwnedRepairPermit.Invalid(); }
            string identity = SecureLocalFile.GetHandleIdentity(stream);
            CurrentAppOwnedDatabaseSnapshot[] baseline = await CurrentAppOwnedSnapshotSerialization.ReadBaselineAsync(
                stream, pool, ct).ConfigureAwait(false);
            ValidateHandle(stream, full);
            if (stream.Length != length || stream.Position != length || SecureLocalFile.GetHandleIdentity(stream) != identity)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
            _held.Add((stream, full, identity));
            held = true;
            Require();
            return baseline;
        }
        catch
        {
            if (held) { _held.RemoveAt(_held.Count - 1); }
            stream.Dispose();
            throw;
        }
    }
    internal async Task WriteBaselineNewAsync(string path, CurrentAppOwnedDatabaseSnapshot[] baseline, CancellationToken ct)
    {
        string full = RequireInside(path);
        Require();
        string expected = CurrentAppOwnedSnapshotSerialization.Sha256(baseline);
        await using var stream = new FileStream(full, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        ValidateHandle(stream, full);
        string identity = SecureLocalFile.GetHandleIdentity(stream);
        await CurrentAppOwnedSnapshotSerialization.WriteAsync(stream, baseline, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
        long length = stream.Length;
        if (length > new CurrentAppOwnedSnapshotLimits().MaximumJsonBytes) { throw CurrentAppOwnedRepairPermit.Invalid(); }
        stream.Position = 0;
        string observed = Convert.ToHexStringLower(await System.Security.Cryptography.SHA256.HashDataAsync(stream, ct).ConfigureAwait(false));
        if (stream.Length != length || stream.Position != length || observed != expected || SecureLocalFile.GetHandleIdentity(stream) != identity)
        { throw CurrentAppOwnedRepairPermit.Invalid(); }
        ValidateHandle(stream, full);
        Require();
    }
    internal void Require()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _ = authority.Binding;
        foreach ((FileStream stream, string path, string identity) in _held)
        {
            ValidateHandle(stream, path);
            if (SecureLocalFile.GetHandleIdentity(stream) != identity) { throw CurrentAppOwnedRepairPermit.Invalid(); }
            if (_borrowedLengths.TryGetValue(stream, out long length) && stream.Length != length)
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
        foreach ((Guid operationId, string[] names) in _retainedReceiptNames)
        {
            if (!names.SequenceEqual(EnumerateReceiptNames(operationId), StringComparer.Ordinal))
            { throw CurrentAppOwnedRepairPermit.Invalid(); }
        }
    }

    private string[] EnumerateReceiptNames(Guid operationId)
    {
        string prefix = $"{operationId:D}-";
        string[] allowed = [.. CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables)
            .SelectMany(database => ReceiptSuffixes
                .Select(suffix => $"{prefix}{database}-{suffix}.json"))];
        string root = authority.Binding.ArtifactRootCanonicalPath;
        string[] names = [.. Directory.EnumerateFileSystemEntries(root)
            .Select(path => Path.GetFileName(path))
            .Where(name => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Order(StringComparer.Ordinal)];
        return names.Any(name => !allowed.Contains(name, StringComparer.Ordinal) ||
            Directory.Exists(Path.Combine(root, name)))
            ? throw CurrentAppOwnedRepairPermit.Invalid()
            : names;
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
    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        foreach (var item in _held) { item.Stream.Dispose(); }
        _held.Clear();
        _borrowedLengths.Clear();
    }

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
