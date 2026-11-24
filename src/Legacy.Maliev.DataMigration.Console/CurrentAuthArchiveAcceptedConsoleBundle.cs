namespace Legacy.Maliev.DataMigration.Console;

// Code-origin prerequisite only. This grants no source acceptance, SDK role, target or execution authority.
internal sealed class CurrentAuthArchiveAcceptedConsoleBundle : IDisposable
{
    private const string Accepted = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\src\Legacy.Maliev.DataMigration.Console\bin\Release\net10.0";
    private readonly string _candidate;
    private readonly string[] _inventory;
    private readonly List<(FileStream Stream, string Path, string Identity)> _files = [];
    private bool _disposed;

    private CurrentAuthArchiveAcceptedConsoleBundle(string candidate, string[] inventory)
    { _candidate = candidate; _inventory = inventory; }

    internal static async Task<CurrentAuthArchiveAcceptedConsoleBundle> HoldAsync(string image, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!Path.IsPathFullyQualified(image) || Path.GetFileName(image) != "Legacy.Maliev.DataMigration.Console.dll" ||
            Path.GetFullPath(image) != image) { throw Invalid(); }
        string candidate = Path.GetDirectoryName(image)!;
        if (StringComparer.OrdinalIgnoreCase.Equals(candidate, Accepted) || !Directory.Exists(Accepted) || !Directory.Exists(candidate)) { throw Invalid(); }
        string[] inventory = Inventory(Accepted, ct);
        if (inventory.Length == 0 || !inventory.SequenceEqual(Inventory(candidate, ct), StringComparer.Ordinal)) { throw Invalid(); }
        var result = new CurrentAuthArchiveAcceptedConsoleBundle(candidate, inventory);
        try
        {
            foreach (string relative in inventory)
            {
                ct.ThrowIfCancellationRequested();
                result.Hold(Path.Combine(Accepted, relative), ownerProtected: false);
                result.Hold(Path.Combine(candidate, relative), ownerProtected: true);
            }
            result.Hold(CurrentAuthTypedHostProducer.Dotnet, ownerProtected: false);
            // No caller-selected baseline: compare the full copy against this fixed canonical anchor while all bytes are held.
            await SourceBackedLocalRepairSourceAcceptance.RequireBundleForPathsAsync(Accepted, candidate, ct).ConfigureAwait(false);
            result.Require(); return result;
        }
        catch { result.Dispose(); throw; }
    }

    private void Hold(string path, bool ownerProtected)
    {
        // Installed/canonical images need not inherit a run-owned ACL, but may never resolve through links.
        FileSystemInfo? item = new FileInfo(path);
        while (item is not null)
        {
            if ((item.Attributes & FileAttributes.ReparsePoint) != 0) { throw Invalid(); }
            item = item is FileInfo file ? file.Directory : (item as DirectoryInfo)?.Parent;
        }
        FileStream stream = ownerProtected ? SecureLocalFile.OpenReadShared(path) : new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            if (stream.Length is < 1 or > 128 * 1024 * 1024 || !SecureLocalFile.HandleResolvesToApprovedPath(stream, path)) { throw Invalid(); }
            _files.Add((stream, path, SecureLocalFile.GetHandleIdentity(stream)));
        }
        catch { stream.Dispose(); throw; }
    }

    internal void Require()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_inventory.SequenceEqual(Inventory(Accepted), StringComparer.Ordinal) || !_inventory.SequenceEqual(Inventory(_candidate), StringComparer.Ordinal)) { throw Invalid(); }
        foreach (var file in _files)
        {
            if (!SecureLocalFile.HandleResolvesToApprovedPath(file.Stream, file.Path) || SecureLocalFile.GetHandleIdentity(file.Stream) != file.Identity) { throw Invalid(); }
        }
    }

    private static string[] Inventory(string root, CancellationToken ct = default)
    {
        var files = new List<string>(); var pending = new Stack<string>(); pending.Push(root);
        int entries = 0;
        while (pending.TryPop(out string? directory))
        {
            ct.ThrowIfCancellationRequested();
            SecureSnapshotFileCreation.RejectLinkedAncestors(directory);
            var info = new DirectoryInfo(directory); info.Refresh();
            if (!info.Exists || info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0) { throw Invalid(); }
            foreach (string path in Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                if (++entries > 4000) { throw Invalid(); }
                FileAttributes attributes = File.GetAttributes(path);
                FileSystemInfo item = (attributes & FileAttributes.Directory) != 0 ? new DirectoryInfo(path) : new FileInfo(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0 || item.LinkTarget is not null) { throw Invalid(); }
                if ((attributes & FileAttributes.Directory) != 0) { pending.Push(path); }
                else { files.Add(Path.GetRelativePath(root, path)); }
            }
        }
        return [.. files.Order(StringComparer.Ordinal)];
    }
    private static MigrationExecutionException Invalid()
    {
        return new("current_auth_archive_console_preexec_invalid",
        "The selected Console code bundle is not the held independent accepted copy.");
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        foreach (var file in _files) { file.Stream.Dispose(); }
    }
}
