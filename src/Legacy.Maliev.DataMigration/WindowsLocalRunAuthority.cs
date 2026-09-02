using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Legacy.Maliev.DataMigration;

public sealed record LocalExecutionBinding(
    int LocalExecutionBindingVersion,
    string HostIdentity,
    string LocalVolumeIdentity,
    string ArtifactRootCanonicalPath,
    string ArtifactRootFilesystemObjectIdentity,
    string RunLockRelativeName,
    string RunLockFilesystemObjectIdentity,
    int LockProtocolVersion)
{
    /// <summary>Domain-separated stable binding digest; does not sign or authorize this binding.</summary>
    public string ComputeSha256()
    {
        using var bytes = new MemoryStream();
        using (var writer = new BinaryWriter(bytes, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write("Legacy.Maliev.DataMigration.LocalExecutionBinding.v1");
            writer.Write(LocalExecutionBindingVersion);
            writer.Write(HostIdentity);
            writer.Write(LocalVolumeIdentity);
            writer.Write(ArtifactRootCanonicalPath);
            writer.Write(ArtifactRootFilesystemObjectIdentity);
            writer.Write(RunLockRelativeName);
            writer.Write(RunLockFilesystemObjectIdentity);
            writer.Write(LockProtocolVersion);
        }
        return Convert.ToHexString(SHA256.HashData(bytes.ToArray())).ToLowerInvariant();
    }
}

/// <summary>
/// Cooperative coordinator authority on a local fixed Windows NTFS volume only.
/// Acquire before journal/remote work and before the store operation lock. Dispose only after
/// all coordinator work/subprocesses have settled. Disposal never removes the permanent lock.
/// This does not establish a remote lease or protect against a malicious host administrator.
/// </summary>
public sealed class WindowsLocalRunAuthority : IDisposable
{
    public const string RunLockRelativeName = ".run.lock";
    private readonly string _root;
    private readonly IReadOnlyList<SafeFileHandle> _directories;
    private readonly SafeFileHandle _lock;
    private readonly LocalExecutionBinding _binding;
    private readonly Lock _sync = new();
    private bool _disposed;

    [SupportedOSPlatform("windows")]
    private WindowsLocalRunAuthority(string root, IReadOnlyList<SafeFileHandle> directories, SafeFileHandle runLock)
    {
        _root = root;
        _directories = directories;
        _lock = runLock;
        _binding = ObserveBinding();
    }

    /// <summary>The freshly revalidated immutable binding for signing by the admission layer.</summary>
    public LocalExecutionBinding Binding
    {
        get { lock (_sync) { ValidateHeld(); return _binding; } }
    }

    /// <summary>Creates a permanent lock in an empty owner-only root; existing locks are never adopted.</summary>
    public static WindowsLocalRunAuthority AcquireFresh(string root)
    {
        return Acquire(root, null);
    }

    /// <summary>Reacquires only the original signed binding. Missing root/lock is never recreated.</summary>
    public static WindowsLocalRunAuthority AcquireResume(string root, LocalExecutionBinding expectedBinding)
    {
        ArgumentNullException.ThrowIfNull(expectedBinding);
        return Acquire(root, expectedBinding);
    }

    private static WindowsLocalRunAuthority Acquire(string root, LocalExecutionBinding? expected)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Coordinator authority requires a local fixed Windows NTFS volume."); }
        string full = WindowsRunFileIdentity.ValidateRootPath(root);
        var directories = new List<SafeFileHandle>();
        SafeFileHandle? runLock = null;
        try
        {
            // Hold every ancestor against rename/deletion before creating/opening its child.
            var paths = new Stack<string>();
            for (DirectoryInfo? current = new(full); current is not null; current = current.Parent) { paths.Push(current.FullName); }
            while (paths.TryPop(out string? path))
            {
                SecureSnapshotFileCreation.RejectLinkedAncestors(path);
                if (!Directory.Exists(path))
                {
                    if (expected is not null) { throw new DirectoryNotFoundException("The admitted artifact root is missing; resume cannot recreate it."); }
                    SecureSnapshotFileCreation.CreateRestrictedDirectory(path);
                }
                SafeFileHandle directory = WindowsRunFileIdentity.OpenDirectory(path);
                directories.Add(directory);
                WindowsRunFileIdentity.ValidateDirectory(directory, path, ownerOnly: paths.Count == 0);
            }
            if (expected is null && Directory.EnumerateFileSystemEntries(full).Any())
            {
                throw new IOException("Fresh authority requires an empty artifact root; existing run state cannot be adopted.");
            }
            string lockPath = Path.Combine(full, RunLockRelativeName);
            WindowsRunFileIdentity.RejectLinkedFile(lockPath);
            runLock = WindowsRunFileIdentity.OpenRunLock(lockPath, create: expected is null);
            var authority = new WindowsLocalRunAuthority(full, directories, runLock);
            return expected is not null && authority._binding != expected
                ? throw new IOException("The observed host, volume, root, or permanent lock differs from the admitted execution binding.")
                : authority;
        }
        catch
        {
            runLock?.Dispose();
            foreach (SafeFileHandle directory in directories.AsEnumerable().Reverse()) { directory.Dispose(); }
            throw;
        }
    }

    /// <summary>Rejects disposed authority, moved objects, unsafe ACLs, links, and changed identities.</summary>
    public void ValidateHeld()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Coordinator authority requires Windows NTFS."); }
            if (_binding != ObserveBinding()) { throw new IOException("The held local execution binding changed."); }
        }
    }

    [SupportedOSPlatform("windows")]
    private LocalExecutionBinding ObserveBinding()
    {
        SecureSnapshotFileCreation.RejectLinkedAncestors(_root);
        WindowsRunFileIdentity.ValidateDirectory(_directories[^1], _root, ownerOnly: true);
        WindowsRunFileIdentity.ValidateLock(_lock, Path.Combine(_root, RunLockRelativeName));
        WindowsRunFileIdentity.Identity root = WindowsRunFileIdentity.Observe(_directories[^1]);
        WindowsRunFileIdentity.Identity runLock = WindowsRunFileIdentity.Observe(_lock);
        return root.Volume != runLock.Volume
            ? throw new UnauthorizedAccessException("Artifact root and run lock must occupy the same local volume.")
            : new(1, WindowsRunFileIdentity.HostIdentity(), root.Volume, _root.ToUpperInvariant(), root.ObjectId,
            RunLockRelativeName, runLock.ObjectId, 1);
    }

    // Enumeration accommodation, not coordinator authority: inspect metadata without requesting file data
    // access (which the lifetime handle excludes). Nothing here creates, replaces, locks, or authorizes a run.
    internal static void ValidateReservedEntry(string path)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("A reserved coordinator lock requires Windows NTFS."); }
        _ = WindowsRunFileIdentity.ValidateRootPath(Path.GetDirectoryName(Path.GetFullPath(path))!);
        WindowsRunFileIdentity.RejectLinkedFile(path);
        using SafeFileHandle metadata = WindowsRunFileIdentity.OpenMetadata(path);
        WindowsRunFileIdentity.ValidateLock(metadata, Path.GetFullPath(path));
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) { return; }
            _disposed = true;
            _lock.Dispose();
            foreach (SafeFileHandle directory in _directories.Reverse()) { directory.Dispose(); }
        }
    }
}
