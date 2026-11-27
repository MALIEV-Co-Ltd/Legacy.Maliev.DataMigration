namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentAuthArchiveDefinitionCodeCopy
{
    // The existing host verifies the full canonical Tests bundle. Only these build/runtime assets may be copied.
    private static readonly string[] FixedAssets = ["database-disposition.json", "CoverletSourceRootsMapping_Legacy.Maliev.DataMigration.Tests",
        ".msCoverageSourceRootsMapping_Legacy.Maliev.DataMigration.Tests",
        "Fixtures/bd201a5-quotation-accepted-outcome.sql", "Fixtures/2026-08-12-ga4-quotation-lifecycle.sql",
        "Fixtures/2026-08-23-quotation-qualified-outcome.sql", "Fixtures/2026-08-30-ga4-quotation-source-reconciliation.sql"];

    internal static bool ApprovedAsset(string relative)
    {
        string normalized = relative.Replace('\\', '/');
        return !Path.IsPathFullyQualified(relative) && !normalized.Contains(':') && normalized.Split('/').All(x => x.Length != 0 && x is not ("." or "..")) &&
            (normalized.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase) || normalized.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase) || FixedAssets.Contains(normalized, StringComparer.Ordinal));
    }

    internal static Task CopyAsync(string qualifiedRoot, CurrentAuthArchiveDefinitionAnchorSession anchor, CancellationToken ct)
    { return CopyCoreAsync(qualifiedRoot, anchor.Binding, ct); }

    internal static Task CopyFinal6Async(string qualifiedRoot, CurrentAuthArchiveFinal6DefinitionAnchorSession anchor, CancellationToken ct)
    { return CopyCoreAsync(qualifiedRoot, anchor.Binding, ct); }

    private static async Task CopyCoreAsync(string qualifiedRoot, LocalExecutionBinding binding, CancellationToken ct)
    {
        string[] inventory = Inventory(qualifiedRoot, ct);
        using var sourceBundle = await CurrentAuthTypedHostProducer.HoldFixedTestBundleAsync(qualifiedRoot, ct);
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        const string canonical = @"B:\maliev-legacy\Legacy.Maliev.DataMigration\tests\Legacy.Maliev.DataMigration.Tests\bin\Release\net10.0";
        var approved = Inventory(canonical, ct).Select(path => Path.GetRelativePath(canonical, path)).ToHashSet(StringComparer.Ordinal);
        var children = new Dictionary<string, (WindowsLocalRunAuthority Authority, CurrentAppOwnedRepairCustody Files)>(StringComparer.OrdinalIgnoreCase);
        Exception? primary = null; var cleanupFailures = new List<Exception>();
        try
        {
            foreach (string path in inventory)
            {
                ct.ThrowIfCancellationRequested(); sourceBundle.Require();
                string relative = Path.GetRelativePath(qualifiedRoot, path);
                if (!ApprovedAsset(relative) || !approved.Contains(relative)) { continue; } // Retained case evidence is not a build asset and is never copied.
                string destination = Path.Combine(binding.ArtifactRootCanonicalPath, relative);
                string directory = Path.GetDirectoryName(destination)!;
                if (!Directory.Exists(directory)) { SecureSnapshotFileCreation.CreateRestrictedDirectory(directory); }
                using var source = SecureLocalFile.OpenReadShared(path);
                if (!SecureLocalFile.HandleResolvesToApprovedPath(source, path) || source.Length is < 1 or > 128 * 1024 * 1024) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
                byte[] bytes = new byte[checked((int)source.Length)]; await source.ReadExactlyAsync(bytes, ct);
                if (Path.GetDirectoryName(destination) == binding.ArtifactRootCanonicalPath) { await files.WriteNewAsync(destination, bytes, ct); }
                else
                {
                    // Only a directory from the authenticated canonical asset inventory can become a child authority.
                    if (!children.TryGetValue(directory, out var child))
                    {
                        var childAuthority = WindowsLocalRunAuthority.AcquireFresh(directory);
                        child = (childAuthority, new CurrentAppOwnedRepairCustody(childAuthority));
                        children.Add(directory, child);
                    }
                    await child.Files.WriteNewAsync(destination, bytes, ct);
                    child.Authority.ValidateHeld();
                }
            }
            sourceBundle.Require();
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            foreach (var (Authority, Files) in children.Values.Reverse())
            {
                try { Files.Dispose(); } catch (Exception failure) { cleanupFailures.Add(failure); }
                try { Authority.Dispose(); } catch (Exception failure) { cleanupFailures.Add(failure); }
            }
        }
        if (cleanupFailures.Count != 0)
        { if (primary is not null) { cleanupFailures.Insert(0, primary); } throw new AggregateException("Fixed canonical asset custody cleanup failed.", cleanupFailures); }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
    }

    internal static void RequireBoundedInventory(string root, CancellationToken ct)
    {
        _ = Inventory(root, ct);
    }

    private static string[] Inventory(string root, CancellationToken ct)
    {
        if (!Path.IsPathFullyQualified(root)) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        var directories = new Stack<string>(); directories.Push(root); var files = new List<string>(); int visited = 0;
        while (directories.Count != 0)
        {
            ct.ThrowIfCancellationRequested(); string directory = directories.Pop();
            // Check every ancestor before enumeration; never traverse a junction and reject it afterwards.
            for (DirectoryInfo? ancestor = new(directory); ancestor is not null; ancestor = ancestor.Parent)
            { if ((ancestor.Attributes & FileAttributes.ReparsePoint) != 0) { throw CurrentAuthArchiveRecoveryV2.Invalid(); } }
            foreach (FileSystemInfo entry in new DirectoryInfo(directory).EnumerateFileSystemInfos())
            {
                ct.ThrowIfCancellationRequested(); if (++visited > 4096 || (entry.Attributes & FileAttributes.ReparsePoint) != 0) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
                if (entry is DirectoryInfo child) { directories.Push(child.FullName); }
                else if (entry is FileInfo file) { files.Add(file.FullName); }
                else { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
            }
        }
        return files.Order(StringComparer.Ordinal).ToArray();
    }
}
