using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Verbatim bounded immutable import from a separately held case root into the parent's immediate root.</summary>
internal static class CurrentAuthTypedProofArtifactImport
{
    internal static async Task<CurrentAuthProofArtifact> ImportAsync(CurrentAppOwnedRepairCustody parent,
        LocalExecutionBinding parentBinding, CurrentAppOwnedRepairCustody child, LocalExecutionBinding childBinding,
        CurrentAuthProofArtifact source, Guid run, CancellationToken ct)
    {
        parent.Require(); child.Require();
        string sourcePath = Path.GetFullPath(source.Path);
        if (run == Guid.Empty || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(sourcePath), childBinding.ArtifactRootCanonicalPath) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFileName(childBinding.ArtifactRootCanonicalPath), "auth-executed-" + run.ToString("N")) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(childBinding.ArtifactRootCanonicalPath), parentBinding.ArtifactRootCanonicalPath) ||
            !CurrentAuthRepairPermit.HashShape(source.Sha256)) { throw CurrentAuthRepairPermit.Invalid(); }
        string target = Path.Combine(parentBinding.ArtifactRootCanonicalPath, "auth-import-" + run.ToString("N") + "-" + Path.GetFileName(sourcePath));
        // These are borrowed handles. The respective custody retains and disposes them.
        FileStream input = child.BorrowReadStream(sourcePath);
        string sourceIdentity = SecureLocalFile.GetHandleIdentity(input); long length = input.Length;
        if (length is < 1 or > 512L * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
        if (File.Exists(target))
        {
            FileStream old = parent.BorrowReadStream(target);
            if (old.Length != length || Convert.ToHexStringLower(await SHA256.HashDataAsync(old, ct).ConfigureAwait(false)) != source.Sha256)
            { throw CurrentAuthRepairPermit.Invalid(); }
        }
        else
        {
            await using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                if (!SecureLocalFile.HandleResolvesToApprovedPath(output, target)) { throw CurrentAuthRepairPermit.Invalid(); }
                byte[] buffer = new byte[65536]; long copied = 0;
                while (true)
                {
                    int count = await input.ReadAsync(buffer, ct).ConfigureAwait(false); if (count == 0) { break; }
                    copied = checked(copied + count); if (copied > length) { throw CurrentAuthRepairPermit.Invalid(); }
                    await output.WriteAsync(buffer.AsMemory(0, count), ct).ConfigureAwait(false);
                }
                if (copied != length) { throw CurrentAuthRepairPermit.Invalid(); }
                await output.FlushAsync(ct).ConfigureAwait(false); output.Flush(flushToDisk: true); output.Position = 0;
                if (Convert.ToHexStringLower(await SHA256.HashDataAsync(output, ct).ConfigureAwait(false)) != source.Sha256 ||
                    !SecureLocalFile.HandleResolvesToApprovedPath(output, target)) { throw CurrentAuthRepairPermit.Invalid(); }
            }
            // Independently reopen through the actual owner/no-link/handle path guard after closing the writer.
            FileStream readback = parent.BorrowReadStream(target);
            if (readback.Length != length || Convert.ToHexStringLower(await SHA256.HashDataAsync(readback, ct).ConfigureAwait(false)) != source.Sha256)
            { throw CurrentAuthRepairPermit.Invalid(); }
        }
        input.Position = 0;
        if (input.Length != length || Convert.ToHexStringLower(await SHA256.HashDataAsync(input, ct).ConfigureAwait(false)) != source.Sha256 ||
            SecureLocalFile.GetHandleIdentity(input) != sourceIdentity) { throw CurrentAuthRepairPermit.Invalid(); }
        parent.Require(); child.Require(); return new(target, source.Sha256);
    }
    internal static LocalExecutionBinding ReadChildBinding(string directory, Guid run)
    {
        string path = Path.Combine(directory, $"auth-observed-{run:N}-00001-run-binding.json");
        using var input = SecureLocalFile.OpenReadShared(path);
        if (input.Length is < 1 or > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] bytes = new byte[checked((int)input.Length)]; input.ReadExactly(bytes);
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bytes);
        if (!StringComparer.OrdinalIgnoreCase.Equals(binding.ArtifactRootCanonicalPath, Path.GetFullPath(directory))) { throw CurrentAuthRepairPermit.Invalid(); }
        return binding;
    }
}
