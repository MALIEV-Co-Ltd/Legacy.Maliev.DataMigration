using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentCustomerClosedArtifactImport
{
    internal static async Task<CustomerDefinitionArtifact> ImportAsync(CurrentAppOwnedRepairCustody destination, LocalExecutionBinding destinationBinding,
        CurrentAppOwnedRepairCustody original, LocalExecutionBinding originalBinding, string sourcePath, string prefix, CancellationToken ct)
    {
        destination.Require(); original.Require();
        if (!Guid.TryParseExact(prefix, "N", out _) || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(sourcePath)), originalBinding.ArtifactRootCanonicalPath) ||
            StringComparer.OrdinalIgnoreCase.Equals(destinationBinding.ArtifactRootCanonicalPath, originalBinding.ArtifactRootCanonicalPath))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string target = Path.Combine(destinationBinding.ArtifactRootCanonicalPath, "customer-closed-import-" + prefix + "-" + Path.GetFileName(sourcePath));
        // Original handles remain owned by their original custody. Copy bytes,
        // never serialize semantic records into a replacement proof artifact.
        FileStream source = original.BorrowReadStream(sourcePath); source.Position = 0;
        long length = source.Length; string identity = SecureLocalFile.GetHandleIdentity(source);
        string hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(source, ct).ConfigureAwait(false)); source.Position = 0;
        if (!File.Exists(target))
        {
            await using var writer = new FileStream(target, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough);
            if (!SecureLocalFile.HandleResolvesToApprovedPath(writer, target) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(target))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            byte[] buffer = new byte[65536]; long copied = 0;
            while (true)
            {
                int count = await source.ReadAsync(buffer, ct).ConfigureAwait(false); if (count == 0) { break; }
                copied = checked(copied + count); if (copied > length) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                await writer.WriteAsync(buffer.AsMemory(0, count), ct).ConfigureAwait(false);
            }
            if (copied != length) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            await writer.FlushAsync(ct).ConfigureAwait(false); writer.Flush(flushToDisk: true); writer.Position = 0;
            if (Convert.ToHexStringLower(await SHA256.HashDataAsync(writer, ct).ConfigureAwait(false)) != hash) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        FileStream held = destination.BorrowReadStream(target); held.Position = 0;
        if (held.Length != length || Convert.ToHexStringLower(await SHA256.HashDataAsync(held, ct).ConfigureAwait(false)) != hash ||
            source.Length != length || SecureLocalFile.GetHandleIdentity(source) != identity) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        source.Position = 0;
        if (Convert.ToHexStringLower(await SHA256.HashDataAsync(source, ct).ConfigureAwait(false)) != hash) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        destination.Require(); original.Require(); return new(target, hash, Path.GetFullPath(sourcePath));
    }
}
