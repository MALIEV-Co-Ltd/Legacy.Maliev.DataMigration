using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class Production181InputRootInitializer
{
    internal const string Command = "production181-initialize-input-root";
    internal static async Task<LocalExecutionBinding> InitializeAsync(string root, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true);
        if (!Path.IsPathFullyQualified(root) || (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any()))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        // Initialize before the owner populates genuine files; no input or evidence is manufactured here.
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root);
        using var authority = WindowsLocalRunAuthority.AcquireFresh(root);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(authority.Binding);
        string path = Path.Combine(authority.Binding.ArtifactRootCanonicalPath, "production181-input-binding.json");
        await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
        if (!files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        files.Require(); return authority.Binding;
    }
}
