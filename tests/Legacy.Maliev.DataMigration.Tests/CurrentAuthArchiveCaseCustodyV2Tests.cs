using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAuthArchiveCaseCustodyV2Tests
{
    [WindowsLocalRunFact]
    public async Task Qualified_child_uses_its_own_exclusive_authority_and_does_not_widen_parent_reads()
    {
        string root = Path.Combine(Path.GetTempPath(), "archive-custody-v2-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var parent = WindowsLocalRunAuthority.AcquireFresh(root);
            using var parentFiles = new CurrentAppOwnedRepairCustody(parent);
            string child = Path.Combine(root, "qualified"); var bindingPath = Path.Combine(child, "fixture-binding.json");
            byte[] bytes;
            using (var fresh = WindowsLocalRunAuthority.AcquireFresh(child))
            using (var files = new CurrentAppOwnedRepairCustody(fresh))
            { bytes = JsonSerializer.SerializeToUtf8Bytes(fresh.Binding); await files.WriteNewAsync(bindingPath, bytes, CancellationToken.None); }
            var reference = new CurrentAuthArchiveProofArtifact(bindingPath, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
            _ = Assert.Throws<MigrationExecutionException>(() => parentFiles.Read(bindingPath));
            var (Authority, Files) = CurrentAuthArchiveCaseCustodyV2.OpenQualified(reference, root);
            using (Authority)
            using (Files)
            {
                Assert.Equal(bytes, Files.Read(bindingPath, sharedReader: true));
                _ = Assert.Throws<IOException>(() => WindowsLocalRunAuthority.AcquireResume(child, Authority.Binding));
                parent.ValidateHeld();
            }
            // Releasing this scope permits the real producer to resume that exact same root.
            var resumed = CurrentAuthArchiveCaseCustodyV2.OpenQualified(reference, root);
            using (resumed.Authority) using (resumed.Files) { resumed.Authority.ValidateHeld(); }
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveCaseCustodyV2.RequireChild(root, root));
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveCaseCustodyV2.RequireChild(root, Path.Combine(child, "nested")));
        }
        finally
        {
            if (Directory.Exists(root)) { Directory.Delete(root, recursive: true); }
        }
    }
}
