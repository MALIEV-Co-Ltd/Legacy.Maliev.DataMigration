using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentCustomerClosedCanonicalPathTests
{
    [WindowsLocalRunFact]
    public void Actual_binding_accepts_case_only_physical_path_and_retains_its_signed_canonical_root()
    {
        string parent = Path.Combine(Path.GetTempPath(), "customer-case-path-" + Guid.NewGuid().ToString("N"));
        string requestedRoot = Path.Combine(parent, "customer-closed-case-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var authority = WindowsLocalRunAuthority.AcquireFresh(requestedRoot);
            LocalExecutionBinding binding = authority.Binding;
            string digest = binding.ComputeSha256();
            string retained = CurrentCustomerClosedEightAssembler.RequireCanonicalCaseRoot(requestedRoot, binding);
            Assert.Equal(binding.ArtifactRootCanonicalPath, retained);
            Assert.Equal(binding.ArtifactRootCanonicalPath,
                CurrentCustomerClosedEightAssembler.RequireCanonicalCaseRoot(requestedRoot.ToLowerInvariant(), binding));
            Assert.Equal(digest, binding.ComputeSha256());
            Assert.NotEqual(digest, (binding with { ArtifactRootCanonicalPath = requestedRoot.ToLowerInvariant() }).ComputeSha256());
            authority.ValidateHeld();
        }
        finally
        {
            if (Directory.Exists(parent)) { Directory.Delete(parent, recursive: true); }
            Assert.False(Directory.Exists(parent));
        }
    }

    [WindowsLocalRunFact]
    public void Actual_assembler_root_guard_rejects_sibling_prefix_and_relative_paths()
    {
        string parent = Path.Combine(Path.GetTempPath(), "customer-case-negative-" + Guid.NewGuid().ToString("N"));
        string root = Path.Combine(parent, "artifacts");
        try
        {
            using var authority = WindowsLocalRunAuthority.AcquireFresh(root);
            LocalExecutionBinding binding = authority.Binding;
            _ = Assert.Throws<MigrationExecutionException>(() =>
                CurrentCustomerClosedEightAssembler.RequireCanonicalCaseRoot(root + "-other", binding));
            _ = Assert.Throws<MigrationExecutionException>(() =>
                CurrentCustomerClosedEightAssembler.RequireCanonicalCaseRoot(Path.Combine(parent, "other"), binding));
            _ = Assert.Throws<MigrationExecutionException>(() =>
                CurrentCustomerClosedEightAssembler.RequireCanonicalCaseRoot("artifacts", binding));
            authority.ValidateHeld();
        }
        finally
        {
            if (Directory.Exists(parent)) { Directory.Delete(parent, recursive: true); }
            Assert.False(Directory.Exists(parent));
        }
    }
}
