using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentCustomerClosedSecretCleanupTests
{
    [WindowsLocalRunFact]
    public void Actual_same_handle_cleanup_removes_only_fixed_operation_secrets()
    {
        string parent = Path.Combine(Path.GetTempPath(), "customer-closed-cleanup-" + Guid.NewGuid().ToString("N"));
        string root = Path.Combine(parent, "artifacts");
        Guid operation = Guid.NewGuid();
        string suffix = operation.ToString("N");
        string[] names = ["operator.txt", "ordinary.txt", "source-connection.txt", "source-token.txt", "customer-closed-review-" + suffix + ".private.pem",
            "customer-closed-authorization-" + suffix + ".private.pem", "customer-closed-receipt-" + suffix + ".private.pem"];
        try
        {
            LocalExecutionBinding binding;
            using (var authority = WindowsLocalRunAuthority.AcquireFresh(root))
            {
                binding = authority.Binding;
                foreach (string name in names) { File.WriteAllBytes(Path.Combine(root, name), [1, 2, 3]); }
                File.WriteAllBytes(Path.Combine(root, "retained-evidence.json"), [4, 5, 6]);
            }
            CurrentCustomerClosedSecretCleanup.RequireRemoved(root, binding, operation);
            Assert.All(names, name => Assert.False(File.Exists(Path.Combine(root, name))));
            Assert.Equal(new byte[] { 4, 5, 6 }, File.ReadAllBytes(Path.Combine(root, "retained-evidence.json")));
            CurrentCustomerClosedSecretCleanup.RequireRemoved(root, binding, operation);
        }
        finally
        {
            // This unique test-owned directory contains no database or recovery material.
            if (Directory.Exists(parent)) { Directory.Delete(parent, recursive: true); }
            Assert.False(Directory.Exists(parent));
        }
    }
}
