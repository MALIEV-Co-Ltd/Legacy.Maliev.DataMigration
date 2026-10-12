using Legacy.Maliev.DataMigration.Console;
using System.Runtime.InteropServices;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAppOwnedRepairCustodyTests : IDisposable
{
    private readonly string _parent = Path.Combine(Path.GetTempPath(), $"repair-custody-{Guid.NewGuid():N}");
    private string Root => Path.Combine(_parent, "artifacts");

    [WindowsLocalRunFact]
    public void Enumerates_exact_operation_receipts_and_holds_them_against_replacement()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        Guid operation = Guid.NewGuid();
        string name = $"{operation:D}-Customer-prepared.json";
        string path = Path.Combine(Root, name);
        File.WriteAllBytes(path, [1, 2, 3]);
        File.WriteAllText(Path.Combine(Root, $"{Guid.NewGuid():D}-unrelated.json"), "unrelated");
        using var custody = new CurrentAppOwnedRepairCustody(authority);
        CurrentAppOwnedRetainedReceipt receipt = Assert.Single(custody.ReadRetainedReceipts(operation));
        Assert.Equal(name, receipt.Name);
        Assert.Equal(new byte[] { 1, 2, 3 }, receipt.ExactBytes);
        _ = Assert.Throws<IOException>(() => File.WriteAllText(path, "changed"));
        _ = Assert.Throws<IOException>(() => File.Delete(path));
        custody.Require();
        _ = Assert.Throws<MigrationExecutionException>(() => custody.ReadRetainedReceipts(operation));
    }

    [WindowsLocalRunTheory]
    [InlineData("Customer-prepared.JSON", false)]
    [InlineData("Customer-unknown.json", false)]
    [InlineData("Customer-prepared.json", true)]
    public void Rejects_operation_aliases_unknown_slots_and_directories(string suffix, bool directory)
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        Guid operation = Guid.NewGuid();
        string path = Path.Combine(Root, $"{operation:D}-{suffix}");
        if (directory) { _ = Directory.CreateDirectory(path); }
        else { File.WriteAllText(path, "synthetic"); }
        using var custody = new CurrentAppOwnedRepairCustody(authority);
        _ = Assert.Throws<MigrationExecutionException>(() => custody.ReadRetainedReceipts(operation));
    }

    [WindowsLocalRunFact]
    public void Rechecks_absent_slots_and_rejects_later_publication()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        Guid operation = Guid.NewGuid();
        using var custody = new CurrentAppOwnedRepairCustody(authority);
        Assert.Empty(custody.ReadRetainedReceipts(operation));
        custody.Require();
        File.WriteAllText(Path.Combine(Root, $"{operation:D}-Order-prepared.json"), "late");
        _ = Assert.Throws<MigrationExecutionException>(custody.Require);
    }

    [WindowsLocalRunFact]
    public void Rejects_oversized_receipt_before_reading_and_releases_handles_on_dispose()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        Guid operation = Guid.NewGuid();
        string path = Path.Combine(Root, $"{operation:D}-Customer-prepared.json");
        File.WriteAllBytes(path, new byte[65537]);
        using var custody = new CurrentAppOwnedRepairCustody(authority);
        _ = Assert.Throws<MigrationExecutionException>(() => custody.ReadRetainedReceipts(operation));
        File.WriteAllText(path, "small");
        _ = Assert.Single(custody.ReadRetainedReceipts(operation));
        custody.Dispose();
        _ = Assert.Throws<ObjectDisposedException>(custody.Require);
        _ = Assert.Throws<ObjectDisposedException>(() => custody.Read(path));
        File.WriteAllText(path, "released");
    }

    [WindowsLocalRunFact]
    public void Rejects_receipt_hardlink_and_active_writer()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        Guid operation = Guid.NewGuid();
        string path = Path.Combine(Root, $"{operation:D}-Customer-prepared.json");
        string alias = Path.Combine(Root, "alias");
        File.WriteAllText(path, "synthetic");
        Assert.True(CreateHardLink(alias, path, IntPtr.Zero));
        using var custody = new CurrentAppOwnedRepairCustody(authority);
        _ = Assert.Throws<MigrationExecutionException>(() => custody.ReadRetainedReceipts(operation));
        File.Delete(alias);
        using (var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
        {
            _ = Assert.Throws<IOException>(() => custody.ReadRetainedReceipts(operation));
        }
        _ = Assert.Single(custody.ReadRetainedReceipts(operation));
    }

    public void Dispose()
    {
        if (Directory.Exists(_parent)) { Directory.Delete(_parent, recursive: true); }
    }

#pragma warning disable SYSLIB1054 // Fixed Windows ABI, matching permanent run-authority tests.
    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string newName, string existingName, IntPtr securityAttributes);
#pragma warning restore SYSLIB1054
}
