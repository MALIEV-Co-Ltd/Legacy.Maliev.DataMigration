using Legacy.Maliev.DataMigration.Console;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class WindowsFocusedCustodyImportTests : IDisposable
{
    private readonly string _parent = Path.Combine(Path.GetTempPath(), $"auth-custody-import-{Guid.NewGuid():N}");
    private string Root => Path.Combine(_parent, "artifacts");

    [WindowsLocalRunTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Actual_extra_hardlink_on_source_or_reused_target_is_rejected(bool targetAlias)
    {
        using WindowsLocalRunAuthority parent = WindowsLocalRunAuthority.AcquireFresh(Root);
        Guid run = Guid.NewGuid(); string childRoot = Path.Combine(Root, "auth-executed-" + run.ToString("N"));
        using WindowsLocalRunAuthority child = WindowsLocalRunAuthority.AcquireFresh(childRoot);
        using var parentFiles = new CurrentAppOwnedRepairCustody(parent);
        using var childFiles = new CurrentAppOwnedRepairCustody(child);
        string source = Path.Combine(childRoot, "actual.json"); byte[] bytes = [1, 2, 3];
        File.WriteAllBytes(source, bytes);
        string target = Path.Combine(Root, "auth-import-" + run.ToString("N") + "-actual.json");
        string aliased = targetAlias ? target : source;
        if (targetAlias) { File.WriteAllBytes(target, bytes); }
        string alias = Path.Combine(Path.GetDirectoryName(aliased)!, "extra-link.json");
        Assert.True(CreateHardLink(alias, aliased, IntPtr.Zero));
        var artifact = new CurrentAuthProofArtifact(source, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        var rejection = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthTypedProofArtifactImport.ImportAsync(
            parentFiles, parent.Binding, childFiles, child.Binding, artifact, run, CancellationToken.None));
        Assert.Equal(CurrentAppOwnedRepairPermit.Invalid().Code, rejection.Code);
        Assert.Equal(bytes, File.ReadAllBytes(source));
        if (targetAlias) { Assert.Equal(bytes, File.ReadAllBytes(target)); }
        else { Assert.False(File.Exists(target)); }
    }

    [WindowsLocalRunFact]
    public async Task Actual_import_reuse_retains_shared_reads_and_releases_only_on_custody_disposal()
    {
        using WindowsLocalRunAuthority parent = WindowsLocalRunAuthority.AcquireFresh(Root);
        Guid run = Guid.NewGuid(); string childRoot = Path.Combine(Root, "auth-executed-" + run.ToString("N"));
        using WindowsLocalRunAuthority child = WindowsLocalRunAuthority.AcquireFresh(childRoot);
        using var parentFiles = new CurrentAppOwnedRepairCustody(parent);
        using var childFiles = new CurrentAppOwnedRepairCustody(child);
        string source = Path.Combine(childRoot, "actual.json"); byte[] bytes = [1, 2, 3];
        File.WriteAllBytes(source, bytes);
        var artifact = new CurrentAuthProofArtifact(source, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        CurrentAuthProofArtifact imported = await CurrentAuthTypedProofArtifactImport.ImportAsync(
            parentFiles, parent.Binding, childFiles, child.Binding, artifact, run, CancellationToken.None);
        Assert.Equal(imported, await CurrentAuthTypedProofArtifactImport.ImportAsync(
            parentFiles, parent.Binding, childFiles, child.Binding, artifact, run, CancellationToken.None));
        Assert.Equal(bytes, parentFiles.Read(imported.Path, sharedReader: true));
        parentFiles.Require(); childFiles.Require();
        _ = Assert.Throws<IOException>(() => File.WriteAllBytes(source, [4]));
        _ = Assert.Throws<IOException>(() => File.Delete(imported.Path));
        childFiles.Dispose(); parentFiles.Dispose();
        childFiles.Dispose(); parentFiles.Dispose();
        File.WriteAllBytes(source, [4]); File.Delete(imported.Path);
    }

    [WindowsLocalRunFact]
    public void Borrowed_stream_is_bounded_shared_and_owned_by_custody()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        string path = Path.Combine(Root, "actual.json"); File.WriteAllBytes(path, [1, 2, 3]);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        _ = Assert.Throws<MigrationExecutionException>(() => files.BorrowReadStream(path, maximumBytes: 2));
        _ = Assert.Throws<MigrationExecutionException>(() => files.BorrowReadStream(path, maximumBytes: (512L * 1024 * 1024) + 1));
        FileStream first = files.BorrowReadStream(path), second = files.BorrowReadStream(path);
        Assert.False(first.CanWrite); Assert.Equal(1, first.ReadByte()); Assert.Equal(1, second.ReadByte());
        files.Require();
        _ = Assert.Throws<IOException>(() => File.WriteAllBytes(path, [4]));
        files.Dispose();
        _ = Assert.Throws<ObjectDisposedException>(() => first.ReadByte());
        _ = Assert.Throws<ObjectDisposedException>(() => second.ReadByte());
        _ = Assert.Throws<ObjectDisposedException>(() => files.BorrowReadStream(path));
        File.WriteAllBytes(path, [4]);
    }

    [WindowsLocalRunFact]
    public void Premature_caller_disposal_cannot_leave_valid_custody()
    {
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Root);
        string path = Path.Combine(Root, "actual.json"); File.WriteAllBytes(path, [1]);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        files.BorrowReadStream(path).Dispose();
        _ = Assert.Throws<ObjectDisposedException>(files.Require);
    }

    public void Dispose()
    {
        if (Directory.Exists(_parent)) { Directory.Delete(_parent, recursive: true); }
    }

#pragma warning disable SYSLIB1054 // Fixed Windows ABI, matching existing custody hardlink regressions.
    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string newName, string existingName, IntPtr securityAttributes);
#pragma warning restore SYSLIB1054
}
