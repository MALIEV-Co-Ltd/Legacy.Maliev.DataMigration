using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class DualTargetNativeProofSecretIdentityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "dual-native-secret-id-" + Guid.NewGuid().ToString("N"));
    private readonly List<DualTargetNativeProofGeneratedSecret> _owned = [];
    private LocalExecutionBinding? _binding;
    private static readonly byte[] Synthetic = "synthetic not-a-real-credential"u8.ToArray();

    [WindowsLocalRunFact]
    public async Task Exact_creation_handle_identity_is_deleted_after_custody_releases()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        string path = await CreateAsync();
        DualTargetNativeProofSecret.RemoveGenerated(_root, _binding!, _owned);
        Assert.False(File.Exists(path));
        using var resumed = WindowsLocalRunAuthority.AcquireResume(_root, _binding!); resumed.ValidateHeld();
    }
    [WindowsLocalRunFact]
    public async Task Identical_bytes_at_replaced_path_do_not_reestablish_original_ownership()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        string path = await CreateAsync(); File.Move(path, path + ".original");
        using (var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding!))
        using (var files = new CurrentAppOwnedRepairCustody(authority)) { await files.WriteNewAsync(path, Synthetic, default); }
        Assert.Equal(_owned.Single().Sha256, CurrentAuthTypedHostProducer.ImageHash(path));
        using (var replacement = SecureLocalFile.OpenReadShared(path))
        { Assert.NotEqual(_owned.Single().Identity, WindowsRunFileIdentity.Observe(replacement.SafeFileHandle)); }
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofSecret.RemoveGenerated(_root, _binding!, _owned));
        Assert.True(File.Exists(path)); Assert.True(File.Exists(path + ".original"));
    }
    [WindowsLocalRunFact]
    public async Task Held_reader_refuses_deletion_then_exact_file_can_be_cleaned()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        string path = await CreateAsync();
        using (var reader = SecureLocalFile.OpenReadShared(path))
        { _ = Assert.Throws<MigrationExecutionException>(() => DualTargetNativeProofSecret.RemoveGenerated(_root, _binding!, _owned)); Assert.True(File.Exists(path)); }
        DualTargetNativeProofSecret.RemoveGenerated(_root, _binding!, _owned); Assert.False(File.Exists(path));
    }
    [WindowsLocalRunFact]
    public async Task Cancelled_write_retains_exact_partial_file_identity_for_cleanup()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        using (var authority = WindowsLocalRunAuthority.AcquireFresh(_root))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            _binding = authority.Binding; string path = FixedName();
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DualTargetNativeProofSecret.WriteGeneratedAsync(files, _root, path, Synthetic, _owned, cancelled.Token));
            _ = Assert.Single(_owned); Assert.Equal(path, _owned[0].Path);
        }
        DualTargetNativeProofSecret.RemoveGenerated(_root, _binding, _owned); Assert.False(File.Exists(_owned[0].Path));
    }
    private async Task<string> CreateAsync()
    {
        using var authority = WindowsLocalRunAuthority.AcquireFresh(_root); _binding = authority.Binding;
        using var files = new CurrentAppOwnedRepairCustody(authority); string path = FixedName();
        await DualTargetNativeProofSecret.WriteGeneratedAsync(files, _root, path, Synthetic, _owned, default);
        _ = Assert.Single(_owned); return path;
    }
    private string FixedName()
    {
        return Path.Combine(_root, "native-proof-" + Guid.NewGuid().ToString("N") + "-operator.txt");
    }

    public void Dispose()
    {
        if (!OperatingSystem.IsWindows() || !Directory.Exists(_root) || _binding is null) { return; }
        string absolute = Path.GetFullPath(_root);
        if (Path.GetDirectoryName(absolute) != Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath())) ||
            !Path.GetFileName(absolute).StartsWith("dual-native-secret-id-", StringComparison.Ordinal) || new DirectoryInfo(absolute).LinkTarget is not null)
        { throw new IOException("dual_native_secret_test_cleanup_ownership_changed"); }
        using (var directory = WindowsRunFileIdentity.OpenDirectory(absolute))
        {
            var actual = WindowsRunFileIdentity.Observe(directory);
            if (actual.Volume != _binding.LocalVolumeIdentity || actual.ObjectId != _binding.ArtifactRootFilesystemObjectIdentity)
            { throw new IOException("dual_native_secret_test_cleanup_identity_changed"); }
        }
        Directory.Delete(absolute, recursive: true);
        if (Directory.Exists(absolute)) { throw new IOException("dual_native_secret_test_cleanup_absence_failed"); }
    }
}
