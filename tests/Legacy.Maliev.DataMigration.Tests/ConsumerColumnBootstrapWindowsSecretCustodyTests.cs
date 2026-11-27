using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class ConsumerColumnBootstrapWindowsSecretCustodyTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "bootstrap-windows-secret-" + Guid.NewGuid().ToString("N"));
    private LocalExecutionBinding? _binding;
    private DateTimeOffset _began;

    [WindowsLocalRunTheory]
    [InlineData("operator.secret")]
    [InlineData("fault-forward-1234567890abcdef1234567890abcdef-review-private.pem")]
    [InlineData("bootstrap-reviewed-1234567890abcdef1234567890abcdef-review.pem")]
    public async Task Created_secret_has_real_NTFS_identity_and_is_removed_after_custody_closes(string name)
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var created = await CreateAsync(name);
        var identity = JsonSerializer.Deserialize<WindowsRunFileIdentity.Identity>(created.Identity)!;
        Assert.StartsWith("windows-ntfs:", identity.Volume, StringComparison.Ordinal);
        Assert.StartsWith("file-id-128:", identity.ObjectId, StringComparison.Ordinal);
        ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(_binding!, [created], _began);
        Assert.False(File.Exists(created.Path)); Assert.True(File.Exists(created.Path + ".bootstrap-secret-custody.json"));
        ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(_binding!, [created], _began);
        using var resumed = WindowsLocalRunAuthority.AcquireResume(_root, _binding!); resumed.ValidateHeld();
    }

    [WindowsLocalRunFact]
    public async Task Same_name_replacement_is_not_deleted_using_the_original_file_ID()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var created = await CreateAsync("operator.secret"); File.Move(created.Path, created.Path + ".original");
        using (var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding!))
        using (var files = new CurrentAppOwnedRepairCustody(authority)) { await files.WriteNewAsync(created.Path, "synthetic replacement"u8.ToArray(), default); }
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(_binding!, [created], _began));
        Assert.True(File.Exists(created.Path)); Assert.True(File.Exists(created.Path + ".original"));
    }

    [WindowsLocalRunFact]
    public async Task Reparse_replacement_is_refused_and_target_is_preserved()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var created = await CreateAsync("operator.secret"); File.Move(created.Path, created.Path + ".original");
        _ = File.CreateSymbolicLink(created.Path, created.Path + ".original");
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(_binding!, [created], _began));
        Assert.True(File.Exists(created.Path + ".original")); Assert.NotNull(new FileInfo(created.Path).LinkTarget);
    }

    [WindowsLocalRunFact]
    public async Task Unknown_name_and_preexisting_untracked_secret_are_preserved()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        Initialize(); string unknown = Path.Combine(_root, "unrelated.txt"), untracked = Path.Combine(_root, "operator.secret");
        using (var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding!))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        { await files.WriteNewAsync(unknown, "synthetic unrelated"u8.ToArray(), default); await files.WriteNewAsync(untracked, "synthetic untracked"u8.ToArray(), default); }
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(_binding!, [(unknown, string.Empty)], _began));
        _ = Assert.Throws<MigrationExecutionException>(() => ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(_binding!, [(untracked, string.Empty)], _began));
        Assert.True(File.Exists(unknown)); Assert.True(File.Exists(untracked));
    }

    [WindowsLocalRunFact]
    public async Task Sidecar_collision_deletes_only_the_new_empty_handle_and_preserves_the_existing_artifact()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        Initialize(); string path = Path.Combine(_root, "operator.secret"), metadata = path + ".bootstrap-secret-custody.json";
        using (var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding!))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await files.WriteNewAsync(metadata, "synthetic retained marker"u8.ToArray(), default);
            _ = await Assert.ThrowsAnyAsync<IOException>(() => ConsumerColumnBootstrapWindowsSecretCustody.CreateAsync(_binding!, files, path, "synthetic not written"u8.ToArray(), default));
        }
        Assert.False(File.Exists(path)); Assert.Equal("synthetic retained marker", await File.ReadAllTextAsync(metadata));
    }

    [WindowsLocalRunFact]
    public async Task Sharing_denial_preserves_secret_then_removal_succeeds_after_the_reader_closes()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var created = await CreateAsync("operator.secret");
        using (var held = SecureLocalFile.OpenReadShared(created.Path))
        { _ = Assert.ThrowsAny<IOException>(() => ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(_binding!, [created], _began)); Assert.True(File.Exists(created.Path)); }
        ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(_binding!, [created], _began); Assert.False(File.Exists(created.Path));
    }

    private void Initialize()
    {
        _began = DateTimeOffset.UtcNow; Assert.False(Directory.Exists(_root));
        using var authority = WindowsLocalRunAuthority.AcquireFresh(_root); _binding = authority.Binding;
    }
    private async Task<(string Path, string Identity)> CreateAsync(string name)
    {
        Initialize(); using var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding!); using var files = new CurrentAppOwnedRepairCustody(authority);
        string path = Path.Combine(_root, name); byte[] bytes = "synthetic disposable secret"u8.ToArray();
        string identity = await ConsumerColumnBootstrapWindowsSecretCustody.CreateAsync(_binding!, files, path, bytes, default);
        Assert.All(bytes, value => Assert.Equal(0, value)); return (path, identity);
    }
    public void Dispose()
    {
        if (!OperatingSystem.IsWindows() || !Directory.Exists(_root) || _binding is null) { return; }
        string absolute = Path.GetFullPath(_root);
        if (Path.GetDirectoryName(absolute) != Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath())) ||
            !Path.GetFileName(absolute).StartsWith("bootstrap-windows-secret-", StringComparison.Ordinal) || new DirectoryInfo(absolute).LinkTarget is not null) { throw new IOException("bootstrap_secret_test_cleanup_ownership_changed"); }
        using (var opened = WindowsRunFileIdentity.OpenDirectory(absolute))
        {
            var identity = WindowsRunFileIdentity.Observe(opened);
            if (identity.Volume != _binding.LocalVolumeIdentity || identity.ObjectId != _binding.ArtifactRootFilesystemObjectIdentity) { throw new IOException("bootstrap_secret_test_cleanup_identity_changed"); }
        }
        Directory.Delete(absolute, recursive: true); if (Directory.Exists(absolute)) { throw new IOException("bootstrap_secret_test_cleanup_absence_failed"); }
    }
}
