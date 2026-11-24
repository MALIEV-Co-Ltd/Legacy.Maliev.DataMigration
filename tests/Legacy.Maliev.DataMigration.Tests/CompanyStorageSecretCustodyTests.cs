using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CompanyStorageSecretCustodyTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "company-secret-custody-" + Guid.NewGuid().ToString("N"));
    private LocalExecutionBinding? _binding;
    private DateTimeOffset _began;

    [WindowsLocalRunFact]
    public async Task Exact_created_NTFS_object_is_deleted_and_coordinator_lock_is_released()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var owned = await CreateAsync("source.secret");
        CompanyStorageSecretCustody.Remove(_root, _binding!, _began, owned);
        Assert.False(File.Exists(owned.Keys.Single()));
        using var resumed = WindowsLocalRunAuthority.AcquireResume(_root, _binding!); resumed.ValidateHeld();
        Assert.True(File.Exists(Path.Combine(_root, WindowsLocalRunAuthority.RunLockRelativeName)));
    }

    [WindowsLocalRunFact]
    public async Task Same_name_replacement_is_preserved_when_its_file_ID_differs()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var owned = await CreateAsync("source.secret"); string path = owned.Keys.Single();
        File.Move(path, path + ".original");
        using (var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding!))
        using (var files = new CurrentAppOwnedRepairCustody(authority)) { await files.WriteNewAsync(path, "synthetic replacement"u8.ToArray(), default); }
        _ = Assert.Throws<MigrationExecutionException>(() => CompanyStorageSecretCustody.Remove(_root, _binding!, _began, owned));
        Assert.True(File.Exists(path)); Assert.True(File.Exists(path + ".original"));
    }

    [WindowsLocalRunFact]
    public async Task Unknown_filename_is_preserved_even_with_an_actual_owned_identity()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var owned = await CreateAsync("unrelated.txt");
        _ = Assert.Throws<MigrationExecutionException>(() => CompanyStorageSecretCustody.Remove(_root, _binding!, _began, owned));
        Assert.True(File.Exists(owned.Keys.Single()));
    }

    [WindowsLocalRunFact]
    public async Task Reparse_replacement_is_refused_without_deleting_its_target()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var owned = await CreateAsync("source.secret"); string path = owned.Keys.Single();
        File.Move(path, path + ".original"); _ = File.CreateSymbolicLink(path, path + ".original");
        _ = Assert.Throws<MigrationExecutionException>(() => CompanyStorageSecretCustody.Remove(_root, _binding!, _began, owned));
        Assert.True(File.Exists(path + ".original")); Assert.NotNull(new FileInfo(path).LinkTarget);
    }

    [WindowsLocalRunFact]
    public async Task Fixture_cleanup_has_one_owner_for_recorded_secrets_and_keeps_other_cleanup()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var owned = await CreateAsync("operator.txt");
        Guid operation = Guid.NewGuid();
        string other = Path.Combine(_root, "ordinary.txt");
        string roleKey = Path.Combine(_root, "auth-closed-review-" + operation.ToString("N") + ".private.pem");
        using (var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding!))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await files.WriteNewAsync(other, "synthetic ordinary secret"u8.ToArray(), default);
            await files.WriteNewAsync(roleKey, "synthetic role key"u8.ToArray(), default);
            using var held = SecureLocalFile.OpenReadShared(other);
            var both = new Dictionary<string, WindowsRunFileIdentity.Identity>(StringComparer.Ordinal);
            foreach (var identity in owned) { both.Add(identity.Key, identity.Value); }
            both.Add(other, CompanyStorageSecretCustody.Observe(held, other)); owned = both;
        }
        var ownership = CompanyStorageFixtureSecretOwnership.FromCreatedFiles(_root, _binding!, _began, owned);
        CurrentAuthClosedSecretCleanup.RequireRemovedForCompany(_root, _binding!, operation, ownership);
        Assert.All(owned.Keys, path => Assert.False(File.Exists(path))); Assert.False(File.Exists(roleKey));
        using var resumed = WindowsLocalRunAuthority.AcquireResume(_root, _binding!); resumed.ValidateHeld();
    }

    [WindowsLocalRunFact]
    public async Task Fixture_cleanup_refuses_replacement_without_generic_cleanup_deleting_it()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var owned = await CreateAsync("operator.txt"); string path = owned.Keys.Single();
        File.Move(path, path + ".original");
        Guid operation = Guid.NewGuid(); string other = Path.Combine(_root, "ordinary.txt");
        using (var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding!))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await files.WriteNewAsync(path, "synthetic replacement"u8.ToArray(), default);
            await files.WriteNewAsync(other, "synthetic ordinary secret"u8.ToArray(), default);
        }
        var ownership = CompanyStorageFixtureSecretOwnership.FromCreatedFiles(_root, _binding!, _began, owned);
        var failure = Assert.Throws<AggregateException>(() => CurrentAuthClosedSecretCleanup.RequireRemovedForCompany(_root, _binding!, operation, ownership));
        _ = Assert.Single(failure.InnerExceptions, x => x is MigrationExecutionException);
        Assert.Equal("synthetic replacement", await File.ReadAllTextAsync(path));
        Assert.True(File.Exists(path + ".original")); Assert.True(File.Exists(other));
    }

    [WindowsLocalRunFact]
    public async Task Fixture_cleanup_does_not_relax_missing_owned_file_failure()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var owned = await CreateAsync("operator.txt"); string path = owned.Keys.Single();
        File.Move(path, path + ".original");
        var ownership = CompanyStorageFixtureSecretOwnership.FromCreatedFiles(_root, _binding!, _began, owned);
        var failure = Assert.Throws<AggregateException>(() => CurrentAuthClosedSecretCleanup.RequireRemovedForCompany(_root, _binding!, Guid.NewGuid(), ownership));
        _ = Assert.Single(failure.InnerExceptions, x => x is IOException);
        Assert.True(File.Exists(path + ".original"));
    }

    [WindowsLocalRunFact]
    public async Task Fixture_cleanup_preserves_primary_and_other_secret_cleanup_failures()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var owned = await CreateAsync("operator.txt"); string path = owned.Keys.Single();
        Guid operation = Guid.NewGuid();
        File.Move(path, path + ".original"); string other = Path.Combine(_root, "auth-closed-review-" + operation.ToString("N") + ".private.pem");
        using (var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding!))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await files.WriteNewAsync(path, "synthetic replacement"u8.ToArray(), default);
            await files.WriteNewAsync(other, "synthetic ordinary secret"u8.ToArray(), default);
        }
        var ownership = CompanyStorageFixtureSecretOwnership.FromCreatedFiles(_root, _binding!, _began, owned);
        using var blocked = new FileStream(other, FileMode.Open, FileAccess.Read, FileShare.None);
        var failure = Assert.Throws<AggregateException>(() => CurrentAuthClosedSecretCleanup.RequireRemovedForCompany(_root, _binding!, operation, ownership));
        Assert.Collection(failure.InnerExceptions,
            first => { _ = Assert.IsType<AggregateException>(first); },
            second => { _ = Assert.IsType<IOException>(second); });
        Assert.True(File.Exists(path)); Assert.True(File.Exists(path + ".original")); Assert.True(File.Exists(other));
    }

    [WindowsLocalRunFact]
    public async Task Fixture_cleanup_rejects_wrong_binding_and_invalid_operation_before_deletion()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var owned = await CreateAsync("operator.txt");
        var ownership = CompanyStorageFixtureSecretOwnership.FromCreatedFiles(_root, _binding!, _began, owned);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthClosedSecretCleanup.RequireRemovedForCompany(_root, _binding!, Guid.Empty, ownership));
        _ = Assert.Throws<MigrationExecutionException>(() => ownership.RequireBinding(Path.Combine(_root, "other"), _binding!));
        Assert.True(File.Exists(owned.Keys.Single()));
    }

    [WindowsLocalRunFact]
    public async Task Partial_pair_capture_deletes_recorded_object_but_preserves_unknown_member_and_fails()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var owned = await CreateAsync("operator.txt");
        Guid operation = Guid.NewGuid(); string unknown = Path.Combine(_root, "ordinary.txt");
        string roleKey = Path.Combine(_root, "auth-closed-review-" + operation.ToString("N") + ".private.pem");
        using (var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding!))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await files.WriteNewAsync(unknown, "untracked replacement after capture failure"u8.ToArray(), default);
            await files.WriteNewAsync(roleKey, "synthetic role key"u8.ToArray(), default);
        }
        var ownership = CompanyStorageFixtureSecretOwnership.FromCreatedFiles(_root, _binding!, _began, owned);
        var failure = Assert.Throws<AggregateException>(() => CurrentAuthClosedSecretCleanup.RequireRemovedForCompany(_root, _binding!, operation, ownership));
        var untracked = Assert.Single(failure.InnerExceptions);
        Assert.Equal("company_untracked_fixture_secret_preserved", untracked.Message);
        Assert.False(File.Exists(owned.Keys.Single())); Assert.False(File.Exists(roleKey));
        Assert.Equal("untracked replacement after capture failure", await File.ReadAllTextAsync(unknown));
    }

    [WindowsLocalRunFact]
    public async Task Zero_capture_failure_never_falls_back_to_name_based_pair_deletion()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var actual = await CreateAsync("operator.txt");
        var ownership = CompanyStorageFixtureSecretOwnership.FromCreatedFiles(_root, _binding!, _began,
            new Dictionary<string, WindowsRunFileIdentity.Identity>(StringComparer.Ordinal));
        var failure = Assert.Throws<AggregateException>(() => CurrentAuthClosedSecretCleanup.RequireRemovedForCompany(_root, _binding!, Guid.NewGuid(), ownership));
        Assert.Equal("company_untracked_fixture_secret_preserved", Assert.Single(failure.InnerExceptions).Message);
        Assert.True(File.Exists(actual.Keys.Single()));
    }

    private async Task<IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity>> CreateAsync(string name)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException(); }
        _began = DateTimeOffset.UtcNow; Assert.False(Directory.Exists(_root));
        using var authority = WindowsLocalRunAuthority.AcquireFresh(_root); _binding = authority.Binding;
        using var files = new CurrentAppOwnedRepairCustody(authority); string path = Path.Combine(_root, name);
        await files.WriteNewAsync(path, "synthetic disposable secret"u8.ToArray(), default);
        using var held = SecureLocalFile.OpenReadShared(path);
        return new Dictionary<string, WindowsRunFileIdentity.Identity>(StringComparer.Ordinal) { [path] = CompanyStorageSecretCustody.Observe(held, path) };
    }

    public void Dispose()
    {
        if (!OperatingSystem.IsWindows() || !Directory.Exists(_root) || _binding is null) { return; }
        string absolute = Path.GetFullPath(_root);
        if (Path.GetDirectoryName(absolute) != Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath())) ||
            !Path.GetFileName(absolute).StartsWith("company-secret-custody-", StringComparison.Ordinal) || new DirectoryInfo(absolute).LinkTarget is not null)
        { throw new IOException("company_secret_test_cleanup_ownership_changed"); }
        using (var opened = WindowsRunFileIdentity.OpenDirectory(absolute))
        {
            var identity = WindowsRunFileIdentity.Observe(opened);
            if (identity.Volume != _binding.LocalVolumeIdentity || identity.ObjectId != _binding.ArtifactRootFilesystemObjectIdentity) { throw new IOException("company_secret_test_cleanup_identity_changed"); }
        }
        Directory.Delete(absolute, recursive: true);
        if (Directory.Exists(absolute)) { throw new IOException("company_secret_test_cleanup_absence_failed"); }
    }
}
