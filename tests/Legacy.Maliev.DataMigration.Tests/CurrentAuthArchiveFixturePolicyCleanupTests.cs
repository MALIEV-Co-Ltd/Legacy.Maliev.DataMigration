using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAuthArchiveFixturePolicyCleanupTests
{
    [WindowsLocalRunFact]
    public void Same_handle_policy_cleanup_removes_only_the_two_exact_expected_secret_files()
    {
        Run((root, binding) =>
        {
            var first = Write(root, "archive-policy-operator.txt", [1, 2, 3]);
            var second = Write(root, "archive-policy-ordinary.txt", [4, 5, 6]);
            string retained = Path.Combine(root, "retained-evidence.json"); File.WriteAllBytes(retained, [7, 8, 9]);
            CurrentAuthArchiveFixturePolicy.CleanupSecrets(root, binding, [first, second]);
            Assert.False(File.Exists(first.Artifact.Path)); Assert.False(File.Exists(second.Artifact.Path));
            Assert.Equal(new byte[] { 7, 8, 9 }, File.ReadAllBytes(retained));
            CurrentAuthArchiveFixturePolicy.CleanupSecrets(root, binding, [first, second]);
        });
    }

    [WindowsLocalRunTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void Changed_or_replaced_secret_is_rejected_and_never_deleted(bool replacement)
    {
        Run((root, binding) =>
        {
            var expected = Write(root, "archive-policy-operator.txt", [1, 2, 3]);
            if (replacement) { File.Move(expected.Artifact.Path, Path.Combine(root, "retained-original.txt")); }
            File.WriteAllBytes(expected.Artifact.Path, [9, 8, 7]);
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFixturePolicy.CleanupSecrets(root, binding, [expected]));
            Assert.Equal(new byte[] { 9, 8, 7 }, File.ReadAllBytes(expected.Artifact.Path));
            if (replacement) { Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(Path.Combine(root, "retained-original.txt"))); }
        });
    }

    [WindowsLocalRunFact]
    public void Other_filenames_cannot_be_admitted_as_policy_credentials()
    {
        Run((root, binding) =>
        {
            var retained = Write(root, "retained-recovery-key.bin", [1, 2, 3]);
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFixturePolicy.CleanupSecrets(root, binding, [retained]));
            Assert.True(File.Exists(retained.Artifact.Path));
        });
    }

    [WindowsLocalRunTheory]
    [InlineData("cancel-after-create")]
    [InlineData("partial-write")]
    public void Interrupted_owned_creation_removes_its_partial_file_through_the_retained_handle(string stage)
    {
        Run((root, binding) =>
        {
            string path = Path.Combine(root, "archive-policy-operator.txt");
            var fault = stage == "cancel-after-create" ? CurrentAuthArchiveFixtureSecretFault.CancelAfterCreate : CurrentAuthArchiveFixtureSecretFault.PartialWrite;
            Task Create()
            {
                return CurrentAuthArchiveFixturePolicy.CreateSecretAsync(root, binding, "archive-policy-operator.txt", [1, 2, 3, 4], CancellationToken.None, fault);
            }

            if (fault == CurrentAuthArchiveFixtureSecretFault.CancelAfterCreate)
            { _ = Assert.ThrowsAnyAsync<OperationCanceledException>(Create).GetAwaiter().GetResult(); }
            else { _ = Assert.ThrowsAsync<IOException>(Create).GetAwaiter().GetResult(); }
            Assert.False(File.Exists(path));
        });
    }

    [WindowsLocalRunFact]
    public void Create_new_collision_never_registers_or_deletes_the_existing_file()
    {
        Run((root, binding) =>
        {
            string path = Path.Combine(root, "archive-policy-operator.txt"); File.WriteAllBytes(path, [9, 8, 7]);
            _ = Assert.ThrowsAsync<IOException>(() => CurrentAuthArchiveFixturePolicy.CreateSecretAsync(root, binding,
                "archive-policy-operator.txt", [1, 2, 3], CancellationToken.None)).GetAwaiter().GetResult();
            Assert.Equal(new byte[] { 9, 8, 7 }, File.ReadAllBytes(path));
        });
    }

    [WindowsLocalRunFact]
    public void Identical_content_replacement_is_rejected_by_original_creation_identity()
    {
        Run((root, binding) =>
        {
            var owned = CurrentAuthArchiveFixturePolicy.CreateSecretAsync(root, binding,
                "archive-policy-operator.txt", [1, 2, 3], CancellationToken.None).GetAwaiter().GetResult();
            string original = Path.Combine(root, "retained-original.txt"); File.Move(owned.Artifact.Path, original);
            File.WriteAllBytes(owned.Artifact.Path, [1, 2, 3]);
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveFixturePolicy.CleanupSecrets(root, binding, [owned]));
            Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(owned.Artifact.Path));
            Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(original));
        });
    }

    private static CurrentAuthArchiveFixtureOwnedCredential Write(string root, string name, byte[] bytes)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException(); }
        string path = Path.Combine(root, name);
        using var held = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        held.Write(bytes); held.Flush(true);
        return new(new(path, Convert.ToHexStringLower(SHA256.HashData(bytes))), WindowsRunFileIdentity.Observe(held.SafeFileHandle));
    }

    private static void Run(Action<string, LocalExecutionBinding> action)
    {
        string parent = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "archive-policy-cleanup-" + Guid.NewGuid().ToString("N")));
        string root = Path.Combine(parent, "artifacts");
        bool cleanupVerified = false;
        try
        {
            LocalExecutionBinding binding;
            using (var authority = WindowsLocalRunAuthority.AcquireFresh(root)) { binding = authority.Binding; }
            action(root, binding);
        }
        finally
        {
            if (parent.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase))
            {
                if (Directory.Exists(parent)) { Directory.Delete(parent, recursive: true); }
                cleanupVerified = !Directory.Exists(parent);
            }
        }
        Assert.True(cleanupVerified);
    }
}

