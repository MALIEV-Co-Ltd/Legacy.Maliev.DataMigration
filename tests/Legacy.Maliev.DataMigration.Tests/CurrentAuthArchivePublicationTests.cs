using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAuthArchivePublicationTests : IDisposable
{
    private readonly string _parent = Path.Combine(Path.GetTempPath(), $"auth-archive-publication-{Guid.NewGuid():N}");

    [WindowsLocalRunFact]
    public async Task Cancellation_after_create_keeps_exact_attempt_in_inventory_for_failure_publication()
    {
        using var local = WindowsLocalRunAuthority.AcquireFresh(Path.Combine(_parent, "local"));
        using var production = WindowsLocalRunAuthority.AcquireFresh(Path.Combine(_parent, "production"));
        using var files = new CurrentAppOwnedRepairCustody(local);
        Guid operation = Guid.NewGuid();
        using var publication = new CurrentAuthLocalSessionArchivePublication(files, local, production, operation);
        string attempted = $"{operation:D}-Auth-session-archive-prepared.json";
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            publication.WriteAndRetainAsync(attempted, [1, 2, 3], cancelled.Token));

        Assert.True(File.Exists(Path.Combine(local.Binding.ArtifactRootCanonicalPath, attempted)));
        Assert.False(publication.IsAcknowledged(attempted));
        publication.RequireInventory();
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await publication.WriteAndRetainAsync($"{operation:D}-Auth-session-archive-failed-or-uncertain.json", [4, 5, 6], cleanup.Token);
        publication.RequireInventory();
    }

    [WindowsLocalRunTheory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task Failed_publication_is_held_but_unacknowledged_and_allows_separate_failure_slot(int fault)
    {
        using var local = WindowsLocalRunAuthority.AcquireFresh(Path.Combine(_parent, "local"));
        using var production = WindowsLocalRunAuthority.AcquireFresh(Path.Combine(_parent, "production"));
        using var files = new CurrentAppOwnedRepairCustody(local);
        Guid operation = Guid.NewGuid();
        using var publication = new CurrentAuthLocalSessionArchivePublication(files, local, production, operation, (CurrentAuthArchivePublicationFault)fault);
        string attempted = $"{operation:D}-Auth-session-archive-prepared.json";
        string path = Path.Combine(local.Binding.ArtifactRootCanonicalPath, attempted);

        _ = await Assert.ThrowsAsync<IOException>(() => publication.WriteAndRetainAsync(attempted, [1, 2, 3, 4], CancellationToken.None));

        Assert.False(publication.IsAcknowledged(attempted));
        publication.RequireInventory();
        _ = Assert.Throws<IOException>(() => File.Delete(path));
        _ = Assert.Throws<IOException>(() => File.Move(path, path + ".replacement"));
        _ = Assert.Throws<IOException>(() => File.WriteAllBytes(path, [9]));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => publication.WriteAndRetainAsync(attempted, [1, 2, 3, 4], CancellationToken.None));
        string failed = $"{operation:D}-Auth-session-archive-failed-or-uncertain.json";
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await publication.WriteAndRetainAsync(failed, [5, 6], cleanup.Token);
        Assert.True(publication.IsAcknowledged(failed));
        Assert.False(publication.IsAcknowledged(attempted));
        publication.RequireInventory();
        publication.Dispose();
        File.Delete(path);
        Assert.False(File.Exists(path));
    }

    [WindowsLocalRunTheory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Foreign_operation_entry_or_slot_collision_is_never_adopted(bool productionEntry, bool directory)
    {
        using var local = WindowsLocalRunAuthority.AcquireFresh(Path.Combine(_parent, "local"));
        using var production = WindowsLocalRunAuthority.AcquireFresh(Path.Combine(_parent, "production"));
        using var files = new CurrentAppOwnedRepairCustody(local);
        Guid operation = Guid.NewGuid();
        using var publication = new CurrentAuthLocalSessionArchivePublication(files, local, production, operation);
        string name = $"{operation:D}-Auth-session-archive-prepared.json";
        string path = Path.Combine((productionEntry ? production : local).Binding.ArtifactRootCanonicalPath, name);
        if (directory) { _ = Directory.CreateDirectory(path); }
        else { File.WriteAllBytes(path, [7, 8]); }

        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => publication.WriteAndRetainAsync(name, [1, 2], CancellationToken.None));

        Assert.False(publication.IsAcknowledged(name));
        _ = Assert.Throws<MigrationExecutionException>(publication.RequireInventory);
        if (!directory) { Assert.Equal(new byte[] { 7, 8 }, File.ReadAllBytes(path)); }
    }

    [WindowsLocalRunFact]
    public async Task Acknowledged_predecessor_stays_held_after_a_later_cancelled_attempt()
    {
        using var local = WindowsLocalRunAuthority.AcquireFresh(Path.Combine(_parent, "local"));
        using var production = WindowsLocalRunAuthority.AcquireFresh(Path.Combine(_parent, "production"));
        using var files = new CurrentAppOwnedRepairCustody(local);
        Guid operation = Guid.NewGuid();
        using var publication = new CurrentAuthLocalSessionArchivePublication(files, local, production, operation);
        string previous = $"{operation:D}-Auth-session-archive-operation-start.json";
        string attempted = $"{operation:D}-Auth-session-archive-prepared.json";
        await publication.WriteAndRetainAsync(previous, [1, 2], CancellationToken.None);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => publication.WriteAndRetainAsync(attempted, [3, 4], cancelled.Token));
        Assert.True(publication.IsAcknowledged(previous));
        Assert.False(publication.IsAcknowledged(attempted));
        publication.RequireInventory();
    }

    public void Dispose()
    {
        if (Directory.Exists(_parent)) { Directory.Delete(_parent, recursive: true); }
    }
}
