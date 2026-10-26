using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveFixtureFrameTests
{
    [WindowsLocalRunTheory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Publication_timeout_settles_the_exact_started_child_and_the_blocked_observer(bool first)
    {
        var frames = new List<CurrentAppOwnedDockerResource>();
        bool publicationSettled = false;
        string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        _ = await Assert.ThrowsAsync<TimeoutException>(() => CurrentAppOwnedRepairDockerProcess.RunChildWithAsyncObserverForTestAsync(
            executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "[Console]::Out.Write('observed'); Start-Sleep -Milliseconds 500"],
            TimeSpan.FromSeconds(15), 4096, async resource =>
            {
                frames.Add(resource);
                if (frames.Count == 1 == first)
                {
                    await CurrentAuthArchiveFixtureFrame.RunAsync(async ct =>
                    {
                        try { await Task.Delay(Timeout.InfiniteTimeSpan, ct); }
                        finally { publicationSettled = true; }
                    }, TimeSpan.FromMilliseconds(100), CancellationToken.None);
                }
            }, CancellationToken.None));
        Assert.True(publicationSettled);
        Assert.Equal(2, frames.Count);
        Assert.Equal(frames[0].ProcessId, frames[1].ProcessId);
        Assert.Equal(frames[0].StartUtcTicks, frames[1].StartUtcTicks);
        Assert.True(frames[1].Exited);
        Assert.True(frames[1].ReadersSettled);
        Assert.False(frames[1].CleanupFailed);
    }
}
