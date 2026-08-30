using System.Diagnostics;
namespace Legacy.Maliev.DataMigration.Tests;

public sealed class PgDumpProcessTerminationTests
{
    [Fact]
    public async Task TerminateAndObserveAsync_KillsCapturedDescendant()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        Process? child = null;
        using Process parent = StartPowerShell(
            $"$child = Start-Process powershell -NoNewWindow -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 60' -PassThru; " +
            "[Console]::Out.WriteLine($child.Id); [Console]::Out.Flush(); Wait-Process -Id $child.Id");
        try
        {
            int childId = await ReadChildPidAsync(parent);
            child = Process.GetProcessById(childId);

            await PgDumpProcessTermination.TerminateAndObserveAsync(parent, TimeSpan.FromSeconds(10));

            Assert.True(parent.HasExited);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));
            Assert.True(child.HasExited);
        }
        finally
        {
            if (!parent.HasExited)
            {
                parent.Kill(entireProcessTree: true);
                await parent.WaitForExitAsync();
            }
            if (child is { HasExited: false })
            {
                child.Kill(entireProcessTree: true);
                await child.WaitForExitAsync();
            }
            child?.Dispose();
        }
    }

    [Fact]
    public async Task TerminateAndObserveAsync_KillFailureStillUsesBoundedObservation()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using Process process = StartPowerShell("Start-Sleep -Seconds 60");
        var stopwatch = Stopwatch.StartNew();
        try
        {
            AggregateException failure = await Assert.ThrowsAsync<AggregateException>(() =>
                PgDumpProcessTermination.TerminateAndObserveAsync(
                    process,
                    TimeSpan.FromMilliseconds(250),
                    _ => throw new InvalidOperationException("controlled kill failure")));

            stopwatch.Stop();
            Assert.Contains(failure.InnerExceptions, exception => exception.Message == "controlled kill failure");
            Assert.Contains(failure.InnerExceptions, exception => exception.Message.Contains("remained alive", StringComparison.Ordinal));
            Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(150), TimeSpan.FromSeconds(3));
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
    }

    [Fact]
    public async Task AwaitDrainAsync_HangingDrainIsBounded()
    {
        var drain = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopwatch = Stopwatch.StartNew();

        _ = await Assert.ThrowsAsync<TimeoutException>(() =>
            PgDumpProcessTermination.AwaitDrainAsync(drain.Task, TimeSpan.FromMilliseconds(100)));

        Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(50), TimeSpan.FromSeconds(2));
    }

    [Fact]
    public void ThrowPrimaryOrAggregate_PreservesPrimaryAndCleanupFailures()
    {
        var primary = new InvalidOperationException("primary");
        var cleanup = new TimeoutException("cleanup");

        AggregateException failure = Assert.Throws<AggregateException>(() =>
            PgDumpProcessTermination.ThrowPrimaryOrAggregate(primary, cleanup));

        Assert.Collection(
            failure.InnerExceptions,
            exception => Assert.Same(primary, exception),
            exception => Assert.Same(cleanup, exception));
    }

    private static Process StartPowerShell(string command)
    {
        return Process.Start(new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            ArgumentList = { "-NoProfile", "-NonInteractive", "-Command", command },
        }) ?? throw new InvalidOperationException("Test process could not start.");
    }

    private static async Task<int> ReadChildPidAsync(Process parent)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        string? line = await parent.StandardOutput.ReadLineAsync(deadline.Token);
        return line is null || !int.TryParse(line.Trim(), out int pid)
            ? throw new InvalidOperationException($"The process fixture did not report a child PID. Output: '{line ?? "<eof>"}'.")
            : pid;
    }
}
