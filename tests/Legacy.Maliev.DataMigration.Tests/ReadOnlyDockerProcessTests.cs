using System.Diagnostics;
using System.Globalization;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ReadOnlyDockerProcessTests
{
    [Fact]
    public async Task Execute_Cancellation_ObservesChildExitBeforeReturningPrimaryCancellation()
    {
        string root = Path.Combine(Path.GetTempPath(), "source-observer-process-" + Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(root);
        string pidPath = Path.Combine(root, "pid");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var start = CreateStart("[System.IO.File]::WriteAllText($env:MALIEV_OBSERVER_PID_PATH, [string]$PID); Start-Sleep -Seconds 30");
        start.Environment["MALIEV_OBSERVER_PID_PATH"] = pidPath;
        Task<BackupProcessResult> running = ReadOnlyDockerProcess.ExecuteAsync(start, cancellation.Token);
        try
        {
            int? pid = null;
            while (pid is null && !running.IsCompleted)
            {
                if (File.Exists(pidPath) &&
                    int.TryParse(await File.ReadAllTextAsync(pidPath, cancellation.Token),
                        NumberStyles.None, CultureInfo.InvariantCulture, out int observedPid) && observedPid > 0)
                {
                    pid = observedPid;
                }
                else
                {
                    await Task.Delay(20, cancellation.Token);
                }
            }

            Assert.True(pid.HasValue, "The child process must publish a complete PID before it exits.");
            await cancellation.CancelAsync();
            _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
            Assert.False(IsRunning(pid.Value));
        }
        finally
        {
            await cancellation.CancelAsync();
            try { _ = await running; } catch (OperationCanceledException) { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Execute_NonzeroExit_ObservesBothStreamsAndExitCode()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        BackupProcessResult result = await ReadOnlyDockerProcess.ExecuteAsync(CreateStart("[Console]::Out.Write('output'); [Console]::Error.Write('error'); exit 19"), timeout.Token);
        Assert.Equal(19, result.ExitCode);
        Assert.Equal("output", result.StandardOutput);
        Assert.Equal("error", result.StandardError);
    }

    private static ProcessStartInfo CreateStart(string script)
    {
        var start = new ProcessStartInfo("pwsh") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script }) { start.ArgumentList.Add(argument); }
        return start;
    }
    private static bool IsRunning(int pid)
    {
        try { using Process process = Process.GetProcessById(pid); return !process.HasExited; }
        catch (ArgumentException) { return false; }
    }
}
