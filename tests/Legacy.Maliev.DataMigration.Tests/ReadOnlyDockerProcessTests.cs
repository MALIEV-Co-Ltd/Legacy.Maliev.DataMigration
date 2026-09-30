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
        string readyPath = pidPath + ".writer-ready";
        string releasePath = pidPath + ".release";
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        // Hold the writer until the parent has checked publication readiness.
        // A final PID must never become visible while its exclusive writer is open.
        var start = CreateStart("""
            $ErrorActionPreference = 'Stop';
            $pending = $env:MALIEV_OBSERVER_PID_PATH + '.pending';
            $file = [System.IO.File]::Open($pending, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None);
            try {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$PID);
                $file.Write($bytes, 0, $bytes.Length);
                $file.Flush();
                [System.IO.File]::WriteAllText($env:MALIEV_OBSERVER_PID_PATH + '.writer-ready', 'ready');
                while (-not [System.IO.File]::Exists($env:MALIEV_OBSERVER_PID_PATH + '.release')) { Start-Sleep -Milliseconds 20; }
            } finally { $file.Dispose(); }
            [System.IO.File]::Move($pending, $env:MALIEV_OBSERVER_PID_PATH);
            Start-Sleep -Seconds 30;
            """);
        start.Environment["MALIEV_OBSERVER_PID_PATH"] = pidPath;
        Task<BackupProcessResult> running = ReadOnlyDockerProcess.ExecuteAsync(start, cancellation.Token);
        try
        {
            while (!File.Exists(readyPath) && !running.IsCompleted)
            {
                await Task.Delay(20, cancellation.Token);
            }
            Assert.True(File.Exists(readyPath), "The child must hold its PID writer before publication is assessed.");
            Assert.False(File.Exists(pidPath), "An open PID writer must not publish the final readiness path.");
            await File.WriteAllTextAsync(releasePath, "release", cancellation.Token);
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
