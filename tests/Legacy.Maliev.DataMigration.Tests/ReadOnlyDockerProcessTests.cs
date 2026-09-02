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
            while (!File.Exists(pidPath) && !running.IsCompleted) { await Task.Delay(20, cancellation.Token); }
            int pid = int.Parse(await File.ReadAllTextAsync(pidPath, cancellation.Token), CultureInfo.InvariantCulture);
            await cancellation.CancelAsync();
            _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
            Assert.False(IsRunning(pid));
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
