using System.Diagnostics;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SystemBackupProcessRunnerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"backup-runner-{Guid.NewGuid():N}");

    [Fact]
    public async Task RunAsync_CancellationDuringStandardInputWriteKillsAndAwaitsChild()
    {
        _ = Directory.CreateDirectory(_root);
        string script = Path.Combine(_root, "hold.ps1");
        string pidFile = Path.Combine(_root, "pid.txt");
        await File.WriteAllTextAsync(script, "$PID | Set-Content -LiteralPath $args[0]; Start-Sleep -Seconds 30");
        var invocation = new SecureBackupProcessInvocation(
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-File", script, pidFile],
            new string('x', 32 * 1024 * 1024));
        using var cancellation = new CancellationTokenSource();
        Task<BackupProcessResult> running = new SystemBackupProcessRunner().RunAsync(invocation, cancellation.Token);
        await WaitForFileAsync(pidFile);
        int pid = int.Parse(await File.ReadAllTextAsync(pidFile), System.Globalization.CultureInfo.InvariantCulture);

        cancellation.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);

        AssertProcessExited(pid);
    }

    [Fact]
    public async Task RunToNewFileAsync_CancellationDuringStandardInputWriteKillsAndAwaitsChild()
    {
        _ = Directory.CreateDirectory(_root);
        string script = Path.Combine(_root, "hold-stream.ps1");
        string pidFile = Path.Combine(_root, "stream-pid.txt");
        string destination = Path.Combine(_root, "streamed.bak");
        await File.WriteAllTextAsync(script, "$PID | Set-Content -LiteralPath $args[0]; Start-Sleep -Seconds 30");
        var invocation = new SecureBackupProcessInvocation(
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-File", script, pidFile],
            new string('x', 32 * 1024 * 1024));
        using var cancellation = new CancellationTokenSource();
        Task<BackupProcessResult> running = new SystemBackupProcessRunner()
            .RunToNewFileAsync(invocation, destination, cancellation.Token);
        await WaitForFileAsync(pidFile);
        int pid = int.Parse(await File.ReadAllTextAsync(pidFile), System.Globalization.CultureInfo.InvariantCulture);

        cancellation.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);

        AssertProcessExited(pid);
    }

    private static async Task WaitForFileAsync(string path)
    {
        for (int attempt = 0; attempt < 100 && !File.Exists(path); attempt++)
        {
            await Task.Delay(25);
        }
        Assert.True(File.Exists(path), "The child process did not publish its PID.");
    }

    private static void AssertProcessExited(int pid)
    {
        try
        {
            using Process process = Process.GetProcessById(pid);
            try
            {
                Assert.True(process.HasExited, "The cancelled backup child process is still running.");
            }
            finally
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit();
                }
            }
        }
        catch (ArgumentException)
        {
            // Process no longer exists.
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}
