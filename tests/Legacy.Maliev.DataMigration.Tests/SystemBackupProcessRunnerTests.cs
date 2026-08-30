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
        int pid = await ReadPidWhenReadyAsync(pidFile);

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
        int pid = await ReadPidWhenReadyAsync(pidFile);

        cancellation.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);

        AssertProcessExited(pid);
    }

    [Fact]
    public async Task RunToNewFileAsync_DestinationOpenFailureKillsAndAwaitsStartedChild()
    {
        (SecureBackupProcessInvocation invocation, _) = await CreateHoldingInvocationAsync("destination-open");
        string destination = Path.Combine(_root, "already-exists.bak");
        var io = new FaultingBackupProcessIo(ProcessIoFailure.DestinationOpen);
        Task<BackupProcessResult> running = new SystemBackupProcessRunner(io)
            .RunToNewFileAsync(invocation, destination, CancellationToken.None);

        _ = await Assert.ThrowsAsync<IOException>(() => running);

        AssertProcessExited(io.ProcessId);
    }

    [Theory]
    [InlineData(ProcessIoFailure.StdoutCopy)]
    [InlineData(ProcessIoFailure.DestinationFlush)]
    [InlineData(ProcessIoFailure.StderrRead)]
    public async Task RunToNewFileAsync_PostStartIoFailureKillsAndAwaitsChild(ProcessIoFailure failure)
    {
        (SecureBackupProcessInvocation invocation, _) = await CreateHoldingInvocationAsync(
            failure.ToString(), failure == ProcessIoFailure.DestinationFlush ? 1 : 30);
        var io = new FaultingBackupProcessIo(failure);
        var runner = new SystemBackupProcessRunner(io);
        Task<BackupProcessResult> running = runner.RunToNewFileAsync(
            invocation, Path.Combine(_root, $"{failure}.bak"), CancellationToken.None);
        _ = await Assert.ThrowsAsync<IOException>(() => running);

        AssertProcessExited(io.ProcessId);
    }

    [Fact]
    public async Task RunAsync_StderrReadFailureKillsAndAwaitsChild()
    {
        (SecureBackupProcessInvocation invocation, _) = await CreateHoldingInvocationAsync("stderr-run");
        var io = new FaultingBackupProcessIo(ProcessIoFailure.StderrRead);
        var runner = new SystemBackupProcessRunner(io);
        Task<BackupProcessResult> running = runner.RunAsync(invocation, CancellationToken.None);

        _ = await Assert.ThrowsAsync<IOException>(() => running);

        AssertProcessExited(io.ProcessId);
    }

    [Fact]
    public async Task RunAsync_StandardInputWriteFailureKillsAndAwaitsChild()
    {
        (SecureBackupProcessInvocation invocation, _) = await CreateHoldingInvocationAsync("stdin-run");
        invocation = new SecureBackupProcessInvocation(
            invocation.FileName, invocation.Arguments, "secret input");
        var io = new FaultingBackupProcessIo(ProcessIoFailure.StdinWrite);
        var runner = new SystemBackupProcessRunner(io);
        Task<BackupProcessResult> running = runner.RunAsync(invocation, CancellationToken.None);

        _ = await Assert.ThrowsAsync<IOException>(() => running);

        AssertProcessExited(io.ProcessId);
    }

    [Theory]
    [InlineData(ProcessIoFailure.Kill)]
    [InlineData(ProcessIoFailure.WaitDuringCleanup)]
    public async Task RunAsync_CleanupPlatformFailureStillObservesChildAndPreservesOriginalFailure(ProcessIoFailure cleanupFailure)
    {
        (SecureBackupProcessInvocation invocation, _) = await CreateHoldingInvocationAsync($"cleanup-{cleanupFailure}");
        var io = new FaultingBackupProcessIo(cleanupFailure, failStandardError: true);

        IOException failure = await Assert.ThrowsAsync<IOException>(
            () => new SystemBackupProcessRunner(io).RunAsync(invocation, CancellationToken.None));

        Assert.Equal("forced stderr read failure", failure.Message);
        Assert.True(io.KillCalls >= (cleanupFailure == ProcessIoFailure.Kill ? 2 : 1));
        Assert.True(io.WaitCalls > 0);
        AssertProcessExited(io.ProcessId);
    }

    private async Task<(SecureBackupProcessInvocation Invocation, string PidFile)> CreateHoldingInvocationAsync(string name, int seconds = 30)
    {
        _ = Directory.CreateDirectory(_root);
        string script = Path.Combine(_root, $"hold-{name}.ps1");
        string pidFile = Path.Combine(_root, $"pid-{name}.txt");
        await File.WriteAllTextAsync(script, $"$PID | Set-Content -LiteralPath $args[0]; Start-Sleep -Seconds {seconds}");
        return (new SecureBackupProcessInvocation(
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-File", script, pidFile],
            string.Empty), pidFile);
    }

    private static async Task WaitForFileAsync(string path)
    {
        for (int attempt = 0; attempt < 100 && !File.Exists(path); attempt++)
        {
            await Task.Delay(25);
        }
        Assert.True(File.Exists(path), "The child process did not publish its PID.");
    }

    private static async Task<int> ReadPidWhenReadyAsync(string path)
    {
        for (int attempt = 0; attempt < 100; attempt++)
        {
            try
            {
                string value = await File.ReadAllTextAsync(path);
                if (int.TryParse(value, System.Globalization.CultureInfo.InvariantCulture, out int pid))
                {
                    return pid;
                }
            }
            catch (IOException) when (attempt < 99)
            {
                // PowerShell's Set-Content may have created the file but still hold its
                // exclusive write handle. Retry until publication is complete.
            }

            await Task.Delay(25);
        }

        throw new InvalidOperationException("The child process PID file was never readable.");
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
        for (int attempt = 0; attempt < 20 && Directory.Exists(_root); attempt++)
        {
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (IOException) when (attempt < 19)
            {
                Thread.Sleep(25);
            }
        }
    }

    public enum ProcessIoFailure
    {
        DestinationOpen,
        StdinWrite,
        StdoutCopy,
        DestinationFlush,
        StderrRead,
        Kill,
        WaitDuringCleanup,
    }

    private sealed class FaultingBackupProcessIo(ProcessIoFailure failure, bool failStandardError = false) : IBackupProcessIo
    {
        private int _waitCalls;

        public int ProcessId { get; private set; }
        public int KillCalls { get; private set; }
        public int WaitCalls => _waitCalls;

        public Stream CreateDestination(string path)
        {
            return failure == ProcessIoFailure.DestinationOpen
                ? throw new IOException("forced destination open failure")
                : new MemoryStream();
        }

        public Task<string> ReadStandardOutputAsync(Process process, CancellationToken cancellationToken)
        {
            return process.StandardOutput.ReadToEndAsync(cancellationToken);
        }

        public Task<string> ReadStandardErrorAsync(Process process, CancellationToken cancellationToken)
        {
            ProcessId = process.Id;
            return failure == ProcessIoFailure.StderrRead || failStandardError
                ? Task.FromException<string>(new IOException("forced stderr read failure"))
                : process.StandardError.ReadToEndAsync(cancellationToken);
        }

        public Task WriteStandardInputAsync(Process process, string input, CancellationToken cancellationToken)
        {
            return failure == ProcessIoFailure.StdinWrite
                ? Task.FromException(new IOException("forced stdin write failure"))
                : process.StandardInput.WriteAsync(input.AsMemory(), cancellationToken);
        }

        public Task CopyStandardOutputAsync(Process process, Stream destination, CancellationToken cancellationToken)
        {
            return failure == ProcessIoFailure.StdoutCopy
                ? Task.FromException(new IOException("forced stdout copy failure"))
                : process.StandardOutput.BaseStream.CopyToAsync(destination, cancellationToken);
        }

        public Task FlushDestinationAsync(Stream destination, CancellationToken cancellationToken)
        {
            return failure == ProcessIoFailure.DestinationFlush
                ? Task.FromException(new IOException("forced destination flush failure"))
                : destination.FlushAsync(cancellationToken);
        }

        public void Kill(Process process)
        {
            KillCalls++;
            if (failure == ProcessIoFailure.Kill)
            {
                throw new System.ComponentModel.Win32Exception("forced kill failure without termination");
            }

            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }

        public async Task WaitForExitAsync(Process process, CancellationToken cancellationToken)
        {
            int call = Interlocked.Increment(ref _waitCalls);
            await process.WaitForExitAsync(cancellationToken);
            if (failure == ProcessIoFailure.WaitDuringCleanup && call > 1)
            {
                throw new InvalidOperationException("forced cleanup wait failure");
            }
        }
    }
}
