using System.Diagnostics;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class LocalPgRestoreProcessTests
{
    [Theory]
    [InlineData(SslMode.Disable, "disable")]
    [InlineData(SslMode.Allow, "allow")]
    [InlineData(SslMode.Prefer, "prefer")]
    [InlineData(SslMode.Require, "require")]
    [InlineData(SslMode.VerifyCA, "verify-ca")]
    [InlineData(SslMode.VerifyFull, "verify-full")]
    public void BuildStartInfo_SslMode_UsesLibpqWireValue(SslMode mode, string expected)
    {
        var target = new NpgsqlConnectionStringBuilder
        {
            Host = "127.0.0.1",
            Port = 5432,
            Username = "local_restore",
            Database = "local_archive_verify_test",
            SslMode = mode
        };
        ProcessStartInfo start = LocalPostgreSqlArchiveVerifier.BuildStartInfo("pg_restore", target);
        Assert.Equal(expected, start.Environment["PGSSLMODE"]);
    }

    [Fact]
    public async Task Restore_NonzeroExit_DrainsWithoutDisclosingOutput()
    {
        using var input = new MemoryStream(new byte[1024]);
        MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            LocalPgRestoreProcess.RestoreAsync(Start("[Console]::OpenStandardInput().CopyTo([System.IO.Stream]::Null); [Console]::Error.Write('secret-row-value'); exit 19"), input, default));
        Assert.Equal("local_archive_restore_failed", error.Code);
        Assert.DoesNotContain("secret-row-value", error.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(19)]
    public async Task Restore_EarlyExit_CancelsAndObservesPendingInput(int exitCode)
    {
        using var input = new WaitingInput();
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            LocalPgRestoreProcess.RestoreAsync(Start($"exit {exitCode}"), input, default)).WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(input.Cancelled);
    }

    [Fact]
    public async Task Restore_Cancellation_ObservesChildExitAndInputBeforeReturning()
    {
        string root = Path.Combine(Path.GetTempPath(), "local-restore-process-" + Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(root);
        string pidPath = Path.Combine(root, "pid");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var input = new WaitingInput();
        // Keep the writer open long enough to exercise publication readiness. Only
        // the same-directory move after close may make File.Exists mean readable.
        ProcessStartInfo start = Start("""
            $pending = $env:MALIEV_RESTORE_PID_PATH + '.pending';
            $file = [System.IO.File]::Open($pending, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None);
            try {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$PID);
                $file.Write($bytes, 0, $bytes.Length);
                $file.Flush();
                Start-Sleep -Milliseconds 250;
            } finally { $file.Dispose(); }
            [System.IO.File]::Move($pending, $env:MALIEV_RESTORE_PID_PATH);
            Start-Sleep -Seconds 30;
            """);
        start.Environment["MALIEV_RESTORE_PID_PATH"] = pidPath;
        Task running = LocalPgRestoreProcess.RestoreAsync(start, input, cancellation.Token);
        try
        {
            while (!File.Exists(pidPath) && !running.IsCompleted) { await Task.Delay(20, cancellation.Token); }
            if (running.IsCompleted) { await running; }
            int pid = int.Parse(await File.ReadAllTextAsync(pidPath, cancellation.Token), System.Globalization.CultureInfo.InvariantCulture);
            await cancellation.CancelAsync();
            _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
            Assert.False(IsRunning(pid));
            Assert.True(input.Cancelled);
        }
        finally
        {
            await cancellation.CancelAsync();
            try { await running; } catch (Exception) { }
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Restore_Success_ConsumesAllInputAndWaitsForExit()
    {
        using var input = new MemoryStream(new byte[1024 * 1024]);
        await LocalPgRestoreProcess.RestoreAsync(Start("[Console]::OpenStandardInput().CopyTo([System.IO.Stream]::Null); exit 0"), input, default);
        Assert.Equal(input.Length, input.Position);
    }

    private static ProcessStartInfo Start(string script)
    {
        var start = new ProcessStartInfo("pwsh") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script }) { start.ArgumentList.Add(arg); }
        return start;
    }

    private static bool IsRunning(int pid)
    {
        try { using Process process = Process.GetProcessById(pid); return !process.HasExited; }
        catch (ArgumentException) { return false; }
    }

    private sealed class WaitingInput : Stream
    {
        public bool Cancelled { get; private set; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0; }
            catch (OperationCanceledException) { Cancelled = true; throw; }
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}
