using System.Diagnostics;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAppOwnedRepairDockerProcessTests
{
    [Fact]
    public async Task Successful_child_is_exited_and_both_readers_settled_without_publishing_error_output()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var evidence = new List<CurrentAppOwnedDockerResource>();
        string result = await RunAsync("[Console]::Out.Write('observed'); [Console]::Error.Write('not-published')", evidence);
        Assert.Equal("observed", result);
        RequireReleased(evidence);
        Assert.Equal(evidence[0].ProcessId, evidence[^1].ProcessId);
        Assert.Equal(evidence[0].StartUtcTicks, evidence[^1].StartUtcTicks);
        Assert.Equal(64, evidence[^1].ExecutableSha256.Length);
    }

    [Fact]
    public async Task Nonzero_exit_is_sanitized_and_child_and_readers_are_released()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var evidence = new List<CurrentAppOwnedDockerResource>();
        MigrationConsoleException failure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            RunAsync("[Console]::Out.Write('secret-output'); [Console]::Error.Write('secret-error'); exit 19", evidence));
        Assert.Equal("current_app_owned_docker_child_failed", failure.Code);
        Assert.DoesNotContain("secret", failure.Message, StringComparison.Ordinal);
        RequireReleased(evidence);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Overflow_on_either_stream_stops_exact_child_and_settles_both_readers(bool errorStream)
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var evidence = new List<CurrentAppOwnedDockerResource>();
        string stream = errorStream ? "Error" : "Out";
        MigrationConsoleException failure = await Assert.ThrowsAsync<MigrationConsoleException>(() => RunAsync(
            "[Console]::" + stream + ".Write(('x' * 10000)); Start-Sleep -Seconds 30", evidence, maximum: 128));
        Assert.Equal("current_app_owned_docker_output_failed", failure.Code);
        RequireReleased(evidence);
    }

    [Fact]
    public async Task Caller_cancellation_after_owned_start_terminates_exact_child_before_return()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var evidence = new List<CurrentAppOwnedDockerResource>();
        var stopwatch = Stopwatch.StartNew();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => RunAsync("Start-Sleep -Seconds 30", evidence,
            ct: cancellation.Token, started: _ => cancellation.Cancel()));
        RequireReleased(evidence);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(12));
    }

    [Fact]
    public async Task Timeout_terminates_exact_child_and_does_not_abandon_readers()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var evidence = new List<CurrentAppOwnedDockerResource>();
        MigrationConsoleException failure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            RunAsync("Start-Sleep -Seconds 30", evidence, lifetime: TimeSpan.FromMilliseconds(100)));
        Assert.Equal("current_app_owned_docker_timeout_failed", failure.Code);
        RequireReleased(evidence);
    }

    [Fact]
    public async Task Precancelled_call_starts_no_child_and_bounds_cannot_be_relaxed()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var evidence = new List<CurrentAppOwnedDockerResource>();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => RunAsync("exit 0", evidence, ct: cancellation.Token));
        Assert.Empty(evidence);
        _ = await Assert.ThrowsAsync<MigrationConsoleException>(() => RunAsync("exit 0", evidence, maximum: 2_000_001));
        _ = await Assert.ThrowsAsync<MigrationConsoleException>(() => RunAsync("exit 0", evidence, lifetime: TimeSpan.FromSeconds(21)));
        Assert.Empty(evidence);
    }

    [Fact]
    public async Task Caller_environment_secrets_are_not_inherited_by_child()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var evidence = new List<CurrentAppOwnedDockerResource>();
        string result = await RunAsync("[Console]::Out.Write([string]::IsNullOrEmpty($env:PATH))", evidence);
        Assert.Equal("True", result);
        RequireReleased(evidence);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Awaited_start_or_final_ledger_failure_cannot_skip_cleanup_or_return_success(bool failStart)
    {
        if (!OperatingSystem.IsWindows()) { return; }
        var evidence = new List<CurrentAppOwnedDockerResource>();
        string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        _ = await Assert.ThrowsAsync<IOException>(() => CurrentAppOwnedRepairDockerProcess.RunChildWithAsyncObserverForTestAsync(
            executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "[Console]::Out.Write('observed')"],
            TimeSpan.FromSeconds(15), 4096, async resource =>
            {
                await Task.Yield();
                evidence.Add(resource);
                if (evidence.Count == 1 == failStart) { throw new IOException("controlled ledger failure"); }
            }, CancellationToken.None));
        RequireReleased(evidence);
    }

    private static Task<string> RunAsync(string script, List<CurrentAppOwnedDockerResource> evidence,
        int maximum = 4096, TimeSpan? lifetime = null,
        Action<CurrentAppOwnedDockerResource>? started = null, CancellationToken ct = default)
    {
        string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        return CurrentAppOwnedRepairDockerProcess.RunChildForTestAsync(executable,
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            lifetime ?? TimeSpan.FromSeconds(15), maximum, resource =>
            {
                evidence.Add(resource);
                if (evidence.Count == 1) { started?.Invoke(resource); }
            }, ct);
    }

    private static void RequireReleased(List<CurrentAppOwnedDockerResource> evidence)
    {
        Assert.Equal(2, evidence.Count);
        CurrentAppOwnedDockerResource final = evidence[^1];
        Assert.True(final.Exited);
        Assert.True(final.ReadersSettled);
        Assert.False(final.CleanupFailed);
        _ = Assert.NotNull(final.ProcessId);
        _ = Assert.NotNull(final.StartUtcTicks);
        int pid = final.ProcessId ?? throw new InvalidOperationException("Missing owned process identity");
        long ticks = final.StartUtcTicks ?? throw new InvalidOperationException("Missing owned start identity");
        try
        {
            using Process actual = Process.GetProcessById(pid);
            Assert.True(actual.HasExited || actual.StartTime.ToUniversalTime().Ticks != ticks);
        }
        catch (ArgumentException) { }
    }
}
