using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthLocalSessionArchiveDeviceProcessTests
{
    private static readonly string[] ExpectedEnvironmentKeys = ["SystemRoot", "WINDIR"];
    [Fact]
    public void Device_dispatch_accepts_only_exact_fixed_three_argument_invocation()
    {
        string path = Path.Combine(Path.GetTempPath(), "synthetic-device-request.json"), hash = new('a', 64);
        Assert.Equal((Path.GetFullPath(path), hash), MigrationConsole.RequireArchiveDeviceInvocation([CurrentAuthLocalSessionArchiveDeviceProcess.Command, path, hash]));
        _ = Assert.Throws<CommandLineException>(() => MigrationConsole.RequireArchiveDeviceInvocation([CurrentAuthLocalSessionArchiveDeviceProcess.Command, "--config", path, hash]));
        _ = Assert.Throws<CommandLineException>(() => MigrationConsole.RequireArchiveDeviceInvocation([CurrentAuthLocalSessionArchiveDeviceProcess.Command, path, hash, "extra"]));
        _ = Assert.Throws<CommandLineException>(() => MigrationConsole.RequireArchiveDeviceInvocation(["arbitrary-helper", path, hash]));
        _ = Assert.Throws<CommandLineException>(() => MigrationConsole.RequireArchiveDeviceInvocation([CurrentAuthLocalSessionArchiveDeviceProcess.Command, path, "caller-summary"]));
    }
    [Theory]
    [InlineData("review-current-auth-local-session-archive")]
    [InlineData("authorize-current-auth-local-session-archive")]
    [InlineData("verify-current-auth-local-session-archive")]
    [InlineData("apply-current-auth-local-session-archive")]
    public void Archive_routes_use_existing_protected_config_invocation(string command)
    {
        string path = Path.Combine(Path.GetTempPath(), "synthetic-archive-config.json");
        Assert.Equal(new ConsoleInvocation(command, path), ConsoleInvocation.Parse([command, "--config", path]));
    }
    [Fact]
    public void Production_start_has_only_fixed_bundle_route_structured_path_digest_and_clean_environment()
    {
        string path = Path.Combine(Path.GetTempPath(), "synthetic-device-request.json");
        var start = CurrentAuthLocalSessionArchiveDeviceProcess.StartInfo(path, new string('a', 64));
        Assert.Equal(Path.Combine(AppContext.BaseDirectory, "Legacy.Maliev.DataMigration.Console.exe"), start.FileName);
        Assert.Equal(new[] { "observe-current-auth-archive-recovery-devices", Path.GetFullPath(path), new string('a', 64) }, start.ArgumentList);
        Assert.False(start.UseShellExecute); Assert.True(start.CreateNoWindow);
        Assert.True(start.RedirectStandardInput); Assert.True(start.RedirectStandardOutput); Assert.True(start.RedirectStandardError);
        Assert.Equal(ExpectedEnvironmentKeys, start.Environment.Keys.Order(StringComparer.Ordinal));
        Assert.DoesNotContain("PATH", start.Environment.Keys); Assert.DoesNotContain("USERPROFILE", start.Environment.Keys);
    }
    [Theory]
    [InlineData("relative.json", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("C:\\synthetic\\request.json", "caller-summary")]
    public void Invalid_config_path_or_digest_cannot_become_process_arguments(string path, string hash)
    { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveDeviceProcess.StartInfo(path, hash)); }

    [Fact]
    public void Serialized_request_has_no_environment_process_or_native_observer_callback()
    {
        byte[] bytes = /*lang=json,strict*/ "{\"Scope\":null,\"FirstRoot\":\"C:\\\\synthetic\",\"SecondRoot\":\"D:\\\\synthetic\",\"Executable\":\"untrusted.exe\"}"u8.ToArray();
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveDeviceRequest>(bytes));
    }
    [Fact]
    public async Task Output_limit_and_cancellation_fail_without_native_calls_or_task_workers()
    {
        using var large = new MemoryStream(Encoding.UTF8.GetBytes(new string('a', 65537)));
        using var reader = new StreamReader(large, new UTF8Encoding(false, true));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveDeviceProcess.ReadOutputForTestAsync(reader, CancellationToken.None));
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        using var small = new MemoryStream("{}"u8.ToArray()); using var cancelledReader = new StreamReader(small);
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAuthLocalSessionArchiveDeviceProcess.ReadOutputForTestAsync(cancelledReader, cancel.Token));
    }
    [Fact]
    public async Task Precancelled_observation_starts_no_child_or_file_operation()
    {
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAuthLocalSessionArchiveDeviceProcess.ObserveAsync(null!, "unused", "unused", null!, null!, cancel.Token));
    }
}
