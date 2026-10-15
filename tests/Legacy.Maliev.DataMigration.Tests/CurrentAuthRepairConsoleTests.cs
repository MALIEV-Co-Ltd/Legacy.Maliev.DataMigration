using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CurrentAuthConsoleSourceTestGroup
{ public const string Name = "Current Auth closed source and exact child custody"; }

[Collection(CurrentAuthConsoleSourceTestGroup.Name)]
public sealed class CurrentAuthRepairConsoleTests
{
    [Theory]
    [InlineData(/*lang=json,strict*/ "{\"sourceSchemaPath\":\"one\",\"SourceSchemaPath\":\"two\"}")]
    [InlineData(/*lang=json,strict*/ "{\"trustedKeys\":[{\"keyId\":\"one\",\"KeyId\":\"two\"}]}")]
    public void Duplicate_properties_are_rejected_before_any_authority(string json)
    { _ = Assert.Throws<MigrationExecutionException>(() => MigrationConsole.DecodeAuthRepair<CurrentAuthRepairConfiguration>(Encoding.UTF8.GetBytes(json))); }
    [Fact]
    public void Serialized_environment_callback_or_unknown_scope_is_not_configuration()
    {
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeAuthRepair<CurrentAuthRepairConfiguration>(/*lang=json,strict*/ "{\"callback\":\"bypass\"}"u8.ToArray()));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthRepairEnvironment.Suffix((CurrentAppOwnedCommitClassification)999));
        Assert.Equal("failed-or-uncertain", CurrentAuthRepairEnvironment.Suffix(CurrentAppOwnedCommitClassification.Uncertain));
    }
    [Theory]
    [InlineData((int)CurrentAuthGitCommand.Head)]
    [InlineData((int)CurrentAuthGitCommand.Status)]
    public void Owner_reader_has_only_fixed_readonly_commands_and_no_inherited_secret_environment(int commandValue)
    {
        CurrentAuthGitCommand command = (CurrentAuthGitCommand)commandValue;
        ProcessStartInfo start = CurrentAuthOwnerSourceReader.StartInfo(command);
        Assert.False(start.UseShellExecute); Assert.True(start.CreateNoWindow);
        Assert.True(start.RedirectStandardInput); Assert.True(start.RedirectStandardOutput); Assert.True(start.RedirectStandardError);
        Assert.EndsWith(Path.Combine("Git", "cmd", "git.exe"), start.FileName, StringComparison.OrdinalIgnoreCase);
        string[] arguments = [.. start.ArgumentList];
        Assert.Equal("--no-optional-locks", arguments[0]);
        Assert.Equal(@"B:\maliev-legacy\Legacy.Maliev.AuthService", arguments[2]);
        Assert.Contains("core.fsmonitor=false", arguments); Assert.Contains("core.untrackedCache=false", arguments);
        Assert.Equal(command == CurrentAuthGitCommand.Head ? "rev-parse" : "status", arguments[7]);
        Assert.Equal("0", start.Environment["GIT_OPTIONAL_LOCKS"]); Assert.Equal("NUL", start.Environment["GIT_CONFIG_GLOBAL"]);
        Assert.Equal("1", start.Environment["GIT_CONFIG_NOSYSTEM"]); Assert.Equal("0", start.Environment["GIT_TERMINAL_PROMPT"]);
        Assert.DoesNotContain("PATH", start.Environment.Keys); Assert.DoesNotContain("GH_TOKEN", start.Environment.Keys);
        Assert.DoesNotContain("GITHUB_TOKEN", start.Environment.Keys); Assert.DoesNotContain("PGPASSWORD", start.Environment.Keys);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthOwnerSourceReader.StartInfo((CurrentAuthGitCommand)3));
    }
    [Fact]
    public async Task Precancelled_owner_reader_never_starts_a_child()
    {
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel(); int frames = 0;
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAuthOwnerSourceReader.RunReadOnlyAsync(CurrentAuthGitCommand.Head,
            _ => { frames++; return Task.CompletedTask; }, cancellation.Token));
        Assert.Equal(0, frames);
    }
    [WindowsLocalRunTheory]
    [InlineData("cancel-at-start")]
    [InlineData("start-frame-failure")]
    [InlineData("final-frame-failure")]
    public async Task Exact_fixed_git_child_cleanup_is_observed_on_cancellation_and_evidence_failure(string fault)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows child custody proof requires Windows."); }
        using var cancellation = new CancellationTokenSource(); var frames = new List<CurrentAuthGitResource>();
        Task Observer(CurrentAuthGitResource resource)
        {
            frames.Add(resource);
            if (frames.Count == 1 && fault == "cancel-at-start") { cancellation.Cancel(); }
            return (frames.Count == 1 && fault == "start-frame-failure") || (resource.ReadersSettled && fault == "final-frame-failure")
                ? throw new IOException("synthetic immutable frame failure")
                : Task.CompletedTask;
        }
        _ = await Assert.ThrowsAnyAsync<Exception>(() => CurrentAuthOwnerSourceReader.RunReadOnlyAsync(CurrentAuthGitCommand.Head, Observer, cancellation.Token));
        Assert.True(frames.Count >= 2); CurrentAuthGitResource final = frames[^1];
        Assert.Equal(frames[0].RunId, final.RunId); Assert.Equal(frames[0].ProcessId, final.ProcessId);
        Assert.Equal(frames[0].StartUtcTicks, final.StartUtcTicks); Assert.Equal(64, final.ExecutableSha256.Length);
        Assert.True(final.Exited); Assert.True(final.ReadersSettled); Assert.False(final.CleanupFailed);
        if (final.ProcessId is { } pid)
        {
            try
            {
                using Process current = Process.GetProcessById(pid);
                Assert.True(current.HasExited || current.StartTime.ToUniversalTime().Ticks != final.StartUtcTicks);
            }
            catch (ArgumentException) { }
        }
    }
    [WindowsLocalRunFact]
    public async Task Successful_fixed_owner_head_read_retains_final_exit_and_settled_reader_observation()
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows child custody proof requires Windows."); }
        var frames = new List<CurrentAuthGitResource>();
        string head = await CurrentAuthOwnerSourceReader.RunReadOnlyAsync(CurrentAuthGitCommand.Head,
            resource => { frames.Add(resource); return Task.CompletedTask; }, CancellationToken.None);
        Assert.Equal(40, head.Trim().Length); Assert.Equal(2, frames.Count);
        Assert.Equal(frames[0].ProcessId, frames[1].ProcessId); Assert.Equal(frames[0].StartUtcTicks, frames[1].StartUtcTicks);
        Assert.True(frames[1].Exited); Assert.True(frames[1].ReadersSettled); Assert.False(frames[1].CleanupFailed);
    }
    [Theory]
    [InlineData("none")]
    [InlineData("current-app-owned-v3-proof")]
    [InlineData("wrong-operation")]
    [InlineData("wrong-binding")]
    [InlineData("wrong-name")]
    [InlineData("two-mounts")]
    public void Disposable_auth_target_refuses_foreign_labels_and_ambiguous_storage(string fault)
    {
        Guid operation = Guid.NewGuid(); string binding = new('a', 64); DateTimeOffset now = DateTimeOffset.UtcNow;
        string name = "legacy-delta-proof-" + operation.ToString("N");
        var labels = new Dictionary<string, string>
        {
            ["codex.repair.purpose"] = fault == "current-app-owned-v3-proof" ? fault : "current-auth-repair-proof",
            ["codex.repair.operation"] = fault == "wrong-operation" ? Guid.NewGuid().ToString("D") : operation.ToString("D"),
            ["codex.repair.run-binding"] = fault == "wrong-binding" ? new string('b', 64) : binding
        };
        object mount = new { Type = "volume", Name = name, RW = true };
        using JsonDocument container = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            Name = fault == "wrong-name" ? "/foreign" : "/" + name,
            Created = now.AddMinutes(-1),
            Config = new { Labels = labels },
            Mounts = fault == "two-mounts" ? new[] { mount, mount } : [mount]
        }));
        using JsonDocument volume = JsonDocument.Parse(JsonSerializer.Serialize(new { Name = name, CreatedAt = now.AddMinutes(-2), Labels = labels, Options = new { } }));
        if (fault == "none")
        { CurrentAuthRepairEnvironment.RequireAuthDisposable(container.RootElement, volume.RootElement, operation, binding, now); }
        else
        { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthRepairEnvironment.RequireAuthDisposable(container.RootElement, volume.RootElement, operation, binding, now)); }
    }
}
