using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class LocalDockerResourceObserverTests
{
    [Theory]
    [InlineData("remote-context")]
    [InlineData("container-id")]
    [InlineData("stopped")]
    [InlineData("host-network")]
    [InlineData("layer-missing")]
    [InlineData("layer-id")]
    [InlineData("mount-bind")]
    [InlineData("volume-driver")]
    [InlineData("volume-options")]
    [InlineData("volume-source")]
    [InlineData("volume-created")]
    [InlineData("stat-symlink")]
    [InlineData("stat-inode")]
    [InlineData("parent-symlink")]
    [InlineData("command-failure")]
    [InlineData("bad-json")]
    public async Task Inspect_UnsupportedOrUnverifiableResource_Rejects(string failure)
    {
        var process = new FakeDockerProcess { Failure = failure };
        MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            new LocalDockerResourceObserver(process).ObserveAsync(SourceObservationFixture.ContainerId, CancellationToken.None));
        Assert.StartsWith("source_observation_", error.Code);
        Assert.DoesNotContain("do-not-log", error.ToString());
        Assert.All(process.Commands, command => Assert.DoesNotContain(".Env", string.Join(' ', command)));
        if (failure == "remote-context") { Assert.Equal(2, process.Commands.Count); }
    }

    [Fact]
    public async Task Inspect_FullLocalIdentity_ReadOnlyCommandsAndPhysicalIdentity()
    {
        var process = new FakeDockerProcess();
        LocalDockerResourceState result = await new LocalDockerResourceObserver(process)
            .ObserveAsync(SourceObservationFixture.ContainerId, CancellationToken.None);
        Assert.Equal("7", Assert.Single(result.Mounts).FileSystemIdentity.Device);
        Assert.Equal("902", Assert.Single(result.Mounts).FileSystemIdentity.Inode);
        Assert.False(Assert.Single(result.Mounts).ReadWrite);
        Assert.Equal(SourceObservationFixture.ContainerId, result.Layer.Id);
        Assert.All(process.Commands.Where(command => command.Contains("exec")), command =>
        {
            Assert.Contains(SourceObservationFixture.ContainerId, command);
            Assert.True(command.Contains("stat") || command.Contains("readlink"));
            Assert.DoesNotContain("sh", command);
        });
    }
}

internal sealed class FakeDockerProcess : IReadOnlyDockerProcess
{
    internal bool ChangeOnRepeat;
    internal string? Failure;
    internal Func<IReadOnlyList<string>, string, BackupProcessResult>? BatchResult;
    internal readonly List<IReadOnlyList<string>> Commands = [];
    private int _containers;
    public Task<BackupProcessResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Commands.Add(arguments.ToArray());
        string[] args = arguments[0] == "--host" ? arguments.Skip(2).ToArray() : arguments.ToArray();
        if (Failure == "command-failure") { return Task.FromResult(new BackupProcessResult(1, "do-not-log", "do-not-log")); }
        if (args.SequenceEqual(["context", "show"])) { return Result("desktop-linux"); }
        if (args[0] == "context") { return Result(Failure == "remote-context" ? "ssh://remote" : "npipe:////./pipe/dockerDesktopLinuxEngine"); }
        if (args[0] == "exec")
        {
            if (args.Contains("--zero") || args.Contains("--printf=%n\\0%d\\0%i\\0%F\\0"))
            {
                string[] paths = args[(Array.IndexOf(args, "--") + 1)..];
                string output = args.Contains("readlink")
                    ? string.Concat(paths.Select(item => (Failure == "parent-symlink" ? "/redirected" : item) + "\0"))
                    : string.Concat(paths.Select(item => item + "\0" + "7\0" + (Failure == "stat-inode" ? "0" : "903") + "\0" +
                        (Failure == "stat-symlink" ? "symbolic link" : "regular file") + "\0"));
                return Task.FromResult(BatchResult?.Invoke(arguments, output) ?? new BackupProcessResult(0, output, ""));
            }
            string path = args[^1];
            if (args.Contains("readlink")) { return Result(Failure == "parent-symlink" ? "/redirected" : path); }
            string type = Failure == "stat-symlink" ? "symbolic link" : path is "/" or "/backup" ? "directory" : "regular file";
            return Result($"7|{(Failure == "stat-inode" ? "0" : path == "/" ? "901" : path == "/backup" ? "902" : "903")}|{type}");
        }
        JsonObject json;
        if (args[0] == "info")
        {
            json = new() { ["ID"] = "daemon-identity", ["DockerRootDir"] = "/var/lib/docker", ["OSType"] = "linux", ["Driver"] = "overlay2" };
        }
        else if (args[0] == "image")
        {
            json = new()
            {
                ["Id"] = SourceObservationFixture.ImageId,
                ["Created"] = "2026-08-01T00:00:00Z",
                ["Os"] = "linux",
                ["Architecture"] = "amd64",
                ["RepoDigests"] = new JsonArray("mcr.microsoft.com/mssql/server@sha256:" + new string('a', 64)),
                ["RootFS"] = new JsonObject { ["Type"] = "layers", ["Layers"] = new JsonArray("sha256:" + new string('b', 64)) }
            };
        }
        else if (args[0] == "volume")
        {
            json = new()
            {
                ["Name"] = "backup-volume",
                ["Driver"] = Failure == "volume-driver" ? "plugin" : "local",
                ["CreatedAt"] = Failure == "volume-created" ? "" : "2026-09-01T00:00:00Z",
                ["Mountpoint"] = Failure == "volume-source" ? "/elsewhere" : "/var/lib/docker/volumes/backup-volume/_data",
                ["Scope"] = "local",
                ["Options"] = Failure == "volume-options" ? new JsonObject { ["device"] = "/tmp/bind" } : null,
                ["RunBinding"] = "run-1",
                ["VolumeBinding"] = "backup-binding",
                ["Fingerprint"] = SourceObservationFixture.Fingerprint
            };
        }
        else if (args[0] == "container")
        {
            _containers++;
            json = new()
            {
                ["Id"] = Failure == "container-id" ? new string('b', 64) : SourceObservationFixture.ContainerId,
                ["Name"] = "/restore-test",
                ["Image"] = SourceObservationFixture.ImageId,
                ["Created"] = "2026-09-01T00:00:00Z",
                ["Hostname"] = "restore-host",
                ["RunBinding"] = "run-1",
                ["Running"] = Failure != "stopped",
                ["Paused"] = false,
                ["Restarting"] = false,
                ["StartedAt"] = ChangeOnRepeat && _containers > 1 ? "2026-09-02T00:00:00Z" : "2026-09-01T00:00:01Z",
                ["ReadonlyRootfs"] = false,
                ["NetworkMode"] = Failure == "host-network" ? "host" : Failure == "network-mode-changed" && _containers > 1 ? "default" : "bridge",
                ["GraphDriver"] = new JsonObject
                {
                    ["Name"] = "overlay2",
                    ["Data"] = new JsonObject
                    {
                        ["ID"] = Failure == "layer-id" ? "wrong" : SourceObservationFixture.ContainerId,
                        ["LowerDir"] = "/var/lib/docker/overlay2/lower/diff",
                        ["MergedDir"] = "/var/lib/docker/overlay2/layer/merged",
                        ["UpperDir"] = Failure == "layer-missing" ? "" : "/var/lib/docker/overlay2/layer/diff",
                        ["WorkDir"] = "/var/lib/docker/overlay2/layer/work",
                    }
                },
                ["Mounts"] = new JsonArray(new JsonObject
                {
                    ["Type"] = Failure == "mount-bind" ? "bind" : "volume",
                    ["Name"] = "backup-volume",
                    ["Source"] = "/var/lib/docker/volumes/backup-volume/_data",
                    ["Destination"] = "/backup",
                    ["Driver"] = "local",
                    ["Mode"] = "z",
                    ["RW"] = false,
                    ["Propagation"] = ""
                }),
                ["Networks"] = new JsonObject { ["bridge"] = new JsonObject { ["NetworkID"] = new string('d', 64), ["EndpointID"] = new string('e', 64), ["IPAddress"] = "172.18.0.2" } },
                ["Ports"] = new JsonObject { ["1433/tcp"] = new JsonArray(new JsonObject { ["HostIp"] = "127.0.0.1", ["HostPort"] = "15433" }) },
            };
            if (Failure == "mount-properties-changed" && _containers > 1) { json["Mounts"]![0]!["NewProperty"] = "changed"; }
        }
        else { throw new InvalidOperationException("Unexpected Docker operation."); }
        return Result(Failure == "bad-json" ? "not json" : json.ToJsonString());
    }

    private static Task<BackupProcessResult> Result(string output)
    {
        return Task.FromResult(new BackupProcessResult(0, output, ""));
    }
}
